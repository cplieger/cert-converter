package process

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestWriteOutcome_derives_the_status_from_two_independent_facts pins the single place
// an entry's outcome is decided, across every combination of the facts it reads.
//
// The routing exists in this shape because the previous one carried the facts
// through ONE value: the content comparison, the refused mode repair and the
// restart-clearability of the write all had to fit in a staleness cause, and every arm
// that could not verify the content overwrote it. That is what made the health-neutral
// outcome unreachable for an unverifiable bundle whose rewrite was refused, i.e. an
// unhealthy container on every scan over an /output permission state no restart can clear.
//
// Three properties are load-bearing here and none of them is visible from a single case:
//
//   - contentUnverified earns the same health-neutral treatment as contentVerifiedCurrent.
//     "I could not read it" is not "it is out of date", and only the second is evidence
//     that the operator is being served the wrong bundle.
//   - contentVerifiedStale NEVER earns it, whatever refused the write. A renewal this app
//     could not publish has to be loud, which is the README's /output contract.
//   - The clearability question is asked of the ERROR, not of the reason for the rewrite,
//     so the same errno routes the same way under both facts that grant neutrality.
//
// The bundle's MODE is deliberately absent from every case: it decides nothing here, and
// listing it would imply otherwise. contentUnresolved is here as the zero value: the
// derivation is spelled as an allowlist, so a fact it does not know takes the loud
// direction rather than silently inheriting neutrality.
func TestWriteOutcome_derives_the_status_from_two_independent_facts(t *testing.T) {
	t.Parallel()
	refused := &fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EACCES}
	full := &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.ENOSPC}
	brokenIO := &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.EIO}
	for name, tc := range map[string]struct {
		writeErr error
		state    bundleState
		want     conversionStatus
	}{
		"a write that landed is a conversion whatever the prior bundle was": {
			state: bundleState{content: contentVerifiedStale}, writeErr: nil, want: statusConverted,
		},
		"a write that landed over an unverifiable prior is a conversion too": {
			state: bundleState{content: contentUnverified}, writeErr: nil, want: statusConverted,
		},
		"a content-matched prior whose rewrite is refused for permissions is health-neutral": {
			state:    bundleState{content: contentVerifiedCurrent},
			writeErr: refused, want: statusUnwritable,
		},
		"a content-matched prior whose rewrite a full volume refuses is health-neutral too": {
			state:    bundleState{content: contentVerifiedCurrent},
			writeErr: full, want: statusUnwritable,
		},
		"an unverifiable prior whose rewrite is refused for permissions is health-neutral": {
			state: bundleState{content: contentUnverified}, writeErr: refused, want: statusUnwritable,
		},
		"an unverifiable prior whose rewrite a full volume refuses is health-neutral": {
			state: bundleState{content: contentUnverified}, writeErr: full, want: statusUnwritable,
		},
		"an unverifiable prior whose rewrite fails for an unattributable reason fails": {
			state: bundleState{content: contentUnverified}, writeErr: brokenIO, want: statusFailed,
		},
		"a content-matched prior whose rewrite fails for an unattributable reason fails": {
			state:    bundleState{content: contentVerifiedCurrent},
			writeErr: brokenIO, want: statusFailed,
		},
		"a stale bundle whose rewrite is refused for permissions is still a failure": {
			state: bundleState{content: contentVerifiedStale}, writeErr: refused, want: statusFailed,
		},
		"a stale bundle whose rewrite a full volume refuses is still a failure": {
			state: bundleState{content: contentVerifiedStale}, writeErr: full, want: statusFailed,
		},
		"a stale bundle whose rewrite fails for an unattributable reason is a failure": {
			state: bundleState{content: contentVerifiedStale}, writeErr: brokenIO, want: statusFailed,
		},
		"an unresolved fact takes the loud direction even under a refusal": {
			state: bundleState{}, writeErr: refused, want: statusFailed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := writeOutcome(tc.state, tc.writeErr); got != tc.want {
				t.Errorf("writeOutcome(%+v, %v) = %v, want %v", tc.state, tc.writeErr, got, tc.want)
			}
		})
	}
}

// TestRestartCanClearWrite_enumerates_the_unclearable_classes pins the third fact on its
// own, because it is the one health ultimately turns on: health answers "should an
// orchestrator restart this container?", so a write failure a restart cannot clear must
// never be the reason it restarts.
//
// The enumeration direction matters as much as the members. An error this app cannot
// attribute to a steady-state condition of the operator's volume is reported clearable —
// the loud direction — so a class nobody thought about flips health instead of being
// silently forgiven.
func TestRestartCanClearWrite_enumerates_the_unclearable_classes(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"EACCES is not clearable by a restart":                        {err: syscall.EACCES, want: false},
		"EPERM is not clearable by a restart":                         {err: syscall.EPERM, want: false},
		"a wrapped permission refusal is not clearable":               {err: &fs.PathError{Err: syscall.EACCES}, want: false},
		"an fs.ErrPermission a seam injects is not either":            {err: fs.ErrPermission, want: false},
		"EROFS is not clearable: a mount option outlives the process": {err: syscall.EROFS, want: false},
		"ENOSPC is not clearable: the volume is still full":           {err: syscall.ENOSPC, want: false},
		"EDQUOT is not clearable: the quota is still exhausted":       {err: syscall.EDQUOT, want: false},
		"EIO is reported clearable, the loud direction":               {err: syscall.EIO, want: true},
		"a symlink refusal is reported clearable":                     {err: errors.New("atomicfile: target is a symlink"), want: true},
		"an unrecognised error is reported clearable":                 {err: errors.New("boom"), want: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := restartCanClearWrite(tc.err); got != tc.want {
				t.Errorf("restartCanClearWrite(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestStoreInspect_reports_content_it_could_not_verify pins the FACT, at the boundary that
// resolves it, for the two prior bundles this app cannot compare: one above the readable
// bound, and one the codec's preflight refuses to look at.
//
// Both must report contentUnverified and NOT contentVerifiedStale. The distinction has no
// visible effect until a rewrite is refused, which is exactly why it needs its own test:
// the scan-level behaviour of both facts is identical (rewrite it), so a regression that
// collapsed them again would be invisible everywhere else and would restore the restart
// loop.
func TestStoreInspect_reports_content_it_could_not_verify(t *testing.T) {
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	for name, stage := range map[string]func(t *testing.T, dir string){
		"a prior above the readable bound was never read": func(t *testing.T, dir string) {
			t.Helper()
			stageOversizedBundle(t, filepath.Join(dir, "out.pfx"))
		},
		"a prior the preflight refuses was never compared": func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, "out.pfx"), []byte("not a pkcs12 bundle"), pfxFileMode); err != nil {
				t.Fatalf("setup: WriteFile: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, pfxDirMode); err != nil {
				t.Fatalf("setup: Chmod(dir): %v", err)
			}
			stage(t, dir)
			s := newOutputStore(t, dir)

			state, err := s.inspect(t.Context(), "out.pfx", &analysis, convert.EncNameModern2023, "pw")
			if err != nil {
				t.Fatalf("inspect(unverifiable prior) = error %v, want nil: it must resolve to a fact, not fail the pair", err)
			}
			if state.content != contentUnverified {
				t.Errorf("inspect(unverifiable prior) content = %v, want contentUnverified: nothing compared these"+
					" bytes, so calling them stale claims evidence this app does not have", state.content)
			}
			if state.upToDate() {
				t.Error("inspect(unverifiable prior).upToDate() = true, want false: a bundle this app cannot" +
					" verify must still be rewritten")
			}
		})
	}
}

// TestScannerRun_rewrites_a_bundle_it_could_not_verify pins the outcome that must NOT
// change: where the app can replace an unverifiable bundle, it does, and the scan is a
// clean conversion with health untouched.
//
// It is the control for the refusal test below. Making the refused case health-neutral is
// only correct if the writable case still converges — otherwise "health is unaffected"
// would be hiding a bundle nobody ever replaces.
func TestScannerRun_rewrites_a_bundle_it_could_not_verify(t *testing.T) {
	for name, stage := range map[string]func(t *testing.T, path string){
		"a prior above the readable bound": func(t *testing.T, path string) {
			t.Helper()
			stageOversizedBundle(t, path)
		},
		"a prior the preflight refuses": func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte("not a pkcs12 bundle"), pfxFileMode); err != nil {
				t.Fatalf("setup: WriteFile: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			certsRoot := t.TempDir()
			outRoot := t.TempDir()
			_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
			writePair(t, certsRoot, "chain", chainPEM, keyPEM)
			pfxPath := filepath.Join(outRoot, "chain.pfx")
			stage(t, pfxPath)

			scanner := New(&Options{
				CertsRoot: certsRoot,
				OutRoot:   outRoot,
				Password:  "pw",
				Encoder:   convert.EncNameModern2023,
			})
			res, err := scanner.Run(t.Context())
			if err != nil {
				t.Fatalf("Run(unverifiable prior) = error %v, want nil", err)
			}
			if res.Converted != 1 || res.Failed != 0 || res.Unwritable != 0 {
				t.Errorf("Run(unverifiable prior) = %+v, want Converted 1 Failed 0 Unwritable 0: an unverifiable"+
					" bundle this app CAN replace is an ordinary conversion", res)
			}
			// The replacement has to be a real bundle, not merely a smaller file: the point of
			// rewriting something unverifiable is that the operator ends up with the bundle
			// these inputs produce.
			written, _ := readBundle(t, pfxPath)
			if got := convert.CheckCurrency(written, "pw", mustAnalyse(t, chainPEM, keyPEM), convert.EncNameModern2023); !got.Current() {
				t.Errorf("Run(unverifiable prior) left a bundle CheckCurrency reports as %v, want a match", got.Reason)
			}
			// And the next scan must go quiet, or the app would churn the bundle (fresh KDF
			// salts, a fresh mtime, a re-replication downstream) on every scan forever.
			res, err = scanner.Run(t.Context())
			if err != nil || res.Unchanged != 1 || res.Converted != 0 {
				t.Errorf("Run(second scan) = %+v, %v, want Unchanged 1 Converted 0 and nil: the rewrite must converge",
					res, err)
			}
		})
	}
}

// TestScannerRun_when_an_unverifiable_bundle_cannot_be_rewritten is the defect this
// restructuring fixes, end to end through the real scan.
//
// A prior bundle this app cannot verify — above the readable bound here, the same class as
// an unreadable one — whose replacing write the volume refuses for a reason no restart can
// clear is HEALTH-NEUTRAL: nothing about the operator's inputs is missing or out of date as
// far as this app knows, it never compared the bytes on disk, and no restart grants a UID
// ownership of /output or frees a full volume. The previous routing could not reach that
// outcome at all: the arm that gave up on reading the bundle overwrote the reason for the
// rewrite, so this landed in ScanResult.Failed, flipped the health marker on EVERY scan,
// and the container restart-looped over a condition a restart cannot fix — the same mistake
// statusUnreadable exists to prevent on the /input side.
//
// Neutral is not silent: the standing WARN names the path, what this app knew about the
// content, and the operator action. And the loud default still stands — a write error this
// app cannot attribute to a steady-state condition of the volume is a conversion failure,
// which is the last case here and what keeps this from forgiving every failed write.
//
// The second scan matters as much as the first: the condition is steady state, so the WARN
// repeats once per scan rather than compounding, and the bundle an operator may still be
// serving must survive untouched.
// Runs serially: it swaps slog.Default() and the write seam.
func TestScannerRun_when_an_unverifiable_bundle_cannot_be_rewritten(t *testing.T) {
	// Spelled out rather than imported from the production consts: an operator's log query
	// keys on these words, so a silent rename must fail here.
	const unreplaceableMsg = "prior pfx could not be replaced and the /output condition that refused the write is" +
		" not one a restart clears; leaving the existing bundle in place, health is unaffected"
	const failedMsg = "conversion failed"
	for name, tc := range map[string]struct {
		writeErr        error
		wantRemediation string
		wantUnwritable  int
		wantFailed      int
	}{
		"a refused write leaves the unverifiable bundle in place without flipping health": {
			writeErr:       &fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EACCES},
			wantUnwritable: 1, wantRemediation: "check /output ownership and permissions for the UID in user:",
		},
		"an EPERM refusal of the same write is the same condition": {
			writeErr:       &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.EPERM},
			wantUnwritable: 1, wantRemediation: "check /output ownership and permissions for the UID in user:",
		},
		"a full volume is the same condition under the volume remediation": {
			writeErr:       &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.ENOSPC},
			wantUnwritable: 1, wantRemediation: "check /output for free space, a quota and a read-only mount",
		},
		"a write error this app cannot attribute to the volume is still a conversion failure": {
			writeErr:   &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.EIO},
			wantFailed: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			certsRoot := t.TempDir()
			outRoot := t.TempDir()
			_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
			writePair(t, certsRoot, "chain", chainPEM, keyPEM)
			pfxPath := filepath.Join(outRoot, "chain.pfx")
			// A prior bundle above the readable bound: present, at the policy mode (so the mode
			// arm is NOT what schedules the rewrite), and never compared.
			stageOversizedBundle(t, pfxPath)
			scanner := New(&Options{
				CertsRoot: certsRoot,
				OutRoot:   outRoot,
				Password:  "pw",
				Encoder:   convert.EncNameModern2023,
			})
			prevWrite := writeFileInRoot
			writeFileInRoot = func(context.Context, *os.Root, string, []byte,
				...atomicfile.Option,
			) (atomicfile.Result, error) {
				return atomicfile.Result{}, tc.writeErr
			}
			t.Cleanup(func() { writeFileInRoot = prevWrite })
			sizeBefore := statSize(t, pfxPath)

			logs := captureLogs(t)
			res, err := scanner.Run(t.Context())
			if err != nil {
				t.Fatalf("Run(unverifiable prior, refused rewrite) = error %v, want nil: neither outcome is a"+
					" scan-level failure", err)
			}
			if res.Unwritable != tc.wantUnwritable || res.Failed != tc.wantFailed || res.Converted != 0 {
				t.Errorf("Run(unverifiable prior, refused rewrite) = %+v, want Unwritable %d Failed %d Converted 0",
					res, tc.wantUnwritable, tc.wantFailed)
			}
			// The message is asserted by NAME: it is the only standing health-neutral WARN
			// left, and an operator's log query keys on its words.
			if got := logs.CountLevel(slog.LevelWarn, unreplaceableMsg); got != boolCount(tc.wantUnwritable > 0) {
				t.Errorf("Run(unverifiable prior, refused rewrite) logged %q at WARN %d times, want %d: %q",
					unreplaceableMsg, got, boolCount(tc.wantUnwritable > 0), logs.Messages())
			}
			if got := logs.CountLevel(slog.LevelError, failedMsg); got != boolCount(tc.wantFailed > 0) {
				t.Errorf("Run(unverifiable prior, refused rewrite) logged %q at ERROR %d times, want %d: %q",
					failedMsg, got, boolCount(tc.wantFailed > 0), logs.Messages())
			}
			if tc.wantUnwritable > 0 {
				for key, want := range map[string]string{
					"path":        "chain.crt",
					"output_path": "chain.pfx",
					"content":     "unverified",
					"remediation": tc.wantRemediation,
				} {
					if !logs.HasAttr(unreplaceableMsg, key, want) {
						got, _ := logs.AttrValue(unreplaceableMsg, key)
						t.Errorf("Run(unverifiable prior, refused rewrite) logged %s=%q, want %q", key, got, want)
					}
				}
			}
			// Nothing truncated, nothing half-written: a write that never landed must leave
			// whatever the operator has exactly as it was, so the next scan can try again.
			if got := statSize(t, pfxPath); got != sizeBefore {
				t.Errorf("Run(unverifiable prior, refused rewrite) left %d bytes at the output path, want %d"+
					" untouched", got, sizeBefore)
			}

			// Steady state: the same verdict and the same one line per scan, no compounding.
			res, err = scanner.Run(t.Context())
			if err != nil {
				t.Fatalf("Run(second scan) = error %v, want nil", err)
			}
			if res.Unwritable != tc.wantUnwritable || res.Failed != tc.wantFailed {
				t.Errorf("Run(second scan) = %+v, want Unwritable %d Failed %d unchanged",
					res, tc.wantUnwritable, tc.wantFailed)
			}
			if tc.wantUnwritable > 0 {
				if got := logs.CountLevel(slog.LevelWarn, unreplaceableMsg); got != 2 {
					t.Errorf("two scans logged %q at WARN %d times, want 2 (one per scan): %q",
						unreplaceableMsg, got, logs.Messages())
				}
			}
		})
	}
}

// TestScannerRun_a_genuine_conversion_failure_still_flips_health pins the DEFAULT of the
// restructured routing from the input side: the two failures that have nothing to do with
// the output tree still count in ScanResult.Failed, which is the field
// main.healthyAfterScan reads.
//
// It sits beside the health-neutral tests deliberately. Every one of those grants
// neutrality on a fact about the bundle already on disk; a pair that cannot be ANALYSED
// never reaches that question, so if a future simplification moved the neutrality check
// earlier — or widened it to "any entry this scan could not publish" — these two would be
// the first casualties, and the container would stay green while nothing converts.
func TestScannerRun_a_genuine_conversion_failure_still_flips_health(t *testing.T) {
	const unreplaceableMsg = "prior pfx could not be replaced and the /output condition that refused the write is" +
		" not one a restart clears; leaving the existing bundle in place, health is unaffected"
	for name, stage := range map[string]func(t *testing.T, certsRoot string){
		"an unparseable certificate": func(t *testing.T, certsRoot string) {
			t.Helper()
			_, keyPEM := testcerts.GenerateSelfSignedCert(t, "broken.example.com", "ecdsa")
			writePair(t, certsRoot, "broken",
				[]byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"), keyPEM)
		},
		"a key that belongs to another certificate": func(t *testing.T, certsRoot string) {
			t.Helper()
			certPEM, _ := testcerts.GenerateSelfSignedCert(t, "one.example.com", "ecdsa")
			_, otherKeyPEM := testcerts.GenerateSelfSignedCert(t, "two.example.com", "ecdsa")
			writePair(t, certsRoot, "broken", certPEM, otherKeyPEM)
		},
	} {
		t.Run(name, func(t *testing.T) {
			certsRoot := t.TempDir()
			outRoot := t.TempDir()
			stage(t, certsRoot)

			logs := captureLogs(t)
			res, err := New(&Options{
				CertsRoot: certsRoot,
				OutRoot:   outRoot,
				Password:  "pw",
				Encoder:   convert.EncNameModern2023,
			}).Run(t.Context())
			if err != nil {
				t.Fatalf("Run(unconvertible pair) = error %v, want nil: a pair-level failure is not a scan-level one", err)
			}
			if res.Failed != 1 || res.Unwritable != 0 || res.Converted != 0 {
				t.Errorf("Run(unconvertible pair) = %+v, want Failed 1 Unwritable 0 Converted 0: health has to flip"+
					" on a pair this app cannot convert at all", res)
			}
			if got := logs.CountLevel(slog.LevelError, "conversion failed"); got != 1 {
				t.Errorf("Run(unconvertible pair) logged %q at ERROR %d times, want exactly 1: %q",
					"conversion failed", got, logs.Messages())
			}
			if got := logs.CountLevel(slog.LevelWarn, unreplaceableMsg); got != 0 {
				t.Errorf("Run(unconvertible pair) logged %q at WARN %d times, want 0: the health-neutral WARN"+
					" describes a bundle on disk, and this failure never got that far: %q",
					unreplaceableMsg, got, logs.Messages())
			}
		})
	}
}

// stageOversizedBundle plants a prior bundle above maxPFXSize at path, at the policy mode
// so nothing about the FILE MODE contributes to the outcome. Sparse: no bytes are written,
// only the reported size crosses the bound, which is the same fixture shape
// TestStoreInspect_regenerates_an_oversized_prior uses.
func stageOversizedBundle(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, pfxFileMode)
	if err != nil {
		t.Fatalf("setup: OpenFile: %v", err)
	}
	if err := f.Truncate(maxPFXSize + 1); err != nil {
		t.Fatalf("setup: Truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("setup: Close: %v", err)
	}
	if err := os.Chmod(path, pfxFileMode); err != nil {
		t.Fatalf("setup: Chmod: %v", err)
	}
}

// statSize reports the size at path, so a test can prove a refused write left the file
// alone without reading maxPFXSize bytes back.
func statSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%s): %v", path, err)
	}
	return fi.Size()
}

// mustAnalyse resolves a pair the way the scanner does, for tests that need the analysis
// only to ask CheckCurrency whether a written bundle matches it.
func mustAnalyse(t *testing.T, certPEM, keyPEM []byte) *convert.Analysis {
	t.Helper()
	analysis, err := convert.Analyse(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	return &analysis
}

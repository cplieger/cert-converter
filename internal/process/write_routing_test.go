package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
//   - contentUnverified is the ONE fact that earns the health-neutral treatment. "I could
//     not read it" is not "it is out of date", and only the second is evidence that the
//     operator is being served the wrong bundle.
//   - contentVerifiedStale NEVER earns it, whatever refused the write. A renewal this app
//     could not publish has to be loud, which is the README's /output contract.
//   - The clearability question is answered by the REFUSAL ITSELF, at the site that
//     refused, and read here from the carried cause — never re-derived from the error and
//     never from the reason for the rewrite.
//
// The bundle's MODE is deliberately absent from every case: it decides nothing here, and
// listing it would imply otherwise. contentUnresolved is here as the zero value: the
// derivation is spelled as an allowlist, so a fact it does not know takes the loud
// direction rather than silently inheriting neutrality.
//
// Every refusal is minted through refuseWrite with the cause the corresponding refusal
// site states, because that carried cause IS what writeOutcome reads now — the error value
// it wraps is diagnostic only.
func TestWriteOutcome_derives_the_status_from_two_independent_facts(t *testing.T) {
	t.Parallel()
	refused := refuseWrite(refusalOwnership, "write pfx: %w",
		&fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EACCES})
	full := refuseWrite(refusalVolume, "write pfx: %w",
		&fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.ENOSPC})
	brokenIO := refuseWrite(refusalTransient, "write pfx: %w",
		&fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.EIO})
	for name, tc := range map[string]struct {
		writeErr writeRefusal
		state    contentState
		want     conversionStatus
	}{
		"a write that landed is a conversion whatever the prior bundle was": {
			state: contentVerifiedStale, writeErr: nil, want: statusConverted,
		},
		"a write that landed over an unverifiable prior is a conversion too": {
			state: contentUnverified, writeErr: nil, want: statusConverted,
		},
		"an unverifiable prior whose rewrite is refused for permissions is health-neutral": {
			state: contentUnverified, writeErr: refused, want: statusUnwritable,
		},
		"an unverifiable prior whose rewrite a full volume refuses is health-neutral": {
			state: contentUnverified, writeErr: full, want: statusUnwritable,
		},
		"an unverifiable prior whose rewrite fails for an unattributable reason fails": {
			state: contentUnverified, writeErr: brokenIO, want: statusFailed,
		},
		"a stale bundle whose rewrite is refused for permissions is still a failure": {
			state: contentVerifiedStale, writeErr: refused, want: statusFailed,
		},
		"a stale bundle whose rewrite a full volume refuses is still a failure": {
			state: contentVerifiedStale, writeErr: full, want: statusFailed,
		},
		"a stale bundle whose rewrite fails for an unattributable reason is a failure": {
			state: contentVerifiedStale, writeErr: brokenIO, want: statusFailed,
		},
		"an unresolved fact takes the loud direction even under a refusal": {
			state: contentUnresolved, writeErr: refused, want: statusFailed,
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

// TestWriteRefusal_carries_a_classification_from_every_refusal_site is the invariant this
// restructuring exists to hold, pinned at the producers: EVERY refusal of an /output write
// states its own class, at the point of refusal, and store.write's three refusal sites do
// not agree about anything except being failures.
//
// It is a table over the SITES rather than over an error-classifying predicate, and that
// is the whole point. The predicate this replaced (restartCanClearWrite) enumerated error
// values with a `default: return true`, so a refusal site nobody had registered there was
// silently called clearable — the health marker dropped on every scan and the container
// restart-looped over an /output layout no restart changes. A fourth site cannot reach that
// state now: store.write returns writeRefusal, whose only constructor takes the cause as
// its first parameter, so a site that states nothing does not compile. This test is the
// other half — it fails if a site stops carrying the verdict it diagnosed, or starts
// carrying a different one.
//
// Each case drives the REAL store through a real refusal rather than injecting an error, so
// what is asserted is the class the site actually reaches for on the condition it actually
// meets. Site 1's residual arm — a MkdirAll failure that is NOT the layout state that site
// names itself — shares classifyWriteErrno with site 3, so site 3's errno rows below cover
// the classifier and site 1's own rows cover the layout class it states directly. The suite
// runs as root, so no fixture here can stage a genuine EACCES; the three volume and
// ownership rows go through the write seam for the same reason writeFileInRoot is a seam
// at all.
//
// Runs serially: several cases swap the write seam.
func TestWriteRefusal_carries_a_classification_from_every_refusal_site(t *testing.T) {
	for name, tc := range map[string]struct {
		// stage builds the /output condition, and returns the root-relative name the
		// write is asked to publish to.
		stage func(t *testing.T, dir string) string
		// pfx is the bundle offered to the write; nil means a small ordinary one.
		pfx             []byte
		want            writeRefusalCause
		wantClearable   bool
		wantRemediation string
	}{
		// Site 1: s.root.MkdirAll. A regular file occupying the LAST component of the
		// mirrored directory path is EEXIST (mkdirat), and one occupying an EARLIER
		// component is ENOTDIR (openat). Both are the same operator layout, so the site
		// states the layout class for both rather than leaving an errno to be matched.
		"a file occupying the mirrored output directory is a layout refusal": {
			stage: func(t *testing.T, dir string) string {
				t.Helper()
				writeBlocker(t, filepath.Join(dir, "sub"))
				return filepath.Join("sub", "out.pfx")
			},
			want: refusalOutputLayout, wantClearable: false, wantRemediation: outputPinRemediation,
		},
		"a file occupying an ancestor of it is the same layout refusal": {
			stage: func(t *testing.T, dir string) string {
				t.Helper()
				writeBlocker(t, filepath.Join(dir, "sub"))
				return filepath.Join("sub", "nested", "out.pfx")
			},
			want: refusalOutputLayout, wantClearable: false, wantRemediation: outputPinRemediation,
		},
		// Site 2: atomicfile.OpenParentInRoot. The directory exists and MkdirAll is happy
		// with it, so only the pin refuses: a symlink inside the root is exactly what
		// confinement alone permits and the pin does not.
		"a symlinked output parent is a layout refusal the pin makes": {
			stage: func(t *testing.T, dir string) string {
				t.Helper()
				if err := os.Mkdir(filepath.Join(dir, "real"), pfxDirMode); err != nil {
					t.Fatalf("setup: Mkdir(real): %v", err)
				}
				if err := os.Symlink("real", filepath.Join(dir, "sub")); err != nil {
					t.Fatalf("setup: Symlink: %v", err)
				}
				return filepath.Join("sub", "out.pfx")
			},
			want: refusalOutputLayout, wantClearable: false, wantRemediation: outputPinRemediation,
		},
		// Site 3: the bounded atomic write, where the errno classes live. A bundle above
		// maxPFXSize is refused by the cap rather than by the volume, so it is the one
		// class a restart could plausibly clear and it keeps the loud outcome.
		"a bundle above the read bound is a transient refusal the write makes": {
			stage: func(_ *testing.T, _ string) string { return "out.pfx" },
			pfx:   make([]byte, maxPFXSize+1),
			want:  refusalTransient, wantClearable: true, wantRemediation: outputTransientRemediation,
		},
		// Site 3 again, through the seam, because a read-only mount and a full volume
		// cannot be staged in a directory the suite owns.
		"a read-only mount is a volume refusal the write makes": {
			stage: func(t *testing.T, _ string) string {
				t.Helper()
				stubWriteRefusal(t, &fs.PathError{Op: "renameat", Path: "out.pfx", Err: syscall.EROFS})
				return "out.pfx"
			},
			want: refusalVolume, wantClearable: false, wantRemediation: outputVolumeRemediation,
		},
		"an exhausted quota is a volume refusal too": {
			stage: func(t *testing.T, _ string) string {
				t.Helper()
				stubWriteRefusal(t, &fs.PathError{Op: "renameat", Path: "out.pfx", Err: syscall.EDQUOT})
				return "out.pfx"
			},
			want: refusalVolume, wantClearable: false, wantRemediation: outputVolumeRemediation,
		},
		"a permission denial is an ownership refusal the write makes": {
			stage: func(t *testing.T, _ string) string {
				t.Helper()
				stubWriteRefusal(t, &fs.PathError{Op: "openat", Path: "out.pfx", Err: syscall.EACCES})
				return "out.pfx"
			},
			want: refusalOwnership, wantClearable: false, wantRemediation: outputPermRemediation,
		},
		// Site 3, one more time, for the class that keeps the LOUD outcome. It is here so the
		// unclearable rows above cannot pass under a classifier that answers "unclearable"
		// for everything.
		"a genuinely transient I/O error keeps the clearable class": {
			stage: func(t *testing.T, _ string) string {
				t.Helper()
				stubWriteRefusal(t, &fs.PathError{Op: "renameat", Path: "out.pfx", Err: syscall.EIO})
				return "out.pfx"
			},
			want: refusalTransient, wantClearable: true, wantRemediation: outputTransientRemediation,
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, pfxDirMode); err != nil {
				t.Fatalf("setup: Chmod(dir): %v", err)
			}
			s := newOutputStore(t, dir)
			rel := tc.stage(t, dir)
			pfx := tc.pfx
			if pfx == nil {
				pfx = []byte("bundle")
			}

			refusal := s.write(t.Context(), rel, pfx)
			if refusal == nil {
				t.Fatalf("store.write(%s) = nil, want a refusal: the fixture staged a condition"+
					" the write cannot publish through", rel)
			}
			if got := refusal.cause(); got != tc.want {
				t.Errorf("store.write(%s).cause() = %v, want %v: the site that refuses states its own"+
					" class, and nothing downstream may re-derive it from %v", rel, got, tc.want, refusal)
			}
			// The two facts the carried class decides, asserted here rather than only on the
			// enum, so a site carrying the wrong class cannot pass by being self-consistent.
			if got := refusal.cause().restartCanClear(); got != tc.wantClearable {
				t.Errorf("store.write(%s).cause().restartCanClear() = %v, want %v", rel, got, tc.wantClearable)
			}
			if got := refusal.cause().remediation(); got != tc.wantRemediation {
				t.Errorf("store.write(%s).cause().remediation() = %q, want %q: an operator sent after the"+
					" wrong cause reads the WARN as noise", rel, got, tc.wantRemediation)
			}
			// The diagnosis has to survive the classification: the refusal still names the
			// write step, and the wrapped error is still reachable by errors.Is.
			if !strings.Contains(refusal.Error(), "write pfx") {
				t.Errorf("store.write(%s) error = %q, want it to name the write step", rel, refusal.Error())
			}
		})
	}
}

// TestWriteRefusalCause_states_both_facts_for_every_declared_cause is the enum-side half
// of the same invariant: a cause added to the enum without stating what it MEANS fails
// here.
//
// refuseWrite's required parameter stops a refusal site from omitting a class; this stops
// a class from omitting its consequences. The walk is over [0, refusalCauseCount), so a
// member added above the count sentinel arrives in this table's iteration with no entry
// and the test fails naming it — which is the only way the two consumers
// (writeOutcome via restartCanClear, reportWriteFailure via remediation) can be kept from
// silently answering for a condition nobody characterised.
//
// The zero value is included deliberately. It is not a cause and nothing produces it, so
// what is pinned is the DIRECTION it takes if one ever reaches a consumer: unclearable,
// the same direction as any unrecognised cause, because the direction that used to be free
// is the one that restart-loops a container.
func TestWriteRefusalCause_states_both_facts_for_every_declared_cause(t *testing.T) {
	t.Parallel()
	want := map[writeRefusalCause]struct {
		name        string
		clearable   bool
		remediation string
	}{
		refusalUnclassified: {"refusalUnclassified", false, outputPermRemediation},
		refusalOwnership:    {"refusalOwnership", false, outputPermRemediation},
		refusalOutputLayout: {"refusalOutputLayout", false, outputPinRemediation},
		refusalVolume:       {"refusalVolume", false, outputVolumeRemediation},
		refusalTransient:    {"refusalTransient", true, outputTransientRemediation},
	}
	for c := range refusalCauseCount {
		tc, ok := want[c]
		if !ok {
			t.Errorf("writeRefusalCause(%d) is declared but states neither of its two facts here:"+
				" a cause added without a restart verdict and a remediation lets writeOutcome and"+
				" reportWriteFailure answer for a condition nobody characterised", int(c))
			continue
		}
		if got := c.restartCanClear(); got != tc.clearable {
			t.Errorf("%s.restartCanClear() = %v, want %v", tc.name, got, tc.clearable)
		}
		if got := c.remediation(); got != tc.remediation {
			t.Errorf("%s.remediation() = %q, want %q", tc.name, got, tc.remediation)
		}
	}
	if len(want) != int(refusalCauseCount) {
		t.Errorf("this table holds %d causes and the enum declares %d: a cause was removed without"+
			" removing its expectation, so the walk above no longer covers the enum", len(want), refusalCauseCount)
	}
	// refusalTransient is the ONE clearable cause, asserted as a property rather than
	// case by case: restartCanClear is an allowlist precisely so a cause added later is
	// unclearable by construction, and a switch that grew a second clearable arm would
	// restore the fail-open direction this shape replaced.
	for c := range refusalCauseCount {
		if c.restartCanClear() && c != refusalTransient {
			t.Errorf("writeRefusalCause(%d).restartCanClear() = true, want only refusalTransient to be"+
				" clearable: any other clearable cause reopens the restart loop", int(c))
		}
	}
}

// TestStoreWrite_a_refusal_stays_unwrappable_so_a_cancelled_write_reads_as_shutdown pins
// the one contract the refusal's classification must not cost: errors.Is still walks
// THROUGH it.
//
// reportWriteFailure hands the refusal to failEntry, whose shutdown split is
// errors.Is(err, context.Canceled). A wrapper that carries a cause but drops Unwrap makes
// that false, so a write interrupted by SIGTERM logs "conversion failed" at ERROR and
// raises the documented CertConverterConversionFailed alert on every normal container
// stop. This repo has already shipped that exact bug once from a wrapper missing Unwrap,
// which is why the property gets a test rather than a comment — and why
// (classifiedWriteError).Unwrap is in .punused-ignore rather than deleted as unreferenced.
//
// Runs serially: it swaps the write seam.
func TestStoreWrite_a_refusal_stays_unwrappable_so_a_cancelled_write_reads_as_shutdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, pfxDirMode); err != nil {
		t.Fatalf("setup: Chmod(dir): %v", err)
	}
	s := newOutputStore(t, dir)
	stubWriteRefusal(t, fmt.Errorf("atomicfile: staging the temp: %w", context.Canceled))

	refusal := s.write(t.Context(), "out.pfx", []byte("bundle"))
	if refusal == nil {
		t.Fatal("store.write(cancelled) = nil, want a refusal")
	}
	if !errors.Is(refusal, context.Canceled) {
		t.Errorf("errors.Is(store.write(cancelled), context.Canceled) = false, want true: the refusal has"+
			" to stay unwrappable, or IsShutdown reports a normal SIGTERM as a conversion failure at"+
			" ERROR and pages an operator. Got %q", refusal.Error())
	}
	if !IsShutdown(refusal) {
		t.Error("IsShutdown(store.write(cancelled)) = false, want true: this is the exact call" +
			" failEntry makes to choose Debug over ERROR")
	}
	// And the classification still travelled: a cancelled write is not one of the volume's
	// steady-state conditions, so it keeps the loud class.
	if got := refusal.cause(); got != refusalTransient {
		t.Errorf("store.write(cancelled).cause() = %v, want refusalTransient", got)
	}
}

// writeBlocker plants a regular file at path, so a store.write asked to create a
// directory there meets the operator layout it cannot publish through.
func writeBlocker(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("blocker"), pfxFileMode); err != nil {
		t.Fatalf("setup: WriteFile(blocker): %v", err)
	}
}

// stubWriteRefusal makes the bounded atomic write fail with err for the rest of the test.
// The seam is the only way in for a read-only mount, a full volume and an exhausted quota:
// the suite owns every directory it creates, and as root nothing refuses it at all.
// A test using it runs serially.
func stubWriteRefusal(t *testing.T, err error) {
	t.Helper()
	prev := writeFileInRoot
	writeFileInRoot = func(context.Context, *os.Root, string, []byte,
		...atomicfile.Option,
	) (atomicfile.Result, error) {
		return atomicfile.Result{}, err
	}
	t.Cleanup(func() { writeFileInRoot = prev })
}

// TestStoreInspect_reports_content_it_could_not_verify pins the FACT, at the boundary that
// resolves it, for the two prior bundles this app cannot compare: one above the readable
// bound, and one whose declared key-derivation work the codec's preflight refuses to
// spend. A file the preflight PROVES foreign is a different fact and is verified stale.
//
// Both must report contentUnverified and NOT contentVerifiedStale. The distinction has no
// visible effect until a rewrite is refused, which is exactly why it needs its own test:
// the scan-level behaviour of both facts is identical (rewrite it), so a regression that
// collapsed them again would be invisible everywhere else and would restore the restart
// loop.
func TestStoreInspect_reports_content_it_could_not_verify(t *testing.T) {
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	for name, stage := range map[string]func(t *testing.T, dir string){
		"a prior above the readable bound was never read": func(t *testing.T, dir string) {
			t.Helper()
			stageOversizedBundle(t, filepath.Join(dir, "out.pfx"))
		},
		"a prior whose declared derivation work the preflight refuses was never compared": func(t *testing.T, dir string) {
			t.Helper()
			stageBudgetRefusedBundle(t, filepath.Join(dir, "out.pfx"), &analysis)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, pfxDirMode); err != nil {
				t.Fatalf("setup: Chmod(dir): %v", err)
			}
			stage(t, dir)
			s := newOutputStore(t, dir)

			state, err := s.inspect(t.Context(), "out.pfx", analysis, convert.EncNameModern2023, "pw")
			if err != nil {
				t.Fatalf("inspect(unverifiable prior) = error %v, want nil: it must resolve to a fact, not fail the pair", err)
			}
			if state != contentUnverified {
				t.Errorf("inspect(unverifiable prior) content = %v, want contentUnverified: nothing compared these"+
					" bytes, so calling them stale claims evidence this app does not have", state)
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
			want := mustAnalyse(t, chainPEM, keyPEM)
			if got := want.CheckCurrency(written, "pw", convert.EncNameModern2023); !got.Current() {
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
		" not one a restart clears; whatever is at the output path is left as found, health is unaffected"
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
			stubWriteRefusal(t, tc.writeErr)
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

// TestScannerRun_when_the_output_parent_cannot_be_pinned pins the routing for the
// /output LAYOUT this app cannot publish through: a mirrored path whose parent is a
// symlink inside the output tree.
//
// It is the same class as the errno refusals above and it reaches health the same way, but
// through a different door: the pin refusal is not an errno, so without
// errOutputPinRefused it fell into restartCanClearWrite's clearable default and every scan
// of a symlinked output sub-directory counted a conversion failure — the health marker
// removed on every cycle over a layout no restart changes, which is the /input symlink
// restart loop the healthcheck contract already rules out.
//
// The bundle already there is up to date, which is what makes the previous outcome plainly
// wrong: nothing about the operator's certificates is missing or stale, and the file is
// left exactly as it was found.
// Runs serially: it swaps slog.Default().
func TestScannerRun_when_the_output_parent_cannot_be_pinned(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
	// The pair lives one directory down, so the output path this scan publishes to is
	// mirrored under a parent component the pin has to descend through.
	inputSub := filepath.Join(certsRoot, "sub")
	if err := os.Mkdir(inputSub, pfxDirMode); err != nil {
		t.Fatalf("setup: Mkdir(input sub): %v", err)
	}
	writePair(t, inputSub, "chain", chainPEM, keyPEM)
	// The real output directory, holding the bundle these very inputs produce...
	realDir := filepath.Join(outRoot, "real")
	if err := os.Mkdir(realDir, pfxDirMode); err != nil {
		t.Fatalf("setup: Mkdir(out real): %v", err)
	}
	analysis := mustAnalyse(t, chainPEM, keyPEM)
	current, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	pfxPath := filepath.Join(realDir, "chain.pfx")
	if err := os.WriteFile(pfxPath, current, pfxFileMode); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	// ...and the mirrored name is a relative symlink to it: inside the root, so
	// confinement alone permits it and only the pin refuses.
	if err := os.Symlink("real", filepath.Join(outRoot, "sub")); err != nil {
		t.Fatalf("setup: Symlink: %v", err)
	}

	logs := captureLogs(t)
	res, err := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	}).Run(t.Context())
	if err != nil {
		t.Fatalf("Run(symlinked output sub-directory) = error %v, want nil: an /output layout is not a"+
			" scan-level failure", err)
	}
	if res.Unwritable != 1 || res.Failed != 0 || res.Converted != 0 {
		t.Errorf("Run(symlinked output sub-directory) = %+v, want Unwritable 1 Failed 0 Converted 0: no"+
			" restart re-reads a different /output layout, so this must not flip health", res)
	}
	if got := logs.CountLevel(slog.LevelWarn, unreplaceableBundleMsg); got != 1 {
		t.Errorf("Run(symlinked output sub-directory) logged %q at WARN %d times, want 1: neutral is not"+
			" silent: %q", unreplaceableBundleMsg, got, logs.Messages())
	}
	// And it names the LAYOUT remediation: a pin refusal is not a volume condition, so an
	// operator sent to check free space, a quota and a read-only mount is sent after a
	// cause that is not there while the symlinked tree stays as it is.
	if got, ok := logs.AttrValue(unreplaceableBundleMsg, "remediation"); !ok || got != outputPinRemediation {
		t.Errorf("Run(symlinked output sub-directory) %q remediation = %v (present %v), want %q: the"+
			" standing record has to name the cause the pin actually refused",
			unreplaceableBundleMsg, got, ok, outputPinRemediation)
	}
	// The existing bundle an operator may still be serving is left exactly as found, which
	// is what the WARN promises.
	if got, _ := readBundle(t, pfxPath); !bytes.Equal(got, current) {
		t.Errorf("Run(symlinked output sub-directory) left %d bytes at the output path, want the %d it"+
			" found: a refused write must not touch the bundle in place", len(got), len(current))
	}
}

// TestScannerRun_when_a_file_blocks_the_mirrored_output_directory pins the routing for the
// one-level mirrored layout: a regular file occupying /output/<dir>, where the pair lives at
// /input/<dir>/<name>.crt. Root.MkdirAll reports EEXIST there, not ENOTDIR, so a classifier
// keyed on the errno alone left this -- the canonical mirrored shape -- counting a conversion
// failure on every scan over a layout no restart changes.
// Runs serially: it swaps slog.Default().
func TestScannerRun_when_a_file_blocks_the_mirrored_output_directory(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
	inputSub := filepath.Join(certsRoot, "sub")
	if err := os.Mkdir(inputSub, pfxDirMode); err != nil {
		t.Fatalf("setup: Mkdir(input sub): %v", err)
	}
	writePair(t, inputSub, "chain", chainPEM, keyPEM)
	// A regular file where the mirrored output directory has to be created.
	if err := os.WriteFile(filepath.Join(outRoot, "sub"), []byte("blocker"), pfxFileMode); err != nil {
		t.Fatalf("setup: WriteFile(blocker): %v", err)
	}

	logs := captureLogs(t)
	res, err := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	}).Run(t.Context())
	if err != nil {
		t.Fatalf("Run(file blocking the mirrored output directory) = error %v, want nil: an /output"+
			" layout is not a scan-level failure", err)
	}
	if res.Unwritable != 1 || res.Failed != 0 || res.Converted != 0 {
		t.Errorf("Run(file blocking the mirrored output directory) = %+v, want Unwritable 1 Failed 0"+
			" Converted 0: no restart removes the file, so this must not flip health", res)
	}
	if got := logs.CountLevel(slog.LevelWarn, unreplaceableBundleMsg); got != 1 {
		t.Errorf("Run(file blocking the mirrored output directory) logged %q at WARN %d times, want 1:"+
			" neutral is not silent: %q", unreplaceableBundleMsg, got, logs.Messages())
	}
	// And it names the LAYOUT cause, not the volume: nothing here is about free space.
	if got, ok := logs.AttrValue(unreplaceableBundleMsg, "remediation"); !ok || got != outputPinRemediation {
		t.Errorf("Run(file blocking the mirrored output directory) %q remediation = %v (present %v),"+
			" want %q", unreplaceableBundleMsg, got, ok, outputPinRemediation)
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
		" not one a restart clears; whatever is at the output path is left as found, health is unaffected"
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

// stageBudgetRefusedBundle plants a prior bundle at path whose FIRST declared
// key-derivation iteration count is a two-byte maximum, so the preflight refuses to spend
// the work and nothing about the bytes is ever compared. The replacement keeps the DER
// length identical, so the surrounding structure stays valid and only the count changes;
// a foreign or truncated file would not do, because the preflight PROVES those are not
// one of this app's bundles and grades them verified stale.
func stageBudgetRefusedBundle(t *testing.T, path string, analysis *convert.Analysis) {
	t.Helper()
	pfx, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	encoded2048 := []byte{0x02, 0x02, 0x08, 0x00}
	if !bytes.Contains(pfx, encoded2048) {
		t.Fatalf("no DER-encoded 2048-iteration count found in a modern2023 bundle: the pinned encoder's" +
			" framing changed, so this fixture no longer produces a budget refusal")
	}
	patched := bytes.Replace(pfx, encoded2048, []byte{0x02, 0x02, 0x7f, 0xff}, 1)
	if err := os.WriteFile(path, patched, pfxFileMode); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
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
func mustAnalyse(t *testing.T, certPEM, keyPEM []byte) convert.Analysis {
	t.Helper()
	analysis, err := convert.Analyse(t.Context(), certPEM, keyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	return analysis
}

// TestScannerRun_inspect_cancelled_by_shutdown_is_reported_quietly pins the one
// producer of the README's second CertConverterConversionFailed matcher, and the
// quiet direction its alert filter depends on.
//
// The alert matches `(conversion failed|failed to inspect existing pfx)` and drops
// `(shutdown)`, and the README states the dropped variants are logged at DEBUG. The
// inspect-error arm of convertEntry is the only site that emits "failed to inspect
// existing pfx", and inspect's only error returns are shutdown races — so if that arm
// ever stopped routing through failEntry's shutdown split, every SIGTERM that lands
// mid-inspect would page an operator, with the whole suite green. The message is
// spelled out here, not read from production, exactly as the health-neutral write
// tests spell theirs: a reword must fail this test, because it silently kills the
// documented alert.
//
// The final assertion is the durability half: a cancelled inspect must not be read
// as "stale" on the way out, or every in-flight pair would be rewritten at shutdown
// with fresh KDF salts and a fresh mtime the documented deployment re-replicates.
//
// Runs serially: it swaps slog.Default() and the read seam.
func TestScannerRun_inspect_cancelled_by_shutdown_is_reported_quietly(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
	writePair(t, certsRoot, "chain", chainPEM, keyPEM)
	// A prior bundle on disk, so inspect gets past its classifying Lstat and the
	// cancellation lands where only the read seam can put it: between the walk's
	// entry check and inspect's own pre-verdict context check.
	prior := []byte("prior bundle this scan never proved wrong")
	pfxPath := filepath.Join(outRoot, "chain.pfx")
	if err := os.WriteFile(pfxPath, prior, 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	prevRead := readBoundedInRoot
	readBoundedInRoot = func(rctx context.Context, _ *os.Root, _ string, _ int64) ([]byte, error) {
		cancel()
		return nil, rctx.Err()
	}
	t.Cleanup(func() { readBoundedInRoot = prevRead })

	logs := captureLogs(t)
	res, err := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	}).Run(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run(cancelled during inspect) error = %v, want context.Canceled: without the walk-level"+
			" cancellation the caller reports a completed scan whose failed count is a shutdown artifact", err)
	}
	if res.Failed != 1 {
		t.Errorf("Run(cancelled during inspect) Failed = %d, want 1: the entry's outcome is recorded, and the"+
			" returned error is what keeps it from reaching the health marker", res.Failed)
	}
	if got := logs.CountLevel(slog.LevelDebug, "failed to inspect existing pfx (shutdown)"); got != 1 {
		t.Errorf("Run(cancelled during inspect) logged %q at DEBUG %d times, want exactly 1: the README's"+
			" alert drops the (shutdown) variant, so this wording and level are the operator contract: %q",
			"failed to inspect existing pfx (shutdown)", got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelError, "failed to inspect existing pfx"); got != 0 {
		t.Errorf("Run(cancelled during inspect) logged %q at ERROR %d times, want 0: a routine SIGTERM must"+
			" not fire CertConverterConversionFailed: %q", "failed to inspect existing pfx", got, logs.Messages())
	}
	if got, _ := readBundle(t, pfxPath); !bytes.Equal(got, prior) {
		t.Errorf("Run(cancelled during inspect) left %d bytes at the output path, want the %d it found: a"+
			" shutdown is neither current nor stale, so nothing may be rewritten on the way out", len(got), len(prior))
	}
}

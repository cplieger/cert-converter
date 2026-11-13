package process

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/go/slogx/capture"
)

// TestScanWalkVisit_classifies_walk_errors pins the /input walk's error triage
// directly, without depending on mode bits: a failure at the root (".") aborts
// the scan so Run reports it and health flips, a failure below the root counts
// one unreadable sub-path and continues so the readable certs still convert, and
// a cancelled context aborts between entries. Collapsing the root case into the
// sub-path case would turn a vanished /input mount into a silently "successful"
// scan; collapsing the sub-path case into the root case would make one
// mis-permissioned cert directory abort every scan.
func TestScanWalkVisit_classifies_walk_errors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")

	t.Run("an error at the root aborts the walk", func(t *testing.T) {
		t.Parallel()
		sw := &scanWalk{seen: make(map[string]struct{})}
		if got := sw.visit(t.Context(), ".", nil, sentinel); !errors.Is(got, sentinel) {
			t.Errorf("visit(\".\", err) = %v, want the walk error so the scan aborts", got)
		}
		if sw.unreadable != 0 {
			t.Errorf("visit(\".\", err) unreadable = %d, want 0 (a root failure is not an unreadable sub-path)", sw.unreadable)
		}
	})

	t.Run("an error below the root is counted and skipped", func(t *testing.T) {
		t.Parallel()
		sw := &scanWalk{seen: make(map[string]struct{})}
		if got := sw.visit(t.Context(), "locked/tls.crt", nil, sentinel); got != nil {
			t.Errorf("visit(\"locked/tls.crt\", err) = %v, want nil so the walk continues", got)
		}
		if sw.unreadable != 1 {
			t.Errorf("visit(sub-path, err) unreadable = %d, want 1", sw.unreadable)
		}
		if len(sw.results) != 0 || len(sw.seen) != 0 {
			t.Errorf("visit(sub-path, err) results/seen = %d/%d, want 0/0 (an unreadable path is not a pair outcome)",
				len(sw.results), len(sw.seen))
		}
	})

	t.Run("an ENOENT below the root is the renewal race, not an unreadable path", func(t *testing.T) {
		t.Parallel()
		sw := &scanWalk{seen: make(map[string]struct{})}
		if got := sw.visit(t.Context(), "renewing", nil, fs.ErrNotExist); got != nil {
			t.Errorf("visit(sub-path, ENOENT) = %v, want nil so the walk continues", got)
		}
		if sw.vanished != 1 {
			t.Errorf("visit(sub-path, ENOENT) vanished = %d, want 1", sw.vanished)
		}
		if sw.unreadable != 0 {
			t.Errorf("visit(sub-path, ENOENT) unreadable = %d, want 0: a directory removed under the walk must not raise the documented unreadable= alert, whose remediation points at /input permissions",
				sw.unreadable)
		}
	})

	t.Run("a cancelled context aborts the walk", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		sw := &scanWalk{seen: make(map[string]struct{})}
		if got := sw.visit(ctx, "anything.crt", nil, nil); !errors.Is(got, context.Canceled) {
			t.Errorf("visit(cancelled ctx) = %v, want context.Canceled", got)
		}
		if len(sw.seen) != 0 {
			t.Errorf("visit(cancelled ctx) seen = %d, want 0 (no entry may be recorded after cancellation)", len(sw.seen))
		}
	})
}

// TestStoreInspect_degrades_when_the_output_cannot_be_inspected pins a DELIBERATE
// reversal. This test previously required an ERROR when the confined root refused to stat
// a prior output, on the reasoning that a refusal is evidence the output tree cannot be
// inspected and should therefore be reported rather than papered over.
//
// The reversal: inspect answers exactly one question — "is the file on disk already the
// bundle these inputs produce?" — and "I cannot tell" answers it. Treating it as stale and
// rewriting is both correct and self-healing for the realistic cause, a root-owned .pfx
// left by a deployment that predates the user: mapping. Erroring instead flipped the pair
// to statusFailed and pinned the container unhealthy over something the app can fix itself.
//
// The old objection — that this silently rewrites forever and hides a broken output mount
// — does not hold, and the second half of this test is why: the WRITE goes through the
// same confined root, so a genuinely broken tree fails at the write, which DOES flip
// health. The honest signal moves from the read to the write rather than disappearing.
// Runs serially: it swaps slog.Default().
func TestStoreInspect_degrades_when_the_output_cannot_be_inspected(t *testing.T) {
	base := t.TempDir()
	outDir := filepath.Join(base, "out")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{outDir, outside} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "tls.pfx"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(outDir, "swapped")); err != nil {
		t.Fatal(err)
	}
	s := newOutputStore(t, outDir)

	current, err := inspectCurrent(t.Context(), s, "swapped/tls.pfx", convert.Analysis{}, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("inspect(uninspectable output) = %v, want nil: an unreadable prior output is stale, not fatal", err)
	}
	if current {
		t.Error("inspect(uninspectable output) = true; a bundle that cannot be inspected must never be reported current")
	}

	// The other half: the tree really is broken, so the rewrite this returns false to
	// authorise must itself fail. That is what keeps health honest.
	if writeErr := s.write(t.Context(), "swapped/tls.pfx", []byte("bundle")); writeErr == nil {
		t.Error("store.write(through a symlink out of the root) = nil error; the confined write must refuse it, or the degrade WOULD hide a broken output mount")
	}
}

// cancelAfterFirstCheck reports "not cancelled" on its first Err() observation
// and "cancelled" on every later one, which is exactly the shape of a SIGTERM
// that lands while a cert is being converted: the walk's entry guard already
// passed, so only the post-conversion re-check can notice it.
type cancelAfterFirstCheck struct{ checks int }

func (*cancelAfterFirstCheck) Deadline() (deadline time.Time, ok bool) { return time.Time{}, false }
func (*cancelAfterFirstCheck) Done() <-chan struct{}                   { return nil }
func (*cancelAfterFirstCheck) Value(any) any                           { return nil }

func (c *cancelAfterFirstCheck) Err() error {
	c.checks++
	if c.checks == 1 {
		return nil
	}
	return context.Canceled
}

// TestScanWalkVisit_cancellation_during_conversion_aborts_the_walk pins the
// second context check in visit. A cancellation that lands mid-conversion turns
// that entry into statusFailed, so without the re-check the walk would finish
// normally and Run would report a "completed" scan whose failed count is really
// a shutdown artifact -- main.go then logs an ERROR and marks the container
// unhealthy on a clean stop. The entry must still be recorded (seen + one
// result) so the cache is not pruned against a partial set.
func TestScanWalkVisit_cancellation_during_conversion_aborts_the_walk(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(certsRoot, "late.crt"), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "late.key"), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(certsRoot, "late.crt"))
	if err != nil {
		t.Fatal(err)
	}
	sw := &scanWalk{src: newInputSource(t, certsRoot), out: newOutputStore(t, t.TempDir()), seen: make(map[string]struct{})}

	got := sw.visit(&cancelAfterFirstCheck{}, "late.crt", fs.FileInfoToDirEntry(fi), nil)

	if !errors.Is(got, context.Canceled) {
		t.Errorf("visit(cancelled during conversion) = %v, want context.Canceled so Run reports the shutdown instead of a completed scan", got)
	}
	if len(sw.results) != 1 {
		t.Errorf("visit(cancelled during conversion) results = %d, want 1 (the entry's outcome must still be recorded)", len(sw.results))
	}
	if _, ok := sw.seen["late.crt"]; !ok {
		t.Error("visit(cancelled during conversion) did not record the entry as seen; an unseen entry would be pruned from the cache")
	}
}

// TestNoteUnwalkableSymlink_reports_resolution_outcomes pins both meaningful
// arms of the symlink notice: a link the confined root refuses to resolve is
// the only operator-visible signal that a linked certificate subtree is
// invisible (WARN), while an in-root directory link whose real target the walk
// reaches anyway is merely tracing detail (DEBUG). Runs serially: it swaps
// slog.Default().
func TestNoteUnwalkableSymlink_reports_resolution_outcomes(t *testing.T) {
	base := t.TempDir()
	input := filepath.Join(base, "input")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{input, outside, filepath.Join(input, "target")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"escape": outside, "inside": "target"} {
		if err := os.Symlink(target, filepath.Join(input, name)); err != nil {
			t.Fatal(err)
		}
	}
	sw := &scanWalk{src: newInputSource(t, input)}

	for _, tt := range []struct {
		name, wantMessage string
		wantLevel         slog.Level
	}{
		{"escape", "skipping symlink that could not be resolved through the input root", slog.LevelWarn},
		{"inside", "skipping symlinked directory; its target is walked directly", slog.LevelDebug},
	} {
		// A fresh recorder per case, replacing the buffer reset the text handler needed.
		logs := captureLogs(t)
		fi, err := os.Lstat(filepath.Join(input, tt.name))
		if err != nil {
			t.Fatal(err)
		}
		sw.noteUnwalkableSymlink(tt.name, fs.FileInfoToDirEntry(fi))
		if got := logs.CountLevel(tt.wantLevel, tt.wantMessage); got != 1 {
			t.Errorf("noteUnwalkableSymlink(%q) logged %q, want message %q at %s", tt.name, logs.Messages(), tt.wantMessage, tt.wantLevel)
		}
	}
}

// TestNoteUnwalkableSymlink_stays_silent_where_nothing_is_hidden pins the
// silence half of the symlink notice, which its message assertions cannot cover.
// A dangling link whose target stays inside the root hides no certificates, and
// a symlinked .crt or .key is already classified and logged by convertEntry, so
// neither may produce a second line; a false positive would send an operator after
// a link that costs nothing. The final case is the
// control: an unresolvable non-cert link must still warn, so the test cannot
// pass by silencing everything. Runs serially: it swaps slog.Default().
func TestNoteUnwalkableSymlink_stays_silent_where_nothing_is_hidden(t *testing.T) {
	base := t.TempDir()
	input := filepath.Join(base, "input")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{input, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		// A dangling link whose target stays INSIDE the root: the confined Stat
		// reports ENOENT, which hides nothing, so it must stay silent.
		"dangling": "no-such-target",
		// Escaping links under the pair names: convertEntry owns these, so the
		// notice must not double-report them.
		"tls.crt": filepath.Join(outside, "real.crt"),
		"tls.key": filepath.Join(outside, "real.key"),
		// The control: same escaping target, a name the notice owns.
		"linked-dir": outside,
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(input, name)); err != nil {
			t.Fatal(err)
		}
	}
	sw := &scanWalk{src: newInputSource(t, input)}

	entry := func(name string) fs.DirEntry {
		fi, lerr := os.Lstat(filepath.Join(input, name))
		if lerr != nil {
			t.Fatal(lerr)
		}
		return fs.FileInfoToDirEntry(fi)
	}

	for _, name := range []string{"dangling", "tls.crt", "tls.key"} {
		// A fresh recorder per case, replacing the buffer reset the text handler needed.
		logs := captureLogs(t)
		sw.noteUnwalkableSymlink(name, entry(name))
		if logs.Len() != 0 {
			t.Errorf("noteUnwalkableSymlink(%q) logged %q, want no output", name, logs.Messages())
		}
		if sw.unresolved != 0 {
			t.Errorf("noteUnwalkableSymlink(%q) left unresolved = %d, want 0: silence and the count are one signal, and a link that hides nothing must move neither",
				name, sw.unresolved)
		}
	}

	logs := captureLogs(t)
	sw.noteUnwalkableSymlink("linked-dir", entry("linked-dir"))
	if !logs.Contains("skipping symlink that could not be resolved through the input root") {
		t.Errorf("noteUnwalkableSymlink(%q) logged %q, want the unresolved-symlink warning", "linked-dir", logs.Messages())
	}
	// The count is the other half of that warning and the only aggregate trace of it:
	// the end-of-scan summary and the reap gate both read it, not the log line.
	if sw.unresolved != 1 {
		t.Errorf("noteUnwalkableSymlink(%q) left unresolved = %d, want 1", "linked-dir", sw.unresolved)
	}
}

// linkBundlePassword is the input password of the bundles writeBundleSource writes.
const linkBundlePassword = "input-password"

// writeBundleSource writes a PKCS#12 bundle at dir/name under linkBundlePassword
// and returns the certificate and key it holds.
func writeBundleSource(t *testing.T, dir, name string) (certPEM, keyPEM []byte) {
	t.Helper()
	certPEM, keyPEM = testcerts.GenerateSelfSignedCert(t, "bundle.example.com", "ecdsa")
	analysis, err := convert.Analyse(t.Context(), certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	data, err := analysis.Encode(convert.EncNameLegacyDES, linkBundlePassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM
}

// recordIndex returns the index of the first record of logs at level whose
// message contains msg and, when kind is not empty, whose condition is kind and
// path is path; -1 when there is none.
func recordIndex(logs *capture.Recorder, level slog.Level, msg, kind, path string) int {
	for i, r := range logs.Records() {
		if r.Level == level && strings.Contains(r.Message, msg) &&
			(kind == "" || attrIs(&r, "condition", kind) && attrIs(&r, "path", path)) {
			return i
		}
	}
	return -1
}

// TestScannerRun_treats_a_source_link_to_nothing_as_a_deleted_source pins that a
// certificate, key or bundle that became a link to a name missing inside /input
// counts and reaps as the deleted file would, and that the link logs one standing
// warning of its own.
// Serial: it swaps slog.Default().
func TestScannerRun_treats_a_source_link_to_nothing_as_a_deleted_source(t *testing.T) {
	const danglingKind = "dangling_source_link"
	for _, lay := range []outputpolicy.Layout{outputpolicy.LayoutFlat, outputpolicy.LayoutMirror} {
		t.Run(string(lay), func(t *testing.T) {
			sync := Options{Layout: lay, Lifecycle: outputpolicy.LifecycleSync}
			bundles := Options{Layout: lay, InputPassword: linkBundlePassword, InputPasswordReady: true}
			t.Run("certificate_beside_its_key", func(t *testing.T) {
				in, out := t.TempDir(), t.TempDir()
				writeSelfSignedPair(t, in, "x")
				logs := captureLogs(t)
				scanner := newVerdictScanner(in, out, sync)
				runScans(t, scanner, 1)
				relink(t, filepath.Join(in, "x.crt"), "gone.crt")

				res := runScans(t, scanner, 1)
				if res.Total != 0 || res.Unreadable != 0 || !res.NoSources || !res.OrphanRemovalDisabled {
					t.Errorf("the scan with x.crt linked to nothing = %+v, want Total 0, Unreadable 0, NoSources and orphan removal disabled", res)
				}
				if _, err := os.Stat(filepath.Join(out, "x.pfx")); err != nil {
					t.Errorf("an empty input tree removed x.pfx: %v", err)
				}
				if got := logs.CountLevel(slog.LevelWarn, "cannot read certificate"); got != 0 {
					t.Errorf("the link logged %d certificate read WARNs, want 0", got)
				}
				if got := logs.CountLevel(slog.LevelWarn, loneKeyRetainedMsg); got != 0 {
					t.Errorf("an empty input tree logged %d lone-key WARNs, want 0", got)
				}
				if got := conditionCount(logs, slog.LevelWarn, danglingKind, "x.crt"); got != 1 {
					t.Errorf("x.crt logged %d dangling_source_link WARNs, want 1", got)
				}
			})
			t.Run("certificate_beside_its_key_with_another_source", func(t *testing.T) {
				in, out := t.TempDir(), t.TempDir()
				writeSelfSignedPair(t, in, "x")
				writeSelfSignedPair(t, in, "other")
				logs := captureLogs(t)
				scanner := newVerdictScanner(in, out, sync)
				runScans(t, scanner, 1)
				relink(t, filepath.Join(in, "x.crt"), "gone.crt")

				res := runScans(t, scanner, 1)
				if res.Unreadable != 0 || res.OrphanRemovalDisabled || res.Removed != 0 {
					t.Errorf("the scan with x.crt linked to nothing = %+v, want Unreadable 0, orphan removal on and nothing removed", res)
				}
				if _, err := os.Stat(filepath.Join(out, "x.pfx")); err != nil {
					t.Errorf("x.pfx was removed while x.key is still in /input: %v", err)
				}
				if got := logs.CountLevel(slog.LevelWarn, loneKeyRetainedMsg); got != 1 || !logs.HasAttr(loneKeyRetainedMsg, "path", "x.pfx") {
					t.Errorf("the scan logged %d lone-key WARNs, want 1 naming x.pfx; log = %q", got, logs.Messages())
				}
				if got := conditionCount(logs, slog.LevelWarn, danglingKind, "x.crt"); got != 1 {
					t.Errorf("x.crt logged %d dangling_source_link WARNs, want 1", got)
				}
			})
			t.Run("certificate_beside_an_unproven_key", func(t *testing.T) {
				in, outside := inputAndOutside(t)
				out := t.TempDir()
				writeSelfSignedPair(t, in, "x")
				writeSelfSignedPair(t, in, "other")
				captureLogs(t)
				scanner := newVerdictScanner(in, out, sync)
				runScans(t, scanner, 1)
				relink(t, filepath.Join(in, "x.crt"), "gone.crt")
				relink(t, filepath.Join(in, "x.key"), filepath.Join(outside, "x.key"))

				if res := runScans(t, scanner, 1); res.Removed != 0 {
					t.Errorf("the scan with x.key out of reach = %+v, want nothing removed", res)
				}
				if _, err := os.Stat(filepath.Join(out, "x.pfx")); err != nil {
					t.Errorf("x.pfx was removed while its key may still exist: %v", err)
				}
			})
			t.Run("bundle", func(t *testing.T) {
				in := t.TempDir()
				writeSelfSignedPair(t, in, "other")
				if err := os.Symlink("gone.pfx", filepath.Join(in, "x.pfx")); err != nil {
					t.Fatal(err)
				}
				logs := captureLogs(t)
				res := runScans(t, newVerdictScanner(in, t.TempDir(), bundles), 1)
				if res.Unreadable != 0 {
					t.Errorf("the scan with x.pfx linked to nothing = %+v, want Unreadable 0", res)
				}
				if got := logs.CountLevel(slog.LevelWarn, "cannot read bundle"); got != 0 {
					t.Errorf("the link logged %d bundle read WARNs, want 0", got)
				}
				if got := conditionCount(logs, slog.LevelWarn, condOrphanCertificates, ""); got != 0 {
					t.Errorf("the scan logged %d orphan_certificates WARNs, want 0", got)
				}
				if got := conditionCount(logs, slog.LevelWarn, danglingKind, "x.pfx"); got != 1 {
					t.Errorf("x.pfx logged %d dangling_source_link WARNs, want 1", got)
				}
			})
			t.Run("certificate_beside_a_bundle", func(t *testing.T) {
				in, out := t.TempDir(), t.TempDir()
				_, keyPEM := writeBundleSource(t, in, "x.pfx")
				if err := os.WriteFile(filepath.Join(in, "x.key"), keyPEM, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("gone.crt", filepath.Join(in, "x.crt")); err != nil {
					t.Fatal(err)
				}
				logs := captureLogs(t)
				res := runScans(t, newVerdictScanner(in, out, bundles), 1)
				if res.Converted != 1 || res.Unreadable != 0 {
					t.Errorf("the scan of x.pfx beside x.crt linked to nothing = %+v, want the bundle converted and Unreadable 0", res)
				}
				if _, err := os.Stat(filepath.Join(out, "x.pfx")); err != nil {
					t.Errorf("the bundle was not converted: %v", err)
				}
				if got := conditionCount(logs, slog.LevelWarn, danglingKind, "x.crt"); got != 1 {
					t.Errorf("x.crt logged %d dangling_source_link WARNs, want 1", got)
				}
			})
			t.Run("key_links_to_nothing_beside_a_bundle", func(t *testing.T) {
				in, out := t.TempDir(), t.TempDir()
				certPEM, _ := writeBundleSource(t, in, "x.pfx")
				if err := os.WriteFile(filepath.Join(in, "x.crt"), certPEM, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("gone.key", filepath.Join(in, "x.key")); err != nil {
					t.Fatal(err)
				}
				logs := captureLogs(t)
				res := runScans(t, newVerdictScanner(in, out, bundles), 1)
				if res.Converted != 1 || res.Orphan != 1 {
					t.Errorf("the scan of x.pfx beside x.key linked to nothing = %+v, want the bundle converted and x.crt an orphan", res)
				}
				if _, err := os.Stat(filepath.Join(out, "x.pfx")); err != nil {
					t.Errorf("the bundle was not converted: %v", err)
				}
				if got := conditionCount(logs, slog.LevelWarn, condAllOrphan, ""); got != 0 {
					t.Errorf("the scan logged %d all_certificates_orphaned WARNs, want 0: the bundle converted", got)
				}
				if got := conditionCount(logs, slog.LevelWarn, danglingKind, "x.key"); got != 1 {
					t.Errorf("x.key logged %d dangling_source_link WARNs, want 1", got)
				}
			})
			for _, tc := range []struct{ name, target string }{
				{name: "key_after_a_whole_read", target: "gone.key"},
				{name: "key_links_through_a_file", target: "file.txt/k"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					in := t.TempDir()
					writeSelfSignedPair(t, in, "x")
					if err := os.WriteFile(filepath.Join(in, "file.txt"), []byte("x"), 0o600); err != nil {
						t.Fatal(err)
					}
					captureLogs(t)
					scanner := newVerdictScanner(in, t.TempDir(), Options{Layout: lay})
					runScans(t, scanner, 1)
					relink(t, filepath.Join(in, "x.key"), tc.target)

					if res := runScans(t, scanner, 1); res.Vanished != 1 || res.Orphan != 0 {
						t.Errorf("the first scan after x.key went nowhere = %+v, want Vanished 1 and Orphan 0, as for a deleted key", res)
					}
					if res := runScans(t, scanner, 1); res.Orphan != 1 || res.Vanished != 0 {
						t.Errorf("the second scan = %+v, want Orphan 1 and Vanished 0: the grace is one scan", res)
					}
				})
			}
			for _, tc := range []struct {
				name  string
				links []string
			}{
				{name: "key_link_beside_a_deleted_certificate", links: []string{"x.key"}},
				{name: "key_link_beside_a_dangling_certificate", links: []string{"x.crt", "x.key"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					in, out := t.TempDir(), t.TempDir()
					writeSelfSignedPair(t, in, "x")
					writeSelfSignedPair(t, in, "other")
					logs := captureLogs(t)
					scanner := newVerdictScanner(in, out, sync)
					runScans(t, scanner, 1)
					if err := os.Remove(filepath.Join(in, "x.crt")); err != nil {
						t.Fatal(err)
					}
					for _, name := range tc.links {
						relink(t, filepath.Join(in, name), "gone-"+name)
					}

					if res := runScans(t, scanner, 1); res.Removed != 1 {
						t.Errorf("the scan after x's pair went nowhere = %+v, want Removed 1", res)
					}
					if _, err := os.Lstat(filepath.Join(out, "x.pfx")); !os.IsNotExist(err) {
						t.Errorf("x.pfx was kept: Lstat = %v", err)
					}
					audit := recordIndex(logs, slog.LevelWarn, reapAuditMsg, "", "")
					for _, name := range tc.links {
						if got := conditionCount(logs, slog.LevelWarn, danglingKind, name); got != 1 {
							t.Errorf("%s logged %d dangling_source_link WARNs, want 1", name, got)
						}
						if at := recordIndex(logs, slog.LevelWarn, "", danglingKind, name); at < 0 || at > audit {
							t.Errorf("the WARN for %s is record %d, the removal record %d: the operator must hear before the removal", name, at, audit)
						}
					}
				})
			}
			t.Run("warning_lifecycle", func(t *testing.T) {
				in, out := t.TempDir(), t.TempDir()
				writeSelfSignedPair(t, in, "other")
				if err := os.Symlink("gone.crt", filepath.Join(in, "x.crt")); err != nil {
					t.Fatal(err)
				}
				logs := captureLogs(t)
				scanner := newVerdictScanner(in, out, Options{Layout: lay})
				for scan := range 2 {
					if res := runScans(t, scanner, 1); res.Total != 1 || res.Unreadable != 0 {
						t.Errorf("scan %d = %+v, want Total 1 and Unreadable 0: the link counts nowhere", scan+1, res)
					}
				}
				if got := conditionCount(logs, slog.LevelWarn, danglingKind, "x.crt"); got != 1 {
					t.Errorf("two scans logged %d dangling_source_link WARNs, want 1", got)
				}
				if got := conditionCount(logs, slog.LevelDebug, danglingKind, "x.crt"); got != 1 {
					t.Errorf("two scans logged %d dangling_source_link Debug records, want 1", got)
				}
				restarted := newVerdictScanner(in, out, Options{Layout: lay})
				runScans(t, restarted, 1)
				if got := conditionCount(logs, slog.LevelWarn, danglingKind, "x.crt"); got != 2 {
					t.Errorf("a restart logged the link %d times in total, want 2: the new process reports it once", got)
				}
				if err := os.Remove(filepath.Join(in, "x.crt")); err != nil {
					t.Fatal(err)
				}
				runScans(t, restarted, 1)
				if got := clearCount(logs, danglingKind, "x.crt"); got != 1 {
					t.Errorf("removing the link logged %d clears, want 1", got)
				}
			})
		})
	}
}

// TestScannerRun_logs_every_directory_alias_at_debug pins that a link to a
// directory inside /input is named at Debug whatever its name, because the walk
// reaches its target under the target's own path.
// Serial: it swaps slog.Default().
func TestScannerRun_logs_every_directory_alias_at_debug(t *testing.T) {
	const aliasMsg = "skipping symlinked directory; its target is walked directly"
	in := t.TempDir()
	if err := os.Mkdir(filepath.Join(in, "moved"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeSelfSignedPair(t, filepath.Join(in, "moved"), "x")
	for _, name := range []string{"site.key", "plain"} {
		if err := os.Symlink("moved", filepath.Join(in, name)); err != nil {
			t.Fatal(err)
		}
	}
	logs := captureLogs(t)
	runScans(t, newVerdictScanner(in, t.TempDir(), Options{}), 1)
	for _, name := range []string{"site.key", "plain"} {
		if got := countRecords(logs, slog.LevelDebug, aliasMsg, "path", name); got != 1 {
			t.Errorf("the alias %s logged %d Debug alias records, want 1", name, got)
		}
	}
}

// TestScannerRun_keeps_a_mirrored_orphan_link_out_of_the_unresolved_report pins
// that, under the mirror layout, a certificate link the scan cannot follow and
// whose key is gone covers only its own stem: it is an orphan certificate, it
// hides nothing, and the scan still reads the whole tree.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_a_mirrored_orphan_link_out_of_the_unresolved_report(t *testing.T) {
	in, outside := inputAndOutside(t)
	writeSelfSignedPair(t, in, "tls")
	writeSelfSignedPair(t, in, "other")
	writeSelfSignedPair(t, outside, "elsewhere")
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutMirror, Lifecycle: outputpolicy.LifecycleSync})
	runScans(t, scanner, 1)
	if err := os.Remove(filepath.Join(in, "tls.key")); err != nil {
		t.Fatal(err)
	}
	relink(t, filepath.Join(in, "tls.crt"), filepath.Join(outside, "elsewhere.crt"))
	if res := runScans(t, scanner, 1); res.Vanished != 1 {
		t.Fatalf("setup: the first scan after the change = %+v, want the key Vanished once", res)
	}

	from := logs.Len()
	res := runScans(t, scanner, 1)
	if res.Orphan != 1 || res.Unresolved != 0 || res.NoSources {
		t.Errorf("the second scan = %+v, want Orphan 1, Unresolved 0 and NoSources false", res)
	}
	orphanWarns, linkRecords := 0, 0
	for _, r := range logs.Records()[from:] {
		if r.Level == slog.LevelWarn && attrIs(&r, "condition", condOrphanCertificates) {
			orphanWarns++
		}
		if attrIs(&r, "condition", condUnresolvedSymlink) {
			linkRecords++
		}
	}
	if orphanWarns != 1 || linkRecords != 0 {
		t.Errorf("the second scan logged %d orphan_certificates WARNs and %d unresolved_symlink records, want 1 and 0", orphanWarns, linkRecords)
	}
	if _, err := os.Stat(filepath.Join(out, "tls.pfx")); err != nil {
		t.Errorf("tls.pfx was removed: %v", err)
	}
}

// TestScannerRun_keeps_an_artifact_whose_key_path_holds_a_directory pins that
// under OUTPUT_LIFECYCLE=sync a deleted certificate's artifact stays while
// something other than a regular file occupies its key path, in both layouts:
// an odd occupant at the key path is not the operator removing the key.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_an_artifact_whose_key_path_holds_a_directory(t *testing.T) {
	for _, lay := range []outputpolicy.Layout{outputpolicy.LayoutFlat, outputpolicy.LayoutMirror} {
		t.Run(string(lay), func(t *testing.T) {
			in, out := t.TempDir(), t.TempDir()
			writeSelfSignedPair(t, in, "x")
			writeSelfSignedPair(t, in, "other")
			logs := captureLogs(t)
			scanner := newVerdictScanner(in, out, Options{Layout: lay, Lifecycle: outputpolicy.LifecycleSync})
			runScans(t, scanner, 1)
			for _, name := range []string{"x.crt", "x.key"} {
				if err := os.Remove(filepath.Join(in, name)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(in, "x.key"), 0o750); err != nil {
				t.Fatal(err)
			}

			if res := runScans(t, scanner, 1); res.Removed != 0 {
				t.Errorf("the scan with a directory at x.key = %+v, want nothing removed", res)
			}
			if _, err := os.Stat(filepath.Join(out, "x.pfx")); err != nil {
				t.Errorf("x.pfx was removed while x.key is occupied: %v", err)
			}
			if got := logs.CountLevel(slog.LevelWarn, loneKeyRetainedMsg); got != 1 {
				t.Errorf("the scan logged %d lone-key WARNs, want 1", got)
			}
		})
	}
}

// TestScannerRun_reaps_beside_an_excluded_directory_at_a_source_name pins that a
// directory at a source name under INPUT_EXCLUDE_PATHS is an excluded source,
// decided from its path alone: it is counted as excluded and does not stop
// OUTPUT_LIFECYCLE=sync from removing another source's orphan.
// Serial: it swaps slog.Default().
func TestScannerRun_reaps_beside_an_excluded_directory_at_a_source_name(t *testing.T) {
	for _, lay := range []outputpolicy.Layout{outputpolicy.LayoutFlat, outputpolicy.LayoutMirror} {
		t.Run(string(lay), func(t *testing.T) {
			in, out := t.TempDir(), t.TempDir()
			writeSelfSignedPair(t, in, "other")
			writeSelfSignedPair(t, in, "gone")
			if err := os.Mkdir(filepath.Join(in, "skip.crt"), 0o750); err != nil {
				t.Fatal(err)
			}
			captureLogs(t)
			opts := Options{Layout: lay, Lifecycle: outputpolicy.LifecycleSync, Exclude: layout.NewExcludeSet([]string{"skip.crt"})}
			scanner := newVerdictScanner(in, out, opts)
			runScans(t, scanner, 1)
			for _, name := range []string{"gone.crt", "gone.key"} {
				if err := os.Remove(filepath.Join(in, name)); err != nil {
					t.Fatal(err)
				}
			}

			res := runScans(t, scanner, 1)
			if res.Unreadable != 0 || res.Excluded != 1 || res.Removed != 1 {
				t.Errorf("the scan after gone's pair left = %+v, want Unreadable 0, Excluded 1 and Removed 1", res)
			}
			if _, err := os.Lstat(filepath.Join(out, "gone.pfx")); !os.IsNotExist(err) {
				t.Errorf("gone.pfx was kept: Lstat = %v", err)
			}
		})
	}
}

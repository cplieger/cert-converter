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
	"time"
	"unicode/utf8"

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/slogx/capture"
)

// newInputSource opens a confined source over dir: the INPUT tree the reap's
// confirming re-check consults before deleting anything. Most reconcile cases want it
// EMPTY, which is the ordinary deletion path — a certificate absent at walk time and
// still absent at the re-check.
func newInputSource(t *testing.T, dir string) *source {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return &source{root: root}
}

// newReaper pairs an output store with an input source and a lifecycle mode: the
// three things reap policy needs, and the only reason these tests construct a store
// at all. It keeps each case's call to reconcile as short as it was when reconcile
// took the source and the mode as arguments.
func newReaper(out *store, src *source, mode outputpolicy.Lifecycle) *reaper {
	return &reaper{src: src, out: out, mode: mode}
}

// writePair writes an already-generated pair into dir under the /input naming rule the
// scanner pairs on (<stem>.crt beside <stem>.key), with the modes every fixture in this
// package uses: a world-readable certificate and an owner-only key.
func writePair(t *testing.T, dir, stem string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, stem+".crt"), certPEM, 0o644); err != nil {
		t.Fatalf("setup: write %s.crt: %v", stem, err)
	}
	if err := os.WriteFile(filepath.Join(dir, stem+".key"), keyPEM, 0o600); err != nil {
		t.Fatalf("setup: write %s.key: %v", stem, err)
	}
}

// writeSelfSignedPair generates a fresh ECDSA self-signed pair for <stem>.example.com and
// writes it as <stem>.crt/<stem>.key: the /input fixture the scan-level cases start from.
func writeSelfSignedPair(t *testing.T, dir, stem string) {
	t.Helper()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, stem+".example.com", "ecdsa")
	writePair(t, dir, stem, certPEM, keyPEM)
}

// TestStoreReconcile pins every rail on orphan deletion. Each case is a way the
// gate must refuse, because getting a deletion wrong destroys private key material
// and the documented deployment replicates the output tree onward to a second host.
func TestStoreReconcile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		mode        outputpolicy.Lifecycle
		rc          *reapContext
		wantDeleted int
		wantPresent bool
	}{
		{
			// The delay is a confirmation step, not a veto: a certificate absent at walk
			// time AND still absent at the re-check is the ordinary deletion path, and it
			// completes within the SAME scan (the user's rejected alternative, two clean
			// scans, would have left the bundle for up to FALLBACK_SCAN_HOURS).
			name: "sync removes an orphan after a clean complete scan and a confirming re-check",
			mode: outputpolicy.LifecycleSync, rc: &reapContext{result: ScanResult{Total: 1}, walkCompleted: true},
			wantDeleted: 1, wantPresent: false,
		},
		{
			// The rail that matters most: an /input mounted empty but READABLE
			// produces a clean, complete walk, so without this the first scan after
			// a slow or wrong mount would delete every bundle.
			name: "sync refuses when the scan found no pairs at all",
			mode: outputpolicy.LifecycleSync, rc: &reapContext{result: ScanResult{Total: 0}, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "sync refuses when the walk did not complete",
			mode: outputpolicy.LifecycleSync, rc: &reapContext{result: ScanResult{Total: 1}, walkCompleted: false},
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "sync refuses when a sub-path was unreadable",
			mode: outputpolicy.LifecycleSync, rc: &reapContext{result: ScanResult{Total: 1, Unreadable: 1}, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			// An input symlink the confined root cannot resolve may hide certificates,
			// so `seen` is incomplete even though the walk reported no error and
			// nothing was unreadable. Reproduced as a live-bundle deletion.
			name: "sync refuses when an input symlink could not be resolved",
			mode: outputpolicy.LifecycleSync, rc: &reapContext{result: ScanResult{Total: 1, Unresolved: 1}, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			// The design promised this rail and the first implementation dropped it: a
			// scan already failing conversions must not also delete.
			name: "sync refuses when a conversion failed",
			mode: outputpolicy.LifecycleSync, rc: &reapContext{result: ScanResult{Total: 1, Failed: 1}, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			// The /output-side sibling of the conversion-failure rail above: a bundle whose
			// replacing write was refused is one this app wanted to replace and could not, so
			// deleting OTHER bundles on the strength of that same
			// volume is what conversionsClean refuses. Unwritable is health-neutral, which
			// is exactly why nothing else fails when this rail is dropped.
			name: "sync refuses when a prior bundle could not be rewritten",
			mode: outputpolicy.LifecycleSync, rc: &reapContext{result: ScanResult{Total: 1, Unwritable: 1}, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			// The MEMORY rail: the walk enumerated the tree perfectly, but the observation
			// log's ceiling dropped the wholeness evidence noteMissingKey classifies a
			// missing sibling key against, so a key being replaced right now would have
			// been recorded as an ordinary orphan — which vetoes nothing. Every other veto
			// reads clean here, which is exactly why the gate has to fail closed on the
			// admitted loss rather than on a symptom of it.
			name: "sync refuses when the observation log evicted wholeness evidence",
			mode: outputpolicy.LifecycleSync,
			rc: &reapContext{
				result: ScanResult{Total: 1}, walkCompleted: true, evidenceEvicted: 1,
			},
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "warn, the default, reports but never deletes",
			mode: outputpolicy.LifecycleWarn, rc: &reapContext{result: ScanResult{Total: 1}, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "keep is silent and never deletes",
			mode: outputpolicy.LifecycleKeep, rc: &reapContext{result: ScanResult{Total: 1}, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			// One orphan (no matching input) and one live bundle whose input is in seen.
			for _, name := range []string{"orphan.pfx", "live.pfx"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("pfx"), 0o600); err != nil {
					t.Fatalf("setup: WriteFile(%s): %v", name, err)
				}
			}
			// A file that is not an output at all must never be a candidate.
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
				t.Fatalf("setup: WriteFile(notes.txt): %v", err)
			}
			s := newOutputStore(t, dir)
			seen := map[string]struct{}{"live.crt": {}}

			got, err := newReaper(s, newInputSource(t, t.TempDir()), tc.mode).
				reconcile(t.Context(), seen, tc.rc)
			if err != nil {
				t.Errorf("reconcile = error %v, want nil: only a cancelled scan reports one", err)
			}
			if got != tc.wantDeleted {
				t.Errorf("reconcile = %d deleted, want %d", got, tc.wantDeleted)
			}

			_, orphanErr := os.Stat(filepath.Join(dir, "orphan.pfx"))
			if present := orphanErr == nil; present != tc.wantPresent {
				t.Errorf("orphan.pfx present = %v, want %v", present, tc.wantPresent)
			}
			// The live bundle and the unrelated file must survive every mode.
			if _, err := os.Stat(filepath.Join(dir, "live.pfx")); err != nil {
				t.Errorf("live.pfx was removed; its input is present in seen: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
				t.Errorf("notes.txt was removed; only the app's own output shape may be a candidate: %v", err)
			}
		})
	}
}

// TestStoreReconcile_warn_mode_reports_report_only_despite_a_conversion_failure pins
// the precedence between the configured lifecycle mode and this scan's conversion
// failure in the orphan report's action attribute. OUTPUT_LIFECYCLE=warn is the
// default and never removes anything, so blaming the inaction on the failure would
// promise the operator a removal on the next clean scan that the mode forbids, while
// the stale bundle stays served and the remediation attribute on the SAME record says
// to remove it by hand. Serial: captureLogs swaps the process-global slog.Default.
func TestStoreReconcile_warn_mode_reports_report_only_despite_a_conversion_failure(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, "orphan.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	logs := captureLogs(t)
	s := newOutputStore(t, dir)

	deleted, reconcileErr := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleWarn).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1, Failed: 1}, walkCompleted: true})
	if reconcileErr != nil {
		t.Fatalf("reconcile(warn, one failed conversion) = error %v, want nil", reconcileErr)
	}
	if deleted != 0 {
		t.Errorf("reconcile(warn, one failed conversion) deleted = %d, want 0", deleted)
	}
	const msg = "output bundles have no matching input"
	if !logs.HasAttr(msg, "action", "reported only (OUTPUT_LIFECYCLE=warn)") {
		got, _ := logs.AttrValue(msg, "action")
		t.Errorf("reconcile(warn, one failed conversion) logged action %q, want the report-only mode explanation", got)
	}
}

// TestStoreReconcile_warn_mode_does_not_claim_a_present_certificate_is_gone pins the
// central claim of the lone-key record on the arm that actually runs: OUTPUT_LIFECYCLE=warn
// is the DEFAULT, and `seen` is filled by the input walk before every remaining conversion
// and before the whole /output walk — so a producer that replaces a certificate without an
// atomic rename leaves it absent from `seen` and present on disk by the time the retention
// loop reads it. That record asserts the certificate is GONE and tells the operator to add
// a file that is already there, so the loop resolves the certificate itself and skips the
// candidate. The aggregate WARN is unaffected: the bundle is still reported as an orphan,
// it is just not reported as a half-deleted pair.
// Serial: captureLogs swaps the process-global slog.Default.
func TestStoreReconcile_warn_mode_does_not_claim_a_present_certificate_is_gone(t *testing.T) {
	out, in := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "back.pfx"), []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(back.pfx): %v", err)
	}
	// Both halves of the pair are under /input while the bundle is still a candidate.
	cert := layout.CertForOutput("back.pfx")
	for _, name := range []string{cert, layout.KeyFor(cert)} {
		if err := os.WriteFile(filepath.Join(in, name), []byte("pem"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s): %v", name, err)
		}
	}
	logs := captureLogs(t)

	deleted, err := newReaper(newOutputStore(t, out), newInputSource(t, in), outputpolicy.LifecycleWarn).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})
	if err != nil {
		t.Fatalf("reconcile(warn, a certificate present on disk) = error %v, want nil", err)
	}
	if deleted != 0 {
		t.Errorf("reconcile(warn) deleted = %d, want 0: this mode never removes anything", deleted)
	}
	if got := logs.CountExact(loneKeyRetainedMsg); got != 0 {
		t.Errorf("reconcile logged %q %d times, want 0: that record asserts the certificate is gone,"+
			" and %q is on disk: %q", loneKeyRetainedMsg, got, cert, logs.Messages())
	}
	const orphanMsg = "output bundles have no matching input"
	if got := logs.CountExact(orphanMsg); got != 1 {
		t.Errorf("reconcile logged %q %d times, want exactly 1: the candidate is still reported,"+
			" just not as a half-deleted pair: %q", orphanMsg, got, logs.Messages())
	}
}

// TestStoreReconcile_unsafe_output_walk_never_advises_deletion drives an unsafe OUTPUT
// walk all the way through reconcile with a real candidate present. The other tests
// stop at orphans reporting safe=false, so nothing pinned the two operator-facing
// attributes that decide what happens to a live bundle: a symlinked output subtree
// enumerates a live private-key bundle under a physical path whose derived input name
// is absent from `seen`, so it reads as an orphan. If either advice guard regresses,
// sync mode deletes it or the operator is told to. Serial: captureLogs swaps
// the process-global slog.Default.
func TestStoreReconcile_unsafe_output_walk_never_advises_deletion(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, "orphan.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	if err := os.Symlink(".", filepath.Join(dir, "linked")); err != nil {
		t.Fatalf("setup: Symlink: %v", err)
	}
	logs := captureLogs(t)
	s := newOutputStore(t, dir)

	deleted, reconcileErr := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})
	if reconcileErr != nil {
		t.Fatalf("reconcile(unsafe output walk) = error %v, want nil", reconcileErr)
	}
	if deleted != 0 {
		t.Errorf("reconcile(unsafe output walk) deleted = %d, want 0", deleted)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Errorf("orphan candidate was removed after an unsafe output walk: %v", err)
	}
	const msg = "output bundles have no matching input; " + reapDisabledPhrase
	if !logs.HasAttr(msg, "action",
		"kept: this scan could not prove every candidate is orphaned, so deleting could remove a live bundle") {
		got, _ := logs.AttrValue(msg, "action")
		t.Errorf("reconcile(unsafe output walk) logged action %q, want the live-bundle deletion warning", got)
	}
	if !logs.HasAttr(msg, "remediation",
		"do not remove anything from this list yet: fix the /output warnings above, then re-check it on a scan that reports no disabled orphan removal") {
		got, _ := logs.AttrValue(msg, "remediation")
		t.Errorf("reconcile(unsafe output walk) logged remediation %q, want advice that forbids manual deletion", got)
	}
}

// TestSampleOrphanPaths_bounds_the_sample_by_bytes pins the BYTE budget on the orphan
// report's paths attribute, which is the whole bound on it: one root-relative path is
// bounded only by the filesystem, so a scan's worth of deeply nested names can put tens
// of kilobytes into a WARN that repeats on every scan for as long as the orphan exists.
// The two cases are the two ways this can go wrong: a normal report losing paths to the
// cap, and an oversized one not being cut (or being cut THROUGH a rune).
func TestSampleOrphanPaths_bounds_the_sample_by_bytes(t *testing.T) {
	t.Parallel()

	t.Run("a realistic sample well under the budget is unchanged", func(t *testing.T) {
		t.Parallel()
		// A scan's worth of orphans in the shape a renewal directory produces them.
		const orphans = 20
		paths := make([]string, 0, orphans)
		for i := range orphans {
			paths = append(paths, fmt.Sprintf("example.com/host%02d/fullchain.pfx", i))
		}
		want := strings.Join(paths, ",")
		if len(want) > maxLoggedOrphanBytes {
			t.Fatalf("setup: %d realistic paths render to %d bytes, which is not below the %d-byte budget this case is about",
				len(paths), len(want), maxLoggedOrphanBytes)
		}
		got := sampleOrphanPaths(paths)
		if got != want {
			t.Errorf("sampleOrphanPaths(%d realistic paths) = %q, want it byte-for-byte %q: the byte cap must not touch an ordinary report",
				len(paths), got, want)
		}
		if strings.Contains(got, logtext.Marker) {
			t.Errorf("sampleOrphanPaths(%d realistic paths) = %q, want no %q marker on a sample inside the budget",
				len(paths), got, logtext.Marker)
		}
	})

	// Multi-byte names, deliberately: every rune here is three bytes and
	// maxLoggedOrphanBytes is not a multiple of three, so the cut offset lands INSIDE a
	// rune. A naive slice would leave a partial-rune tail whose raw 0x80-0x9F bytes a
	// non-UTF-8 terminal reads as C1 escape introducers, which is the class
	// runesafe.CapBytes exists to prevent.
	t.Run("an oversized sample is cut on a rune boundary and marked", func(t *testing.T) {
		t.Parallel()
		paths := []string{strings.Repeat("→", maxLoggedOrphanBytes) + "/leaf.pfx"}
		got := sampleOrphanPaths(paths)
		if !strings.HasSuffix(got, logtext.Marker) {
			t.Errorf("sampleOrphanPaths(one %d-byte path) rendered %d bytes without the %q marker: a reader cannot tell the list was cut",
				len(paths[0]), len(got), logtext.Marker)
		}
		if maxLen := maxLoggedOrphanBytes + len(logtext.Marker); len(got) > maxLen {
			t.Errorf("sampleOrphanPaths(one %d-byte path) rendered %d bytes, want at most %d",
				len(paths[0]), len(got), maxLen)
		}
		if !utf8.ValidString(got) {
			t.Errorf("sampleOrphanPaths(one %d-byte path) rendered invalid UTF-8: the cut split a rune", len(paths[0]))
		}
		kept := strings.TrimSuffix(got, logtext.Marker)
		if !strings.HasPrefix(paths[0], kept) {
			t.Errorf("sampleOrphanPaths(one %d-byte path) kept %d bytes that are not a prefix of the path: the sample must not rewrite a name",
				len(paths[0]), len(kept))
		}
		// The rune backoff may discard up to utf8.UTFMax-1 bytes below the budget and no
		// more; a cap that threw away much more would be a silent second truncation.
		if minKept := maxLoggedOrphanBytes - (utf8.UTFMax - 1); len(kept) < minKept {
			t.Errorf("sampleOrphanPaths(one %d-byte path) kept only %d bytes, want at least %d: the rune backoff must not discard more than one rune",
				len(paths[0]), len(kept), minKept)
		}
	})
}

// TestStoreReconcile_oversized_orphan_sample_keeps_the_count drives the byte cap
// through the real report. The paths attribute is a sample and may be cut; the count
// attribute is the actionable number and must survive that cut, or an operator reading
// a truncated list cannot tell whether 20 or 2000 bundles are stale. Asserted on the
// emitted record rather than on sampleOrphanPaths, because the count is a SEPARATE
// attribute at the call site and that separation is the whole guarantee. Serial:
// captureLogs swaps the process-global slog.Default.
func TestStoreReconcile_oversized_orphan_sample_keeps_the_count(t *testing.T) {
	dir := t.TempDir()
	// Long enough that a scan's worth of them exceeds the byte budget, short enough to
	// stay inside the 255-byte filename limit.
	const nameLen = 250
	const orphans = 20
	for i := range orphans {
		name := strings.Repeat(string(rune('a'+i)), nameLen-len(".pfx")) + ".pfx"
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pfx"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile: %v", err)
		}
	}
	logs := captureLogs(t)
	s := newOutputStore(t, dir)

	deleted, reconcileErr := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleWarn).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: orphans}, walkCompleted: true})
	if reconcileErr != nil {
		t.Fatalf("reconcile(%d oversized orphan names) = error %v, want nil", orphans, reconcileErr)
	}
	if deleted != 0 {
		t.Errorf("reconcile(warn mode) deleted = %d, want 0", deleted)
	}
	const msg = "output bundles have no matching input"
	if want := fmt.Sprint(orphans); !logs.HasAttr(msg, "count", want) {
		got, _ := logs.AttrValue(msg, "count")
		t.Errorf("orphan report logged count %q, want %q: the count must survive the paths cut", got, want)
	}
	paths, ok := logs.AttrValue(msg, "paths")
	if !ok {
		t.Fatalf("orphan report logged no paths attribute; records: %v", logs.Messages())
	}
	if !strings.HasSuffix(paths, logtext.Marker) {
		t.Errorf("orphan report logged a %d-byte paths attribute without the %q marker", len(paths), logtext.Marker)
	}
	if maxLen := maxLoggedOrphanBytes + len(logtext.Marker); len(paths) > maxLen {
		t.Errorf("orphan report logged a %d-byte paths attribute, want at most %d", len(paths), maxLen)
	}
}

// cancelAfterNChecks reports itself live for the first n Err() observations and
// cancelled from then on, which makes "cancellation landed between two guards of the
// same loop" deterministic without a sleep or a goroutine race: the code's own
// ctx.Err() calls are the clock.
type cancelAfterNChecks struct {
	context.Context
	calls *int
	live  int
}

func (c cancelAfterNChecks) Err() error {
	*c.calls++
	if *c.calls <= c.live {
		return nil
	}
	return context.Canceled
}

// TestReapConfirmed_cancelled_context_stops_before_deletion pins reapConfirmed's
// PRE-UNLINK shutdown guard: a scan cancelled by SIGTERM must delete no key material
// and must report the cancellation, so the caller can classify the scan as a shutdown
// instead of a clean reap. The guard is load-bearing because cancellation can arrive
// while the candidate's sibling key is being re-checked, after the guard at the top of
// the loop has already passed.
//
// live: 1 is reapConfirmed's own Err() sequence for one candidate with the deferral's
// wait stubbed out: the loop's guard after the certificate re-check, and then the guard
// under test. So no earlier guard can answer for this one, and deleting the guard makes
// the reap unlink the bundle — which every assertion below then fails on.
// Serial: it swaps the package's reap-wait var.
func TestReapConfirmed_cancelled_context_stops_before_deletion(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, "orphan.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newOutputStore(t, dir)
	stubReapWait(t, func(context.Context) error { return nil })
	calls := 0
	ctx := cancelAfterNChecks{Context: t.Context(), calls: &calls, live: 1}

	deleted, err := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
		reapConfirmed(ctx, []string{"orphan.pfx"})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("reapConfirmed(cancelled before the unlink) error = %v, want context.Canceled", err)
	}
	if deleted != 0 {
		t.Errorf("reapConfirmed(cancelled before the unlink) deleted = %d, want 0", deleted)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Errorf("orphan was removed after shutdown cancellation: %v", err)
	}
}

// TestReapConfirmed_shutdown_reports_the_candidates_it_has_not_reached pins what the two
// shutdown records in reapConfirmed's loop COUNT, which is the half a "did it delete
// anything" assertion cannot see.
//
// `remaining` answers one operator question — how much of this batch did the shutdown
// leave undone — so it must be derived from the loop's POSITION, not from the deletion
// count. len(orphaned)-deleted charges every candidate the loop already examined and
// legitimately skipped (a certificate that came back, a key still present, a removal the
// store refused) to the outstanding work, so a batch that was fully examined and
// deliberately deleted nothing reports its whole length as remaining. Both guards in the
// loop abandon it before candidate i's unlink, so the accurate answer is len(orphaned)-i
// and both must give it: two records for one condition in one loop that disagree about
// their scope are worse than either alone.
//
// The fixture makes the two arithmetics differ: candidate one is skipped because its
// certificate came back, so at candidate two's pre-unlink guard deleted is still 0 while
// i is 1. Reverting either guard to len(orphaned)-deleted reports remaining=2.
// Serial: it swaps the package's reap-wait var and slog's default.
func TestReapConfirmed_shutdown_reports_the_candidates_it_has_not_reached(t *testing.T) {
	logs := captureLogs(t)
	out := t.TempDir()
	for _, name := range []string{"back.pfx", "gone.pfx"} {
		if err := os.WriteFile(filepath.Join(out, name), []byte("pfx"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// back.crt is present again: the ordinary producer transaction the delay exists for,
	// so this candidate is examined and skipped rather than deleted.
	in := t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "back.crt"), []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	stubReapWait(t, func(context.Context) error { return nil })
	// The Err() sequence: back's top-of-loop guard, gone's top-of-loop guard, and
	// finally gone's pre-unlink guard, which is the one under test.
	calls := 0
	ctx := cancelAfterNChecks{Context: t.Context(), calls: &calls, live: 2}

	deleted, err := newReaper(newOutputStore(t, out), newInputSource(t, in), outputpolicy.LifecycleSync).
		reapConfirmed(ctx, []string{"back.pfx", "gone.pfx"})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reapConfirmed(cancelled before the second unlink) error = %v, want context.Canceled", err)
	}
	if deleted != 0 {
		t.Errorf("reapConfirmed(cancelled before every unlink) deleted = %d, want 0", deleted)
	}
	const msg = "orphan removal interrupted by shutdown"
	if got := logs.CountExact(msg); got != 1 {
		t.Fatalf("reapConfirmed logged %q %d times, want exactly 1 (logs %v)", msg, got, logs.Messages())
	}
	if got, ok := logs.AttrValueExact(msg, "remaining"); !ok || got != "1" {
		t.Errorf("reapConfirmed(shutdown at candidate 2 of 2, one already examined and skipped) logged remaining=%q, want \"1\": a candidate this loop already examined is not outstanding work", got)
	}
	if got, ok := logs.AttrValueExact(msg, "removed"); !ok || got != "0" {
		t.Errorf("reapConfirmed logged removed=%q, want \"0\": nothing was unlinked", got)
	}
	// The sibling guard at the top of the loop carries the cancellation cause; one
	// condition reported two ways must not drop it on one of them.
	if _, ok := logs.AttrValueExact(msg, "error"); !ok {
		t.Errorf("reapConfirmed's pre-unlink shutdown record carries no %q attribute, unlike the same loop's re-check guard", "error")
	}
}

// TestReapConfirmed_shutdown_at_the_recheck_reports_the_candidates_it_has_not_reached
// pins the FIRST of reapConfirmed's two shutdown records: the one that fires when the
// cancellation is observed at the top of the loop, before that candidate's certificate
// verdict is used.
//
// Its sibling above drives the PRE-UNLINK guard, and the two must agree about what
// `remaining` counts -- the loop's POSITION, not the deletion count -- because two
// records for one condition in one loop that disagree about their scope are worse than
// either alone. Nothing exercised this one, so reverting it alone to
// len(orphaned)-deleted (which charges every candidate the loop already examined and
// legitimately skipped to the outstanding work) leaves the whole suite green while the
// operator is told a shutdown left more of the batch undone than it did.
//
// The fixture makes the two arithmetics differ: candidate one is examined and skipped
// because its certificate came back, so at candidate two's top-of-loop guard `deleted`
// is still 0 while `i` is 1 -- len(orphaned)-i is 1, len(orphaned)-deleted is 2.
// live: 1 is the Err() sequence: back's top-of-loop guard, then gone's, which is the one
// under test.
// Serial: it swaps the package's reap-wait var and slog's default.
func TestReapConfirmed_shutdown_at_the_recheck_reports_the_candidates_it_has_not_reached(t *testing.T) {
	const msg = "orphan removal interrupted by shutdown during the confirming re-check"

	logs := captureLogs(t)
	out := t.TempDir()
	for _, name := range []string{"back.pfx", "gone.pfx"} {
		if err := os.WriteFile(filepath.Join(out, name), []byte("pfx"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// back.crt is present again: the ordinary producer transaction the delay exists for,
	// so this candidate is examined and skipped rather than deleted.
	in := t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "back.crt"), []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	stubReapWait(t, func(context.Context) error { return nil })
	calls := 0
	ctx := cancelAfterNChecks{Context: t.Context(), calls: &calls, live: 1}

	deleted, err := newReaper(newOutputStore(t, out), newInputSource(t, in), outputpolicy.LifecycleSync).
		reapConfirmed(ctx, []string{"back.pfx", "gone.pfx"})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reapConfirmed(cancelled at the second candidate's re-check) error = %v, want context.Canceled", err)
	}
	if deleted != 0 {
		t.Errorf("reapConfirmed(cancelled before every unlink) deleted = %d, want 0", deleted)
	}
	if got := logs.CountExact(msg); got != 1 {
		t.Fatalf("reapConfirmed logged %q %d times, want exactly 1: %q", msg, got, logs.Messages())
	}
	if got, ok := logs.AttrValueExact(msg, "remaining"); !ok || got != "1" {
		t.Errorf("reapConfirmed(shutdown at candidate 2 of 2, one already examined and skipped) logged"+
			" remaining=%q, want \"1\": a candidate this loop already examined is not outstanding work", got)
	}
	if got, ok := logs.AttrValueExact(msg, "removed"); !ok || got != "0" {
		t.Errorf("reapConfirmed logged removed=%q, want \"0\": nothing was unlinked", got)
	}
	for _, name := range []string{"back.pfx", "gone.pfx"} {
		if _, statErr := os.Stat(filepath.Join(out, name)); statErr != nil {
			t.Errorf("%s was deleted after the shutdown was observed: %v", name, statErr)
		}
	}
}

// TestReapConfirmed_reports_a_restored_pair_as_restored pins which of the two questions
// the confirming pass asks about each candidate DECIDES the record it emits.
//
// The scan's input enumeration is already stale by the time the reap runs, so a
// certificate can have RETURNED between the enumeration and the re-check. The loop reads
// the sibling key first, so the certificate's own Lstat is the freshest observation before
// the unlink — but the key's answer must not be allowed to speak for the certificate's: a
// pass that reported the key retention on the strength of the enumeration reads a restored
// pair as a half-deleted one, emitting loneKeyRetainedMsg — which asserts the certificate
// is GONE, and it is not — and dropping the candidate, so the accurate "certificate came
// back during the confirmation delay" INFO can never fire for it. The operator is told the
// wrong thing about a healthy pair, and the one record that says the delay did its job goes
// missing.
//
// The fixture is that state exactly: both halves of the pair are under /input while the
// bundle is still in the batch, which is what a certificate restored after the enumeration
// looks like from here.
// Serial: it swaps the package's reap-wait var and slog's default.
func TestReapConfirmed_reports_a_restored_pair_as_restored(t *testing.T) {
	logs := captureLogs(t)
	out, in := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "back.pfx"), []byte("pfx"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The restored pair: the certificate came back, and its sibling key never left.
	cert := layout.CertForOutput("back.pfx")
	for _, name := range []string{cert, layout.KeyFor(cert)} {
		if err := os.WriteFile(filepath.Join(in, name), []byte("pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stubReapWait(t, func(context.Context) error { return nil })

	deleted, err := newReaper(newOutputStore(t, out), newInputSource(t, in), outputpolicy.LifecycleSync).
		reapConfirmed(t.Context(), []string{"back.pfx"})
	if err != nil {
		t.Fatalf("reapConfirmed = error %v, want nil: a certificate that came back is the ordinary"+
			" producer transaction this delay exists for, not a failure", err)
	}
	if deleted != 0 {
		t.Errorf("reapConfirmed deleted = %d, want 0: the certificate is back", deleted)
	}
	if got := logs.CountExact(loneKeyRetainedMsg); got != 0 {
		t.Errorf("reapConfirmed logged %q %d times, want 0: that record asserts the certificate is gone,"+
			" and this one came back: %q", loneKeyRetainedMsg, got, logs.Messages())
	}
	const backMsg = "keeping an output bundle whose certificate came back during the confirmation delay"
	if got := logs.CountExact(backMsg); got != 1 {
		t.Errorf("reapConfirmed logged %q %d times, want exactly 1: it is the only trace that the delay"+
			" did its job: %q", backMsg, got, logs.Messages())
	}
	if _, statErr := os.Stat(filepath.Join(out, "back.pfx")); statErr != nil {
		t.Errorf("back.pfx was deleted while its certificate was present: %v", statErr)
	}
}

// TestStoreReconcile_propagates_a_shutdown_from_the_orphan_walk pins the one
// reconcile outcome that must reach the caller as an ERROR rather than as "nothing to
// reap": a cancellation that arrives after the input walk finished cleanly, which is
// the case Run cannot notice for itself. Degrading it to (0, nil) would make Run log
// "scan complete" at Info and leave the health marker set for a scan that stopped
// partway through the output tree -- under OUTPUT_LIFECYCLE=sync, after deleting some
// bundles and not others.
func TestStoreReconcile_propagates_a_shutdown_from_the_orphan_walk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	orphan := filepath.Join(dir, "orphan.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newOutputStore(t, dir)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// sync over a tree with one orphan: the mode that would delete, so nothing about
	// the arrangement excuses the refusal except the cancellation itself.
	deleted, err := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
		reconcile(ctx, map[string]struct{}{}, &reapContext{result: ScanResult{Total: 1}, walkCompleted: true})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("reconcile(cancelled ctx) error = %v, want context.Canceled so Run does not report a complete scan", err)
	}
	if deleted != 0 {
		t.Errorf("reconcile(cancelled ctx) deleted = %d, want 0", deleted)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Errorf("orphan.pfx was deleted during a cancelled scan: %v", statErr)
	}
}

// TestStoreReconcile_reports_the_output_budget_as_its_own_condition pins the /output
// entry budget's REPORTING half: which arm reconcile takes when listOutputs aborts on
// size, and that the abort is health-neutral.
//
// The two arms are one `errors.Is` apart and their remediations point at different
// things: this one names the tree's size and MAX_SCAN_ENTRIES, the generic one sends the
// operator to /output ownership, which repairs nothing when the tree is simply larger
// than one walk enumerates. Both disable reaping, and a disabled reap is invisible
// otherwise — the README says it is indistinguishable from "nothing to reap" except
// through this WARN — so a misrouted sentinel turns off orphan removal indefinitely with
// health green and the wrong operator action on screen.
// Serial: it swaps slog.Default.
func TestStoreReconcile_reports_the_output_budget_as_its_own_condition(t *testing.T) {
	logs := captureLogs(t)
	dir := t.TempDir()
	for _, name := range []string{"a.pfx", "b.pfx", "c.pfx"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pfx"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := newOutputStore(t, dir)
	s.maxEntries = 2
	// sync over a tree of nothing but orphans: the mode that would delete every one of
	// them, so only the budget stands between this scan and three deletions.
	deleted, err := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{}, &reapContext{result: ScanResult{Total: 1}, walkCompleted: true})

	if deleted != 0 || err != nil {
		t.Fatalf("reconcile(an /output over the budget) = (%d, %v), want (0, nil): the abort is"+
			" health-neutral, because no restart shrinks the tree", deleted, err)
	}
	if got := logs.CountLevel(slog.LevelWarn, outputBudgetMsg); got != 1 {
		t.Fatalf("reconcile(an /output over the budget) logged %q at WARN %d times, want exactly 1: %q",
			outputBudgetMsg, got, logs.Messages())
	}
	if got, ok := logs.AttrValue(outputBudgetMsg, "remediation"); !ok || got != outputBudgetRemediation {
		t.Errorf("reconcile(an /output over the budget) logged remediation %q, want %q: a SIZE condition"+
			" must not send the operator to /output ownership", got, outputBudgetRemediation)
	}
	if logs.Contains(outputPermRemediation) {
		t.Errorf("reconcile(an /output over the budget) took the generic permission arm as well (%q):"+
			" the sentinel must route to exactly one diagnosis", logs.Messages())
	}
	for _, name := range []string{"a.pfx", "b.pfx", "c.pfx"} {
		if _, statErr := os.Stat(filepath.Join(dir, name)); statErr != nil {
			t.Errorf("%s was deleted on a scan that could not enumerate /output: %v", name, statErr)
		}
	}
}

// TestStoreInspect_rewrites_on_an_encoder_change pins the currency half of the
// preflight, which is the reason it exists.
//
// A bundle's leaf, key and chain are unchanged by a PFX_ENCODER switch, so
// comparing only those reports the bundle CURRENT and the operator's deliberate
// change silently applies to nothing: every file keeps its old algorithms while the
// startup log announces the new profile, until some certificate happens to renew.
func TestStoreInspect_rewrites_on_an_encoder_change(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}

	dir := t.TempDir()
	s := newOutputStore(t, dir)

	written, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if err := s.write(t.Context(), "out.pfx", written); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	// Same configured profile: current, nothing to do.
	current, err := inspectCurrent(t.Context(), s, "out.pfx", analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("inspect(same profile) = error %v, want nil", err)
	}
	if !current {
		t.Error("inspect(same profile) = false, want true: nothing about this bundle changed")
	}

	// Every other profile must read as stale, including the sibling that shares an
	// encryption algorithm (modern2026) and the sibling that shares a MAC (legacyrc2
	// vs legacydes) — the pair of fields is what discriminates them.
	for _, other := range []convert.EncoderType{
		convert.EncNameModern2026,
		convert.EncNameLegacyDES,
		convert.EncNameLegacyRC2,
	} {
		t.Run(string(other), func(t *testing.T) {
			current, err := inspectCurrent(t.Context(), s, "out.pfx", analysis, other, "pw")
			if err != nil {
				t.Fatalf("inspect(configured %s) = error %v, want nil", other, err)
			}
			if current {
				t.Errorf("inspect(configured %s over a modern2023 bundle) = true, want false: the encoder change must take effect", other)
			}
		})
	}
}

// TestStoreReconcile_sync_spares_a_nested_live_bundle pins orphan detection for
// the canonical Caddy layout, where every pair lives in a per-domain
// subdirectory. The reverse name derivation must preserve the directory prefix:
// if it collapsed to a basename, every LIVE nested bundle would fail to match the
// input path recorded in `seen` and OUTPUT_LIFECYCLE=sync — the mode the
// documented deployment runs — would delete it along with the real orphan.
func TestStoreReconcile_sync_spares_a_nested_live_bundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	nested := filepath.Join(dir, "acme-v02", "example.com")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatalf("setup: MkdirAll: %v", err)
	}
	for _, name := range []string{"live.pfx", "gone.pfx"} {
		if err := os.WriteFile(filepath.Join(nested, name), []byte("pfx"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s): %v", name, err)
		}
	}
	s := newOutputStore(t, dir)
	seen := map[string]struct{}{filepath.Join("acme-v02", "example.com", "live.crt"): {}}

	got, reconcileErr := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
		reconcile(t.Context(), seen, &reapContext{result: ScanResult{Total: 1}, walkCompleted: true})
	if reconcileErr != nil {
		t.Errorf("reconcile(nested output tree) = error %v, want nil", reconcileErr)
	}
	if got != 1 {
		t.Errorf("reconcile(nested output tree) = %d deleted, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(nested, "live.pfx")); err != nil {
		t.Errorf("the nested live bundle was deleted (%v); the reverse name derivation must preserve the directory prefix", err)
	}
	if _, err := os.Stat(filepath.Join(nested, "gone.pfx")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("os.Stat(nested orphan) error = %v, want fs.ErrNotExist", err)
	}
}

// TestStoreReconcile_spares_a_live_bundle_when_an_ancestor_is_swapped_for_a_symlink is
// h-f8's regression: the orphan walk vetoes every symlink it SEES, but that snapshot is
// taken before reapConfirmed waits reapDeferral, and os.Root deliberately follows a
// symlink component that stays inside the root. Swapping an approved candidate's PARENT
// directory for a symlink to a live directory therefore used to redirect both the
// pre-unlink lstat and the unlink itself at a live bundle whose certificate still
// exists, while the input confirmation had been asked about the approved path. The
// pinned parent root is what refuses it. Serial: it swaps waitBeforeReap and
// slog.Default.
func TestStoreReconcile_spares_a_live_bundle_when_an_ancestor_is_swapped_for_a_symlink(t *testing.T) {
	outDir, inDir := t.TempDir(), t.TempDir()
	for _, sub := range []string{"live", "old"} {
		if err := os.Mkdir(filepath.Join(outDir, sub), 0o750); err != nil {
			t.Fatalf("setup: Mkdir(%s): %v", sub, err)
		}
		if err := os.WriteFile(filepath.Join(outDir, sub, "x.pfx"), []byte("pfx"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s/x.pfx): %v", sub, err)
		}
	}
	// live/x.crt exists, so live/x.pfx is not a candidate; old/x.crt does not, so
	// old/x.pfx is the one candidate the reap approves.
	if err := os.Mkdir(filepath.Join(inDir, "live"), 0o750); err != nil {
		t.Fatalf("setup: Mkdir(input live): %v", err)
	}
	if err := os.WriteFile(filepath.Join(inDir, "live", "x.crt"), []byte("crt"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(input live/x.crt): %v", err)
	}
	// The namespace swap lands inside the confirmation window, which is the whole
	// point: everything the walk observed was symlink-free.
	stubReapWait(t, func(context.Context) error {
		if err := os.Remove(filepath.Join(outDir, "old", "x.pfx")); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(outDir, "old")); err != nil {
			return err
		}
		return os.Symlink("live", filepath.Join(outDir, "old"))
	})
	logs := captureLogs(t)
	s := newOutputStore(t, outDir)

	deleted, err := newReaper(s, newInputSource(t, inDir), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{"live/x.crt": {}},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})
	if err != nil {
		t.Fatalf("reconcile(ancestor swapped for a symlink) = %v, want nil", err)
	}
	if deleted != 0 {
		t.Errorf("reconcile(ancestor swapped for a symlink) deleted = %d, want 0", deleted)
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "live", "x.pfx")); statErr != nil {
		t.Fatalf("the live bundle was deleted through the swapped ancestor: %v", statErr)
	}
	if got := logs.CountLevel(slog.LevelWarn, pinRedirectedMsg); got != 1 {
		t.Errorf("reconcile(ancestor swapped for a symlink) logged %q at WARN %d times, want exactly 1: %q",
			pinRedirectedMsg, got, logs.Messages())
	}
	if !logs.HasAttr(pinRedirectedMsg, "path", "old/x.pfx") {
		t.Errorf("reconcile(ancestor swapped for a symlink) logged %q without path=old/x.pfx: %q",
			pinRedirectedMsg, logs.Messages())
	}
}

// TestStoreRemoveOrphan_spares_non_regular_candidate_and_continues pins the
// pre-unlink type re-check: a path that changed from the regular file found during
// the orphan walk into a directory must be left in place, while another regular
// orphan is still removed. Serial: captureLogs swaps the process-global slog.Default.
//
// The directory is left EMPTY on purpose: Root.Remove would succeed on it, so if the
// non-regular guard were removed the boolean, the surviving-directory stat and the WARN
// all fail rather than only the log assertion.
func TestStoreRemoveOrphan_spares_non_regular_candidate_and_continues(t *testing.T) {
	const wantMsg = "orphaned output path is not a regular file; leaving it in place"

	dir := t.TempDir()
	stuck := filepath.Join(dir, "stuck.pfx")
	if err := os.Mkdir(stuck, 0o750); err != nil {
		t.Fatalf("setup: Mkdir: %v", err)
	}
	reapable := filepath.Join(dir, "reapable.pfx")
	if err := os.WriteFile(reapable, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile reapable.pfx: %v", err)
	}
	logs := captureLogs(t)
	s := newOutputStore(t, dir)

	if got := s.removeOrphan("stuck.pfx"); got != reapAttemptRefused {
		t.Errorf("removeOrphan(non-regular candidate) = %d, want reapAttemptRefused: a directory is not a bundle this app wrote", got)
	}
	if got := s.removeOrphan("reapable.pfx"); got != reapAttemptRemoved {
		t.Errorf("removeOrphan(regular candidate) = %d, want reapAttemptRemoved: a regular orphan must still go", got)
	}
	if _, statErr := os.Stat(reapable); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(reapable.pfx) = %v, want fs.ErrNotExist", statErr)
	}
	if fi, statErr := os.Stat(stuck); statErr != nil {
		t.Errorf("the non-regular candidate vanished: %v", statErr)
	} else if !fi.IsDir() {
		t.Errorf("stuck.pfx mode = %v, want a directory left in place", fi.Mode())
	}
	if got := logs.CountLevel(slog.LevelWarn, wantMsg); got != 1 {
		t.Fatalf("removeOrphan(non-regular candidate) logged %q at WARN %d times, want exactly 1: %q", wantMsg, got, logs.Messages())
	}
	if !logs.HasAttr(wantMsg, "path", "stuck.pfx") {
		t.Errorf("removeOrphan(non-regular candidate) logged %q without path=stuck.pfx: %q", wantMsg, logs.Messages())
	}
}

// TestStoreInspect_rewrites_after_a_password_rotation pins the second reason
// output-derived currency replaced the fingerprint cache: the cache answered "have
// these input bytes been converted?", so rotating PFX_PASSWORD changed nothing
// until some certificate happened to renew. Decoding the prior bundle with the
// CONFIGURED password is what makes the rotation take effect, and a failed decode
// must resolve to stale rather than to a failed pair.
func TestStoreInspect_rewrites_after_a_password_rotation(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	s := newOutputStore(t, t.TempDir())

	written, err := analysis.Encode(convert.EncNameModern2023, "old-password")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if err := s.write(t.Context(), "out.pfx", written); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	current, err := inspectCurrent(t.Context(), s, "out.pfx", analysis, convert.EncNameModern2023, "old-password")
	if err != nil {
		t.Fatalf("inspect(unrotated password) = error %v, want nil", err)
	}
	if !current {
		t.Fatal("inspect(unrotated password) = false, want true: nothing about this bundle changed")
	}

	current, err = inspectCurrent(t.Context(), s, "out.pfx", analysis, convert.EncNameModern2023, "new-password")
	if err != nil {
		t.Fatalf("inspect(rotated password) = error %v, want nil: a bundle that will not decode is stale, not fatal", err)
	}
	if current {
		t.Error("inspect(rotated password) = true, want false: a PFX_PASSWORD rotation must take effect without waiting for a renewal")
	}
}

// TestStoreInspect_treats_an_undecodable_prior_as_stale pins the self-healing
// half of the currency check: a foreign, empty or truncated file sitting at an
// output name is not this bundle, so it must be REWRITTEN rather than reported as
// a failed pair. Returning an error instead would pin the container unhealthy over
// a condition the app repairs itself on the same scan.
// Runs serially: it swaps slog.Default().
func TestStoreInspect_treats_an_undecodable_prior_as_stale(t *testing.T) {
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	full, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	dir := t.TempDir()
	s := newOutputStore(t, dir)

	for _, tc := range []struct {
		name    string
		rel     string
		content []byte
	}{
		{"a foreign file", "foreign.pfx", []byte("this is not a pkcs#12 bundle")},
		{"an empty file", "empty.pfx", nil},
		{"a truncated bundle", "truncated.pfx", full[:len(full)/2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, tc.rel), tc.content, pfxFileMode); err != nil {
				t.Fatalf("setup: WriteFile: %v", err)
			}
			logs := captureLogs(t)
			current, err := inspectCurrent(t.Context(), s, tc.rel, analysis, convert.EncNameModern2023, "pw")
			if err != nil {
				t.Errorf("inspect(%s) = error %v, want nil: an undecodable prior output is stale, not a failed pair", tc.name, err)
			}
			if current {
				t.Errorf("inspect(%s) = true, want false: a file that is not this bundle must be rewritten", tc.name)
			}
			// Which arm answered matters as much as the answer: the size arm reaches
			// this same verdict without reading the bundle, so asserting the outcome
			// alone lets the preflight go unexercised.
			if !logs.Contains("prior pfx was not written by this app; regenerating") {
				t.Errorf("inspect(%s) logged %q, want the foreign-file notice: the stale verdict must come from the preflight proving these bytes are not ours, not from an earlier arm", tc.name, logs.Messages())
			}
		})
	}
}

// TestStoreInspect_regenerates_an_oversized_prior pins the size guard in front
// of the prior-output read. Two things must hold and neither is covered by the
// outcome alone: an oversized prior resolves to STALE rather than to an error
// (erroring would flip health over a file the app can replace itself), and the
// operator gets the size-bound diagnosis rather than the generic
// cannot-read-prior-pfx warning, which points at /output permissions and would
// send them chasing the wrong cause. Runs serially: it swaps slog.Default().
func TestStoreInspect_regenerates_an_oversized_prior(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "big.pfx"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("setup: OpenFile: %v", err)
	}
	// Sparse: no bytes are written, only the reported size crosses the bound.
	if err := f.Truncate(maxPFXSize + 1); err != nil {
		t.Fatalf("setup: Truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("setup: Close: %v", err)
	}
	s := newOutputStore(t, dir)

	logs := captureLogs(t)
	current, err := inspectCurrent(t.Context(), s, "big.pfx", convert.Analysis{}, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("inspect(oversized prior) = error %v, want nil: it must resolve to stale, not fail the pair", err)
	}
	if current {
		t.Error("inspect(oversized prior) = true, want false")
	}
	const sizeMsg = "prior pfx exceeds the readable bound"
	if !logs.Contains(sizeMsg) {
		t.Errorf("inspect(oversized prior) logged %q, want the size-bound notice rather than a permissions hint", logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelWarn, sizeMsg); got != 1 {
		t.Errorf("inspect(oversized prior) logged %q at WARN %d times, want exactly 1", sizeMsg, got)
	}
}

// boolCount turns "should this message have been logged?" into the count a log assertion
// compares against, so a table case can name the message it expects rather than carry a
// number per message.
func boolCount(want bool) int {
	if want {
		return 1
	}
	return 0
}

// TestScannerRun_a_stale_bundle_with_a_lax_mode_is_a_conversion_failure pins the boundary
// of the health-neutral outcome from the other side: neutrality is granted only where this
// app never PROVED the bundle on disk wrong. A bundle that is a renewal behind was compared
// and found stale (contentVerifiedStale), so a refused rewrite of it counts in
// ScanResult.Failed and flips health -- otherwise the operator's PFX holds the previous
// certificate with a green marker and no alert, which is the condition this boundary exists
// to prevent. The sibling test stages the fact that DOES earn neutrality (content this app
// could not verify at all); both are needed, or either arm can be deleted silently.
//
// The lax mode is staged here on purpose, so the ONLY difference from the neutral sibling is
// the content fact. It proves the mode does not launder a stale bundle into neutrality, and
// that it does not launder it into a SKIP either: a lax mode never decides anything, so the
// stale content still routes this write and still makes its refusal a failure.
//
// The write is refused for permissions here on purpose too: it is the errno that earns
// neutrality under the other content fact, so this case proves the CONTENT fact is what
// refuses it and not the error class.
//
// Failed rather than main.healthyAfterScan is asserted because that predicate lives in
// package main and reads exactly this field (`return r.Failed == 0`), pinned there by
// TestHealthyAfterScan.
// Runs serially: it swaps slog.Default() and the write seam.
func TestScannerRun_a_stale_bundle_with_a_lax_mode_is_a_conversion_failure(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
	crtPath := filepath.Join(certsRoot, "chain.crt")
	keyPath := filepath.Join(certsRoot, "chain.key")
	writePair(t, certsRoot, "chain", chainPEM, keyPEM)
	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	})
	// The first scan runs with the write seam live, so the bundle under test is a real one
	// this app wrote -- for the PREVIOUS certificate.
	if res, err := scanner.Run(t.Context()); err != nil || res.Converted != 1 {
		t.Fatalf("setup: initial Run = %+v, %v, want Converted 1 and nil", res, err)
	}
	pfxPath := filepath.Join(outRoot, "chain.pfx")
	before, _ := readBundle(t, pfxPath)

	// The renewal: a different cert/key pair at the same input names, so the bundle on
	// disk is stale for an ORDINARY reason (wrong bytes) and not merely for its mode.
	_, renewedKeyPEM, _, renewedChainPEM := testcerts.GenerateCertChain(t)
	if err := os.WriteFile(crtPath, renewedChainPEM, 0o644); err != nil {
		t.Fatalf("setup: rewrite crt: %v", err)
	}
	if err := os.WriteFile(keyPath, renewedKeyPEM, 0o600); err != nil {
		t.Fatalf("setup: rewrite key: %v", err)
	}
	// Laxer than pfxFileMode, so the mode fact is set as well as the content fact: the
	// point of this case is that the stale content still decides the outcome.
	if err := os.Chmod(pfxPath, 0o644); err != nil {
		t.Fatalf("setup: Chmod: %v", err)
	}
	stubWriteRefusal(t, &fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EACCES})

	logs := captureLogs(t)
	res, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(stale bundle, lax mode, refused rewrite) = error %v, want nil: this is a"+
			" pair-level failure, not a scan-level one", err)
	}
	if res.Failed != 1 || res.Unwritable != 0 || res.Converted != 0 {
		t.Errorf("Run(stale bundle, lax mode, refused rewrite) = %+v, want Failed 1 Unwritable 0"+
			" Converted 0: only a content-matched bundle earns the health-neutral arm", res)
	}
	// The lax mode is still announced: detection runs before the content read, so its
	// absence would mean this test never reached the arm under test.
	if got := logs.CountLevel(slog.LevelWarn, laxBundleMsg); got != 1 {
		t.Errorf("logged %q at WARN %d times, want exactly 1: %q", laxBundleMsg, got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelError, "conversion failed"); got != 1 {
		t.Errorf("logged %q at ERROR %d times, want exactly 1: an unwritten renewal is a conversion"+
			" failure: %q", "conversion failed", got, logs.Messages())
	}
	// The LOUD register takes its remediation from the refusal's own carried cause, exactly
	// as the health-neutral one does. Asserted here because this is the only test that
	// reaches that arm with a cause other than refusalTransient, whose remediation is
	// byte-identical to the composed literal the rewiring replaced -- so without this line a
	// revert to that literal passes the whole suite.
	if got, ok := logs.AttrValue("conversion failed", "remediation"); !ok || got != outputPermRemediation {
		t.Errorf("the conversion-failure record remediation = %q (present %v), want %q: an EACCES"+
			" refusal is an ownership condition, and a loud record naming free space or a planted"+
			" symlink instead sends the operator after the wrong cause", got, ok, outputPermRemediation)
	}
	// The health-neutral message may not appear: a bundle this app compared and found
	// stale earns no standing WARN in place of the failure.
	if got := logs.CountLevel(slog.LevelWarn, unreplaceableBundleMsg); got != 0 {
		t.Errorf("logged %q at WARN %d times, want 0: the health-neutral WARN belongs only to a bundle"+
			" this app never proved wrong: %q", unreplaceableBundleMsg, got, logs.Messages())
	}
	// Nothing deleted, nothing truncated: the refused write must leave the stale bundle
	// exactly as it was, so the next scan can try again.
	after, afterInfo := readBundle(t, pfxPath)
	if !bytes.Equal(after, before) {
		t.Error("Run(stale bundle, refused rewrite) changed the bundle's bytes, want them untouched")
	}
	if got := afterInfo.Mode().Perm(); got != 0o644 {
		t.Errorf("Run(stale bundle, refused rewrite) left mode %o, want 0644 untouched", got)
	}
}

// readBundle returns a bundle's bytes and its FileInfo, so a caller can prove a
// later call left both the contents and the mtime alone.
func readBundle(t *testing.T, path string) ([]byte, os.FileInfo) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle %s: %v", path, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat bundle %s: %v", path, err)
	}
	return content, fi
}

// TestStoreInspect_propagates_a_shutdown_instead_of_reporting_stale pins the one
// inspect outcome that is neither current nor stale. Every other "I cannot tell what
// is on disk" case resolves to "rewrite it", so if a cancelled read joined them, a
// SIGTERM landing mid-scan would regenerate every remaining pair on the way out --
// fresh KDF salts and mtimes on bundles that were already correct, re-replicated
// downstream -- and convertEntry, whose error arm assumes "only shutdown gets here",
// would report those as conversions rather than as a cancelled scan.
func TestStoreInspect_propagates_a_shutdown_instead_of_reporting_stale(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	s := newOutputStore(t, t.TempDir())
	// Written through store.write, so the file on disk is a real bundle and only the
	// read can answer the question.
	if err := s.write(t.Context(), "out.pfx", mustEncode(t, analysis)); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	current, err := inspectCurrent(ctx, s, "out.pfx", analysis, convert.EncNameModern2023, "pw")

	if !errors.Is(err, context.Canceled) {
		t.Errorf("inspect(cancelled ctx) error = %v, want context.Canceled: a shutdown is neither current nor stale", err)
	}
	if current {
		t.Error("inspect(cancelled ctx) = true, want false")
	}
}

// mustEncode encodes analysis with the suite's standard profile and password.
func mustEncode(t *testing.T, analysis convert.Analysis) []byte {
	t.Helper()
	pfx, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	return pfx
}

// concatPEM joins PEM blobs. Duplicated from the convert test package because the
// two live in different packages and a shared test helper module is not worth it.
func concatPEM(blobs ...[]byte) []byte {
	var out []byte
	for _, b := range blobs {
		out = append(out, b...)
	}
	return out
}

// TestContentFromCurrency_maps_every_outcome pins the translation from a
// convert.Currency verdict into a content FACT, one arm per outcome. Two distinctions
// carry the weight.
//
// The first is which outcomes count as VERIFIED stale and which as unverified, because
// only the first grants health the right to flip on a refused rewrite (writeOutcome).
// A profile mismatch, a content mismatch, a failed DECODE and a FOREIGN file are
// verified stale: the codec either looked and found what is on disk will not open with
// the configured password or is not what these inputs produce, or it proved the bytes
// are not a bundle any of this app's profiles writes — either way the operator is being
// served the wrong bundle. A budget PREFLIGHT refusal is not: the preflight refuses to
// LOOK, so nothing about the bytes was established, and reporting that as proof the
// bundle is wrong is exactly the conflation this routing was restructured to remove.
//
// The second is the shutdown arm, which has no other test: a decode INTERRUPTED by
// shutdown is neither current nor stale, so it must propagate the cancellation. If it
// joined the ordinary decode-failure arm, a SIGTERM landing during a bundle's KDF decode
// would report that pair stale and rewrite it on the way out -- a fresh salt and a fresh
// mtime on a bundle that was already correct, which the documented downstream rsync then
// re-replicates -- and convertEntry, whose error arm assumes "only shutdown gets here",
// would count it as a conversion instead of a cancelled scan. The remaining arms pin the
// level each outcome is reported at (Info for a deliberate encoder change, Debug for the
// two expected failures, silence for a match or an ordinary renewal), and each one repeats
// under a cancelled context: the shutdown gate sits ahead of the whole switch, so no
// verdict arm may report a fact once cancellation is requested. Runs serially: it swaps
// slog.Default().
func TestContentFromCurrency_maps_every_outcome(t *testing.T) {
	for _, tc := range []struct {
		res         convert.Currency
		name        string
		wantMsg     string
		wantLevel   slog.Level
		wantContent contentState
		cancelled   bool
		wantErr     bool
	}{
		{
			res:  convert.Currency{Reason: convert.CurrencyMatch},
			name: "a match is verified current and silent", wantContent: contentVerifiedCurrent,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyContentMismatch},
			name: "a renewed certificate is verified stale and silent", wantContent: contentVerifiedStale,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyPreflightFailed, Err: errors.New("bounded out")},
			name: "a failed preflight is UNVERIFIED at debug", wantContent: contentUnverified,
			wantMsg: "prior pfx failed preflight; regenerating", wantLevel: slog.LevelDebug,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyForeign, Err: errors.New("not one of ours")},
			name: "a file the preflight proved foreign is verified stale at debug", wantContent: contentVerifiedStale,
			wantMsg: "prior pfx was not written by this app; regenerating", wantLevel: slog.LevelDebug,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyProfileMismatch, Profile: convert.EncNameLegacyDES},
			name: "an encoder change is verified stale at info", wantContent: contentVerifiedStale,
			wantMsg: "prior pfx uses a different encoder profile; regenerating", wantLevel: slog.LevelInfo,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyDecodeFailed, Err: errors.New("mac mismatch")},
			name: "a failed decode is verified stale at debug", wantContent: contentVerifiedStale,
			wantMsg: "prior pfx did not decode; regenerating", wantLevel: slog.LevelDebug,
		},
		{
			res:  convert.Currency{Reason: "not-a-reason"},
			name: "a verdict this app does not map is UNVERIFIED at warn", wantContent: contentUnverified,
			wantMsg: "prior pfx currency verdict is not one this app maps; regenerating", wantLevel: slog.LevelWarn,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyDecodeFailed, Err: errors.New("mac mismatch")},
			name: "a decode interrupted by shutdown is an error, not a fact", cancelled: true, wantErr: true,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyMatch},
			name: "a match under shutdown is an error, not current", cancelled: true, wantErr: true,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyContentMismatch},
			name: "a renewal under shutdown is an error, not stale", cancelled: true, wantErr: true,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyPreflightFailed, Err: errors.New("bounded out")},
			name: "a failed preflight under shutdown is an error, not a fact", cancelled: true, wantErr: true,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyProfileMismatch, Profile: convert.EncNameLegacyDES},
			name: "an encoder change under shutdown is an error, not stale", cancelled: true, wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			if tc.cancelled {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			logs := captureLogs(t)

			content, err := contentFromCurrency(ctx, "example.com/tls.pfx", tc.res, convert.EncNameModern2023)

			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("contentFromCurrency(%s) error = %v, want an error: %v", tc.res.Reason, err, tc.wantErr)
			}
			if tc.wantErr {
				if !errors.Is(err, context.Canceled) {
					t.Errorf("contentFromCurrency(cancelled, %s) error = %v, want context.Canceled so the scan reports the shutdown instead of rewriting every remaining pair",
						tc.res.Reason, err)
				}
				// The zero value, and it is deliberately not an outcome: an error return must
				// carry no fact at all, or a caller that ignored the error would read one.
				if content != contentUnresolved {
					t.Errorf("contentFromCurrency(cancelled, %s) = %v, want contentUnresolved alongside the error",
						tc.res.Reason, content)
				}
			}
			if content != tc.wantContent {
				t.Errorf("contentFromCurrency(%s) = %v, want %v", tc.res.Reason, content, tc.wantContent)
			}
			if tc.wantMsg == "" {
				if logs.Len() != 0 {
					t.Errorf("contentFromCurrency(%s) logged %q, want no output at all", tc.res.Reason, logs.Messages())
				}
				return
			}
			if got := logs.CountLevel(tc.wantLevel, tc.wantMsg); got != 1 {
				t.Errorf("contentFromCurrency(%s) logged %q at %s %d times, want exactly 1", tc.res.Reason, tc.wantMsg, tc.wantLevel, got)
			}
			if !logs.HasAttr(tc.wantMsg, "path", "example.com/tls.pfx") {
				t.Errorf("contentFromCurrency(%s) logged %q, want the output path named", tc.res.Reason, logs.Messages())
			}
		})
	}
}

// stubReapWait swaps the reap deferral's wait for during, restoring whatever was
// installed (TestMain's no-op, in the normal case) when the test ends. Every caller
// runs serially: the var is package state.
func stubReapWait(t *testing.T, during func(ctx context.Context) error) {
	t.Helper()
	prev := waitBeforeReap
	waitBeforeReap = func(ctx context.Context, _ time.Duration) error { return during(ctx) }
	t.Cleanup(func() { waitBeforeReap = prev })
}

// TestWaitForReapDeferral pins the production wait itself, which no other test
// reaches: TestMain replaces waitBeforeReap for the whole package so the suite does
// not spend reapDeferral per case, and this is what keeps the real function's two
// outcomes covered. The cancellation arm is the load-bearing one — the wait blocks the
// scan's only goroutine, so a wait that ignored the context would hold SIGTERM for
// reapDeferral and then delete key material on the way out.
func TestWaitForReapDeferral(t *testing.T) {
	t.Parallel()

	t.Run("a cancelled context returns immediately without waiting out the delay", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		// An hour: if the select ignored the context this case would hang, and no
		// wall-clock threshold would be needed to tell.
		if err := waitForReapDeferral(ctx, time.Hour); !errors.Is(err, context.Canceled) {
			t.Errorf("waitForReapDeferral(cancelled ctx) = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("waitForReapDeferral(cancelled ctx) took %v, want an immediate return", elapsed)
		}
	})

	t.Run("an elapsed delay returns nil", func(t *testing.T) {
		t.Parallel()
		if err := waitForReapDeferral(t.Context(), time.Millisecond); err != nil {
			t.Errorf("waitForReapDeferral(elapsed delay) = %v, want nil", err)
		}
	})
}

// TestStoreReconcile_spares_an_orphan_whose_certificate_returns_during_the_recheck is
// the reason the deferral exists. A producer that replaces a certificate by
// unlink-then-write, or an rsync that deletes before it transfers, is observed between
// the two steps by the very scan the removal event scheduled (internal/watch requests
// a rescan on any Remove; the debounce is 2s). Every reap veto passes — the walk
// completed, nothing was unreadable, another pair is present, no conversion failed —
// so without the re-check the bundle is deleted and then regenerated with fresh KDF
// salts and a fresh mtime, which is the downstream re-replication output-derived
// currency exists to prevent.
//
// The re-check cancelling one deletion is an ordinary producer transaction, not an
// error: the scan must still report success (health is derived from conversion
// failures, so a scan error here is what would flip it) and every OTHER candidate must
// still be reaped. Serial: it swaps waitBeforeReap and slog.Default.
func TestStoreReconcile_spares_an_orphan_whose_certificate_returns_during_the_recheck(t *testing.T) {
	out := t.TempDir()
	for _, name := range []string{"returning.pfx", "gone.pfx"} {
		if err := os.WriteFile(filepath.Join(out, name), []byte("pfx"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s): %v", name, err)
		}
	}
	in := t.TempDir()
	s := newOutputStore(t, out)
	// The producer's write lands INSIDE the deferral window, after the candidates were
	// identified and before they are confirmed.
	stubReapWait(t, func(context.Context) error {
		return os.WriteFile(filepath.Join(in, "returning.crt"), []byte("cert"), 0o600)
	})
	logs := captureLogs(t)

	deleted, reconcileErr := newReaper(s, newInputSource(t, in), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})

	if reconcileErr != nil {
		t.Fatalf("reconcile(certificate returned during the re-check) = error %v, want nil:"+
			" a producer transaction is not a scan failure and must not flip health", reconcileErr)
	}
	if deleted != 1 {
		t.Errorf("reconcile(certificate returned during the re-check) deleted = %d, want 1:"+
			" only the candidate whose certificate stayed gone may go", deleted)
	}
	if _, statErr := os.Stat(filepath.Join(out, "returning.pfx")); statErr != nil {
		t.Errorf("the bundle whose certificate came back was deleted: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(out, "gone.pfx")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(gone.pfx) = %v, want fs.ErrNotExist: one cancelled deletion must not"+
			" spare the rest of the batch", statErr)
	}
	const kept = "keeping an output bundle whose certificate came back during the confirmation delay"
	if logs.CountLevel(slog.LevelInfo, kept) != 1 {
		t.Errorf("reconcile logged %q, want the cancelled deletion named once at INFO", logs.Messages())
	}
	if !logs.HasAttr(reapRecheckMsg, "recheck_in", reapDeferral.String()) {
		got, _ := logs.AttrValue(reapRecheckMsg, "recheck_in")
		t.Errorf("the deferral announcement logged recheck_in %q, want %q: an operator reading a"+
			" pause in the log has to be told how long it lasts", got, reapDeferral.String())
	}
}

// TestStoreReconcile_shutdown_during_the_recheck_abandons_the_reap pins the
// cancellation contract of the window itself, which is the cost of waiting at all: the
// wait blocks the Scanner's only goroutine, so a SIGTERM arriving inside it must
// ABANDON the reap — delete nothing — and report the cancellation the way every other
// interrupted path in this file does, or Run logs "scan complete" and leaves the health
// marker set for a scan that stopped halfway through the output tree.
//
// The Debug trace is asserted too, because it is what distinguishes abandoning the
// window from the next guard downstream: reapConfirmed re-checks the context before
// every unlink, so a wait whose error were dropped would still delete nothing — and
// nothing would record that the deferral was cut short.
// Serial: it swaps waitBeforeReap and slog.Default.
func TestStoreReconcile_shutdown_during_the_recheck_abandons_the_reap(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, "orphan.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	s := newOutputStore(t, dir)
	// A context that is live when the candidates are identified and cancelled inside
	// the window, which is the only arrangement the earlier shutdown guards cannot
	// already catch.
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	stubReapWait(t, func(ctx context.Context) error {
		cancel()
		return ctx.Err()
	})
	logs := captureLogs(t)

	deleted, reconcileErr := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
		reconcile(ctx, map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})

	if !errors.Is(reconcileErr, context.Canceled) {
		t.Errorf("reconcile(shutdown inside the re-check window) error = %v, want context.Canceled"+
			" so Run does not report a complete scan", reconcileErr)
	}
	if deleted != 0 {
		t.Errorf("reconcile(shutdown inside the re-check window) deleted = %d, want 0", deleted)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Errorf("an orphan was deleted after the process started shutting down: %v", statErr)
	}
	const abandoned = "orphan removal abandoned during shutdown before the confirming re-check"
	if logs.CountLevel(slog.LevelDebug, abandoned) != 1 {
		t.Errorf("reconcile(shutdown inside the re-check window) logged %q, want the abandoned"+
			" deferral named once at Debug", logs.Messages())
	}
}

// TestStoreReconcile_defers_once_per_batch pins the two things that decide what the
// deferral COSTS. It waits once for the whole batch, not once per candidate: at
// reapDeferral each, a tree with twenty stale bundles would hold the scan's only
// goroutine for ten minutes. And it is not entered at all when there is nothing to
// confirm — the empty-/input guard refuses before the delay, so a wrong or slow mount
// neither pauses the scan nor reaches the re-check.
// Serial: it swaps waitBeforeReap.
func TestStoreReconcile_defers_once_per_batch(t *testing.T) {
	for _, tc := range []struct {
		name        string
		total       int
		wantWaits   int
		wantDeleted int
	}{
		{"three orphans share one wait", 1, 1, 3},
		{"an empty input tree never reaches the wait", 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			names := []string{"a.pfx", "b.pfx", "c.pfx"}
			for _, name := range names {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("pfx"), 0o600); err != nil {
					t.Fatalf("setup: WriteFile(%s): %v", name, err)
				}
			}
			s := newOutputStore(t, dir)
			waits := 0
			stubReapWait(t, func(context.Context) error {
				waits++
				return nil
			})

			deleted, reconcileErr := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
				reconcile(t.Context(), map[string]struct{}{},
					&reapContext{result: ScanResult{Total: tc.total}, walkCompleted: true})

			if reconcileErr != nil {
				t.Fatalf("reconcile = error %v, want nil", reconcileErr)
			}
			if waits != tc.wantWaits {
				t.Errorf("reconcile(%d candidates) waited %d times, want %d", len(names), waits, tc.wantWaits)
			}
			if deleted != tc.wantDeleted {
				t.Errorf("reconcile(%d candidates) deleted = %d, want %d", len(names), deleted, tc.wantDeleted)
			}
		})
	}
}

// TestScannerRun_reports_a_shutdown_that_arrives_during_reconciliation pins the one
// place Scanner.Run turns a reconciliation error into the scan's own outcome. The input
// walk completed cleanly, so walkErr is nil and nothing else in Run can notice that the
// scan stopped halfway through the OUTPUT tree: without the fold, Run returns nil, logs
// "scan complete" at Info -- the record the README's stall alert keys on -- and
// main.healthyAfterScan leaves the health marker set for a scan that was cancelled
// mid-reap under OUTPUT_LIFECYCLE=sync. Serial: it swaps waitBeforeReap and
// slog.Default.
func TestScannerRun_reports_a_shutdown_that_arrives_during_reconciliation(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	writeSelfSignedPair(t, certsRoot, "live")
	// One orphan bundle, so reconciliation has something to confirm and the deferral is
	// entered at all.
	orphan := filepath.Join(outRoot, "gone.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: write orphan: %v", err)
	}
	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
		Lifecycle: outputpolicy.LifecycleSync,
	})
	// Live for the whole walk and cancelled inside the confirmation window: the only
	// arrangement in which the walk succeeds and reconciliation does not.
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	stubReapWait(t, func(ctx context.Context) error {
		cancel()
		return ctx.Err()
	})
	logs := captureLogs(t)

	res, err := scanner.Run(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run(shutdown during reconciliation) error = %v, want context.Canceled: a scan that stopped partway through the output tree is not complete", err)
	}
	if res.Removed != 0 {
		t.Errorf("Run(shutdown during reconciliation) Removed = %d, want 0", res.Removed)
	}
	if got := logs.CountExact("scan complete"); got != 0 {
		t.Errorf("Run(shutdown during reconciliation) logged %q, want no scan-complete record: it would leave the health marker set and satisfy the stall alert", logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelDebug, "scan cancelled during shutdown"); got != 1 {
		t.Errorf("Run(shutdown during reconciliation) logged %q, want the shutdown summary once at Debug", logs.Messages())
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Errorf("os.Stat(%q) = %v, want the orphan left in place: nothing may be deleted once the process is stopping", orphan, statErr)
	}
}

// TestScannerRun_reports_the_reap_count pins Scanner.Run's one assignment of the reap
// count into its own result. Every existing reap test asserts Removed == 0 on a scan
// that must NOT delete, so a Run that dropped the assignment would report removed=0 for
// the life of the deployment -- in the ScanResult the composition root logs and in the
// summary attribute the README documents -- while bundles really were being deleted.
func TestScannerRun_reports_the_reap_count(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	writeSelfSignedPair(t, certsRoot, "live")
	orphan := filepath.Join(outRoot, "gone.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: write orphan: %v", err)
	}
	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
		Lifecycle: outputpolicy.LifecycleSync,
	})

	res, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(one orphan, sync) = error %v, want nil", err)
	}
	if res.Removed != 1 {
		t.Errorf("Run(one orphan, sync) Removed = %d, want 1: the count the operator sees must be the count that was deleted", res.Removed)
	}
	if _, statErr := os.Stat(orphan); statErr == nil {
		t.Errorf("os.Stat(%q) = nil, want the orphan deleted: the case must exercise a real reap", orphan)
	}
}

// TestLogScanOutcome_names_the_output_side_counts pins the two /output-side counts in
// the end-of-scan summary, the pair no other test asserts (unresolved and vanished each
// have their own). Both are operator signals: removed is how many bundles this scan
// deleted under OUTPUT_LIFECYCLE=sync, and unwritable is the health-neutral count of
// bundles whose replacing write the volume refused, deliberately kept out of failed= and
// unreadable= so each documented alert keeps its own diagnosis. Dropping either
// attribute leaves a scan that deleted key material, or that left a world-readable
// private key in place, indistinguishable from a clean one. Serial: it swaps
// slog.Default.
func TestLogScanOutcome_names_the_output_side_counts(t *testing.T) {
	logs := captureLogs(t)

	logScanOutcome(t.Context(), &ScanResult{Total: 2, Converted: 1, Removed: 3, Unwritable: 2}, nil)

	for key, want := range map[string]string{"removed": "3", "unwritable": "2"} {
		if !logs.HasAttr("scan complete", key, want) {
			got, _ := logs.AttrValue("scan complete", key)
			t.Errorf("logScanOutcome logged %s=%q, want %q", key, got, want)
		}
	}
}

// TestScanWalk_streams_directories_larger_than_one_read_batch pins the scan's entry
// accounting across a tree bigger than one of the walk's read batches.
//
// atomicfile.WalkDirInRoot reads each directory in fixed-size batches through the
// confined root instead of handing the whole thing to fs.WalkDir, which reads AND sorts
// a directory's complete inventory before the entry budget gets to see a single path —
// so a hostile flat /input could force that inventory into memory before it could be
// refused. The batching itself is the library's contract (and pinned in its own suite);
// what this pins is the half that stays here: every entry, at every depth, must reach
// this app's visitor exactly once, so the budget charges what the scan actually visited.
func TestScanWalk_streams_directories_larger_than_one_read_batch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Comfortably more than atomicfile's fixed 256-entry read batch, so the walk's
	// per-directory loop has to span several of them.
	const flat = 293
	for i := range flat {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("entry-%04d.txt", i)), []byte("x"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile: %v", err)
		}
	}
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o750); err != nil {
		t.Fatalf("setup: Mkdir: %v", err)
	}
	const deep = 5
	for i := range deep {
		if err := os.WriteFile(filepath.Join(nested, fmt.Sprintf("deep-%d.txt", i)), []byte("x"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile: %v", err)
		}
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	sw := &scanWalk{src: &source{root: root}, seen: make(map[string]struct{}), observations: newObservationLog(0)}

	if walkErr := atomicfile.WalkDirInRoot(t.Context(), root, func(rel string, d fs.DirEntry, err error) error {
		return sw.visit(t.Context(), rel, d, err)
	}); walkErr != nil {
		t.Fatalf("WalkDirInRoot(a tree spanning several read batches) = %v, want nil", walkErr)
	}
	// The root, every flat entry, the nested directory, and everything inside it.
	if want := 1 + flat + 1 + deep; sw.budget.Count() != want {
		t.Errorf("the walk visited %d entries, want %d: a batched read must reach every entry of every directory exactly once",
			sw.budget.Count(), want)
	}
	if sw.unreadable != 0 || sw.unresolved != 0 || sw.vanished != 0 {
		t.Errorf("the walk reported unreadable=%d unresolved=%d vanished=%d on a clean tree, want zeros",
			sw.unreadable, sw.unresolved, sw.vanished)
	}
}

// TestScanWalk_charges_an_unreadable_directory_once pins the entry accounting: the
// budget counts ENUMERATED paths, so a directory the walk cannot open is charged when
// its parent enumerates it and NOT again when the streaming read reports the open
// failure through visit for that same path.
//
// Charging both made the operator's MAX_SCAN_ENTRIES bite below its configured value on
// any tree with unreadable directories, and made the `entries=` figure in the abort WARN
// overstate what the scan visited — sending the operator to raise a limit that was never
// reached. Skipped as root, which no directory mode refuses.
func TestScanWalk_charges_an_unreadable_directory_once(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0o000 directory is still readable")
	}
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o000); err != nil {
		t.Fatalf("setup: Mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o750) })

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	sw := &scanWalk{src: &source{root: root}, seen: make(map[string]struct{}), observations: newObservationLog(0)}

	if walkErr := atomicfile.WalkDirInRoot(t.Context(), root, func(rel string, d fs.DirEntry, err error) error {
		return sw.visit(t.Context(), rel, d, err)
	}); walkErr != nil {
		t.Fatalf("WalkDirInRoot(tree with one unreadable directory) = %v, want nil: an unreadable"+
			" sub-path must not abort the walk", walkErr)
	}
	// The root and the blocked directory: two enumerated paths, two charges. The open
	// failure visit for "blocked" must add nothing.
	if want := 2; sw.budget.Count() != want {
		t.Errorf("the walk charged %d entries, want %d: a directory the walk cannot open is"+
			" reported through visit for a path its parent already charged, so charging there"+
			" enforces MAX_SCAN_ENTRIES below its configured value", sw.budget.Count(), want)
	}
	if sw.unreadable != 1 {
		t.Errorf("the walk reported unreadable=%d, want 1", sw.unreadable)
	}
}

// The directory half of the FIFO guarantee — a reader-less pipe swapped in for a
// directory between the readdir that classified it and the open must be REFUSED with
// ENOTDIR, never waited on — moved with the walk into atomicfile
// (TestWalkDirInRoot_refuses_a_fifo_in_a_directory_position), which owns the O_DIRECTORY
// open. Its app-level consequence is pinned here by the unreadable-sub-path tests: such a
// path is one unreadable entry, health-neutral and reap-vetoing.

// TestScannerRun_refuses_a_tree_over_the_entry_budget pins the entry budget, the bound on
// how much of an untrusted /input one scan takes on, and — the load-bearing half — what
// the abort must NOT do: reap, or flip health.
//
// /input is a mounted tree this app does not own, and before the budget nothing capped
// how many entries the walk accepted: every one costs cumulative memory (a `seen` key, a
// result, an observation entry), so a large planted inventory drove the daemon into an
// OOM kill and stopped conversion for every certificate. Aborting mid-tree makes `seen`
// a PARTIAL enumeration, which must never authorise a deletion: without the veto, sync
// mode would read every bundle whose certificate the walk never reached as an orphan and
// delete live key material.
//
// The OLD defence — Run returns errScanBudgetExceeded to its caller — is void, and
// deliberately so: main.scanAndSetHealth clears the health marker on any non-shutdown
// error from Run, so a too-large tree restart-looped the container on a condition no
// restart can clear. It is now reported (scanBudgetMsg at WARN, with the remediation that
// names MAX_SCAN_ENTRIES) and health-neutral, the same reading this app already gives
// every /input path it could not read. What replaces the assertion is its inverse: the
// error must NOT reach the caller, and the WARN must.
//
// The budget is injected (Options.MaxScanEntries) rather than swapped through a package
// var. Serial: it swaps slog.Default.
func TestScannerRun_refuses_a_tree_over_the_entry_budget(t *testing.T) {
	inDir, outDir := t.TempDir(), t.TempDir()
	for _, name := range []string{"a.crt", "b.crt", "c.crt"} {
		if err := os.WriteFile(filepath.Join(inDir, name), []byte("not a pem"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s): %v", name, err)
		}
	}
	// A bundle with no input at all: the candidate sync mode would delete if a truncated
	// enumeration were allowed to stand in for a complete one.
	orphan := filepath.Join(outDir, "gone.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(gone.pfx): %v", err)
	}
	logs := captureLogs(t)

	result, err := New(&Options{
		CertsRoot: inDir, OutRoot: outDir,
		Encoder:  convert.EncNameModern2023,
		Password: "pw", Lifecycle: outputpolicy.LifecycleSync,
		// Two: the walk root itself plus one entry, so the third hand-off trips the budget.
		MaxScanEntries: 2,
	}).Run(t.Context())
	if err != nil {
		t.Fatalf("Run(tree over the entry budget) = %v, want nil: a tree bigger than the budget"+
			" is not restart-clearable, so it must not reach the health marker", err)
	}
	if result.Failed != 0 {
		t.Errorf("Run(tree over the entry budget) failed = %d, want 0: health is driven by Failed alone", result.Failed)
	}
	if result.Removed != 0 {
		t.Errorf("Run(tree over the entry budget) removed = %d, want 0", result.Removed)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Errorf("the orphan candidate was deleted on a truncated enumeration: %v", statErr)
	}
	if got := logs.CountLevel(slog.LevelWarn, scanBudgetMsg); got != 1 {
		t.Errorf("Run(tree over the entry budget) logged %q at WARN %d times, want exactly 1: %q",
			scanBudgetMsg, got, logs.Messages())
	}
	// The remediation is the ONLY operator action for this condition now that no error
	// propagates, so it has to name the way out of a legitimately large tree.
	assertRemediationMentions(t, logs, scanBudgetMsg, "MAX_SCAN_ENTRIES")
}

// TestScannerRun_takes_the_injected_entry_budget is the negative half of the injected
// ceiling: internal/config owns MAX_SCAN_ENTRIES (its default, its ceiling and every
// diagnostic for a repaired value) and hands the number to this package, which must not
// read the environment itself. Together with the budget of 2 above — the case that proves
// the injected number is the one enforced — this pins the BOUNDARY: the budget is a
// maximum, so a tree of exactly as many entries as the budget allows must scan cleanly.
// Walking the root plus three certificates is four entries against a budget of four, so a
// bound that refused AT the limit instead of past it would report here.
func TestScannerRun_takes_the_injected_entry_budget(t *testing.T) {
	inDir, outDir := t.TempDir(), t.TempDir()
	for _, name := range []string{"a.crt", "b.crt", "c.crt"} {
		if err := os.WriteFile(filepath.Join(inDir, name), []byte("not a pem"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s): %v", name, err)
		}
	}
	logs := captureLogs(t)

	if _, err := New(&Options{
		CertsRoot: inDir, OutRoot: outDir,
		Encoder:  convert.EncNameModern2023,
		Password: "pw", Lifecycle: outputpolicy.LifecycleSync,
		// Exactly the tree's size: the root plus a.crt, b.crt and c.crt.
		MaxScanEntries: 4,
	}).Run(t.Context()); err != nil {
		t.Fatalf("Run(tree inside the injected budget) = %v, want nil", err)
	}

	if got := logs.CountLevel(slog.LevelWarn, scanBudgetMsg); got != 0 {
		t.Errorf("a tree of 4 entries tripped a budget of 4 (%d %q records): the budget is a maximum, not a limit the walk stops short of: %q",
			got, scanBudgetMsg, logs.Messages())
	}
}

// TestObservationLog_is_bounded_across_path_churn pins the other half of the same bound.
// forget only prunes on a walk that PROVED the enumeration complete, so a deployment
// whose scans keep ending incomplete never reclaims the entries of paths that are gone,
// and /input path churn then grows process-lifetime state without a ceiling.
//
// Eviction spends the SIGNATURE freely (a re-emitted WARN, and no currency decision reads
// this log at all). It does not get to spend the WHOLENESS evidence silently, which is
// what the second half of this test pins: every wholeness entry dropped is counted, and
// Scanner.Run turns the count into that scan's reap veto — see
// TestScannerRun_fails_closed_when_the_observation_log_evicts_wholeness_evidence.
func TestObservationLog_is_bounded_across_path_churn(t *testing.T) {
	log := newObservationLog(2)
	for _, rel := range []string{"a.crt", "b.crt", "c.crt", "d.crt", "e.crt"} {
		log.note(rel, pairFingerprint([]byte(rel), []byte("key")), nil)
	}

	if got := len(log.seen); got > log.maxObservedPairs() {
		t.Errorf("observationLog holds %d signatures after churn across 5 paths, want at most %d",
			got, log.maxObservedPairs())
	}
	if got := len(log.whole); got > log.maxObservedPairs() {
		t.Errorf("observationLog holds %d wholeness entries after churn across 5 paths, want at most %d:"+
			" an eviction must not leave the two halves out of step", got, log.maxObservedPairs())
	}
	// The path recorded last is the one an operator is most likely to ask about next, and
	// re-noting a remembered path must never evict anything.
	if !log.completedPair("e.crt") {
		t.Errorf("observationLog forgot the most recently recorded pair; eviction must make room, not drop the new entry")
	}
	// Every pair that lost its wholeness evidence has to be reported, because that
	// evidence is what separates a replaced key from an absent one: three of the five
	// paths above were evicted from a log that may hold two.
	if got := log.takeEvictedWholeness(); got != 3 {
		t.Errorf("takeEvictedWholeness after churn across 5 paths at a ceiling of 2 = %d, want 3:"+
			" a dropped wholeness entry is a lost reap justification, not free memory", got)
	}
	if got := log.takeEvictedWholeness(); got != 0 {
		t.Errorf("takeEvictedWholeness re-read = %d, want 0: the veto covers the scan that spent the evidence", got)
	}

	// The readPair boundary records wholeness for pairs that never reach note or record
	// (an Analyse failure, an Encode failure, a failed write), so the structural half has
	// to be bounded at its OWN entry point, not only through the signature writers.
	structural := newObservationLog(2)
	for _, rel := range []string{"f.crt", "g.crt", "h.crt", "i.crt", "j.crt"} {
		structural.markWhole(rel)
	}
	if got := len(structural.whole); got > structural.maxObservedPairs() {
		t.Errorf("markWhole alone left %d wholeness entries after churn across 5 paths, want at most %d",
			got, structural.maxObservedPairs())
	}
	if !structural.completedPair("j.crt") {
		t.Errorf("markWhole evicted the pair it was reserving room for; eviction must pick another victim")
	}
	if got := structural.takeEvictedWholeness(); got != 3 {
		t.Errorf("takeEvictedWholeness after markWhole-only churn = %d, want 3: the structural entry"+
			" point has to report its own evictions", got)
	}
}

// TestObservationLog_counts_only_evidence_it_actually_held guards the eviction counter
// against the opposite error: vetoing a reap for evidence that never existed. A path the
// signature half knows and the wholeness half does not is the common shape (note is
// reached for pairs whose key is missing), and evicting it costs a deduplicated WARN and
// nothing else. Only a dropped WHOLENESS entry is a lost reap justification.
func TestObservationLog_counts_only_evidence_it_actually_held(t *testing.T) {
	log := newObservationLog(1)
	log.seen["a.crt"] = pairFingerprint([]byte("a"), []byte("k"))
	// b.crt reserves the last slot, so a.crt — signature-only — is the victim.
	log.note("b.crt", pairFingerprint([]byte("b"), []byte("k")), nil)

	if _, held := log.seen["a.crt"]; held {
		t.Fatal("setup did not evict the signature-only entry; the rest of this test proves nothing")
	}
	if got := log.takeEvictedWholeness(); got != 0 {
		t.Errorf("takeEvictedWholeness after evicting a signature-only entry = %d, want 0:"+
			" a scan must not lose orphan removal for evidence the log never held", got)
	}
}

func TestObservationLog_wholeness_eviction_makes_room_without_touching_the_reserved_path(t *testing.T) {
	log := newObservationLog(1)
	// The reachable shape: a.crt is remembered by the SIGNATURE half (note ran for it)
	// while its wholeness entry is gone, and the wholeness half is already full.
	// reserve routes this through the wholeness-half reservation, which must evict the OTHER pair,
	// keep the reserved path's signature entry, hold the half at its ceiling, and
	// count the drop as this scan's reap veto. (The `victim == keep` guards themselves
	// are unreachable from reserve, whose preconditions exclude the reserved path from
	// the half being evicted; they are defensive only.)
	log.seen["a.crt"] = pairFingerprint([]byte("a"), []byte("k"))
	log.whole["b.crt"] = struct{}{}

	log.markWhole("a.crt")

	if _, held := log.seen["a.crt"]; !held {
		t.Error("markWhole evicted the signature entry of the path it was reserving room for")
	}
	if _, held := log.whole["b.crt"]; held {
		t.Error("markWhole made no room in the wholeness half; want the other path evicted")
	}
	if got := len(log.whole); got != 1 {
		t.Errorf("len(whole) = %d, want 1: the wholeness half must stay at its ceiling", got)
	}
	if got := log.takeEvictedWholeness(); got != 1 {
		t.Errorf("takeEvictedWholeness = %d, want 1: a dropped wholeness entry is this scan's reap veto", got)
	}
}

// TestObservationLog_eviction_spares_the_wholeness_the_active_scan_established pins
// canEvict's active-scan arm, which is the whole of the protection the ceiling's victim
// choice would otherwise defeat.
//
// reserve's victim is arbitrary (map iteration order), so without the arm a pair THIS
// walk already read whole can be the one evicted — and then noteMissingKey, later in the
// same walk, cannot tell a private key being replaced from one that was never there. The
// eviction does raise the scan's reap veto, but that veto is consumed by the scan that
// spent the evidence, so it is already gone by the scan that needed the evidence: the
// protection has to be in the victim choice, not in the counter.
//
// Two halves, because either alone is passable for the wrong reason. The protected half
// drives the ceiling with the active pair as the ONLY candidate, so deleting canEvict's
// activeWhole arm fails it deterministically rather than half the time. The unprotected
// half proves the same ceiling really does evict, so the first half cannot be passing
// merely because nothing was ever at risk.
func TestObservationLog_eviction_spares_the_wholeness_the_active_scan_established(t *testing.T) {
	t.Parallel()

	t.Run("a pair this walk read whole survives the ceiling", func(t *testing.T) {
		t.Parallel()
		log := newObservationLog(1)
		log.beginScan()
		t.Cleanup(log.endScan)

		log.markWhole("active.crt")
		// At the ceiling now, so reserving a second pair looks for a victim — and the
		// only candidate is the pair this walk just read whole.
		log.markWhole("fresh.crt")

		if !log.completedPair("active.crt") {
			t.Error("the pair this walk read whole lost its wholeness to the ceiling: noteMissingKey" +
				" would report a key being replaced as an ordinary orphan, which vetoes nothing")
		}
		if got := log.takeEvictedWholeness(); got != 0 {
			t.Errorf("takeEvictedWholeness = %d, want 0: nothing evictable existed, so the log holds"+
				" one entry over the ceiling rather than spending the active scan's evidence", got)
		}
	})

	t.Run("a pair an earlier scan read whole is still evictable", func(t *testing.T) {
		t.Parallel()
		log := newObservationLog(1)
		// Established outside any walk: what an earlier scan leaves behind, and what an
		// eviction may legitimately take.
		log.markWhole("stale.crt")
		log.beginScan()
		t.Cleanup(log.endScan)

		log.markWhole("fresh.crt")

		if log.completedPair("stale.crt") {
			t.Error("nothing was evicted at the ceiling, so the protected-pair case above would pass" +
				" even with the ceiling removed")
		}
		if got := log.takeEvictedWholeness(); got != 1 {
			t.Errorf("takeEvictedWholeness = %d, want 1: a dropped wholeness entry is this scan's reap veto", got)
		}
	})
}

// TestObservationLog_signature_eviction_spares_the_wholeness_the_active_scan_established
// is the SIGNATURE arm of the protection the test above pins on the wholeness arm.
//
// reserve has two eviction entry points and both route through ONE shared eviction
// (evictFrom), whose canEvict consultation the wholeness arm above already pins — its
// protected-half subtest reserves at the ceiling with the active pair as the only
// candidate, so an unguarded eviction fails it deterministically. What THIS arm pins is
// the signature-half entry point the test above never enters (it drives markWhole only,
// which leaves `seen` empty): reserveSeen making room in `seen` for a note-driven pair
// must spare the wholeness of a pair the active walk read whole — the evidence
// noteMissingKey classifies a replaced private key against. Were it spent, the scan
// would read a key being replaced as an ordinary
// orphan, which vetoes nothing, and unrelated bundles are deleted on an enumeration it can
// no longer defend.
//
// note rather than markWhole is what puts the pair in BOTH halves, which is what makes the
// signature half reach its ceiling and hunt a victim at all.
func TestObservationLog_signature_eviction_spares_the_wholeness_the_active_scan_established(t *testing.T) {
	t.Parallel()
	log := newObservationLog(1)
	log.beginScan()
	t.Cleanup(log.endScan)

	log.note("active.crt", pairFingerprint([]byte("cert"), []byte("key")), nil)
	// The signature half is at its ceiling now, so reserving room for a second pair hunts a
	// victim in `seen` -- where the only candidate is the pair this walk read whole.
	log.note("fresh.crt", pairFingerprint([]byte("fresh"), []byte("key")), nil)

	if !log.completedPair("active.crt") {
		t.Error("the signature eviction spent the wholeness of a pair this walk read whole:" +
			" noteMissingKey would report a key being replaced as an ordinary orphan, which vetoes" +
			" nothing, so the scan would delete bundles on an enumeration it cannot defend")
	}
	if got := log.takeEvictedWholeness(); got != 0 {
		t.Errorf("takeEvictedWholeness = %d, want 0: nothing evictable existed, so the log holds one"+
			" entry over the ceiling rather than spending the active scan's evidence", got)
	}
	if !log.completedPair("fresh.crt") {
		t.Error("the pair being reserved for lost its own wholeness: reserve must never take the path" +
			" it is making room for as its victim")
	}
}

// TestScannerRun_fails_closed_when_the_observation_log_evicts_wholeness_evidence is the
// deletion-side consequence of the bound above, and the one the bounded-log test cannot
// see: that test drives the log through one entry point and asserts on its SIZE, while
// the damage is in the scan that spent the evidence.
//
// noteMissingKey reads the wholeness evidence as "this certificate HAD its sibling key",
// and only that reading produces the reap-vetoing statusVanished; without it the same
// ENOENT is an ordinary statusOrphan, which vetoes nothing. So an eviction silently
// converted "I cannot tell whether this key is being replaced" into "the enumeration is
// complete", and unrelated leftover bundles were deleted on the strength of it. The gate
// now fails closed on the loss: nothing is deleted, and the loss is named at WARN with
// the budget as the remediation.
//
// The log is pre-loaded to its ceiling because that is the state earlier scans leave
// behind (forget only prunes on a walk that PROVED the enumeration complete, so a
// deployment whose scans keep ending incomplete accumulates), and driving it from the
// filesystem would need more /input entries than the same number allows one scan to walk.
// Serial: it swaps waitBeforeReap and slog.Default.
func TestScannerRun_fails_closed_when_the_observation_log_evicts_wholeness_evidence(t *testing.T) {
	certsRoot, outRoot := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, certsRoot, "live")
	// A bundle with no input: the candidate this scan must NOT delete once it admits it
	// lost the evidence behind its own missing-key classification.
	orphan := filepath.Join(outRoot, "gone.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: write orphan: %v", err)
	}
	// Three entries walked (root, live.crt, live.key) sit inside a budget of 4, so the
	// walk completes and every other veto is clear; the log arrives already holding its
	// four pairs, so reserving room for live.crt has to evict one.
	scanner := New(&Options{
		CertsRoot: certsRoot, OutRoot: outRoot,
		Password: "pw", Encoder: convert.EncNameModern2023,
		Lifecycle:      outputpolicy.LifecycleSync,
		MaxScanEntries: 4,
	})
	for _, rel := range []string{"a.crt", "b.crt", "c.crt", "d.crt"} {
		scanner.observations.markWhole(rel)
	}
	if got := scanner.observations.takeEvictedWholeness(); got != 0 {
		t.Fatalf("setup evicted %d entries while filling the log to its ceiling, want 0:"+
			" the scan under test has to be the one that evicts", got)
	}
	stubReapWait(t, func(context.Context) error { return nil })
	logs := captureLogs(t)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(log at its ceiling) = %v, want nil: losing a diagnostic memory is not a scan failure", err)
	}
	if result.Removed != 0 {
		t.Errorf("Run(log at its ceiling) removed = %d, want 0: the reap gate must fail closed on evicted evidence", result.Removed)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Errorf("an orphan was deleted on a scan that lost the evidence separating a replaced key from a missing one: %v", statErr)
	}
	const disabledWarn = reapDisabledPhrase + ": this scan cannot prove any /output bundle is orphaned"
	if got := logs.CountLevel(slog.LevelWarn, disabledWarn); got != 1 {
		t.Errorf("Run(log at its ceiling) logged %q at WARN %d times, want exactly 1: %q",
			disabledWarn, got, logs.Messages())
	}
	assertRemediationMentions(t, logs, disabledWarn, "MAX_SCAN_ENTRIES")
}

// TestScannerRun_prunes_the_observation_log_despite_an_eviction pins the RECOVERY half
// of the evicted-evidence gate: the scan that lost wholeness evidence refuses to reap,
// but it must still PRUNE, so the next scan is clean.
//
// Gating the prune on the full enumerationClean (which includes evidenceComplete) made
// eviction pressure disable the only mechanism that relieves it: the log stays pinned
// at its ceiling, the next scan evicts again, and orphan reaping is off until a process
// restart. The prune is therefore gated on walkEnumerationComplete alone, and forget()
// deletes from both halves directly rather than through dropWholeness, so pruning
// cannot manufacture the next scan's veto.
// Serial: it swaps waitBeforeReap and slog.Default.
func TestScannerRun_prunes_the_observation_log_despite_an_eviction(t *testing.T) {
	certsRoot, outRoot := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, certsRoot, "live")
	scanner := New(&Options{
		CertsRoot: certsRoot, OutRoot: outRoot,
		Password: "pw", Encoder: convert.EncNameModern2023,
		Lifecycle:      outputpolicy.LifecycleSync,
		MaxScanEntries: 4,
	})
	// Four remembered pairs, none of which exists under /input, so the log is at its
	// ceiling and reserving room for live.crt has to evict one.
	for _, rel := range []string{"a.crt", "b.crt", "c.crt", "d.crt"} {
		scanner.observations.markWhole(rel)
	}
	if got := scanner.observations.takeEvictedWholeness(); got != 0 {
		t.Fatalf("setup evicted %d entries, want 0", got)
	}
	stubReapWait(t, func(context.Context) error { return nil })
	captureLogs(t)

	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatalf("Run(log at its ceiling) = %v, want nil", err)
	}
	// The gone pairs are reclaimed even though this scan evicted: only live.crt, the
	// one path the walk saw, may remain.
	for _, rel := range []string{"a.crt", "b.crt", "c.crt", "d.crt"} {
		if _, held := scanner.observations.whole[rel]; held {
			t.Errorf("observation log still holds wholeness for %q, which is absent from /input:"+
				" gating the prune on the evidence half leaves the log pinned at its ceiling and"+
				" orphan reaping off until a restart", rel)
		}
	}
	// The prune must not itself count as an evidence loss, or the NEXT scan inherits
	// this scan's veto and the state is self-sustaining after all.
	if got := scanner.observations.takeEvictedWholeness(); got != 0 {
		t.Errorf("after Run the pending evicted-wholeness count is %d, want 0: forget() must"+
			" delete evidence for gone paths without charging it as a loss", got)
	}
}

// assertRemediationMentions requires msg's record to carry a remediation naming want.
// These conditions are reported and never fixed by the app, so the remediation IS the
// operator's only way out and a hint that does not name the setting is not one.
func assertRemediationMentions(t *testing.T, logs *capture.Recorder, msg, want string) {
	t.Helper()
	got, ok := logs.AttrValue(msg, "remediation")
	if !ok {
		t.Errorf("record %q carries no remediation: it is the only line the operator sees", msg)
		return
	}
	if !strings.Contains(got, want) {
		t.Errorf("record %q remediation = %q, want it to name %q", msg, got, want)
	}
}

// TestStoreReconcile_rechecks_each_candidate_immediately_before_its_own_deletion is
// h-f7's regression: the absence observation that authorizes deleting a bundle has to be
// adjacent to that deletion.
//
// A batch confirmation pass — re-check every candidate, THEN unlink every survivor —
// makes each candidate's authorizing observation older by however long the rest of the
// batch takes to check, and a producer that restores a certificate inside that stretch
// loses its live bundle anyway. The sequence must stay one shared wait followed by, per
// candidate, `input re-check -> output lstat -> unlink`.
//
// The per-path ORDER is what pins it: the per-path deletion line (Debug, the unbounded
// detail behind the once-per-scan audit record) and the keep line for a cancelled one.
// Under the batch shape every keep precedes every removal; interleaved, `early.pfx` is
// gone before `later.pfx` is ever looked at. Serial: it swaps waitBeforeReap and
// slog.Default.
func TestStoreReconcile_rechecks_each_candidate_immediately_before_its_own_deletion(t *testing.T) {
	out := t.TempDir()
	// Walk order is lexical, so early.pfx is the candidate processed first.
	for _, name := range []string{"early.pfx", "later.pfx"} {
		if err := os.WriteFile(filepath.Join(out, name), []byte("pfx"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s): %v", name, err)
		}
	}
	in := t.TempDir()
	s := newOutputStore(t, out)
	stubReapWait(t, func(context.Context) error {
		return os.WriteFile(filepath.Join(in, "later.crt"), []byte("cert"), 0o600)
	})
	logs := captureLogs(t)

	deleted, reconcileErr := newReaper(s, newInputSource(t, in), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})

	if reconcileErr != nil {
		t.Fatalf("reconcile(interleaved re-check) = error %v, want nil", reconcileErr)
	}
	if deleted != 1 {
		t.Errorf("reconcile(interleaved re-check) deleted = %d, want 1", deleted)
	}
	const (
		removedMsg = "removed orphaned output whose input is gone"
		keptMsg    = "keeping an output bundle whose certificate came back during the confirmation delay"
	)
	removedAt, keptAt := -1, -1
	for i, msg := range logs.Messages() {
		switch msg {
		case removedMsg:
			removedAt = i
		case keptMsg:
			keptAt = i
		}
	}
	if removedAt < 0 || keptAt < 0 {
		t.Fatalf("reconcile logged %q, want both the deletion audit line and the cancelled deletion", logs.Messages())
	}
	if removedAt > keptAt {
		t.Errorf("reconcile logged %q: later.pfx was re-checked before early.pfx was unlinked, so the whole batch is authorized by observations taken before any deletion — every candidate must be re-checked immediately before its own unlink",
			logs.Messages())
	}
	if _, statErr := os.Stat(filepath.Join(out, "early.pfx")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(early.pfx) = %v, want fs.ErrNotExist: its certificate stayed gone", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(out, "later.pfx")); statErr != nil {
		t.Errorf("the bundle whose certificate came back was deleted: %v", statErr)
	}
}

// TestStoreReconcile_keeps_a_bundle_whose_private_key_is_still_present is h-f3's
// regression, on the only path in this app that deletes private-key material.
//
// The confirming re-check asked one question — did the CERTIFICATE come back within
// reapDeferral — and a producer that writes a pair key-first with more than 30 seconds
// between the two steps (an rsync of a large tree, a manual install, a slow network
// mount) presents exactly the observation of a deleted certificate. Its live bundle was
// removed. The sibling key is the second, independent piece of evidence: a pair whose key
// is still there is a pair somebody is still keeping.
//
// The 30-second confirmation is KEPT, not widened into a one-scan grace: a grace would lag
// an intentional deletion by up to FALLBACK_SCAN_HOURS, and while it stood an old PFX
// would coexist with a newly arrived certificate so a consumer could read the stale
// bundle. Serial: it swaps waitBeforeReap and slog.Default.
func TestStoreReconcile_keeps_a_bundle_whose_private_key_is_still_present(t *testing.T) {
	out := t.TempDir()
	// Walk order is lexical: half.pfx keeps its key, whole.pfx has neither input left.
	for _, name := range []string{"half.pfx", "whole.pfx"} {
		if err := os.WriteFile(filepath.Join(out, name), []byte("pfx"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s): %v", name, err)
		}
	}
	in := t.TempDir()
	// The key arrived; its certificate has not. Every reap veto is otherwise clear, which
	// is why nothing but this check stands between the key and its bundle's deletion.
	if err := os.WriteFile(filepath.Join(in, "half.key"), []byte("key"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(half.key): %v", err)
	}
	s := newOutputStore(t, out)
	stubReapWait(t, func(context.Context) error { return nil })
	logs := captureLogs(t)

	deleted, reconcileErr := newReaper(s, newInputSource(t, in), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})

	if reconcileErr != nil {
		t.Fatalf("reconcile(lone key) = error %v, want nil: a half-written pair is not a scan failure", reconcileErr)
	}
	if deleted != 1 {
		t.Errorf("reconcile(lone key) deleted = %d, want 1: only the pair that is gone entirely may go", deleted)
	}
	if _, statErr := os.Stat(filepath.Join(out, "half.pfx")); statErr != nil {
		t.Errorf("the bundle of a certificate whose private key is still in /input was deleted: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(out, "whole.pfx")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(whole.pfx) = %v, want fs.ErrNotExist: vetoing on a lone key must not"+
			" defer a genuine full deletion to a later scan", statErr)
	}
	// Nothing in this app reported a lone key at any level before, so the indefinite
	// retention this veto introduces would otherwise be completely silent.
	if got := logs.CountLevel(slog.LevelWarn, loneKeyRetainedMsg); got != 1 {
		t.Errorf("reconcile(lone key) logged %q at WARN %d times, want exactly 1: %q",
			loneKeyRetainedMsg, got, logs.Messages())
	}
	if !logs.HasAttr(loneKeyRetainedMsg, "key", "half.key") {
		got, _ := logs.AttrValue(loneKeyRetainedMsg, "key")
		t.Errorf("the lone-key WARN named key=%q, want %q: the operator has to be told which file to finish or remove",
			got, "half.key")
	}
	if !logs.HasAttr(loneKeyRetainedMsg, "path", "half.pfx") {
		got, _ := logs.AttrValue(loneKeyRetainedMsg, "path")
		t.Errorf("the lone-key WARN named path=%q, want %q: the retained bundle is the subject of the record", got, "half.pfx")
	}
	assertRemediationMentions(t, logs, loneKeyRetainedMsg, ".crt")
}

// TestStoreReconcile_lone_key_veto_reads_any_occupant_as_a_key pins the deliberate rule
// for a key path that holds something other than a regular file.
//
// The key is asked for with the SAME ENOENT-only semantics as the certificate
// (source.pathAbsent, one primitive for both questions): only an ENOENT counts as "no
// key". A directory, a FIFO or a symlink whose target does not resolve therefore vetoes
// the deletion too, because the alternative is unlinking private-key material on evidence
// that amounts to "the key path is odd" — and an odd occupant is not the operator
// removing the key. It never counts silently: the same WARN names the retention, which is
// what turns a stray directory at a key path from a never-reaped bundle nobody can explain
// into a named condition. Serial: it swaps waitBeforeReap and slog.Default.
func TestStoreReconcile_lone_key_veto_reads_any_occupant_as_a_key(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "odd.pfx"), []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(odd.pfx): %v", err)
	}
	in := t.TempDir()
	// A DIRECTORY at the key path: present, unreadable as a key, and not evidence that
	// the operator removed anything.
	if err := os.Mkdir(filepath.Join(in, "odd.key"), 0o750); err != nil {
		t.Fatalf("setup: Mkdir(odd.key): %v", err)
	}
	s := newOutputStore(t, out)
	stubReapWait(t, func(context.Context) error { return nil })
	logs := captureLogs(t)

	deleted, reconcileErr := newReaper(s, newInputSource(t, in), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})

	if reconcileErr != nil {
		t.Fatalf("reconcile(directory at the key path) = error %v, want nil", reconcileErr)
	}
	if deleted != 0 {
		t.Errorf("reconcile(directory at the key path) deleted = %d, want 0: an occupant that is not"+
			" a key is still not proof the key was removed", deleted)
	}
	if _, statErr := os.Stat(filepath.Join(out, "odd.pfx")); statErr != nil {
		t.Errorf("the bundle was deleted on the strength of an odd occupant at its key path: %v", statErr)
	}
	if got := logs.CountLevel(slog.LevelWarn, loneKeyRetainedMsg); got != 1 {
		t.Errorf("reconcile(directory at the key path) logged %q at WARN %d times, want exactly 1: %q",
			loneKeyRetainedMsg, got, logs.Messages())
	}
}

// TestStoreReconcile_names_a_certificate_recheck_it_could_not_make pins the OTHER caller of
// the same record, on the sync path: a candidate whose CERTIFICATE re-check fails inside
// the confirmation window must not be reported as "the certificate came back".
//
// That INFO states a positive fact — the producer wrote the pair back — and an operator
// told it while the mount is broken reads a working producer where there is none. At
// LOG_LEVEL=warn the INFO says nothing at all, so the stale bundle would sit in /output
// with no record of why. Serial: it swaps waitBeforeReap and slog.Default.
func TestStoreReconcile_names_a_certificate_recheck_it_could_not_make(t *testing.T) {
	out := t.TempDir()
	if err := os.Mkdir(filepath.Join(out, "blocked"), 0o750); err != nil {
		t.Fatalf("setup: Mkdir(out blocked): %v", err)
	}
	pfx := filepath.Join(out, "blocked", "x.pfx")
	if err := os.WriteFile(pfx, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(blocked/x.pfx): %v", err)
	}
	in := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(in, "blocked")); err != nil {
		t.Fatalf("setup: Symlink: %v", err)
	}
	s := newOutputStore(t, out)
	stubReapWait(t, func(context.Context) error { return nil })
	logs := captureLogs(t)

	deleted, err := newReaper(s, newInputSource(t, in), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})
	if err != nil {
		t.Fatalf("reconcile(uninspectable certificate path) = error %v, want nil", err)
	}
	if deleted != 0 {
		t.Errorf("reconcile(uninspectable certificate path) deleted = %d, want 0: an unanswerable question"+
			" never authorizes deleting key material", deleted)
	}
	if _, statErr := os.Stat(pfx); statErr != nil {
		t.Errorf("the bundle was deleted on a re-check that could not be made: %v", statErr)
	}
	if got := logs.CountLevel(slog.LevelWarn, recheckUnreadableMsg); got != 1 {
		t.Errorf("reconcile(uninspectable certificate path) logged %q at WARN %d times, want exactly 1: %q",
			recheckUnreadableMsg, got, logs.Messages())
	}
	const cameBackMsg = "keeping an output bundle whose certificate came back during the confirmation delay"
	if got := logs.CountLevel(slog.LevelInfo, cameBackMsg); got != 0 {
		t.Errorf("reconcile(uninspectable certificate path) logged %q at INFO %d times, want 0: a failed"+
			" re-check is not evidence the producer wrote the pair back: %q", cameBackMsg, got, logs.Messages())
	}
}

// TestStoreReconcile_audits_deletions_once_per_scan_at_warn pins the deletion audit
// record, the app's warn-visible contract for the one destructive action it takes.
//
// Successful deletions were named per path at INFO, so at LOG_LEVEL=warn — the level an
// operator runs a quiet daemon at — private-key bundles disappeared silently while only
// the FAILURES of orphan removal were loud. One structured record per deletion-bearing
// scan carries the count and the paths, through the SAME bounded sample the orphan report
// uses (sampleOrphanPaths, bounded at maxLoggedOrphanBytes) so
// a tree that lost many certificates at once cannot turn the audit into a multi-kilobyte
// line. Serial: it swaps waitBeforeReap and slog.Default.
func TestStoreReconcile_audits_deletions_once_per_scan_at_warn(t *testing.T) {
	out := t.TempDir()
	for _, name := range []string{"one.pfx", "two.pfx"} {
		if err := os.WriteFile(filepath.Join(out, name), []byte("pfx"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s): %v", name, err)
		}
	}
	s := newOutputStore(t, out)
	stubReapWait(t, func(context.Context) error { return nil })
	logs := captureLogs(t)

	deleted, reconcileErr := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})

	if reconcileErr != nil {
		t.Fatalf("reconcile(two orphans) = error %v, want nil", reconcileErr)
	}
	if deleted != 2 {
		t.Fatalf("reconcile(two orphans) deleted = %d, want 2", deleted)
	}
	if got := logs.CountLevel(slog.LevelWarn, reapAuditMsg); got != 1 {
		t.Errorf("a scan that deleted two bundles logged %q at WARN %d times, want exactly 1:"+
			" one record per deletion-bearing scan, not one per path", reapAuditMsg, got)
	}
	if !logs.HasAttr(reapAuditMsg, "count", "2") {
		got, _ := logs.AttrValue(reapAuditMsg, "count")
		t.Errorf("the deletion audit record count = %q, want %q", got, "2")
	}
	paths, ok := logs.AttrValue(reapAuditMsg, "paths")
	if !ok {
		t.Fatalf("the deletion audit record carries no paths attribute: the count alone does not say WHICH key material is gone")
	}
	for _, want := range []string{"one.pfx", "two.pfx"} {
		if !strings.Contains(paths, want) {
			t.Errorf("the deletion audit record paths = %q, want it to name %q", paths, want)
		}
	}
	// The per-path detail stays available for a reader who asked for it, one level down.
	if got := logs.CountLevel(slog.LevelDebug, "removed orphaned output whose input is gone"); got != 2 {
		t.Errorf("the per-path deletion detail logged %d times at DEBUG, want 2: the audit record"+
			" collapses the default-level report, it does not remove the detail", got)
	}
	// Nothing was refused, so the refusal half of the pair must stay silent, exactly as the
	// audit record does for a scan that deleted nothing.
	if got := logs.CountLevel(slog.LevelWarn, removalRefusedMsg); got != 0 {
		t.Errorf("a scan whose every unlink succeeded logged %q at WARN %d times, want 0: %q",
			removalRefusedMsg, got, logs.Messages())
	}
}

// TestStoreReconcile_no_audit_record_when_nothing_was_deleted is the other half of that
// contract: the audit record is WARN, so a scan that deleted nothing must not emit it. Its
// absence is what "nothing was deleted" looks like in a quiet log, and a record emitted
// with count=0 would train an operator to ignore the one line that reports destroyed key
// material. Serial: it swaps waitBeforeReap and slog.Default.
func TestStoreReconcile_no_audit_record_when_nothing_was_deleted(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "kept.pfx"), []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(kept.pfx): %v", err)
	}
	in := t.TempDir()
	// The certificate comes back inside the window, so the one candidate is spared and
	// the scan deletes nothing.
	stubReapWait(t, func(context.Context) error {
		return os.WriteFile(filepath.Join(in, "kept.crt"), []byte("cert"), 0o600)
	})
	logs := captureLogs(t)

	deleted, reconcileErr := newReaper(newOutputStore(t, out), newInputSource(t, in), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})

	if reconcileErr != nil {
		t.Fatalf("reconcile(candidate spared) = error %v, want nil", reconcileErr)
	}
	if deleted != 0 {
		t.Fatalf("reconcile(candidate spared) deleted = %d, want 0", deleted)
	}
	if got := logs.CountLevel(slog.LevelWarn, reapAuditMsg); got != 0 {
		t.Errorf("a scan that deleted nothing logged %q %d times at WARN, want 0: %q",
			reapAuditMsg, got, logs.Messages())
	}
}

// TestReapConfirmed_reports_refused_removals_once_per_scan_at_warn is the failure half of
// the deletion audit. ScanResult.Removed reports 0 for a scan whose every unlink was refused
// -- the same 0 a scan with nothing to reap reports -- so this record is the only countable
// signal that OUTPUT_LIFECYCLE=sync has stopped reconciling.
//
// The candidate is a DIRECTORY at an output name rather than a write-denied parent: the suite
// runs as uid 0, where directory permissions are ignored and the sibling permission-based
// fixture skips. reapConfirmed is driven directly so the walk's own candidate rules are not
// part of the fixture. Serial: it swaps waitBeforeReap and slog.Default.
func TestReapConfirmed_reports_refused_removals_once_per_scan_at_warn(t *testing.T) {
	out := t.TempDir()
	if err := os.Mkdir(filepath.Join(out, "stuck.pfx"), 0o750); err != nil {
		t.Fatalf("setup: Mkdir(stuck.pfx): %v", err)
	}
	stubReapWait(t, func(context.Context) error { return nil })
	logs := captureLogs(t)

	deleted, err := newReaper(newOutputStore(t, out), newInputSource(t, t.TempDir()),
		outputpolicy.LifecycleSync).reapConfirmed(t.Context(), []string{"stuck.pfx"})
	if err != nil {
		t.Fatalf("reapConfirmed(refused candidate) = error %v, want nil: a refusal is not a scan failure", err)
	}
	if deleted != 0 {
		t.Fatalf("reapConfirmed(refused candidate) deleted = %d, want 0", deleted)
	}
	if got := logs.CountLevel(slog.LevelWarn, removalRefusedMsg); got != 1 {
		t.Errorf("a scan whose only unlink was refused logged %q at WARN %d times, want exactly 1: it"+
			" is the only countable signal that /output stopped reconciling: %q",
			removalRefusedMsg, got, logs.Messages())
	}
	if !logs.HasAttr(removalRefusedMsg, "count", "1") {
		got, _ := logs.AttrValue(removalRefusedMsg, "count")
		t.Errorf("the refusal record count = %q, want %q: the count is what an operator alerts on", got, "1")
	}
	if paths, ok := logs.AttrValue(removalRefusedMsg, "paths"); !ok || !strings.Contains(paths, "stuck.pfx") {
		t.Errorf("the refusal record paths = %q (present %v), want it to name stuck.pfx", paths, ok)
	}
	// The aggregate's remediation must stay cause-NEUTRAL. refusedPaths mixes a
	// permission denial, an OpenParentInRoot layout refusal and a non-regular occupant
	// (this fixture), each of which already logged its own action per path, so naming any
	// one cause here sends the operator after the wrong one for the other two.
	if got, ok := logs.AttrValue(removalRefusedMsg, "remediation"); !ok || got == outputPermRemediation {
		t.Errorf("the refusal record remediation = %q (present %v), want a cause-neutral hint rather than %q:"+
			" this scan's refusal was a non-regular occupant, which ownership and permissions do not explain",
			got, ok, outputPermRemediation)
	}
	if !logs.AttrContains(removalRefusedMsg, "remediation", "per-path") {
		got, _ := logs.AttrValue(removalRefusedMsg, "remediation")
		t.Errorf("the refusal record remediation = %q, want it to send the operator to the per-path WARN"+
			" records, which are the only place the cause-specific action is stated", got)
	}
	// A refusal is not a deletion: the audit record for the destructive action must stay silent.
	if got := logs.CountLevel(slog.LevelWarn, reapAuditMsg); got != 0 {
		t.Errorf("a scan that deleted nothing logged %q at WARN %d times, want 0: %q",
			reapAuditMsg, got, logs.Messages())
	}
}

// TestReapConfirmed_audits_deletions_made_before_a_shutdown pins why the two audit
// records are emitted from a defer rather than at the loop's normal exit: a deletion
// that happened must not go unrecorded because the process stopped afterwards. Every
// other shutdown case in this file deletes nothing, so the defer's whole contract had
// no red path: a scan interrupted mid-batch would destroy private-key material with no
// WARN-level trace, and the audit is the app's only warn-visible record of the one
// destructive action it takes.
//
// The fixture deletes candidate one and observes the cancellation at candidate two's
// re-check guard. live: 2 is reapConfirmed's own Err() sequence with the wait stubbed:
// one.pfx's top-of-loop guard, one.pfx's pre-unlink guard, then two.pfx's top-of-loop
// guard, which is the one that fires. The shutdown record must also report removed=1;
// every existing shutdown case asserts removed="0", so the deleted-something half of
// that attribute was unpinned too.
// Serial: it swaps the package's reap-wait var and slog's default.
func TestReapConfirmed_audits_deletions_made_before_a_shutdown(t *testing.T) {
	logs := captureLogs(t)
	out := t.TempDir()
	for _, name := range []string{"one.pfx", "two.pfx"} {
		if err := os.WriteFile(filepath.Join(out, name), []byte("pfx"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stubReapWait(t, func(context.Context) error { return nil })
	calls := 0
	ctx := cancelAfterNChecks{Context: t.Context(), calls: &calls, live: 2}

	deleted, err := newReaper(newOutputStore(t, out), newInputSource(t, t.TempDir()),
		outputpolicy.LifecycleSync).reapConfirmed(ctx, []string{"one.pfx", "two.pfx"})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reapConfirmed(cancelled after the first unlink) error = %v, want context.Canceled", err)
	}
	if deleted != 1 {
		t.Fatalf("reapConfirmed(cancelled after the first unlink) deleted = %d, want 1", deleted)
	}
	if _, statErr := os.Stat(filepath.Join(out, "one.pfx")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(one.pfx) = %v, want fs.ErrNotExist: the first candidate's unlink preceded the shutdown", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(out, "two.pfx")); statErr != nil {
		t.Errorf("two.pfx was deleted after the shutdown was observed: %v", statErr)
	}
	if got := logs.CountLevel(slog.LevelWarn, reapAuditMsg); got != 1 {
		t.Fatalf("an interrupted scan that deleted one bundle logged %q at WARN %d times, want exactly 1:"+
			" the audit must cover every exit from the loop, the shutdown return included: %q",
			reapAuditMsg, got, logs.Messages())
	}
	if paths, ok := logs.AttrValue(reapAuditMsg, "paths"); !ok || !strings.Contains(paths, "one.pfx") ||
		strings.Contains(paths, "two.pfx") {
		t.Errorf("the audit record paths = %q, want it to name one.pfx and not two.pfx: it reports what"+
			" actually happened, not the batch", paths)
	}
	if !logs.HasAttr(reapAuditMsg, "count", "1") {
		got, _ := logs.AttrValue(reapAuditMsg, "count")
		t.Errorf("the audit record count = %q, want %q", got, "1")
	}
	const msg = "orphan removal interrupted by shutdown during the confirming re-check"
	if got, ok := logs.AttrValueExact(msg, "removed"); !ok || got != "1" {
		t.Errorf("the shutdown record logged removed=%q, want \"1\": a deletion that happened must be"+
			" counted, not only audited", got)
	}
}

// TestReapConfirmed_reports_refusals_made_before_a_shutdown is the refusal half of the
// defer's contract, and the half its audit sibling above cannot reach: that fixture's
// refusedPaths is empty throughout, so relocating logReapRefusals alone to the loop's
// normal exit leaves the whole suite green while a scan interrupted after a refused unlink
// emits no countable signal that sync mode stopped reconciling -- this file's own reason
// for the record.
//
// live: 2 is reapConfirmed's own Err() sequence with the wait stubbed: stuck.pfx's
// top-of-loop check, stuck.pfx's pre-unlink check, then two.pfx's top-of-loop check, which
// is the one that fires. two.pfx need not exist on disk: the loop abandons it before its
// unlink.
// Serial: it swaps the package's reap-wait var and slog's default.
func TestReapConfirmed_reports_refusals_made_before_a_shutdown(t *testing.T) {
	logs := captureLogs(t)
	out := t.TempDir()
	if err := os.Mkdir(filepath.Join(out, "stuck.pfx"), 0o750); err != nil {
		t.Fatalf("setup: Mkdir(stuck.pfx): %v", err)
	}
	stubReapWait(t, func(context.Context) error { return nil })
	calls := 0
	ctx := cancelAfterNChecks{Context: t.Context(), calls: &calls, live: 2}

	deleted, err := newReaper(newOutputStore(t, out), newInputSource(t, t.TempDir()),
		outputpolicy.LifecycleSync).reapConfirmed(ctx, []string{"stuck.pfx", "two.pfx"})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reapConfirmed(refusal then shutdown) error = %v, want context.Canceled", err)
	}
	if deleted != 0 {
		t.Fatalf("reapConfirmed(refusal then shutdown) deleted = %d, want 0", deleted)
	}
	if got := logs.CountLevel(slog.LevelWarn, removalRefusedMsg); got != 1 {
		t.Errorf("an interrupted scan that was refused one unlink logged %q at WARN %d times,"+
			" want exactly 1: the refusal audit must cover every exit from this loop, the"+
			" shutdown return included: %q", removalRefusedMsg, got, logs.Messages())
	}
	if !logs.HasAttr(removalRefusedMsg, "count", "1") {
		got, _ := logs.AttrValue(removalRefusedMsg, "count")
		t.Errorf("the refusal record count = %q, want %q: the count is what an operator alerts on", got, "1")
	}
}

// TestStoreReconcile_keep_is_silent_with_orphans_present pins the half of the README's
// OUTPUT_LIFECYCLE contract the mode table cannot see: "keep is silent and never
// deletes". The table case asserts only the non-deletion half, so routing keep through
// the report path -- where resolveReap's default arm names it "reported only
// (OUTPUT_LIFECYCLE=keep)" and the orphan WARN fires on every scan -- keeps the whole
// suite green while the documented silent mode becomes a per-scan WARN stream. Total
// silence also pins keep's early return ahead of the output walk: a keep-mode scan
// does not enumerate /output at all.
// Serial: captureLogs swaps the process-global slog.Default.
func TestStoreReconcile_keep_is_silent_with_orphans_present(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, "orphan.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	logs := captureLogs(t)
	s := newOutputStore(t, dir)

	deleted, err := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleKeep).
		reconcile(t.Context(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})
	if err != nil {
		t.Fatalf("reconcile(keep, one orphan) = error %v, want nil", err)
	}
	if deleted != 0 {
		t.Errorf("reconcile(keep, one orphan) deleted = %d, want 0", deleted)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Errorf("keep mode deleted a bundle: %v", statErr)
	}
	if logs.Len() != 0 {
		t.Errorf("reconcile(keep, one orphan) logged %q, want nothing at all: the README promises keep"+
			" is silent", logs.Messages())
	}
}

// TestLoneKeyRemediation_promises_a_reap_only_where_one_can_follow pins the tail the
// retained-lone-key report appends per mode. Only sync ever removes a bundle, so
// promising "so the bundle can be reaped" under warn or keep has the operator finish a
// change under /input for an outcome that cannot follow, and withholding it under sync
// leaves them thinking the leftover is permanent. The prefix is shared and asserted
// with it, because the sentence has to read as one instruction either way.
func TestLoneKeyRemediation_promises_a_reap_only_where_one_can_follow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode outputpolicy.Lifecycle
		want string
	}{
		{
			mode: outputpolicy.LifecycleSync,
			want: "finish the change under /input: add the matching <name>.crt, or remove the leftover <name>.key so the bundle can be reaped",
		},
		{
			mode: outputpolicy.LifecycleWarn,
			want: "finish the change under /input: add the matching <name>.crt, or remove the leftover <name>.key; OUTPUT_LIFECYCLE=warn never removes a bundle, so this one is kept either way",
		},
		{
			mode: outputpolicy.LifecycleKeep,
			want: "finish the change under /input: add the matching <name>.crt, or remove the leftover <name>.key; OUTPUT_LIFECYCLE=keep never removes a bundle, so this one is kept either way",
		},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			if got := loneKeyRemediation(tc.mode); got != tc.want {
				t.Errorf("loneKeyRemediation(%q) = %q, want %q", tc.mode, got, tc.want)
			}
		})
	}
}

// TestScannerRun_stays_quiet_when_the_shutdown_arrives_during_the_input_walk pins how
// the reap gate learns that an incomplete enumeration was a SHUTDOWN rather than a
// broken /input tree. The sibling above cancels during reconciliation, where the walk
// finished cleanly, and walk_log_policy_test's case hands the gate that fact ready-made;
// neither exercises the derivation, so a scan stopping at SIGTERM could start emitting
// the operator-actionable orphan-removal-disabled WARN -- the record the README's
// CertConverterOrphanRemovalDisabled alert keys on -- on every container stop, with a
// remediation pointing at a mount that is fine. Serial: it swaps slog.Default.
func TestScannerRun_stays_quiet_when_the_shutdown_arrives_during_the_input_walk(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	writeSelfSignedPair(t, certsRoot, "live")
	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
		Lifecycle: outputpolicy.LifecycleSync,
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	logs := captureLogs(t)

	if _, err := scanner.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run(a context already cancelled) error = %v, want context.Canceled", err)
	}

	if got := logs.CountLevel(slog.LevelWarn, ""); got != 0 {
		t.Errorf("Run(shutdown during the input walk) logged %d WARN record(s) (%q), want 0: a container stop is not an operator-actionable incomplete enumeration",
			got, logs.Messages())
	}
	const dbg = "skipping orphan reconciliation; scan cancelled during shutdown"
	if got := logs.CountLevel(slog.LevelDebug, dbg); got != 1 {
		t.Errorf("Run(shutdown during the input walk) logged %q, want %q once at Debug", logs.Messages(), dbg)
	}
}

// TestStoreInspect_reads_a_prior_at_the_readable_bound pins the accepting side of the
// bound the sibling above pins the refusing side of. maxPFXSize is the largest prior
// bundle this app READS, so a bundle of exactly that size has to be read and compared;
// refusing it makes the bound one byte smaller than it is documented as, and the app
// then rewrites that bundle on every scan for ever while telling the operator their
// output is too large to read.
//
// The read is stubbed rather than allowed to run so the fixture stays sparse: the gate
// under test is the size compare, and a real read here would allocate the whole bound.
// Runs serially: it swaps slog.Default() and the read seam.
func TestStoreInspect_reads_a_prior_at_the_readable_bound(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "bound.pfx"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("setup: OpenFile: %v", err)
	}
	// Sparse: no bytes are written, only the reported size reaches the bound.
	if err := f.Truncate(maxPFXSize); err != nil {
		t.Fatalf("setup: Truncate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("setup: Close: %v", err)
	}
	s := newOutputStore(t, dir)

	attempted := false
	prevRead := readBoundedInRoot
	readBoundedInRoot = func(context.Context, *os.Root, string, int64) ([]byte, error) {
		attempted = true
		return nil, errors.New("stubbed read")
	}
	t.Cleanup(func() { readBoundedInRoot = prevRead })

	logs := captureLogs(t)
	current, err := inspectCurrent(t.Context(), s, "bound.pfx", convert.Analysis{}, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("inspect(a prior at the readable bound) = error %v, want nil", err)
	}
	if current {
		t.Error("inspect(a prior at the readable bound) = true, want false: the stubbed read resolves nothing")
	}
	if !attempted {
		t.Errorf("inspect(a prior of exactly %d bytes) never read it: a bundle AT the bound is inside it", maxPFXSize)
	}
	if sizeMsg := "prior pfx exceeds the readable bound"; logs.Contains(sizeMsg) {
		t.Errorf("inspect(a prior of exactly %d bytes) logged %q, want no size-bound notice: that size is the largest this app reads, not the smallest it refuses",
			maxPFXSize, sizeMsg)
	}
}

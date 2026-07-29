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

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
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
// took the source and the mode as arguments. The observation log is the reap's
// lone-key de-duplication state; a fresh one per reaper is the process-start position,
// where a first lone key is reported.
func newReaper(out *store, src *source, mode outputpolicy.Lifecycle) *reaper {
	return &reaper{src: src, out: out, mode: mode, observations: newObservationLog(0)}
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
			// mode repair AND repairing rewrite were both refused is one this app wanted to
			// replace and could not, so deleting OTHER bundles on the strength of that same
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
				reconcile(context.Background(), seen, tc.rc)
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
		reconcile(context.Background(), map[string]struct{}{},
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
		reconcile(context.Background(), map[string]struct{}{},
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
	const msg = "output bundles have no matching input"
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

// TestStoreReconcile_vanished_input_is_reported_at_debug_not_as_a_mount_warning pins
// the diagnostic split for a scan whose only incomplete-enumeration cause is a cert
// replaced between readdir and the read. Reaping stays blocked either way, but the
// operator-facing WARN points at the /input mount and its unreadable-path warnings,
// which is the wrong diagnosis — and a false page — for the ordinary renewal this
// daemon exists to process. Serial: captureLogs swaps the process-global
// slog.Default.
func TestStoreReconcile_vanished_input_is_reported_at_debug_not_as_a_mount_warning(t *testing.T) {
	dir := t.TempDir()
	logs := captureLogs(t)
	s := newOutputStore(t, dir)

	deleted, reconcileErr := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
		reconcile(context.Background(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: 1, Vanished: 1}, walkCompleted: true})
	if reconcileErr != nil {
		t.Fatalf("reconcile(vanished input) = error %v, want nil", reconcileErr)
	}
	if deleted != 0 {
		t.Errorf("reconcile(vanished input) deleted = %d, want 0: an incomplete enumeration cannot prove any output orphaned", deleted)
	}
	const warn = "orphan removal is disabled for this scan: the scan did not fully enumerate the input tree, so no output can be proven orphaned"
	if logs.Contains(warn) {
		t.Errorf("reconcile(vanished input) logged the /input-mount WARN, want the transient renewal race reported at Debug: %q", logs.Messages())
	}
	const dbg = "skipping orphan reconciliation; input files were replaced during the scan"
	if logs.CountLevel(slog.LevelDebug, dbg) != 1 {
		t.Errorf("reconcile(vanished input) logged %q, want the transient notice at Debug", logs.Messages())
	}
}

// TestSampleOrphanPaths_bounds_the_logged_sample pins the bound on the orphan report's
// paths attribute. reconcile emits that line on every scan for as long as an orphan
// exists, so an unbounded sample is a permanent multi-kilobyte log record per scan,
// while a sample that elides without saying how many it dropped hides the scale.
func TestSampleOrphanPaths_bounds_the_logged_sample(t *testing.T) {
	t.Parallel()
	// DISTINCT names: with one name repeated, a sample taken from the wrong window
	// (one that drops the first orphan, or starts one past it) renders the same count
	// of ".pfx" occurrences, so the count assertion below cannot tell the two apart --
	// and this attribute is the operator's only view of WHICH bundles are reported.
	all := make([]string, 0, maxLoggedOrphans+5)
	for i := range maxLoggedOrphans + 5 {
		all = append(all, string(rune('A'+i))+".pfx")
	}
	for _, tc := range []struct {
		name      string
		n         int
		wantNamed int
		wantMore  string
	}{
		{"under the cap names every path", maxLoggedOrphans - 1, maxLoggedOrphans - 1, ""},
		{"exactly the cap names every path", maxLoggedOrphans, maxLoggedOrphans, ""},
		{"over the cap elides the rest and says how many", maxLoggedOrphans + 5, maxLoggedOrphans, " (+5 more)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sampleOrphanPaths(all[:tc.n])
			if named := strings.Count(got, ".pfx"); named != tc.wantNamed {
				t.Errorf("sampleOrphanPaths(%d paths) named %d paths, want %d: %q", tc.n, named, tc.wantNamed, got)
			}
			if !strings.HasPrefix(got, all[0]+",") {
				t.Errorf("sampleOrphanPaths(%d paths) = %q, want it to start at the first path %q: the sample must not drop the head of the list",
					tc.n, got, all[0])
			}
			if strings.Contains(got, all[maxLoggedOrphans]) {
				t.Errorf("sampleOrphanPaths(%d paths) = %q, want %q elided: the sample must stop at the cap", tc.n, got, all[maxLoggedOrphans])
			}
			if tc.wantMore == "" {
				if strings.Contains(got, "more)") {
					t.Errorf("sampleOrphanPaths(%d paths) = %q, want no elision notice", tc.n, got)
				}
				return
			}
			if !strings.HasSuffix(got, tc.wantMore) {
				t.Errorf("sampleOrphanPaths(%d paths) = %q, want it to end with %q", tc.n, got, tc.wantMore)
			}
		})
	}
}

// TestSampleOrphanPaths_bounds_the_sample_by_bytes pins the BYTE budget on the same
// attribute, which the item cap above does not provide: one root-relative path is
// bounded only by the filesystem, so maxLoggedOrphans deeply nested names can still put
// tens of kilobytes into a WARN that repeats on every scan for as long as the orphan
// exists. The three cases are the three ways this can go wrong: a normal report losing
// paths to the new cap, an oversized one not being cut (or being cut THROUGH a rune),
// and one cap replacing the other instead of composing with it.
func TestSampleOrphanPaths_bounds_the_sample_by_bytes(t *testing.T) {
	t.Parallel()

	t.Run("a realistic sample well under the budget is unchanged", func(t *testing.T) {
		t.Parallel()
		paths := make([]string, 0, maxLoggedOrphans)
		for i := range maxLoggedOrphans {
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
		if strings.Contains(got, truncationMarker) {
			t.Errorf("sampleOrphanPaths(%d realistic paths) = %q, want no %q marker on a sample inside the budget",
				len(paths), got, truncationMarker)
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
		if !strings.HasSuffix(got, truncationMarker) {
			t.Errorf("sampleOrphanPaths(one %d-byte path) rendered %d bytes without the %q marker: a reader cannot tell the list was cut",
				len(paths[0]), len(got), truncationMarker)
		}
		if maxLen := maxLoggedOrphanBytes + len(truncationMarker); len(got) > maxLen {
			t.Errorf("sampleOrphanPaths(one %d-byte path) rendered %d bytes, want at most %d",
				len(paths[0]), len(got), maxLen)
		}
		if !utf8.ValidString(got) {
			t.Errorf("sampleOrphanPaths(one %d-byte path) rendered invalid UTF-8: the cut split a rune", len(paths[0]))
		}
		kept := strings.TrimSuffix(got, truncationMarker)
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

	// Both caps engage on the same sample. The byte cut must not swallow the item
	// cap's elision notice, because the notice (with the record's own count attribute)
	// is what tells the operator how many bundles are affected once names are cut.
	t.Run("the item cap and the byte cap compose", func(t *testing.T) {
		t.Parallel()
		const elidedCount = 5
		long := strings.Repeat("d", 300)
		paths := make([]string, 0, maxLoggedOrphans+elidedCount)
		for i := range maxLoggedOrphans + elidedCount {
			paths = append(paths, fmt.Sprintf("%s/%02d.pfx", long, i))
		}
		got := sampleOrphanPaths(paths)
		wantMore := fmt.Sprintf(" (+%d more)", elidedCount)
		if !strings.HasSuffix(got, wantMore) {
			t.Errorf("sampleOrphanPaths(%d oversized paths) rendered %d bytes not ending in %q: the byte cap dropped the item cap's scale",
				len(paths), len(got), wantMore)
		}
		if !strings.Contains(got, truncationMarker) {
			t.Errorf("sampleOrphanPaths(%d oversized paths) rendered %d bytes without the %q marker: the item cap is not a byte bound",
				len(paths), len(got), truncationMarker)
		}
		if maxLen := maxLoggedOrphanBytes + len(truncationMarker) + len(wantMore); len(got) > maxLen {
			t.Errorf("sampleOrphanPaths(%d oversized paths) rendered %d bytes, want at most %d", len(paths), len(got), maxLen)
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
	// Long enough that maxLoggedOrphans of them exceed the byte budget, short enough to
	// stay inside the 255-byte filename limit.
	const nameLen = 250
	for i := range maxLoggedOrphans {
		name := strings.Repeat(string(rune('a'+i)), nameLen-len(".pfx")) + ".pfx"
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pfx"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile: %v", err)
		}
	}
	logs := captureLogs(t)
	s := newOutputStore(t, dir)

	deleted, reconcileErr := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleWarn).
		reconcile(context.Background(), map[string]struct{}{},
			&reapContext{result: ScanResult{Total: maxLoggedOrphans}, walkCompleted: true})
	if reconcileErr != nil {
		t.Fatalf("reconcile(%d oversized orphan names) = error %v, want nil", maxLoggedOrphans, reconcileErr)
	}
	if deleted != 0 {
		t.Errorf("reconcile(warn mode) deleted = %d, want 0", deleted)
	}
	const msg = "output bundles have no matching input"
	if want := fmt.Sprint(maxLoggedOrphans); !logs.HasAttr(msg, "count", want) {
		got, _ := logs.AttrValue(msg, "count")
		t.Errorf("orphan report logged count %q, want %q: the count must survive the paths cut", got, want)
	}
	paths, ok := logs.AttrValue(msg, "paths")
	if !ok {
		t.Fatalf("orphan report logged no paths attribute; records: %v", logs.Messages())
	}
	if !strings.HasSuffix(paths, truncationMarker) {
		t.Errorf("orphan report logged a %d-byte paths attribute without the %q marker", len(paths), truncationMarker)
	}
	if maxLen := maxLoggedOrphanBytes + len(truncationMarker); len(paths) > maxLen {
		t.Errorf("orphan report logged a %d-byte paths attribute, want at most %d", len(paths), maxLen)
	}
}

// TestStoreRemoveOrphans_cancelled_context_stops_before_deletion pins
// removeOrphans' own shutdown guard: a scan cancelled by SIGTERM must delete no
// key material and must report the cancellation, so the caller can classify the
// scan as a shutdown instead of a clean reap.
func TestStoreRemoveOrphans_cancelled_context_stops_before_deletion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	orphan := filepath.Join(dir, "orphan.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newOutputStore(t, dir)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	deleted, err := s.removeOrphans(ctx, []string{"orphan.pfx"})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("removeOrphans(cancelled context) error = %v, want context.Canceled", err)
	}
	if deleted != 0 {
		t.Errorf("removeOrphans(cancelled context) deleted = %d, want 0", deleted)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Errorf("orphan was removed after shutdown cancellation: %v", err)
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
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}

	dir := t.TempDir()
	s := newOutputStore(t, dir)

	written, err := convert.Encode(&analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if err := s.write(t.Context(), "out.pfx", written); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	// Same configured profile: current, nothing to do.
	current, err := inspectCurrent(t.Context(), s, "out.pfx", &analysis, convert.EncNameModern2023, "pw")
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
			current, err := inspectCurrent(t.Context(), s, "out.pfx", &analysis, other, "pw")
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
		reconcile(context.Background(), seen, &reapContext{result: ScanResult{Total: 1}, walkCompleted: true})
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

// TestStoreRemoveOrphans_spares_non_regular_candidate_and_continues pins the
// pre-unlink type re-check: a path that changed from the regular file found during
// the orphan walk into a directory must be left in place, while a later regular
// orphan is still removed. Serial: captureLogs swaps the process-global slog.Default.
//
// The directory is left EMPTY on purpose: Root.Remove would succeed on it, so if the
// non-regular guard were removed the count, the surviving-directory stat and the WARN
// all fail rather than only the log assertion.
func TestStoreRemoveOrphans_spares_non_regular_candidate_and_continues(t *testing.T) {
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

	deleted, err := s.removeOrphans(t.Context(), []string{"stuck.pfx", "reapable.pfx"})
	if err != nil {
		t.Fatalf("removeOrphans(non-regular candidate) = %v, want nil", err)
	}
	if deleted != 1 {
		t.Errorf("removeOrphans(non-regular candidate) deleted = %d, want 1: the later regular orphan must still go", deleted)
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
		t.Fatalf("removeOrphans(non-regular candidate) logged %q at WARN %d times, want exactly 1: %q", wantMsg, got, logs.Messages())
	}
	if !logs.HasAttr(wantMsg, "path", "stuck.pfx") {
		t.Errorf("removeOrphans(non-regular candidate) logged %q without path=stuck.pfx: %q", wantMsg, logs.Messages())
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
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	s := newOutputStore(t, t.TempDir())

	written, err := convert.Encode(&analysis, convert.EncNameModern2023, "old-password")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if err := s.write(t.Context(), "out.pfx", written); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	current, err := inspectCurrent(t.Context(), s, "out.pfx", &analysis, convert.EncNameModern2023, "old-password")
	if err != nil {
		t.Fatalf("inspect(unrotated password) = error %v, want nil", err)
	}
	if !current {
		t.Fatal("inspect(unrotated password) = false, want true: nothing about this bundle changed")
	}

	current, err = inspectCurrent(t.Context(), s, "out.pfx", &analysis, convert.EncNameModern2023, "new-password")
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
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	full, err := convert.Encode(&analysis, convert.EncNameModern2023, "pw")
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
			current, err := inspectCurrent(t.Context(), s, tc.rel, &analysis, convert.EncNameModern2023, "pw")
			if err != nil {
				t.Errorf("inspect(%s) = error %v, want nil: an undecodable prior output is stale, not a failed pair", tc.name, err)
			}
			if current {
				t.Errorf("inspect(%s) = true, want false: a file that is not this bundle must be rewritten", tc.name)
			}
			// Which arm answered matters as much as the answer: the size arm reaches
			// this same verdict without reading the bundle, so asserting the outcome
			// alone lets the preflight go unexercised.
			if !logs.Contains("prior pfx failed preflight; regenerating") {
				t.Errorf("inspect(%s) logged %q, want the preflight notice: the stale verdict must come from the preflight, not from an earlier arm", tc.name, logs.Messages())
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
	current, err := inspectCurrent(t.Context(), s, "big.pfx", &convert.Analysis{}, convert.EncNameModern2023, "pw")
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

// TestStoreInspect_tightens_a_lax_mode_without_regenerating pins the approved
// replacement for the retired mode arm: pfxFileMode is enforced on a bundle already
// on disk with a chmod, never with a rewrite, and only downward.
//
// Both halves are load-bearing. A bundle the operator made STRICTER than policy
// (0400) is left exactly as it is — it was already usable, since the atomic
// temp+rename never needs the old file to be owner-writable, and "converging" it to
// 0600 would have discarded the protection they chose and moved its mtime. A LAXER
// bundle is tightened in place, and the content-and-mtime assertions are what catch a
// regression to rewriting it: a rewrite re-encodes with a fresh KDF salt and leaves a
// fresh mtime, which the documented downstream rsync replication then copies again.
//
// Successful real-filesystem cases assert the exact surviving bits: tightening may
// clear only permissions outside policy, never an allowed owner bit. The next test
// separately covers filesystems that refuse or ignore chmod. Runs serially: it swaps
// slog.Default().
func TestStoreInspect_tightens_a_lax_mode_without_regenerating(t *testing.T) {
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	for _, tc := range []struct {
		name        string
		mode        os.FileMode
		wantTighten bool
		// wantMode is the mode expected after the tightening; zero means the generic
		// ceiling every mode carrying an owner read or write bit masks to
		// (tc.mode & pfxFileMode). A lax mode with NO owner read or write bit masks to
		// 0000, which is not a tightening at all — the app could not read its own
		// bundle back through it — so that case names the mode it must land on instead.
		wantMode os.FileMode
	}{
		{"the policy mode is left alone", pfxFileMode, false, 0},
		{"a stricter read-only bundle is left alone", 0o400, false, 0},
		{"a group-readable bundle is tightened", 0o640, true, 0},
		{"a world-readable bundle is tightened", 0o644, true, 0},
		{"an execute bit is cleared too", 0o700, true, 0},
		{"a mode with no owner read or write bit is tightened to policy, not to 0000", 0o044, true, pfxFileMode},
		{"an owner-execute-only mode is tightened to policy, not to 0000", 0o100, true, pfxFileMode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := newOutputStore(t, dir)
			if err := s.write(t.Context(), "out.pfx", mustEncode(t, &analysis)); err != nil {
				t.Fatalf("setup: write: %v", err)
			}
			path := filepath.Join(dir, "out.pfx")
			// The output DIRECTORY's mode is fixture noise here, but it is not noise to
			// inspect: reportLaxDir warns when the directory is laxer than pfxDirMode,
			// and what t.TempDir creates depends on the host (an inherited ACL widens it).
			// Pinned so the log assertions below observe the FILE's mode only.
			if err := os.Chmod(dir, pfxDirMode); err != nil {
				t.Fatalf("setup: Chmod(dir): %v", err)
			}
			// Chmod explicitly: a filesystem can widen the mode O_CREATE asks for (an
			// inherited ACL does), so the fixture cannot get tc.mode from the write.
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("setup: Chmod: %v", err)
			}
			wantContent, before := readBundle(t, path)

			logs := captureLogs(t)
			// Spelled out rather than imported from the production const: an operator's
			// log query keys on these words, so a silent rename must fail here.
			const tightenedMsg = "tightened the file mode of a prior pfx"
			current, err := inspectCurrent(t.Context(), s, "out.pfx", &analysis, convert.EncNameModern2023, "pw")
			if err != nil {
				t.Fatalf("inspect(mode %o) = error %v, want nil", tc.mode, err)
			}
			if !current {
				t.Errorf("inspect(mode %o) = false, want true: a permission bit is not part of currency,"+
					" and rewriting for one cannot converge on a filesystem that will not store it", tc.mode)
			}

			gotContent, after := readBundle(t, path)
			if !bytes.Equal(gotContent, wantContent) {
				t.Errorf("inspect(mode %o) changed the bundle's bytes; the mode must be fixed with a"+
					" chmod, not by re-encoding it with a fresh salt", tc.mode)
			}
			if !after.ModTime().Equal(before.ModTime()) {
				t.Errorf("inspect(mode %o) moved the mtime from %v to %v; a chmod does not, a rewrite does",
					tc.mode, before.ModTime(), after.ModTime())
			}
			if tc.wantTighten {
				if got := logs.CountLevel(slog.LevelInfo, tightenedMsg); got != 1 {
					t.Errorf("inspect(mode %o) logged %q at INFO %d times, want exactly 1: %q",
						tc.mode, tightenedMsg, got, logs.Messages())
				}
				if logs.Len() != 1 {
					t.Errorf("inspect(mode %o) logged %q, want only the tighten notice: a repaired mode is"+
						" not also a warning", tc.mode, logs.Messages())
				}
				want := tc.wantMode
				if want == 0 {
					want = tc.mode & pfxFileMode
				}
				if got := after.Mode().Perm(); got != want {
					t.Errorf("inspect(mode %o) tightened mode to %o, want %o: allowed owner bits must survive", tc.mode, got, want)
				}
				return
			}
			if logs.Len() != 0 {
				t.Errorf("inspect(mode %o) logged %q, want nothing at all: a mode at or stricter than"+
					" policy is not this app's to touch", tc.mode, logs.Messages())
			}
			if got, want := after.Mode().Perm(), before.Mode().Perm(); got != want {
				t.Errorf("inspect(mode %o) changed the mode to %v, want %v left untouched", tc.mode, got, want)
			}
		})
	}
}

// TestStoreInspect_keeps_a_bundle_whose_mode_cannot_be_tightened pins the
// convergence property the retired mode arm got wrong, for every tightening failure a
// rewrite would NOT fix.
//
// On a filesystem that will not store the bit — CIFS/vfat with mount-forced modes, an
// NFS squash config, all plausible for the /output volume of a Synology deployment —
// the old design called every bundle stale on every scan, so the "fix" was a
// permanent rewrite loop: fresh KDF salts, fresh mtimes, and the documented
// downstream rsync re-replicating the entire output tree every cycle. A read-only or
// mode-forcing mount that fails the chmod outright (EROFS, EINVAL) is the same
// situation: the error proves the chmod did not land, never that a rewrite would, and
// rewriting there trades one WARN per scan for a failed encode+write per scan. Here
// the bundle stays CURRENT and the whole cost is one WARN per scan naming the mode
// found and the mode wanted, which a second scan repeats rather than compounding.
//
// The one failure that IS convergeable — a chmod refused on a bundle owned by ANOTHER
// UID — deliberately does not appear in this table; it belongs to
// TestScannerRun_regenerates_a_bundle_whose_mode_repair_was_refused, which pins the
// opposite verdict. Keeping the two in separate tests is what stops a future
// simplification from collapsing them back into one non-action. A refusal on a bundle
// this process OWNS is NOT that case and does belong here: a UID that owns a file may
// always chmod it, so what was refused is the requested BITS, and the replacement a
// rewrite would write lands with the same forced mode.
//
// The chmod is stubbed because none of these failures is reproducible in a temp
// directory: no local filesystem ignores permission bits or refuses a chmod to the
// UID running the suite.
// Runs serially: it swaps slog.Default() and the chmod seam.
func TestStoreInspect_keeps_a_bundle_whose_mode_cannot_be_tightened(t *testing.T) {
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	for _, tc := range []struct {
		name  string
		chmod func(*os.Root, string, os.FileMode) error
	}{
		{
			"a filesystem that accepts the chmod and stores nothing",
			func(*os.Root, string, os.FileMode) error { return nil },
		},
		{
			// A read-only mount: the chmod fails, but replacing the file would fail too,
			// so the error is no reason to try.
			"a chmod a read-only filesystem fails",
			func(_ *os.Root, name string, _ os.FileMode) error {
				return &fs.PathError{Op: "chmod", Path: name, Err: syscall.EROFS}
			},
		},
		{
			// A filesystem that rejects the mode itself rather than the caller's right to
			// set it. Same reasoning, and it is what proves the refusal test below keys on
			// the ERROR rather than on "the chmod failed".
			"a chmod the filesystem rejects as invalid",
			func(_ *os.Root, name string, _ os.FileMode) error {
				return &fs.PathError{Op: "chmod", Path: name, Err: syscall.EINVAL}
			},
		},
		{
			// A mode-forcing mount that REFUSES rather than silently ignoring the
			// chmod (fat_setattr returns EPERM for any mode outside the mount's
			// fmask). The bundle is this process's own, so the refusal is about the
			// BITS and not about ownership, and the replacement a rewrite would
			// publish lands with the same forced mode — the one arm where a refusal
			// must NOT schedule one. Deliberately no fileOwnedByProcess override:
			// the fixture is owned by the test process, which is the premise, so the
			// production discriminator is what routes this case.
			"a chmod a mode-forcing filesystem refuses on a bundle this process owns",
			func(_ *os.Root, name string, _ os.FileMode) error {
				return &fs.PathError{Op: "chmod", Path: name, Err: syscall.EPERM}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := newOutputStore(t, dir)
			if err := s.write(t.Context(), "out.pfx", mustEncode(t, &analysis)); err != nil {
				t.Fatalf("setup: write: %v", err)
			}
			// Same bytes, laxer mode: a cp/tar restore of the output volume.
			if err := os.Chmod(filepath.Join(dir, "out.pfx"), 0o644); err != nil {
				t.Fatalf("setup: Chmod: %v", err)
			}
			prev := chmodInRoot
			chmodInRoot = tc.chmod
			t.Cleanup(func() { chmodInRoot = prev })

			logs := captureLogs(t)
			// Spelled out rather than imported from the production const: an operator's
			// log query keys on these words, so a silent rename must fail here.
			const notTightenedMsg = "prior pfx is more permissive than policy and could not be tightened"
			current, err := inspectCurrent(t.Context(), s, "out.pfx", &analysis, convert.EncNameModern2023, "pw")
			if err != nil {
				t.Fatalf("inspect(untightenable mode) = error %v, want nil", err)
			}
			if !current {
				t.Error("inspect(untightenable mode) = false, want true: calling it stale is the rewrite" +
					" loop this design exists to avoid")
			}
			if got := logs.CountLevel(slog.LevelWarn, notTightenedMsg); got != 1 {
				t.Errorf("inspect(untightenable mode) logged %q at WARN %d times, want exactly 1: %q",
					notTightenedMsg, got, logs.Messages())
			}
			// Keyed attributes, not a line substring: the mode found and the mode wanted
			// must each appear under their own key, or a line naming one twice would pass.
			for key, want := range map[string]string{"mode": "-rw-r--r--", "want": "-rw-------"} {
				if !logs.HasAttr(notTightenedMsg, key, want) {
					got, _ := logs.AttrValue(notTightenedMsg, key)
					t.Errorf("inspect(untightenable mode) logged %s=%q, want %q", key, got, want)
				}
			}

			// The next scan reaches the same verdict and says the same thing once more:
			// steady state, not an escalation and not a rewrite.
			current, err = inspectCurrent(t.Context(), s, "out.pfx", &analysis, convert.EncNameModern2023, "pw")
			if err != nil || !current {
				t.Fatalf("inspect(untightenable mode, second scan) = (%v, %v), want (true, nil)", current, err)
			}
			if got := logs.CountLevel(slog.LevelWarn, notTightenedMsg); got != 2 {
				t.Errorf("two scans logged %q at WARN %d times, want exactly 2 (one per scan): %q",
					notTightenedMsg, got, logs.Messages())
			}
			// Neither the refusal message nor a repair notice belongs here: this bundle is
			// not being regenerated and its mode was not repaired.
			for _, unwanted := range []string{
				"prior pfx is more permissive than policy and the mode repair was refused; regenerating",
				"tightened the file mode of a prior pfx",
			} {
				if logs.Contains(unwanted) {
					t.Errorf("inspect(untightenable mode) logged %q; %q is the wrong message for a"+
						" tightening no rewrite can fix", logs.Messages(), unwanted)
				}
			}
			if _, after := readBundle(t, filepath.Join(dir, "out.pfx")); after.Mode().Perm() != 0o644 {
				t.Errorf("inspect(untightenable mode) left mode %o, want 0644 untouched: the stub stored"+
					" nothing, so nothing may claim otherwise", after.Mode().Perm())
			}
		})
	}
}

// TestScannerRun_regenerates_a_bundle_whose_mode_repair_was_refused pins the other
// half of the mode policy, and the reason it is a WHOLE-SCAN test rather than an
// inspect one: the property that matters is that the refusal ends in a REPLACED
// bundle, which only the scan can show.
//
// The scenario is the one this file's stat-failure arm already names as realistic: a
// prior .pfx owned by another UID (a root-owned bundle left behind by an earlier
// deployment, before the user: mapping changed) whose bytes are still correct but
// whose mode is 0644 — a private key readable by every process on the /output volume
// and by the documented downstream rsync replica. A chmod cannot fix that, because
// os.Root.Chmod needs ownership; a temp+rename rewrite can, because it needs write
// permission on the output DIRECTORY instead. Before this arm existed the bundle kept
// mode 0644 for the life of the deployment and produced one WARN per scan forever.
//
// Both refusal errnos are covered because they are two different refusals of the same
// kind (EPERM: not the owner; EACCES: the path denies it) and only the errno
// classification tells them apart from the EROFS/EINVAL failures the sibling test
// keeps WARN-only. The third scan is the point of the test as much as the second: a
// permanently refusing chmod must still converge, because the REPLACEMENT is
// owner-only and never reaches the repair path again.
//
// Runs serially: it swaps slog.Default() and the chmod seam.
func TestScannerRun_regenerates_a_bundle_whose_mode_repair_was_refused(t *testing.T) {
	// Spelled out rather than imported from the production consts: an operator's log
	// query keys on these words, so a silent rename must fail here.
	const refusedMsg = "prior pfx is more permissive than policy and the mode repair was refused; regenerating"
	const notTightenedMsg = "prior pfx is more permissive than policy and could not be tightened"
	for _, tc := range []struct {
		name  string
		errno syscall.Errno
	}{
		{"a bundle owned by another UID", syscall.EPERM},
		{"a chmod the path denies", syscall.EACCES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certsRoot := t.TempDir()
			outRoot := t.TempDir()
			_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
			writePair(t, certsRoot, "chain", chainPEM, keyPEM)
			scanner := New(&Options{
				CertsRoot: certsRoot,
				OutRoot:   outRoot,
				Password:  "pw",
				Encoder:   convert.EncNameModern2023,
			})
			if res, err := scanner.Run(t.Context()); err != nil || res.Converted != 1 {
				t.Fatalf("setup: initial Run = %+v, %v, want Converted 1 and nil", res, err)
			}
			pfxPath := filepath.Join(outRoot, "chain.pfx")
			before, _ := readBundle(t, pfxPath)
			// Correct bytes, wrong mode: a restore of the output volume, or a bundle
			// written by an earlier deployment under a different UID.
			if err := os.Chmod(pfxPath, 0o644); err != nil {
				t.Fatalf("setup: Chmod: %v", err)
			}
			// The refusal itself cannot be staged in a temp directory the suite's own UID
			// owns, so it comes from the seam — in the shape os.Root.Chmod really returns
			// it, an *fs.PathError around the errno, because the classification reads
			// through that wrapping.
			prev := chmodInRoot
			chmodInRoot = func(_ *os.Root, name string, _ os.FileMode) error {
				return &fs.PathError{Op: "chmod", Path: name, Err: tc.errno}
			}
			t.Cleanup(func() { chmodInRoot = prev })
			// The injected refusal MEANS "another UID owns this bundle", so the
			// ownership read has to agree: a refusal on a file this process owns is the
			// filesystem refusing the BITS, which is the WARN-only arm.
			prevOwned := fileOwnedByProcess
			fileOwnedByProcess = func(os.FileInfo) bool { return false }
			t.Cleanup(func() { fileOwnedByProcess = prevOwned })

			logs := captureLogs(t)
			res, err := scanner.Run(t.Context())
			if err != nil {
				t.Fatalf("Run(refused mode repair) = error %v, want nil", err)
			}
			if res.Converted != 1 || res.Unchanged != 0 || res.Failed != 0 {
				t.Errorf("Run(refused mode repair) = %+v, want Converted 1 Unchanged 0 Failed 0: a repair"+
					" this app cannot make with a chmod is one it must make by rewriting", res)
			}
			if got := logs.CountLevel(slog.LevelWarn, refusedMsg); got != 1 {
				t.Errorf("Run(refused mode repair) logged %q at WARN %d times, want exactly 1: %q",
					refusedMsg, got, logs.Messages())
			}
			if logs.Contains(notTightenedMsg) {
				t.Errorf("Run(refused mode repair) logged %q, want the refusal message instead: the two"+
					" causes now end differently and must not share one line", logs.Messages())
			}
			// The refusal is an ownership problem, so it must carry the ownership hint and
			// name both modes under their own keys.
			for key, want := range map[string]string{
				"mode":        "-rw-r--r--",
				"want":        "-rw-------",
				"remediation": "check /output ownership and permissions for the UID in user:",
			} {
				if !logs.HasAttr(refusedMsg, key, want) {
					got, _ := logs.AttrValue(refusedMsg, key)
					t.Errorf("Run(refused mode repair) logged %s=%q, want %q", key, got, want)
				}
			}
			after, afterInfo := readBundle(t, pfxPath)
			if bytes.Equal(after, before) {
				t.Error("Run(refused mode repair) left the bundle's bytes untouched, want a rewritten bundle:" +
					" a replacement is encoded with a fresh KDF salt, so identical bytes mean nothing was written")
			}
			if got := afterInfo.Mode().Perm(); got != pfxFileMode {
				t.Errorf("Run(refused mode repair) left mode %o, want %o: the rewrite is what converges the"+
					" mode the chmod could not", got, pfxFileMode)
			}

			// Converged: the replacement is owner-only, so the next scan has nothing to
			// repair, nothing to say, and nothing to rewrite. Without this the fix would
			// trade one WARN per scan for one rewrite per scan.
			res, err = scanner.Run(t.Context())
			if err != nil {
				t.Fatalf("Run(after the rewrite) = error %v, want nil", err)
			}
			if res.Unchanged != 1 || res.Converted != 0 {
				t.Errorf("Run(after the rewrite) = %+v, want Unchanged 1 Converted 0: the rewritten bundle is"+
					" already at policy", res)
			}
			if got := logs.CountLevel(slog.LevelWarn, refusedMsg); got != 1 {
				t.Errorf("two scans logged %q at WARN %d times, want exactly 1 (the second scan has nothing"+
					" left to repair): %q", refusedMsg, got, logs.Messages())
			}
		})
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

// TestScannerRun_when_the_repairing_rewrite_is_also_refused splits the outcome of a
// refused mode repair by WHY its rewrite failed, which is this arm's whole health
// contract.
//
// The sibling test above covers the convergent case: a foreign-owned bundle in a
// directory this UID CAN write is rewritten on the first scan and goes quiet. But the
// deployment that leaves a foreign-owned FILE behind plausibly leaves a foreign-owned
// DIRECTORY too — an operator who changed PUID and left root-owned output behind owns
// neither — and there the rewrite is refused as well. Counting that as a conversion
// failure flips health on a condition no restart can clear, i.e. a restart loop in the
// most likely instance of the very case the mode arm exists to fix. It is the same
// mistake statusUnreadable exists to prevent on the /input side, where treating a read
// refusal as a conversion failure once made a symlinked /input restart-loop forever.
//
// So a refusal NO RESTART CAN CLEAR is health-neutral: the bundle on disk still holds
// the right bytes, the operator gets a standing WARN naming the remedy, and the outcome
// is accounted in ScanResult.Unwritable instead of Failed — which is the field
// main.healthyAfterScan reads, and TestHealthyAfterScan pins that this shape stays
// healthy through that real predicate.
//
// Which refusals those are is a property of the ERROR CLASS and of nothing else
// (restartCanClearWrite): a permission denial, a read-only mount, a full volume and an
// exhausted quota all survive a restart, so restarting is the wrong answer to every one
// of them. The ENOSPC case is here for that reason and its expectation CHANGED with this
// routing: it used to count as a conversion failure on the theory that a full volume is
// not an ownership problem, which is true and beside the point — an orchestrator
// restarting this container writes the same bytes into the same full volume. A write
// error this app CANNOT attribute to such a condition (EIO here) stays a conversion
// failure and still flips health, which is what keeps "a failed PFX write is a
// conversion failure" the default the README documents.
//
// The two messages are load-bearing too: only the content-matched-plus-permission shape
// carries unwritableBundleMsg, whose text promises the bytes were compared and matched
// and which the README's alerting section keys on. A refusal by the VOLUME cannot make
// that promise about permissions, so it carries unreplaceableBundleMsg with the volume
// remediation instead — an operator sent to check ownership over a full disk reads the
// WARN as noise.
//
// The second scan matters as much as the first: the condition is steady state, so the
// WARN repeats once per scan rather than compounding, and nothing may be deleted or
// corrupted while it persists.
//
// Both seams are the only way in: the suite owns every file it creates (and here runs
// as root), so no temp directory can refuse it either a chmod or a write.
// Runs serially: it swaps slog.Default(), the chmod seam and the write seam.
func TestScannerRun_when_the_repairing_rewrite_is_also_refused(t *testing.T) {
	// Spelled out rather than imported from the production consts: an operator's log
	// query keys on these words, so a silent rename must fail here.
	const refusedMsg = "prior pfx is more permissive than policy and the mode repair was refused; regenerating"
	const unwritableMsg = "prior pfx is more permissive than policy and neither the mode repair nor the replacing" +
		" write was permitted; leaving the existing bundle in place, health is unaffected"
	const unreplaceableMsg = "prior pfx could not be replaced and the /output condition that refused the write is" +
		" not one a restart clears; leaving the existing bundle in place, health is unaffected"
	const failedMsg = "conversion failed"
	const ownershipRemediation = "check /output ownership and permissions for the UID in user:"
	const volumeRemediation = "check /output for free space, a quota and a read-only mount"
	for _, tc := range []struct {
		writeErr        error
		name            string
		wantNeutralMsg  string
		wantRemediation string
		wantUnwritable  int
		wantFailed      int
	}{
		{
			// The temp cannot be created: /output itself belongs to another UID.
			name:           "a refused write leaves the bundle in place without flipping health",
			writeErr:       &fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EACCES},
			wantUnwritable: 1, wantNeutralMsg: unwritableMsg, wantRemediation: ownershipRemediation,
		},
		{
			// The other refusal errno, for the same reason the sibling test covers both:
			// only the classification tells them apart from the failures below.
			name:           "an EPERM refusal of the same write is the same condition",
			writeErr:       &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.EPERM},
			wantUnwritable: 1, wantNeutralMsg: unwritableMsg, wantRemediation: ownershipRemediation,
		},
		{
			// A full volume is not an ownership problem, which is exactly why it carries the
			// OTHER message — but it is not clearable by a restart either, so it is
			// health-neutral all the same. This expectation is the one this routing changed.
			name:           "a full volume is health-neutral under its own message",
			writeErr:       &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.ENOSPC},
			wantUnwritable: 1, wantNeutralMsg: unreplaceableMsg, wantRemediation: volumeRemediation,
		},
		{
			// An I/O error is not attributable to any steady-state condition of the volume,
			// so the default stands: an unwritten PFX is a conversion failure and health
			// flips. Without this case every write failure could be made neutral and the
			// suite would still pass.
			name:       "a write error this app cannot attribute to the volume is still a conversion failure",
			writeErr:   &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.EIO},
			wantFailed: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certsRoot := t.TempDir()
			outRoot := t.TempDir()
			_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
			writePair(t, certsRoot, "chain", chainPEM, keyPEM)
			scanner := New(&Options{
				CertsRoot: certsRoot,
				OutRoot:   outRoot,
				Password:  "pw",
				Encoder:   convert.EncNameModern2023,
			})
			// The first scan runs with both seams live, so the bundle under test is a real
			// one this app wrote.
			if res, err := scanner.Run(t.Context()); err != nil || res.Converted != 1 {
				t.Fatalf("setup: initial Run = %+v, %v, want Converted 1 and nil", res, err)
			}
			pfxPath := filepath.Join(outRoot, "chain.pfx")
			before, _ := readBundle(t, pfxPath)
			// Correct bytes, wrong mode: the foreign-owned bundle the mode arm exists for.
			if err := os.Chmod(pfxPath, 0o644); err != nil {
				t.Fatalf("setup: Chmod: %v", err)
			}
			prevChmod := chmodInRoot
			chmodInRoot = func(_ *os.Root, name string, _ os.FileMode) error {
				return &fs.PathError{Op: "chmod", Path: name, Err: syscall.EPERM}
			}
			t.Cleanup(func() { chmodInRoot = prevChmod })
			// The injected refusal MEANS "another UID owns this bundle" (see the sibling
			// table above), so the ownership read has to agree.
			prevOwned := fileOwnedByProcess
			fileOwnedByProcess = func(os.FileInfo) bool { return false }
			t.Cleanup(func() { fileOwnedByProcess = prevOwned })
			prevWrite := writeFileInRoot
			writeFileInRoot = func(context.Context, *os.Root, string, []byte,
				...atomicfile.Option,
			) (atomicfile.Result, error) {
				return atomicfile.Result{}, tc.writeErr
			}
			t.Cleanup(func() { writeFileInRoot = prevWrite })

			logs := captureLogs(t)
			res, err := scanner.Run(t.Context())
			if err != nil {
				t.Fatalf("Run(refused repair, refused rewrite) = error %v, want nil: neither outcome is a"+
					" scan-level failure", err)
			}
			if res.Unwritable != tc.wantUnwritable || res.Failed != tc.wantFailed || res.Converted != 0 {
				t.Errorf("Run(refused repair, refused rewrite) = %+v, want Unwritable %d Failed %d Converted 0",
					res, tc.wantUnwritable, tc.wantFailed)
			}
			// The refusal of the chmod is announced either way: it is what schedules the
			// rewrite, so its absence would mean this test is not exercising the arm at all.
			if got := logs.CountLevel(slog.LevelWarn, refusedMsg); got != 1 {
				t.Errorf("Run(refused repair, refused rewrite) logged %q at WARN %d times, want exactly 1: %q",
					refusedMsg, got, logs.Messages())
			}
			wantUnwritableLines, wantFailedLines := 0, 1
			if tc.wantUnwritable > 0 {
				wantUnwritableLines, wantFailedLines = 1, 0
			}
			// Once per scan for this bundle, not once per attempt: the entry is written at
			// most once per scan, and an operator watching a permanently foreign-owned
			// volume must not get a line per retry behind it. The message is asserted by
			// NAME, so a neutral outcome reported under the content-matched promise when the
			// volume was the refuser fails here.
			for msg, want := range map[string]int{
				unwritableMsg:    boolCount(tc.wantNeutralMsg == unwritableMsg),
				unreplaceableMsg: boolCount(tc.wantNeutralMsg == unreplaceableMsg),
			} {
				if got := logs.CountLevel(slog.LevelWarn, msg); got != want {
					t.Errorf("Run(refused repair, refused rewrite) logged %q at WARN %d times, want %d: %q",
						msg, got, want, logs.Messages())
				}
			}
			if got := logs.CountLevel(slog.LevelError, failedMsg); got != wantFailedLines {
				t.Errorf("Run(refused repair, refused rewrite) logged %q at ERROR %d times, want %d: %q",
					failedMsg, got, wantFailedLines, logs.Messages())
			}
			if tc.wantUnwritable > 0 {
				// The standing WARN has to name the bundle, what this app knew about its
				// content, and the operator action that clears the refusal — never a restart.
				for key, want := range map[string]string{
					"path":        "chain.crt",
					"output_path": "chain.pfx",
					"content":     "verified-current",
					"remediation": tc.wantRemediation,
				} {
					if !logs.HasAttr(tc.wantNeutralMsg, key, want) {
						got, _ := logs.AttrValue(tc.wantNeutralMsg, key)
						t.Errorf("Run(refused repair, refused rewrite) logged %s=%q, want %q", key, got, want)
					}
				}
			}
			// Nothing deleted, nothing truncated, nothing half-written: the bundle an
			// operator is still serving must survive a refused replacement untouched.
			after, afterInfo := readBundle(t, pfxPath)
			if !bytes.Equal(after, before) {
				t.Error("Run(refused repair, refused rewrite) changed the bundle's bytes, want them untouched:" +
					" a write that never landed must leave the served bundle alone")
			}
			if got := afterInfo.Mode().Perm(); got != 0o644 {
				t.Errorf("Run(refused repair, refused rewrite) left mode %o, want 0644 untouched: both the"+
					" chmod and the rewrite were refused, so nothing may claim otherwise", got)
			}

			// Steady state: the same verdict, the same one line, no compounding and still no
			// deletion. This is what a restart-looping container would look like instead if
			// the permission arm were counted as a conversion failure.
			res, err = scanner.Run(t.Context())
			if err != nil {
				t.Fatalf("Run(second scan) = error %v, want nil", err)
			}
			if res.Unwritable != tc.wantUnwritable || res.Failed != tc.wantFailed {
				t.Errorf("Run(second scan) = %+v, want Unwritable %d Failed %d unchanged",
					res, tc.wantUnwritable, tc.wantFailed)
			}
			if tc.wantUnwritable > 0 {
				if got := logs.CountLevel(slog.LevelWarn, tc.wantNeutralMsg); got != 2*wantUnwritableLines {
					t.Errorf("two scans logged %q at WARN %d times, want %d (one per scan): %q",
						tc.wantNeutralMsg, got, 2*wantUnwritableLines, logs.Messages())
				}
			}
			if _, statErr := os.Stat(pfxPath); statErr != nil {
				t.Errorf("os.Stat(%s) = %v, want the bundle still in place", pfxPath, statErr)
			}
		})
	}
}

// TestScannerRun_a_stale_bundle_whose_mode_repair_was_refused_is_a_conversion_failure pins
// the boundary of the health-neutral outcome from the other side: neutrality is granted only
// where this app never PROVED the bundle on disk wrong. A bundle that is a renewal behind was
// compared and found stale (contentVerifiedStale), so a refused rewrite of it counts in
// ScanResult.Failed and flips health -- otherwise the operator's PFX holds the previous
// certificate with a green marker and no alert, which is the condition this boundary exists
// to prevent. The two sibling tests stage the facts that DO earn neutrality (correct bytes
// with a refused mode repair, and content this app could not verify at all); all three are
// needed, or any one arm can be deleted silently.
//
// The write is refused for permissions here on purpose: it is the errno that earns neutrality
// under either other fact, so this case proves the CONTENT fact is what refuses it and not the
// error class.
//
// Failed rather than main.healthyAfterScan is asserted because that predicate lives in
// package main and reads exactly this field (`return r.Failed == 0`), pinned there by
// TestHealthyAfterScan.
// Runs serially: it swaps slog.Default(), the chmod seam and the write seam.
func TestScannerRun_a_stale_bundle_whose_mode_repair_was_refused_is_a_conversion_failure(t *testing.T) {
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
	// The first scan runs with both seams live, so the bundle under test is a real one
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
	// Laxer than pfxFileMode, so tightenMode runs and its refusal is remembered.
	if err := os.Chmod(pfxPath, 0o644); err != nil {
		t.Fatalf("setup: Chmod: %v", err)
	}
	prevChmod := chmodInRoot
	chmodInRoot = func(_ *os.Root, name string, _ os.FileMode) error {
		return &fs.PathError{Op: "chmod", Path: name, Err: syscall.EPERM}
	}
	t.Cleanup(func() { chmodInRoot = prevChmod })
	// The injected refusal MEANS "another UID owns this bundle", so the ownership read
	// has to agree.
	prevOwned := fileOwnedByProcess
	fileOwnedByProcess = func(os.FileInfo) bool { return false }
	t.Cleanup(func() { fileOwnedByProcess = prevOwned })
	prevWrite := writeFileInRoot
	writeFileInRoot = func(context.Context, *os.Root, string, []byte,
		...atomicfile.Option,
	) (atomicfile.Result, error) {
		return atomicfile.Result{}, &fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EACCES}
	}
	t.Cleanup(func() { writeFileInRoot = prevWrite })

	logs := captureLogs(t)
	res, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(stale bundle, refused repair, refused rewrite) = error %v, want nil: this is a"+
			" pair-level failure, not a scan-level one", err)
	}
	if res.Failed != 1 || res.Unwritable != 0 || res.Converted != 0 {
		t.Errorf("Run(stale bundle, refused repair, refused rewrite) = %+v, want Failed 1 Unwritable 0"+
			" Converted 0: only a content-matched bundle earns the health-neutral arm", res)
	}
	// The chmod refusal is still announced: tightenMode runs before the content read, so
	// its absence would mean this test never reached the arm under test.
	if got := logs.CountLevel(slog.LevelWarn, modeRepairRefusedMsg); got != 1 {
		t.Errorf("logged %q at WARN %d times, want exactly 1: %q", modeRepairRefusedMsg, got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelError, "conversion failed"); got != 1 {
		t.Errorf("logged %q at ERROR %d times, want exactly 1: an unwritten renewal is a conversion"+
			" failure: %q", "conversion failed", got, logs.Messages())
	}
	// Neither health-neutral message may appear: a bundle this app compared and found
	// stale earns no standing WARN in place of the failure, whichever promise the message
	// would have made about it.
	for _, msg := range []string{unwritableBundleMsg, unreplaceableBundleMsg} {
		if got := logs.CountLevel(slog.LevelWarn, msg); got != 0 {
			t.Errorf("logged %q at WARN %d times, want 0: the health-neutral WARNs belong only to a bundle"+
				" this app never proved wrong: %q", msg, got, logs.Messages())
		}
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
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	s := newOutputStore(t, t.TempDir())
	// Written through store.write, so the file on disk is a real bundle and only the
	// read can answer the question.
	if err := s.write(t.Context(), "out.pfx", mustEncode(t, &analysis)); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	current, err := inspectCurrent(ctx, s, "out.pfx", &analysis, convert.EncNameModern2023, "pw")

	if !errors.Is(err, context.Canceled) {
		t.Errorf("inspect(cancelled ctx) error = %v, want context.Canceled: a shutdown is neither current nor stale", err)
	}
	if current {
		t.Error("inspect(cancelled ctx) = true, want false")
	}
}

// mustEncode encodes analysis with the suite's standard profile and password.
func mustEncode(t *testing.T, analysis *convert.Analysis) []byte {
	t.Helper()
	pfx, err := convert.Encode(analysis, convert.EncNameModern2023, "pw")
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
// A profile mismatch, a content mismatch and a failed DECODE are verified stale: the
// codec looked, and what is on disk will not open with the configured password or is
// not what these inputs produce, so the operator is being served the wrong bundle. A
// failed PREFLIGHT is not: the preflight refuses to LOOK, so nothing about the bytes was
// compared, and reporting that as proof the bundle is wrong is exactly the conflation
// this routing was restructured to remove.
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
		if err := waitForReapDeferral(context.Background(), time.Millisecond); err != nil {
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
		reconcile(context.Background(), map[string]struct{}{},
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
// window from the next guard downstream: removeOrphans re-checks the context before
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
	ctx, cancel := context.WithCancel(context.Background())
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
				reconcile(context.Background(), map[string]struct{}{},
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
	ctx, cancel := context.WithCancel(context.Background())
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
// bundles whose mode repair the volume refused, deliberately kept out of failed= and
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
	if want := 1 + flat + 1 + deep; sw.entries != want {
		t.Errorf("the walk visited %d entries, want %d: a batched read must reach every entry of every directory exactly once",
			sw.entries, want)
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
	if want := 2; sw.entries != want {
		t.Errorf("the walk charged %d entries, want %d: a directory the walk cannot open is"+
			" reported through visit for a path its parent already charged, so charging there"+
			" enforces MAX_SCAN_ENTRIES below its configured value", sw.entries, want)
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

func TestObservationLog_keeps_reporting_a_lone_key_once_the_dedup_set_is_full(t *testing.T) {
	log := newObservationLog(1)

	if !log.markLoneKey("a.crt") {
		t.Fatal("markLoneKey(first retention) = false, want true: a newly retained bundle must be reported")
	}
	if log.markLoneKey("a.crt") {
		t.Error("markLoneKey(same retention again) = true, want false: the report is deduplicated per change, not per scan")
	}

	// The set is now at its ceiling, so a SECOND retained pair cannot be remembered.
	// It must still be named -- on every scan, if that is what it takes -- because
	// nothing else in this app reports a lone key at any level: the bundle is not
	// converted, not reaped, and counted in nothing.
	if !log.markLoneKey("b.crt") {
		t.Error("markLoneKey(second retention at the ceiling) = false, want true: a retention the log cannot remember must still be named")
	}
	if !log.markLoneKey("b.crt") {
		t.Error("markLoneKey(second retention at the ceiling, repeated) = false, want true: re-reporting is the safe direction, silence is not")
	}
	if got := len(log.loneKeys); got != 1 {
		t.Errorf("len(loneKeys) = %d, want 1: the ceiling arm must report without growing the set", got)
	}
}

func TestObservationLog_wholeness_eviction_makes_room_without_touching_the_reserved_path(t *testing.T) {
	log := newObservationLog(1)
	// The reachable shape: a.crt is remembered by the SIGNATURE half (note ran for it)
	// while its wholeness entry is gone, and the wholeness half is already full.
	// reserve routes this through evictWholeness, which must evict the OTHER pair,
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
	if got := logs.CountLevel(slog.LevelWarn, evictedEvidenceMsg); got != 1 {
		t.Errorf("Run(log at its ceiling) logged %q at WARN %d times, want exactly 1: %q",
			evictedEvidenceMsg, got, logs.Messages())
	}
	assertRemediationMentions(t, logs, evictedEvidenceMsg, "MAX_SCAN_ENTRIES")
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
		reconcile(context.Background(), map[string]struct{}{},
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
		reconcile(context.Background(), map[string]struct{}{},
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
		reconcile(context.Background(), map[string]struct{}{},
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

// TestStoreReconcile_lone_key_warn_is_deduplicated_per_change pins the report's
// de-duplication schedule, which is per CHANGE rather than per scan: the retention lasts
// for as long as the operator leaves the pair half-deleted, and this app rescans on every
// fsnotify event and every fallback tick, so a per-scan report is a permanent WARN stream
// for a condition already named. The state is remembered in the observation log — the same
// machinery that deduplicates the input observations — and retired when the pair reads
// whole again. Serial: it swaps waitBeforeReap and slog.Default.
func TestStoreReconcile_lone_key_warn_is_deduplicated_per_change(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "half.pfx"), []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(half.pfx): %v", err)
	}
	in := t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "half.key"), []byte("key"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(half.key): %v", err)
	}
	s := newOutputStore(t, out)
	stubReapWait(t, func(context.Context) error { return nil })
	logs := captureLogs(t)
	// One reaper across both scans: the observation log is Scanner-lifetime state, which
	// is what makes "once per change" expressible at all.
	rp := newReaper(s, newInputSource(t, in), outputpolicy.LifecycleSync)
	rc := &reapContext{result: ScanResult{Total: 1}, walkCompleted: true}

	for range 3 {
		if _, err := rp.reconcile(context.Background(), map[string]struct{}{}, rc); err != nil {
			t.Fatalf("reconcile(lone key) = error %v, want nil", err)
		}
	}

	if got := logs.CountLevel(slog.LevelWarn, loneKeyRetainedMsg); got != 1 {
		t.Errorf("three scans of one unchanged lone key logged %q at WARN %d times, want exactly 1: %q",
			loneKeyRetainedMsg, got, logs.Messages())
	}

	// The pair reading whole again is the CHANGE that retires the report, so the next time
	// it loses its certificate the operator is told again.
	rp.observations.markWhole("half.crt")
	if _, err := rp.reconcile(context.Background(), map[string]struct{}{}, rc); err != nil {
		t.Fatalf("reconcile(lone key after the pair read whole) = error %v, want nil", err)
	}
	if got := logs.CountLevel(slog.LevelWarn, loneKeyRetainedMsg); got != 2 {
		t.Errorf("a lone key that recurred after the pair read whole logged %q at WARN %d times,"+
			" want 2: the report is deduplicated per change, not for the process lifetime",
			loneKeyRetainedMsg, got)
	}
}

// TestStoreReconcile_audits_deletions_once_per_scan_at_warn pins the deletion audit
// record, the app's warn-visible contract for the one destructive action it takes.
//
// Successful deletions were named per path at INFO, so at LOG_LEVEL=warn — the level an
// operator runs a quiet daemon at — private-key bundles disappeared silently while only
// the FAILURES of orphan removal were loud. One structured record per deletion-bearing
// scan carries the count and the paths, through the SAME bounded sample the orphan report
// uses (sampleOrphanPaths: at most maxLoggedOrphans paths within maxLoggedOrphanBytes) so
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
		reconcile(context.Background(), map[string]struct{}{},
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
		reconcile(context.Background(), map[string]struct{}{},
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

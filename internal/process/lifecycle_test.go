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
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			defer root.Close()
			s := &store{root: root}
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	logs := captureLogs(t)
	s := &store{root: root}

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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	logs := captureLogs(t)
	s := &store{root: root}

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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	logs := captureLogs(t)
	s := &store{root: root}

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
		if max := maxLoggedOrphanBytes + len(truncationMarker); len(got) > max {
			t.Errorf("sampleOrphanPaths(one %d-byte path) rendered %d bytes, want at most %d",
				len(paths[0]), len(got), max)
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
		if min := maxLoggedOrphanBytes - (utf8.UTFMax - 1); len(kept) < min {
			t.Errorf("sampleOrphanPaths(one %d-byte path) kept only %d bytes, want at least %d: the rune backoff must not discard more than one rune",
				len(paths[0]), len(kept), min)
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
		if max := maxLoggedOrphanBytes + len(truncationMarker) + len(wantMore); len(got) > max {
			t.Errorf("sampleOrphanPaths(%d oversized paths) rendered %d bytes, want at most %d", len(paths), len(got), max)
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	logs := captureLogs(t)
	s := &store{root: root}

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
	if max := maxLoggedOrphanBytes + len(truncationMarker); len(paths) > max {
		t.Errorf("orphan report logged a %d-byte paths attribute, want at most %d", len(paths), max)
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s := &store{root: root}
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s := &store{root: root}
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

// TestStoreIsCurrent_rewrites_on_an_encoder_change pins the currency half of the
// preflight, which is the reason it exists.
//
// A bundle's leaf, key and chain are unchanged by a PFX_ENCODER switch, so
// comparing only those reports the bundle CURRENT and the operator's deliberate
// change silently applies to nothing: every file keeps its old algorithms while the
// startup log announces the new profile, until some certificate happens to renew.
func TestStoreIsCurrent_rewrites_on_an_encoder_change(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}

	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}

	written, err := convert.Encode(&analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if err := s.write(t.Context(), "out.pfx", written); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	// Same configured profile: current, nothing to do.
	current, _, err := s.isCurrent(t.Context(), "out.pfx", &analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("isCurrent(same profile) = error %v, want nil", err)
	}
	if !current {
		t.Error("isCurrent(same profile) = false, want true: nothing about this bundle changed")
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
			current, _, err := s.isCurrent(t.Context(), "out.pfx", &analysis, other, "pw")
			if err != nil {
				t.Fatalf("isCurrent(configured %s) = error %v, want nil", other, err)
			}
			if current {
				t.Errorf("isCurrent(configured %s over a modern2023 bundle) = true, want false: the encoder change must take effect", other)
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}
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

// TestStoreRemoveOrphans_skips_an_undeletable_orphan_and_continues pins the
// "skipping (never aborting on) an individual removal failure" half of removeOrphans'
// contract. Aborting instead would let one stuck path permanently stop the reap of
// every later bundle under OUTPUT_LIFECYCLE=sync, and the two behaviours are
// indistinguishable from the logs: both WARN about the offending path, the scan still
// completes and health stays green.
func TestStoreRemoveOrphans_skips_an_undeletable_orphan_and_continues(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A NON-EMPTY directory wearing an output name: Remove refuses it with ENOTEMPTY
	// whatever uid the test runs as, so the case does not silently pass as root.
	stuck := filepath.Join(dir, "stuck.pfx")
	if err := os.Mkdir(stuck, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stuck, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	reapable := filepath.Join(dir, "reapable.pfx")
	if err := os.WriteFile(reapable, []byte("pfx"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s := &store{root: root}

	deleted, err := s.removeOrphans(t.Context(), []string{"stuck.pfx", "reapable.pfx"})
	if err != nil {
		t.Fatalf("removeOrphans = %v, want nil: one refused removal is not a scan error", err)
	}
	if deleted != 1 {
		t.Errorf("removeOrphans deleted = %d, want 1: the orphan after the refused one must still go", deleted)
	}
	if _, statErr := os.Stat(reapable); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(reapable.pfx) = %v, want fs.ErrNotExist: a later orphan must not be blocked by an earlier failure", statErr)
	}
	if _, statErr := os.Stat(stuck); statErr != nil {
		t.Errorf("the undeletable path vanished (%v); only what Remove accepted may disappear", statErr)
	}
}

// TestStoreIsCurrent_rewrites_after_a_password_rotation pins the second reason
// output-derived currency replaced the fingerprint cache: the cache answered "have
// these input bytes been converted?", so rotating PFX_PASSWORD changed nothing
// until some certificate happened to renew. Decoding the prior bundle with the
// CONFIGURED password is what makes the rotation take effect, and a failed decode
// must resolve to stale rather than to a failed pair.
func TestStoreIsCurrent_rewrites_after_a_password_rotation(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}

	written, err := convert.Encode(&analysis, convert.EncNameModern2023, "old-password")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if err := s.write(t.Context(), "out.pfx", written); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	current, _, err := s.isCurrent(t.Context(), "out.pfx", &analysis, convert.EncNameModern2023, "old-password")
	if err != nil {
		t.Fatalf("isCurrent(unrotated password) = error %v, want nil", err)
	}
	if !current {
		t.Fatal("isCurrent(unrotated password) = false, want true: nothing about this bundle changed")
	}

	current, _, err = s.isCurrent(t.Context(), "out.pfx", &analysis, convert.EncNameModern2023, "new-password")
	if err != nil {
		t.Fatalf("isCurrent(rotated password) = error %v, want nil: a bundle that will not decode is stale, not fatal", err)
	}
	if current {
		t.Error("isCurrent(rotated password) = true, want false: a PFX_PASSWORD rotation must take effect without waiting for a renewal")
	}
}

// TestStoreIsCurrent_treats_an_undecodable_prior_as_stale pins the self-healing
// half of the currency check: a foreign, empty or truncated file sitting at an
// output name is not this bundle, so it must be REWRITTEN rather than reported as
// a failed pair. Returning an error instead would pin the container unhealthy over
// a condition the app repairs itself on the same scan.
// Runs serially: it swaps slog.Default().
func TestStoreIsCurrent_treats_an_undecodable_prior_as_stale(t *testing.T) {
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}

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
			current, _, err := s.isCurrent(t.Context(), tc.rel, &analysis, convert.EncNameModern2023, "pw")
			if err != nil {
				t.Errorf("isCurrent(%s) = error %v, want nil: an undecodable prior output is stale, not a failed pair", tc.name, err)
			}
			if current {
				t.Errorf("isCurrent(%s) = true, want false: a file that is not this bundle must be rewritten", tc.name)
			}
			// Which arm answered matters as much as the answer: the size arm reaches
			// this same verdict without reading the bundle, so asserting the outcome
			// alone lets the preflight go unexercised.
			if !logs.Contains("prior pfx failed preflight; regenerating") {
				t.Errorf("isCurrent(%s) logged %q, want the preflight notice: the stale verdict must come from the preflight, not from an earlier arm", tc.name, logs.Messages())
			}
		})
	}
}

// TestStoreIsCurrent_regenerates_an_oversized_prior pins the size guard in front
// of the prior-output read. Two things must hold and neither is covered by the
// outcome alone: an oversized prior resolves to STALE rather than to an error
// (erroring would flip health over a file the app can replace itself), and the
// operator gets the size-bound diagnosis rather than the generic
// cannot-read-prior-pfx warning, which points at /output permissions and would
// send them chasing the wrong cause. Runs serially: it swaps slog.Default().
func TestStoreIsCurrent_regenerates_an_oversized_prior(t *testing.T) {
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}

	logs := captureLogs(t)
	current, _, err := s.isCurrent(t.Context(), "big.pfx", &convert.Analysis{}, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("isCurrent(oversized prior) = error %v, want nil: it must resolve to stale, not fail the pair", err)
	}
	if current {
		t.Error("isCurrent(oversized prior) = true, want false")
	}
	const sizeMsg = "prior pfx exceeds the readable bound"
	if !logs.Contains(sizeMsg) {
		t.Errorf("isCurrent(oversized prior) logged %q, want the size-bound notice rather than a permissions hint", logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelWarn, sizeMsg); got != 1 {
		t.Errorf("isCurrent(oversized prior) logged %q at WARN %d times, want exactly 1", sizeMsg, got)
	}
}

// TestStoreIsCurrent_tightens_a_lax_mode_without_regenerating pins the approved
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
func TestStoreIsCurrent_tightens_a_lax_mode_without_regenerating(t *testing.T) {
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
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			defer root.Close()
			s := &store{root: root}
			if err := s.write(t.Context(), "out.pfx", mustEncode(t, &analysis)); err != nil {
				t.Fatalf("setup: write: %v", err)
			}
			path := filepath.Join(dir, "out.pfx")
			// The output DIRECTORY's mode is fixture noise here, but it is not noise to
			// isCurrent: reportLaxDir warns when the directory is laxer than pfxDirMode,
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
			current, _, err := s.isCurrent(t.Context(), "out.pfx", &analysis, convert.EncNameModern2023, "pw")
			if err != nil {
				t.Fatalf("isCurrent(mode %o) = error %v, want nil", tc.mode, err)
			}
			if !current {
				t.Errorf("isCurrent(mode %o) = false, want true: a permission bit is not part of currency,"+
					" and rewriting for one cannot converge on a filesystem that will not store it", tc.mode)
			}

			gotContent, after := readBundle(t, path)
			if !bytes.Equal(gotContent, wantContent) {
				t.Errorf("isCurrent(mode %o) changed the bundle's bytes; the mode must be fixed with a"+
					" chmod, not by re-encoding it with a fresh salt", tc.mode)
			}
			if !after.ModTime().Equal(before.ModTime()) {
				t.Errorf("isCurrent(mode %o) moved the mtime from %v to %v; a chmod does not, a rewrite does",
					tc.mode, before.ModTime(), after.ModTime())
			}
			if tc.wantTighten {
				if got := logs.CountLevel(slog.LevelInfo, tightenedMsg); got != 1 {
					t.Errorf("isCurrent(mode %o) logged %q at INFO %d times, want exactly 1: %q",
						tc.mode, tightenedMsg, got, logs.Messages())
				}
				if logs.Len() != 1 {
					t.Errorf("isCurrent(mode %o) logged %q, want only the tighten notice: a repaired mode is"+
						" not also a warning", tc.mode, logs.Messages())
				}
				want := tc.wantMode
				if want == 0 {
					want = tc.mode & pfxFileMode
				}
				if got := after.Mode().Perm(); got != want {
					t.Errorf("isCurrent(mode %o) tightened mode to %o, want %o: allowed owner bits must survive", tc.mode, got, want)
				}
				return
			}
			if logs.Len() != 0 {
				t.Errorf("isCurrent(mode %o) logged %q, want nothing at all: a mode at or stricter than"+
					" policy is not this app's to touch", tc.mode, logs.Messages())
			}
			if got, want := after.Mode().Perm(), before.Mode().Perm(); got != want {
				t.Errorf("isCurrent(mode %o) changed the mode to %v, want %v left untouched", tc.mode, got, want)
			}
		})
	}
}

// TestStoreIsCurrent_keeps_a_bundle_whose_mode_cannot_be_tightened pins the
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
// The one failure that IS convergeable — a REFUSED chmod, i.e. a bundle owned by
// another UID — deliberately does not appear in this table; it belongs to
// TestScannerRun_regenerates_a_bundle_whose_mode_repair_was_refused, which pins the
// opposite verdict. Keeping the two in separate tests is what stops a future
// simplification from collapsing them back into one non-action.
//
// The chmod is stubbed because none of these failures is reproducible in a temp
// directory: no local filesystem ignores permission bits or refuses a chmod to the
// UID running the suite.
// Runs serially: it swaps slog.Default() and the chmod seam.
func TestStoreIsCurrent_keeps_a_bundle_whose_mode_cannot_be_tightened(t *testing.T) {
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			defer root.Close()
			s := &store{root: root}
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
			current, _, err := s.isCurrent(t.Context(), "out.pfx", &analysis, convert.EncNameModern2023, "pw")
			if err != nil {
				t.Fatalf("isCurrent(untightenable mode) = error %v, want nil", err)
			}
			if !current {
				t.Error("isCurrent(untightenable mode) = false, want true: calling it stale is the rewrite" +
					" loop this design exists to avoid")
			}
			if got := logs.CountLevel(slog.LevelWarn, notTightenedMsg); got != 1 {
				t.Errorf("isCurrent(untightenable mode) logged %q at WARN %d times, want exactly 1: %q",
					notTightenedMsg, got, logs.Messages())
			}
			// Keyed attributes, not a line substring: the mode found and the mode wanted
			// must each appear under their own key, or a line naming one twice would pass.
			for key, want := range map[string]string{"mode": "-rw-r--r--", "want": "-rw-------"} {
				if !logs.HasAttr(notTightenedMsg, key, want) {
					got, _ := logs.AttrValue(notTightenedMsg, key)
					t.Errorf("isCurrent(untightenable mode) logged %s=%q, want %q", key, got, want)
				}
			}

			// The next scan reaches the same verdict and says the same thing once more:
			// steady state, not an escalation and not a rewrite.
			current, _, err = s.isCurrent(t.Context(), "out.pfx", &analysis, convert.EncNameModern2023, "pw")
			if err != nil || !current {
				t.Fatalf("isCurrent(untightenable mode, second scan) = (%v, %v), want (true, nil)", current, err)
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
					t.Errorf("isCurrent(untightenable mode) logged %q; %q is the wrong message for a"+
						" tightening no rewrite can fix", logs.Messages(), unwanted)
				}
			}
			if _, after := readBundle(t, filepath.Join(dir, "out.pfx")); after.Mode().Perm() != 0o644 {
				t.Errorf("isCurrent(untightenable mode) left mode %o, want 0644 untouched: the stub stored"+
					" nothing, so nothing may claim otherwise", after.Mode().Perm())
			}
		})
	}
}

// TestScannerRun_regenerates_a_bundle_whose_mode_repair_was_refused pins the other
// half of the mode policy, and the reason it is a WHOLE-SCAN test rather than an
// isCurrent one: the property that matters is that the refusal ends in a REPLACED
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
			if err := os.WriteFile(filepath.Join(certsRoot, "chain.crt"), chainPEM, 0o644); err != nil {
				t.Fatalf("setup: write crt: %v", err)
			}
			if err := os.WriteFile(filepath.Join(certsRoot, "chain.key"), keyPEM, 0o600); err != nil {
				t.Fatalf("setup: write key: %v", err)
			}
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
// So a PERMISSION refusal of that rewrite is health-neutral: the bundle on disk still
// holds the right bytes, the operator gets a standing WARN naming ownership as the
// remedy, and the outcome is accounted in ScanResult.Unwritable instead of Failed —
// which is the field main.healthyAfterScan reads, and TestHealthyAfterScan pins that
// this shape stays healthy through that real predicate. Any OTHER failure of the same
// write stays a conversion failure and still flips health: a failed PFX write is a
// conversion failure, as the README documents, and an ENOSPC is no evidence about
// ownership.
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
	const failedMsg = "conversion failed"
	for _, tc := range []struct {
		writeErr       error
		name           string
		wantUnwritable int
		wantFailed     int
	}{
		{
			// The temp cannot be created: /output itself belongs to another UID.
			name:           "a refused write leaves the bundle in place without flipping health",
			writeErr:       &fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EACCES},
			wantUnwritable: 1,
		},
		{
			// The other refusal errno, for the same reason the sibling test covers both:
			// only the classification tells them apart from the failures below.
			name:           "an EPERM refusal of the same write is the same condition",
			writeErr:       &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.EPERM},
			wantUnwritable: 1,
		},
		{
			// A full volume is not an ownership problem, and the next scan might well
			// succeed, so the general rule stands: an unwritten PFX is a conversion failure.
			name:       "a write that fails for any other reason is still a conversion failure",
			writeErr:   &fs.PathError{Op: "renameat", Path: "chain.pfx", Err: syscall.ENOSPC},
			wantFailed: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certsRoot := t.TempDir()
			outRoot := t.TempDir()
			_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
			if err := os.WriteFile(filepath.Join(certsRoot, "chain.crt"), chainPEM, 0o644); err != nil {
				t.Fatalf("setup: write crt: %v", err)
			}
			if err := os.WriteFile(filepath.Join(certsRoot, "chain.key"), keyPEM, 0o600); err != nil {
				t.Fatalf("setup: write key: %v", err)
			}
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
			// volume must not get a line per retry behind it.
			if got := logs.CountLevel(slog.LevelWarn, unwritableMsg); got != wantUnwritableLines {
				t.Errorf("Run(refused repair, refused rewrite) logged %q at WARN %d times, want %d: %q",
					unwritableMsg, got, wantUnwritableLines, logs.Messages())
			}
			if got := logs.CountLevel(slog.LevelError, failedMsg); got != wantFailedLines {
				t.Errorf("Run(refused repair, refused rewrite) logged %q at ERROR %d times, want %d: %q",
					failedMsg, got, wantFailedLines, logs.Messages())
			}
			if tc.wantUnwritable > 0 {
				// The standing WARN has to name the bundle and the operator action; ownership,
				// not a restart, is what clears this.
				for key, want := range map[string]string{
					"path":        "chain.crt",
					"output_path": "chain.pfx",
					"remediation": "check /output ownership and permissions for the UID in user:",
				} {
					if !logs.HasAttr(unwritableMsg, key, want) {
						got, _ := logs.AttrValue(unwritableMsg, key)
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
			if got := logs.CountLevel(slog.LevelWarn, unwritableMsg); got != 2*wantUnwritableLines {
				t.Errorf("two scans logged %q at WARN %d times, want %d (one per scan): %q",
					unwritableMsg, got, 2*wantUnwritableLines, logs.Messages())
			}
			if _, statErr := os.Stat(pfxPath); statErr != nil {
				t.Errorf("os.Stat(%s) = %v, want the bundle still in place", pfxPath, statErr)
			}
		})
	}
}

// TestScannerRun_a_stale_bundle_whose_mode_repair_was_refused_is_a_conversion_failure pins the
// half of the staleModeRepairRefused contract that store.isCurrent's tail gate establishes:
// health-neutrality is granted ONLY to a bundle whose CONTENT was compared and matched. A
// bundle that is a renewal behind is stale for an ordinary reason, so a refused rewrite of it
// counts in ScanResult.Failed and flips health -- otherwise the operator's PFX holds the
// previous certificate with a green marker and no alert, which is the condition this gate
// exists to prevent. The sibling test above stages the opposite (correct bytes, wrong mode)
// and must keep reporting Unwritable; both are needed or either arm can be deleted silently.
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
	if err := os.WriteFile(crtPath, chainPEM, 0o644); err != nil {
		t.Fatalf("setup: write crt: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("setup: write key: %v", err)
	}
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
	if got := logs.CountLevel(slog.LevelWarn, unwritableBundleMsg); got != 0 {
		t.Errorf("logged %q at WARN %d times, want 0: the standing health-neutral WARN belongs only to a"+
			" bundle whose bytes were compared and matched: %q", unwritableBundleMsg, got, logs.Messages())
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

// TestStoreIsCurrent_propagates_a_shutdown_instead_of_reporting_stale pins the one
// isCurrent outcome that is neither current nor stale. Every other "I cannot tell what
// is on disk" case resolves to "rewrite it", so if a cancelled read joined them, a
// SIGTERM landing mid-scan would regenerate every remaining pair on the way out --
// fresh KDF salts and mtimes on bundles that were already correct, re-replicated
// downstream -- and convertEntry, whose error arm assumes "only shutdown gets here",
// would report those as conversions rather than as a cancelled scan.
func TestStoreIsCurrent_propagates_a_shutdown_instead_of_reporting_stale(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}
	// Written through store.write, so the file on disk is a real bundle and only the
	// read can answer the question.
	if err := s.write(t.Context(), "out.pfx", mustEncode(t, &analysis)); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	current, _, err := s.isCurrent(ctx, "out.pfx", &analysis, convert.EncNameModern2023, "pw")

	if !errors.Is(err, context.Canceled) {
		t.Errorf("isCurrent(cancelled ctx) error = %v, want context.Canceled: a shutdown is neither current nor stale", err)
	}
	if current {
		t.Error("isCurrent(cancelled ctx) = true, want false")
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

// TestCurrentFromCurrency_maps_every_outcome pins the translation from a
// convert.Currency verdict into isCurrent's answer, one arm per outcome. The arm
// that has no other test is the last one: a decode INTERRUPTED by shutdown is
// neither current nor stale, so it must propagate the cancellation. If it joined
// the ordinary decode-failure arm, a SIGTERM landing during a bundle's KDF decode
// would report that pair stale and rewrite it on the way out -- a fresh salt and a
// fresh mtime on a bundle that was already correct, which the documented
// downstream rsync then re-replicates -- and convertEntry, whose error arm assumes
// "only shutdown gets here", would count it as a conversion instead of a cancelled
// scan. The other arms pin the level each outcome is reported at (Info for a
// deliberate encoder change, Debug for the two expected failures, silence for a
// match or an ordinary renewal), and each one repeats under a cancelled context:
// the shutdown gate sits ahead of the whole switch, so no verdict arm may report
// current or stale once cancellation is requested. Runs serially: it swaps
// slog.Default().
func TestCurrentFromCurrency_maps_every_outcome(t *testing.T) {
	for _, tc := range []struct {
		res         convert.Currency
		name        string
		wantMsg     string
		wantLevel   slog.Level
		cancelled   bool
		wantCurrent bool
		wantErr     bool
	}{
		{
			res:  convert.Currency{Reason: convert.CurrencyMatch},
			name: "a match is current and silent", wantCurrent: true,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyContentMismatch},
			name: "a renewed certificate is stale and silent",
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyPreflightFailed, Err: errors.New("bounded out")},
			name: "a failed preflight is stale at debug", wantMsg: "prior pfx failed preflight; regenerating",
			wantLevel: slog.LevelDebug,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyProfileMismatch, Profile: convert.EncNameLegacyDES},
			name: "an encoder change is stale at info", wantMsg: "prior pfx uses a different encoder profile; regenerating",
			wantLevel: slog.LevelInfo,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyDecodeFailed, Err: errors.New("mac mismatch")},
			name: "a failed decode is stale at debug", wantMsg: "prior pfx did not decode; regenerating",
			wantLevel: slog.LevelDebug,
		},
		{
			res:  convert.Currency{Reason: convert.CurrencyDecodeFailed, Err: errors.New("mac mismatch")},
			name: "a decode interrupted by shutdown is an error, not stale", cancelled: true, wantErr: true,
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
			name: "a failed preflight under shutdown is an error, not stale", cancelled: true, wantErr: true,
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

			current, err := currentFromCurrency(ctx, "example.com/tls.pfx", tc.res, convert.EncNameModern2023)

			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("currentFromCurrency(%s) error = %v, want an error: %v", tc.res.Reason, err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, context.Canceled) {
				t.Errorf("currentFromCurrency(cancelled, %s) error = %v, want context.Canceled so the scan reports the shutdown instead of rewriting every remaining pair",
					tc.res.Reason, err)
			}
			if current != tc.wantCurrent {
				t.Errorf("currentFromCurrency(%s) = %v, want %v", tc.res.Reason, current, tc.wantCurrent)
			}
			if tc.wantMsg == "" {
				if logs.Len() != 0 {
					t.Errorf("currentFromCurrency(%s) logged %q, want no output at all", tc.res.Reason, logs.Messages())
				}
				return
			}
			if got := logs.CountLevel(tc.wantLevel, tc.wantMsg); got != 1 {
				t.Errorf("currentFromCurrency(%s) logged %q at %s %d times, want exactly 1", tc.res.Reason, tc.wantMsg, tc.wantLevel, got)
			}
			if !logs.HasAttr(tc.wantMsg, "path", "example.com/tls.pfx") {
				t.Errorf("currentFromCurrency(%s) logged %q, want the output path named", tc.res.Reason, logs.Messages())
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
	outRoot, err := os.OpenRoot(out)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = outRoot.Close() })
	in := t.TempDir()
	s := &store{root: outRoot}
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s := &store{root: root}
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
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			t.Cleanup(func() { _ = root.Close() })
			s := &store{root: root}
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
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "live.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "live.crt"), certPEM, 0o644); err != nil {
		t.Fatalf("setup: write crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "live.key"), keyPEM, 0o600); err != nil {
		t.Fatalf("setup: write key: %v", err)
	}
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
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "live.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "live.crt"), certPEM, 0o644); err != nil {
		t.Fatalf("setup: write crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "live.key"), keyPEM, 0o600); err != nil {
		t.Fatalf("setup: write key: %v", err)
	}
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

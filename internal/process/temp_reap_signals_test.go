package process

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTempReapLogOutcome_operator_signals pins the /output sweep's end-of-sweep
// log contract, which is the ONLY observable output of the sweep for three
// conditions that never reach ScanResult or the health marker: a sweep that
// aborted, candidates that could not be inspected or unlinked, and output
// sub-paths the sweep could not enter. A shutdown abort must stay at Debug so a
// normal container stop never pages, every other abort is a Warn, and the two
// steady-state misconfiguration counters must reach the default level with their
// count and a remediation hint (they are the only signal that atomic-write
// artifacts are accumulating in /output). Runs serially: it swaps
// slog.Default().
func TestTempReapLogOutcome_operator_signals(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	tests := []struct {
		walkErr    error
		name       string
		wantMsg    string
		wantAttr   string
		wantLevel  slog.Level
		reaped     int
		failed     int
		unreadable int
	}{
		{nil, "a reclaimed orphan is reported at info", "reaped stale temp files", "count=2", slog.LevelInfo, 2, 0, 0},
		{
			nil, "uninspectable candidates warn with a remediation hint",
			"some stale output temps could not be inspected or removed", "remediation=", slog.LevelWarn, 0, 3, 0,
		},
		{
			nil, "unreadable output sub-paths warn with a remediation hint",
			"some output paths could not be inspected during stale temp cleanup", "remediation=", slog.LevelWarn, 0, 0, 4,
		},
		{errors.New("permission denied"), "a failed sweep warns", "stale temp cleanup failed", "error=", slog.LevelWarn, 0, 0, 0},
		{
			context.Canceled, "a shutdown abort stays at debug",
			"stale temp cleanup cancelled during shutdown", "error=", slog.LevelDebug, 0, 0, 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			tr := &tempReap{store: &store{root: root}, cutoff: time.Now(), reaped: tt.reaped, failed: tt.failed, unreadable: tt.unreadable}
			tr.logOutcome(tt.walkErr)

			out := buf.String()
			if !strings.Contains(out, tt.wantMsg) {
				t.Errorf("logOutcome(%v) logged %q, want message %q", tt.walkErr, out, tt.wantMsg)
			}
			if !strings.Contains(out, "level="+tt.wantLevel.String()) {
				t.Errorf("logOutcome(%v) logged %q, want level %s", tt.walkErr, out, tt.wantLevel)
			}
			if !strings.Contains(out, tt.wantAttr) {
				t.Errorf("logOutcome(%v) logged %q, want attribute %q", tt.walkErr, out, tt.wantAttr)
			}
		})
	}
}

// TestTempReapVisit_aggregates_non_benign_candidate_failures pins the wiring
// between the per-candidate reaper and the sweep's aggregate operator warning:
// a candidate the confined root refuses to inspect must land in tr.failed (which
// is what makes logOutcome warn) without being counted as a reaped orphan or as
// an unreadable sub-path, and must abort nothing. Without this, reapStaleTemp
// could report a failure that visit silently discards and the sweep would look
// clean while stale artifacts accumulate.
func TestTempReapVisit_aggregates_non_benign_candidate_failures(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	dir := filepath.Join(base, "out")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{dir, outside} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	temp := filepath.Join(outside, ".atomicfile-444.tmp")
	if err := os.WriteFile(temp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(temp, old, old); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(temp)
	if err != nil {
		t.Fatal(err)
	}
	// An output subdirectory swapped for a symlink out of the volume: the
	// confined Lstat refuses it, and that refusal must reach the aggregate.
	if err := os.Symlink(outside, filepath.Join(dir, "swapped")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	tr := &tempReap{store: &store{root: root}, cutoff: time.Now().Add(-staleTempAge)}
	if got := tr.visit(t.Context(), "swapped/.atomicfile-444.tmp", fs.FileInfoToDirEntry(fi), nil); got != nil {
		t.Errorf("visit(refused candidate) = %v, want nil so the rest of the tree is still swept", got)
	}
	if tr.failed != 1 {
		t.Errorf("visit(refused candidate) failed = %d, want 1 so the aggregate warning fires", tr.failed)
	}
	if tr.reaped != 0 || tr.unreadable != 0 {
		t.Errorf("visit(refused candidate) reaped/unreadable = %d/%d, want 0/0 (it is neither a reaped orphan nor an unreadable sub-path)",
			tr.reaped, tr.unreadable)
	}
	if _, statErr := os.Stat(temp); statErr != nil {
		t.Errorf("os.Stat(%q) = %v, want nil: nothing outside the output root may be unlinked", temp, statErr)
	}
}

// TestTempReapLogOutcome_is_silent_for_a_clean_sweep pins the quiet steady state
// of the /output sweep: with nothing reaped, nothing refused, no unreadable
// sub-path and no walk error, logOutcome must emit nothing at all.
// sweepStaleTemps runs at the start of every scan -- each debounced fsnotify
// event and each fallback tick -- so a counter guard that also fired on zero
// would put a "count=0" info line, and for the two aggregate counters an
// operator-facing warning with a remediation hint, into the log on every scan of
// a perfectly healthy /output. Runs serially: it swaps slog.Default().
func TestTempReapLogOutcome_is_silent_for_a_clean_sweep(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	tr := &tempReap{store: &store{root: root}, cutoff: time.Now()}
	tr.logOutcome(nil)

	if out := buf.String(); out != "" {
		t.Errorf("logOutcome(clean sweep) logged %q, want no output at all", out)
	}
}

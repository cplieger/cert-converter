package process

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/cplieger/atomicfile/v2"
)

// TestStoreLogSweepOutcome_operator_signals pins the /output sweep's end-of-sweep
// log contract, which is the ONLY observable output of the sweep for three
// conditions that never reach ScanResult or the health marker: a sweep that
// aborted, candidates that could not be inspected or unlinked, and output
// sub-paths the sweep could not enter. A shutdown abort must stay at Debug so a
// normal container stop never pages, every other abort is a Warn, and the two
// steady-state misconfiguration counters must reach the default level with their
// count and a remediation hint (they are the only signal that atomic-write
// artifacts are accumulating in /output).
//
// The sweep mechanics moved to atomicfile.CleanupStaleTempsInRoot, which reports
// counts rather than logging; this narrative stayed here because the remediation
// hint names THIS app's volume and user: mapping. Runs serially: it swaps
// slog.Default().
func TestStoreLogSweepOutcome_operator_signals(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	tests := []struct {
		walkErr   error
		name      string
		wantMsg   string
		wantAttr  string
		res       atomicfile.SweepResult
		wantLevel slog.Level
	}{
		{
			nil, "a reclaimed orphan is reported at info", "reaped stale temp files", "count=2",
			atomicfile.SweepResult{Removed: 2},
			slog.LevelInfo,
		},
		{
			nil, "uninspectable candidates warn with a remediation hint",
			"some stale output temps could not be inspected or removed", "remediation=",
			atomicfile.SweepResult{Failed: 3},
			slog.LevelWarn,
		},
		{
			nil, "unreadable output sub-paths warn with a remediation hint",
			"some output paths could not be inspected during stale temp cleanup", "remediation=",
			atomicfile.SweepResult{Unreadable: 4},
			slog.LevelWarn,
		},
		{
			errors.New("permission denied"), "a failed sweep warns", "stale temp cleanup failed", "error=",
			atomicfile.SweepResult{},
			slog.LevelWarn,
		},
		{
			context.Canceled, "a shutdown abort stays at debug",
			"stale temp cleanup cancelled during shutdown", "error=",
			atomicfile.SweepResult{},
			slog.LevelDebug,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			s := &store{root: root}
			s.logSweepOutcome(tt.res, tt.walkErr)

			out := buf.String()
			if !strings.Contains(out, tt.wantMsg) {
				t.Errorf("logSweepOutcome(%v) logged %q, want message %q", tt.walkErr, out, tt.wantMsg)
			}
			if !strings.Contains(out, "level="+tt.wantLevel.String()) {
				t.Errorf("logSweepOutcome(%v) logged %q, want level %s", tt.walkErr, out, tt.wantLevel)
			}
			if !strings.Contains(out, tt.wantAttr) {
				t.Errorf("logSweepOutcome(%v) logged %q, want attribute %q", tt.walkErr, out, tt.wantAttr)
			}
		})
	}
}

// TestStoreLogSweepOutcome_is_silent_for_a_clean_sweep pins the quiet steady state
// of the /output sweep: with nothing reaped, nothing refused, no unreadable
// sub-path and no walk error, logSweepOutcome must emit nothing at all.
// sweepStaleTemps runs at the start of every scan -- each debounced fsnotify
// event and each fallback tick -- so a counter guard that also fired on zero
// would put a "count=0" info line, and for the two aggregate counters an
// operator-facing warning with a remediation hint, into the log on every scan of
// a perfectly healthy /output. Runs serially: it swaps slog.Default().
func TestStoreLogSweepOutcome_is_silent_for_a_clean_sweep(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s := &store{root: root}
	s.logSweepOutcome(atomicfile.SweepResult{}, nil)

	if out := buf.String(); out != "" {
		t.Errorf("logSweepOutcome(clean sweep) logged %q, want no output at all", out)
	}
}

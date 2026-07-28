package process

import (
	"context"
	"errors"
	"log/slog"
	"os"
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
// CleanupStaleTempsInRoot owns the sweep mechanics and returns counts; this
// package tests the app-specific logs because their remediation names /output
// and the deployment's user mapping. Runs serially because it swaps slog.Default().
func TestStoreLogSweepOutcome_operator_signals(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	tests := []struct {
		walkErr       error
		name          string
		wantMsg       string
		wantAttrKey   string
		wantAttrValue string
		res           atomicfile.SweepResult
		wantLevel     slog.Level
	}{
		{
			nil, "a reclaimed orphan is reported at info", "reaped stale temp files", "count", "2",
			atomicfile.SweepResult{Removed: 2},
			slog.LevelInfo,
		},
		{
			nil, "uninspectable candidates warn with a remediation hint",
			"some stale output temps could not be inspected or removed", "remediation", "",
			atomicfile.SweepResult{Failed: 3},
			slog.LevelWarn,
		},
		{
			nil, "unreadable output sub-paths warn with a remediation hint",
			"some output paths could not be inspected during stale temp cleanup", "remediation", "",
			atomicfile.SweepResult{Unreadable: 4},
			slog.LevelWarn,
		},
		{
			errors.New("permission denied"), "a failed sweep warns", "stale temp cleanup failed", "error", "",
			atomicfile.SweepResult{},
			slog.LevelWarn,
		},
		{
			context.Canceled, "a shutdown abort stays at debug",
			"stale temp cleanup cancelled during shutdown", "error", "",
			atomicfile.SweepResult{},
			slog.LevelDebug,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			s := &store{root: root}
			s.logSweepOutcome(tt.res, tt.walkErr)

			if !logs.Contains(tt.wantMsg) {
				t.Errorf("logSweepOutcome(%v) logged %q, want message %q", tt.walkErr, logs.Messages(), tt.wantMsg)
			}
			if got := logs.CountLevel(tt.wantLevel, tt.wantMsg); got != 1 {
				t.Errorf("logSweepOutcome(%v) logged %q at %s %d times, want 1", tt.walkErr, tt.wantMsg, tt.wantLevel, got)
			}
			// The attribute is asserted by KEY on the record carrying the message, so a
			// value that happens to appear elsewhere in the line cannot satisfy it. An
			// empty wantAttrValue asserts presence only.
			got, ok := logs.AttrValue(tt.wantMsg, tt.wantAttrKey)
			if !ok {
				t.Errorf("logSweepOutcome(%v) logged %q, want attribute %q", tt.walkErr, logs.Messages(), tt.wantAttrKey)
			}
			if tt.wantAttrValue != "" && got != tt.wantAttrValue {
				t.Errorf("logSweepOutcome(%v) logged %s=%q, want %q", tt.walkErr, tt.wantAttrKey, got, tt.wantAttrValue)
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

	logs := captureLogs(t)

	s := &store{root: root}
	s.logSweepOutcome(atomicfile.SweepResult{}, nil)

	if logs.Len() != 0 {
		t.Errorf("logSweepOutcome(clean sweep) logged %q, want no output at all", logs.Messages())
	}
}

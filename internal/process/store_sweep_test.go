package process

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/cert-converter/internal/convert"
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
			name:        "a reclaimed orphan is reported at info",
			res:         atomicfile.SweepResult{Removed: 2},
			wantLevel:   slog.LevelInfo,
			wantMsg:     "reaped stale temp files",
			wantAttrKey: "count", wantAttrValue: "2",
		},
		{
			name:        "uninspectable candidates warn with a remediation hint",
			res:         atomicfile.SweepResult{Failed: 3},
			wantLevel:   slog.LevelWarn,
			wantMsg:     "some stale output temps could not be inspected or removed",
			wantAttrKey: "remediation",
		},
		{
			name:        "unreadable output sub-paths warn with a remediation hint",
			res:         atomicfile.SweepResult{Unreadable: 4},
			wantLevel:   slog.LevelWarn,
			wantMsg:     "some output paths could not be inspected during stale temp cleanup",
			wantAttrKey: "remediation",
		},
		{
			name:        "a failed sweep warns",
			walkErr:     errors.New("permission denied"),
			wantLevel:   slog.LevelWarn,
			wantMsg:     "stale temp cleanup failed",
			wantAttrKey: "error",
		},
		{
			name:        "a shutdown abort stays at debug",
			walkErr:     context.Canceled,
			wantLevel:   slog.LevelDebug,
			wantMsg:     "stale temp cleanup cancelled during shutdown",
			wantAttrKey: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			s := newOutputStore(t, t.TempDir())
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
// A sweep runs at most once per staleTempAge, but that is still every fallback
// tick on a long-running container, so a counter guard that also fired on zero
// would put a "count=0" info line, and for the two aggregate counters an
// operator-facing warning with a remediation hint, into the log on a perfectly
// healthy /output. Runs serially: it swaps slog.Default().
func TestStoreLogSweepOutcome_is_silent_for_a_clean_sweep(t *testing.T) {
	logs := captureLogs(t)

	s := newOutputStore(t, t.TempDir())
	s.logSweepOutcome(atomicfile.SweepResult{}, nil)

	if logs.Len() != 0 {
		t.Errorf("logSweepOutcome(clean sweep) logged %q, want no output at all", logs.Messages())
	}
}

// TestScannerRun_sweeps_stale_temps_once_per_window pins the throttle on the /output
// stale-temp sweep: a temp is only reclaimable once it is staleTempAge old, so a scan
// inside that window must not re-walk the untrusted output tree, and the first scan
// past it must sweep again.
func TestScannerRun_sweeps_stale_temps_once_per_window(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	now := time.Now()
	prev := sweepClock
	sweepClock = func() time.Time { return now }
	t.Cleanup(func() { sweepClock = prev })

	staleTemp := func(name string) string {
		t.Helper()
		p := filepath.Join(outRoot, name)
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%q): %v", p, err)
		}
		aged := time.Now().Add(-2 * staleTempAge)
		if err := os.Chtimes(p, aged, aged); err != nil {
			t.Fatalf("setup: Chtimes(%q): %v", p, err)
		}
		return p
	}

	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	})

	first := staleTemp(".atomicfile-111111.tmp")
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatalf("Run(first scan) = %v, want nil", err)
	}
	if _, err := os.Stat(first); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("os.Stat(%q) = %v, want fs.ErrNotExist: the first scan of a process has no earlier"+
			" sweep to defer to", first, err)
	}

	inWindow := staleTemp(".atomicfile-222222.tmp")
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatalf("Run(second scan inside the window) = %v, want nil", err)
	}
	if _, err := os.Stat(inWindow); err != nil {
		t.Errorf("os.Stat(%q) = %v, want nil: a scan inside staleTempAge must not sweep again",
			inWindow, err)
	}

	now = now.Add(staleTempAge)
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatalf("Run(scan past the window) = %v, want nil", err)
	}
	if _, err := os.Stat(inWindow); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("os.Stat(%q) = %v, want fs.ErrNotExist: the first scan past staleTempAge sweeps again",
			inWindow, err)
	}
}

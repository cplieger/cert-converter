package watch

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
)

// TestWatchLoop_converts_a_real_cert_write_through_the_debounce is the first
// end-to-end coverage of the select wiring itself: a real inotify Write on a
// cert file inside the watched tree must reach onChange exactly once via the
// debounce timer, and the loop must return nil when the context is cancelled.
// The per-arm helpers are unit-tested individually, but nothing pins that they
// are actually wired into the loop's select.
func TestWatchLoop_converts_a_real_cert_write_through_the_debounce(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)

	root := t.TempDir()
	scans := make(chan struct{}, 8)
	w := New(root, func(context.Context) { scans <- struct{}{} }, WithDebounce(20*time.Millisecond))
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.watchLoop(ctx, watcher) }()

	if err := os.WriteFile(filepath.Join(root, "tls.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("watchLoop never ran a scan after a cert write; the fsnotify event or the debounce arm is not wired into the select")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("watchLoop(cancelled ctx) = %v, want nil (shutdown is not lost change detection)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watchLoop did not return after ctx cancellation")
	}
}

// TestWatchLoop_returns_a_LostError_when_the_watcher_dies pins the liveness
// exit through the loop rather than through the helper: closing the watcher
// closes its Events channel under a live ctx, which must end the loop with
// a *LostError so main exits non-zero and the container restarts with a fresh
// watcher instead of running forever with no change detection.
func TestWatchLoop_returns_a_LostError_when_the_watcher_dies(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {}, WithDebounce(20*time.Millisecond))
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs = %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- w.watchLoop(t.Context(), watcher) }()

	if err := watcher.Close(); err != nil {
		t.Fatalf("watcher.Close() = %v", err)
	}

	select {
	case err := <-done:
		var lost *LostError
		if !errors.As(err, &lost) {
			t.Errorf("watchLoop(dead watcher) = %v, want a *LostError", err)
		}
		// The specific loss, not just "something died": main names it in the one
		// announcement it makes. Closing the watcher closes BOTH channels and the
		// select picks a ready case at random, so either closure arm is correct
		// here — but a neighbouring cause (the root-watch loss) is not.
		if err != error(errEventsChannelClosed) && err != error(errErrorsChannelClosed) {
			t.Errorf("watchLoop(dead watcher) = %v, want one of the channel-closure losses (%v / %v)",
				err, errEventsChannelClosed, errErrorsChannelClosed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watchLoop did not return after the watcher died; the process would keep running with no change detection")
	}
}

// TestPollLoopWithUpgrade_reports_dead_change_detection pins the one state in
// which this app could lie about being healthy.
//
// With FALLBACK_SCAN_HOURS disabling the operator's own rescan AND fsnotify
// unavailable (inotify instance exhaustion is ordinary host pressure), poll mode
// holds no watch to react to and no cadence to tick on, so nothing in this process
// notices a renewal. Parking on ctx.Done() and returning nil at shutdown would leave
// the health marker written by the initial scan standing until the probe's freshness
// deadline expires — three times the reconciliation floor at this cadence — so the
// container would report HEALTHY across that whole window while converting nothing,
// and the operator's first signal would be a downstream service serving an expired
// certificate.
//
// Returning a *LostError reaches main's existing non-zero exit path, and exiting
// promptly is what keeps recovery on a restart's timescale instead of the 24h
// reconciliation floor a watch-mode loop would wait for. That is the right answer
// here specifically BECAUSE the failure is restart-clearable — unlike a missing
// volume or a bad symlink, an exhausted inotify table usually clears — so the
// restart has a real chance of succeeding rather than looping pointlessly.
//
// It also pins how the operator learns about it: this path is the only
// operator-fixable loss, so the error it returns carries the FALLBACK_SCAN_HOURS
// remediation out to main, which announces it. This package emits no ERROR of its
// own — that would be a second announcement of one event.
// Serial (no t.Parallel): it swaps the process-global slog default.
func TestPollLoopWithUpgrade_reports_dead_change_detection(t *testing.T) {
	// onChange is a required dependency, so it is wired even here: poll mode runs
	// one scan before deciding change detection is dead, and converting whatever is
	// already on disk is the only useful work this process can do before exiting for
	// a restart.
	scanned := make(chan struct{}, 1)
	// No WithFallback, i.e. FALLBACK_SCAN_HOURS=0/false.
	w := New(t.TempDir(), func(context.Context) { scanned <- struct{}{} })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	logs := capture.Default(t)

	done := runPollLoop(ctx, w)

	select {
	case res := <-done:
		if res.upgraded != nil {
			res.upgraded.Close()
			t.Error("pollLoopWithUpgrade(no fallback, no fsnotify) handed back a watcher, want none")
		}
		var lost *LostError
		if !errors.As(res.err, &lost) {
			t.Fatalf("pollLoopWithUpgrade(no fallback, no fsnotify) = %v, want a *LostError so main can reach the remediation", res.err)
		}
		if !strings.Contains(lost.Remediation, "FALLBACK_SCAN_HOURS") {
			t.Errorf("remediation = %q, want it to name FALLBACK_SCAN_HOURS: this is the one lost-detection cause an operator can fix, and the hint must survive the trip to main",
				lost.Remediation)
		}
	case <-time.After(2 * time.Second):
		// The defect was precisely that this call never returns.
		t.Fatal("pollLoopWithUpgrade did not return; it parked on ctx.Done() with change detection dead, which is what let the container report healthy forever")
	}

	select {
	case <-scanned:
	default:
		t.Error("pollLoopWithUpgrade exited without scanning; main no longer scans before Run, so this is the only conversion the process would perform")
	}
	if n := logs.CountLevel(slog.LevelError, ""); n != 0 {
		t.Errorf("pollLoopWithUpgrade logged %d ERROR records %v, want 0: main states the conclusion once, and a record here makes it twice",
			n, logs.Messages())
	}
}

func TestRun_falls_back_to_polling_when_the_watch_set_cannot_be_built(t *testing.T) {
	t.Parallel()
	scans := 0
	missingRoot := filepath.Join(t.TempDir(), "missing")
	// No WithFallback: poll mode then has no interval, so it scans once and returns
	// a *LostError -- an outcome reachable only through the poll fallback.
	w := New(missingRoot, func(context.Context) { scans++ })

	err := w.Run(t.Context())

	var lost *LostError
	if !errors.As(err, &lost) {
		t.Errorf("Run(unwatchable root) = %v, want a *LostError via the poll fallback: an unwatchable /input must degrade to polling, not abort the watcher", err)
	}
	if scans != 1 {
		t.Errorf("Run(unwatchable root) ran %d scans, want 1: poll mode must still convert what is already on disk", scans)
	}
}

func TestWatchLoop_runs_the_periodic_fallback_scan_without_any_event(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	scans := make(chan struct{}, 8)
	// A one-hour debounce: nothing is written under root, and even a stray event
	// could not produce a scan on this timescale, so the scan below can only come
	// from the fallback arm.
	w := New(root, func(context.Context) { scans <- struct{}{} },
		WithDebounce(time.Hour), WithFallback(20*time.Millisecond))
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.watchLoop(ctx, watcher) }()

	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("watchLoop never ran the periodic fallback scan; the safety net that covers network mounts and missed fsnotify events is not wired into the select")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("watchLoop(cancelled ctx) = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watchLoop did not return after ctx cancellation")
	}
}

// TestWatchLoop_reports_lost_change_detection_when_the_root_watch_disappears
// pins handleRootWatchLoss's terminal branch: with the periodic rescan disabled, losing the watch on
// the root itself is unrecoverable in-process (no Create can announce a
// replacement, and both fsnotify channels stay open), so the loop must exit with
// a *LostError for a restart rather than schedule a rescan — reporting the
// root-watch loss specifically, and announcing nothing itself (main owns the
// single ERROR).
// Serial (no t.Parallel): it swaps the process-global slog default.
func TestWatchLoop_reports_lost_change_detection_when_the_root_watch_disappears(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "input")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	watcher := newTestWatcher(t)
	// No WithFallback: the disabled-rescan configuration is the only one where
	// root loss is terminal.
	w := New(root, func(context.Context) {})
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("addWatchDirs: %v", err)
	}
	logs := capture.Default(t)

	done := make(chan error, 1)
	go func() { done <- w.watchLoop(t.Context(), watcher) }()

	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var lost *LostError
		if !errors.As(err, &lost) {
			t.Errorf("watchLoop(root removed, fallback disabled) = %v, want a *LostError", err)
		}
		if err != error(errRootWatchRemoved) {
			t.Errorf("watchLoop(root removed, fallback disabled) = %v, want the root-watch-removed loss (%v)", err, errRootWatchRemoved)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watchLoop did not return after the root watch was removed")
	}
	if n := logs.CountLevel(slog.LevelError, ""); n != 0 {
		t.Errorf("watchLoop(root removed) logged %d ERROR records %v, want 0: main states the conclusion once, and a record here makes it twice",
			n, logs.Messages())
	}
}

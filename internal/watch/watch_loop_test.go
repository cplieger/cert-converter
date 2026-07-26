package watch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

	ctx, cancel := context.WithCancel(context.Background())
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

// TestWatchLoop_returns_ErrWatchLost_when_the_watcher_dies pins the liveness
// exit through the loop rather than through the helper: closing the watcher
// closes its Events channel under a live ctx, which must end the loop with
// ErrWatchLost so main exits non-zero and the container restarts with a fresh
// watcher instead of running forever with no change detection.
func TestWatchLoop_returns_ErrWatchLost_when_the_watcher_dies(t *testing.T) {
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
		if !errors.Is(err, ErrWatchLost) {
			t.Errorf("watchLoop(dead watcher) = %v, want ErrWatchLost", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watchLoop did not return after the watcher died; the process would keep running with no change detection")
	}
}

// TestPollLoopWithUpgrade_reports_dead_change_detection pins the fix for the one
// state in which this app could lie about being healthy.
//
// With FALLBACK_SCAN_HOURS disabling the periodic rescan AND fsnotify unavailable
// (inotify instance exhaustion is ordinary host pressure), there is no mechanism
// left that can ever notice a renewal. The loop used to log once and park on
// ctx.Done(), returning nil at shutdown. Because the initial scan had already
// written the health marker, and because disabling the fallback also disarms the
// probe's freshness deadline, nothing contradicted it: the container reported
// HEALTHY indefinitely while converting nothing, and the operator's first signal
// was a downstream service serving an expired certificate.
//
// Returning ErrWatchLost reaches main's existing non-zero exit path. That is the
// right answer here specifically BECAUSE the failure is restart-clearable — unlike
// a missing volume or a bad symlink, an exhausted inotify table usually clears — so
// the restart has a real chance of succeeding rather than looping pointlessly.
func TestPollLoopWithUpgrade_reports_dead_change_detection(t *testing.T) {
	t.Parallel()

	// onChange is a required dependency, so it is wired even here: poll mode now runs
	// one scan before deciding change detection is dead (deferred finding d-u5c6-1),
	// and converting whatever is already on disk is the only useful work this process
	// can do before exiting for a restart.
	scanned := make(chan struct{}, 1)
	w := &Watcher{ // FALLBACK_SCAN_HOURS=0/false
		fallback: 0,
		onChange: func(context.Context) { scanned <- struct{}{} },
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.pollLoopWithUpgrade(ctx) }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrWatchLost) {
			t.Errorf("pollLoopWithUpgrade(no fallback, no fsnotify) = %v, want ErrWatchLost", err)
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
}

func TestRun_falls_back_to_polling_when_the_watch_set_cannot_be_built(t *testing.T) {
	t.Parallel()
	scans := 0
	missingRoot := filepath.Join(t.TempDir(), "missing")
	// No WithFallback: poll mode then has no interval, so it scans once and returns
	// ErrWatchLost -- an outcome reachable only through the poll fallback.
	w := New(missingRoot, func(context.Context) { scans++ })

	err := w.Run(t.Context())

	if !errors.Is(err, ErrWatchLost) {
		t.Errorf("Run(unwatchable root) = %v, want ErrWatchLost via the poll fallback: an unwatchable /input must degrade to polling, not abort the watcher", err)
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

	ctx, cancel := context.WithCancel(context.Background())
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
// pins the h-f10 branch: with the periodic rescan disabled, losing the watch on
// the root itself is unrecoverable in-process (no Create can announce a
// replacement, and both fsnotify channels stay open), so the loop must exit with
// ErrWatchLost for a restart rather than schedule a rescan.
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

	done := make(chan error, 1)
	go func() { done <- w.watchLoop(t.Context(), watcher) }()

	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrWatchLost) {
			t.Errorf("watchLoop(root removed, fallback disabled) = %v, want ErrWatchLost", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watchLoop did not return after the root watch was removed")
	}
}

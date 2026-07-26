package watch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
	"github.com/fsnotify/fsnotify"
)

// TestPollLoopWithUpgrade_upgrades_to_fsnotify_and_scans_first pins the poll
// mode recovery path: on a tick where fsnotify becomes available again the
// watch set is rebuilt, a scan runs with it already live (attach-then-scan, so a
// renewal during the scan still produces an event), and control hands off to the
// watch loop, which returns nil on shutdown. Runs serially (no t.Parallel): it
// swaps the process-global slog default to read the upgrade log line.
func TestPollLoopWithUpgrade_upgrades_to_fsnotify_and_scans_first(t *testing.T) {
	logs := capture.Default(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}
	scans := make(chan struct{}, 8)
	w := New(root, func(context.Context) { scans <- struct{}{} },
		WithDebounce(20*time.Millisecond), WithFallback(20*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.pollLoopWithUpgrade(ctx) }()

	// The immediate initial scan, which poll mode now performs before entering the
	// ticker loop (deferred finding d-u5c6-1). It arrives before any tick, so it must
	// be consumed here or it would be mistaken for the upgrade's scan below.
	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("pollLoopWithUpgrade never ran its initial scan")
	}

	// Wait for the upgrade itself rather than inferring it from a scan: the poll tick
	// and the watch loop's fallback tick both scan on the same 20ms interval, so a
	// build that never upgraded would keep feeding the scans channel forever. Only
	// the upgrade branch logs this, and it logs it before handing off to watchLoop.
	deadline := time.Now().Add(10 * time.Second)
	for !logs.Contains("fsnotify recovered, upgrading from poll to watch") {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("pollLoopWithUpgrade never upgraded; log = %v", logs.Messages())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The upgrade handed off to watchLoop, so a real cert write is now detected
	// as an event rather than waiting for the next poll tick.
	if err := os.WriteFile(filepath.Join(root, "example.com", "tls.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("no scan after a cert write; pollLoopWithUpgrade did not hand off to the watch loop")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("pollLoopWithUpgrade(cancelled ctx) = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pollLoopWithUpgrade did not return after ctx cancellation")
	}
}

// TestPollTick_stays_in_poll_mode_when_watch_set_rebuild_fails pins the poll
// tick's independently reachable middle branch: fsnotify constructs fine but the
// watch set cannot be rebuilt (a missing root), so the tick must stay in poll
// mode (done=false) and still run the safety-net scan that keeps change
// detection alive.
func TestPollTick_stays_in_poll_mode_when_watch_set_rebuild_fails(t *testing.T) {
	t.Parallel()
	// Availability probe only: skips on hosts without inotify so this test cannot
	// pass through pollTick's NewWatcher-failure branch instead of the rebuild one.
	newTestWatcher(t)
	scans := 0
	missingRoot := filepath.Join(t.TempDir(), "missing")
	w := New(missingRoot, func(context.Context) { scans++ }, WithFallback(time.Hour))

	done, err := w.pollTick(t.Context())
	if err != nil {
		t.Errorf("pollTick(missing root) error = %v, want nil", err)
	}
	if done {
		t.Error("pollTick(missing root) done = true, want false so polling continues")
	}
	if scans != 1 {
		t.Errorf("pollTick(missing root) ran %d scans, want 1", scans)
	}
}

// TestPollLoopWithUpgrade_treats_shutdown_before_the_first_scan_as_a_clean_stop
// pins the ctx guard that opens pollLoopWithUpgrade: a shutdown arriving before
// the initial scan outranks the dead-change-detection exit.
func TestPollLoopWithUpgrade_treats_shutdown_before_the_first_scan_as_a_clean_stop(t *testing.T) {
	t.Parallel()
	scans := 0
	// No WithFallback, i.e. the dead-change-detection configuration: a live ctx
	// here returns ErrWatchLost, so this pins that shutdown outranks that exit.
	w := New(t.TempDir(), func(context.Context) { scans++ })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := w.pollLoopWithUpgrade(ctx); err != nil {
		t.Errorf("pollLoopWithUpgrade(cancelled ctx) = %v, want nil: a SIGTERM must not exit 1 claiming change detection is dead", err)
	}
	if scans != 0 {
		t.Errorf("pollLoopWithUpgrade(cancelled ctx) ran %d scans, want 0: a shutdown must not start a scan that still drives the health marker", scans)
	}
}

// TestPollTick_treats_shutdown_during_the_watch_set_rebuild_as_a_stop pins the
// ctx check inside pollTick's rebuild-failure branch: a shutdown mid-walk stops
// the poll loop instead of logging a degraded upgrade failure and scanning again.
func TestPollTick_treats_shutdown_during_the_watch_set_rebuild_as_a_stop(t *testing.T) {
	t.Parallel()
	// Availability probe only: skips on hosts without inotify, so this test cannot
	// pass through pollTick's NewWatcher-failure branch instead of the rebuild one.
	newTestWatcher(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}
	scans := 0
	w := New(root, func(context.Context) { scans++ }, WithFallback(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done, err := w.pollTick(ctx)
	if err != nil {
		t.Errorf("pollTick(cancelled ctx) error = %v, want nil (a shutdown mid-walk is not an upgrade failure)", err)
	}
	if !done {
		t.Error("pollTick(cancelled ctx) done = false, want true so the poll loop returns instead of logging a degraded upgrade failure")
	}
	if scans != 0 {
		t.Errorf("pollTick(cancelled ctx) ran %d scans, want 0: a shutdown must not start a scan that still drives the health marker", scans)
	}
}

// TestRun_falls_back_to_polling_when_fsnotify_is_unavailable drives the seam
// l-f46 exists for: with the constructor failing, Run must degrade to polling
// rather than abort, which is unreachable on a host where inotify works.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestRun_falls_back_to_polling_when_fsnotify_is_unavailable(t *testing.T) {
	prev := newFSWatcher
	newFSWatcher = func() (*fsnotify.Watcher, error) { return nil, errors.New("inotify exhausted") }
	t.Cleanup(func() { newFSWatcher = prev })

	scans := 0
	// No WithFallback: poll mode then has no interval, so Run scans once and
	// returns ErrWatchLost -- reachable only through the unavailable-fsnotify
	// dispatch.
	w := New(t.TempDir(), func(context.Context) { scans++ })

	if err := w.Run(t.Context()); !errors.Is(err, ErrWatchLost) {
		t.Errorf("Run(fsnotify unavailable, no fallback) = %v, want ErrWatchLost", err)
	}
	if scans != 1 {
		t.Errorf("Run(fsnotify unavailable) ran %d scans, want 1: poll mode must still convert what is already on disk", scans)
	}
}

// TestRun_treats_shutdown_during_fsnotify_construction_failure_as_a_clean_stop
// pins the cancellation precedence in Run's constructor-failure branch: the
// sibling addWatchDirs branch is already pinned for shutdown, and this one must
// behave the same way. Without the guard a SIGTERM arriving while inotify is
// exhausted enters poll mode, reports ErrWatchLost, and turns a graceful stop
// into exit 1 with the critical dead-change-detection alert.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestRun_treats_shutdown_during_fsnotify_construction_failure_as_a_clean_stop(t *testing.T) {
	prev := newFSWatcher
	newFSWatcher = func() (*fsnotify.Watcher, error) { return nil, errors.New("inotify exhausted") }
	t.Cleanup(func() { newFSWatcher = prev })

	scans := 0
	w := New(t.TempDir(), func(context.Context) { scans++ })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := w.Run(ctx); err != nil {
		t.Errorf("Run(cancelled ctx, fsnotify unavailable) = %v, want nil", err)
	}
	if scans != 0 {
		t.Errorf("Run(cancelled ctx, fsnotify unavailable) ran %d scans, want 0", scans)
	}
}

// TestPollTick_stays_in_poll_mode_when_fsnotify_remains_unavailable pins the
// third of pollTick's arms, the one the newFSWatcher seam exists for: with the
// constructor still failing, the tick must stay in poll mode (done=false) and
// still run the polling scan that is then the only live change detection.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestPollTick_stays_in_poll_mode_when_fsnotify_remains_unavailable(t *testing.T) {
	prev := newFSWatcher
	newFSWatcher = func() (*fsnotify.Watcher, error) { return nil, errors.New("inotify exhausted") }
	t.Cleanup(func() { newFSWatcher = prev })

	scans := 0
	w := New(t.TempDir(), func(context.Context) { scans++ }, WithFallback(time.Hour))

	done, err := w.pollTick(t.Context())
	if err != nil {
		t.Errorf("pollTick(fsnotify unavailable) error = %v, want nil", err)
	}
	if done {
		t.Error("pollTick(fsnotify unavailable) done = true, want false so polling continues")
	}
	if scans != 1 {
		t.Errorf("pollTick(fsnotify unavailable) ran %d scans, want 1", scans)
	}
}

// TestPollTick_treats_shutdown_during_fsnotify_retry_as_a_stop pins the
// cancellation precedence of the same arm: a shutdown arriving during the retry
// must stop the poll loop (done=true) without a scan that would still drive the
// health marker on the way out.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestPollTick_treats_shutdown_during_fsnotify_retry_as_a_stop(t *testing.T) {
	prev := newFSWatcher
	newFSWatcher = func() (*fsnotify.Watcher, error) { return nil, errors.New("inotify exhausted") }
	t.Cleanup(func() { newFSWatcher = prev })

	scans := 0
	w := New(t.TempDir(), func(context.Context) { scans++ }, WithFallback(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done, err := w.pollTick(ctx)
	if err != nil {
		t.Errorf("pollTick(cancelled ctx, fsnotify unavailable) error = %v, want nil", err)
	}
	if !done {
		t.Error("pollTick(cancelled ctx, fsnotify unavailable) done = false, want true so polling stops")
	}
	if scans != 0 {
		t.Errorf("pollTick(cancelled ctx, fsnotify unavailable) ran %d scans, want 0", scans)
	}
}

// TestPollLoopWithUpgrade_treats_shutdown_during_the_initial_scan_as_a_clean_stop
// pins the ctx guard AFTER the initial scan, distinct from the one before it: a
// SIGTERM arriving while that scan runs is still a clean stop. A callback that
// cancels the context models the race deterministically, with no sleeps. Without
// the guard the disabled-fallback path returns ErrWatchLost and main emits the
// false critical change-detection-dead alert on a graceful stop.
func TestPollLoopWithUpgrade_treats_shutdown_during_the_initial_scan_as_a_clean_stop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	scans := 0
	// No WithFallback: the dead-change-detection configuration, where a live ctx
	// after the initial scan returns ErrWatchLost.
	w := New(t.TempDir(), func(context.Context) {
		scans++
		cancel()
	})

	if err := w.pollLoopWithUpgrade(ctx); err != nil {
		t.Errorf("pollLoopWithUpgrade(ctx cancelled during initial scan) = %v, want nil", err)
	}
	if scans != 1 {
		t.Errorf("pollLoopWithUpgrade(ctx cancelled during initial scan) ran %d scans, want 1", scans)
	}
}

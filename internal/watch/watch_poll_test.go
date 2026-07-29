package watch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
	"github.com/fsnotify/fsnotify"
)

// stubFSWatcherUnavailable makes the newFSWatcher seam fail for the duration of
// the test, which is how these tests reach the fsnotify-unavailable dispatch on a
// host where inotify works. A caller must not call t.Parallel: the seam is
// package-level state.
func stubFSWatcherUnavailable(t *testing.T) {
	t.Helper()
	prev := newFSWatcher
	newFSWatcher = func() (*fsnotify.Watcher, error) { return nil, errors.New("inotify exhausted") }
	t.Cleanup(func() { newFSWatcher = prev })
}

// pollResult is one pollLoopWithUpgrade return carried across a goroutine
// boundary: the upgraded watcher (nil unless poll mode handed watch mode over)
// and the mode's terminal error.
type pollResult struct {
	upgraded *fsnotify.Watcher
	err      error
}

// runPollLoop runs poll mode in a goroutine and reports its whole return pair.
// The caller owns any watcher it receives (watchMode is what closes one in
// production), so a test that gets one must close it.
func runPollLoop(ctx context.Context, w *Watcher) <-chan pollResult {
	out := make(chan pollResult, 1)
	go func() {
		fw, err := w.pollLoopWithUpgrade(ctx)
		out <- pollResult{upgraded: fw, err: err}
	}()
	return out
}

// stubFSWatcherFailingOnce fails the FIRST newFSWatcher call and constructs a
// real watcher on every later one, which is how a test drives the whole
// poll-to-watch upgrade on a host where inotify works: Run's initial attach
// selects poll mode, and the first poll tick upgrades out of it. A caller must
// not call t.Parallel: the seam is package-level state.
func stubFSWatcherFailingOnce(t *testing.T) {
	t.Helper()
	prev := newFSWatcher
	var mu sync.Mutex
	failed := false
	newFSWatcher = func() (*fsnotify.Watcher, error) {
		mu.Lock()
		defer mu.Unlock()
		if !failed {
			failed = true
			return nil, errors.New("inotify exhausted")
		}
		return prev()
	}
	t.Cleanup(func() { newFSWatcher = prev })
}

// TestPollLoopWithUpgrade_hands_the_upgraded_watcher_back_without_scanning
// pins ownership transfer and the no-duplicate-scan handoff. Poll mode has ONE
// exit: on the tick where fsnotify becomes available again it rebuilds the watch
// set and returns the watcher for Run to run watch mode over, while ctx is still
// live. Because that is a return and not a nested call, the poll loop cannot run
// another scan after the handoff.
//
// The assertions pin that single exit, that the watcher handed back is the
// attached one rather than a bare constructor result, and that the upgrade tick
// itself performs no scan: the post-attach scan belongs to watch mode's
// attach-then-scan sequence.
//
// Runs serially (no t.Parallel): it swaps the process-global slog default.
func TestPollLoopWithUpgrade_hands_the_upgraded_watcher_back_without_scanning(t *testing.T) {
	logs := capture.Default(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}
	scans := make(chan struct{}, 8)
	w := New(root, func(context.Context) { scans <- struct{}{} },
		WithDebounce(20*time.Millisecond), WithFallback(20*time.Millisecond))

	ctx := t.Context()
	done := runPollLoop(ctx, w)

	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		t.Fatal("pollLoopWithUpgrade never ran its initial scan")
	}

	var res pollResult
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("pollLoopWithUpgrade did not return after fsnotify became available; poll mode must hand the watcher back instead of running watch mode inside its own tick")
	}
	if res.upgraded == nil {
		t.Fatalf("pollLoopWithUpgrade returned no watcher (err = %v); watch mode has nothing to run", res.err)
	}
	defer res.upgraded.Close()

	if res.err != nil {
		t.Errorf("pollLoopWithUpgrade(upgrade) err = %v, want nil", res.err)
	}
	if ctx.Err() != nil {
		t.Error("pollLoopWithUpgrade only returned once ctx was cancelled; the upgrade must end poll mode while the process is still live")
	}
	if !slices.Contains(res.upgraded.WatchList(), root) {
		t.Errorf("pollLoopWithUpgrade handed back a watcher watching %v, want the rebuilt watch set including %s", res.upgraded.WatchList(), root)
	}
	if !logs.Contains("fsnotify recovered, upgrading from poll to watch") {
		t.Errorf("upgrade log missing; log = %v", logs.Messages())
	}
	if n := len(scans); n != 0 {
		t.Errorf("upgrade tick ran %d scans, want 0: the post-attach scan belongs to watch mode", n)
	}
	if n := logs.Count("poll tick"); n != 1 {
		t.Errorf("poll mode logged %d poll ticks, want exactly the one that upgraded; log = %v", n, logs.Messages())
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

	if fw, err := w.pollLoopWithUpgrade(ctx); err != nil {
		if fw != nil {
			fw.Close()
		}
		t.Errorf("pollLoopWithUpgrade(cancelled ctx) = %v, want nil: a SIGTERM must not exit 1 claiming change detection is dead", err)
	} else if fw != nil {
		fw.Close()
		t.Error("pollLoopWithUpgrade(cancelled ctx) handed back a watcher, want none: a shutdown must not start watch mode")
	}
	if scans != 0 {
		t.Errorf("pollLoopWithUpgrade(cancelled ctx) ran %d scans, want 0: a shutdown must not start a scan that still drives the health marker", scans)
	}
}

// TestPollTick_treats_shutdown_during_the_watch_set_rebuild_as_a_stop pins the
// ctx check inside pollTick's rebuild-failure branch: a shutdown mid-walk stops
// the poll loop instead of logging a degraded upgrade failure and scanning again.
//
// The ctx must be LIVE when pollTick is entered, or its entry guard answers first
// and this branch is never reached. The seam hands back a real watcher and cancels
// on the way out, so the shutdown lands while the watch-set walk is running — the
// same deterministic-race trick
// TestPollLoopWithUpgrade_returns_when_a_shutdown_interrupts_a_poll_tick uses for
// the constructor arm.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestPollTick_treats_shutdown_during_the_watch_set_rebuild_as_a_stop(t *testing.T) {
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
	defer cancel()
	prev := newFSWatcher
	t.Cleanup(func() { newFSWatcher = prev })
	newFSWatcher = func() (*fsnotify.Watcher, error) {
		fw, err := prev()
		cancel() // the shutdown lands after the upgrade, while the walk is running
		return fw, err
	}

	upgraded, stopped := w.pollTick(ctx)
	if upgraded != nil {
		upgraded.Close()
		t.Error("pollTick(cancelled ctx) handed back a watcher, want none: a shutdown mid-walk must not start watch mode")
	}
	if !stopped {
		t.Error("pollTick(cancelled ctx) stopped = false, want true so the poll loop returns instead of logging a degraded upgrade failure")
	}
	if scans != 0 {
		t.Errorf("pollTick(cancelled ctx) ran %d scans, want 0: a shutdown must not start a scan that still drives the health marker", scans)
	}
}

// TestPollLoopWithUpgrade_returns_when_a_shutdown_interrupts_a_poll_tick pins
// the loop's handling of poll mode's third tick outcome, the one that is neither
// "stay in poll" nor "upgrade": a shutdown that lands while the tick is
// attempting the upgrade must end poll mode then and there, rather than looping
// back for another tick's worth of scanning on the way out. The per-tick
// contract is pinned directly by the pollTick tests above; this pins that the
// loop acts on it.
//
// The seam cancels the context and then fails, which is exactly the race the
// guard exists for, made deterministic.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestPollLoopWithUpgrade_returns_when_a_shutdown_interrupts_a_poll_tick(t *testing.T) {
	prev := newFSWatcher
	t.Cleanup(func() { newFSWatcher = prev })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newFSWatcher = func() (*fsnotify.Watcher, error) {
		cancel() // the shutdown lands during the tick's upgrade attempt
		return nil, errors.New("inotify exhausted")
	}

	scans := 0
	w := New(t.TempDir(), func(context.Context) { scans++ }, WithFallback(20*time.Millisecond))

	fw, err := w.pollLoopWithUpgrade(ctx)

	if fw != nil {
		fw.Close()
		t.Error("pollLoopWithUpgrade(shutdown during a tick) handed back a watcher, want none")
	}
	if err != nil {
		t.Errorf("pollLoopWithUpgrade(shutdown during a tick) = %v, want nil: a SIGTERM is a clean stop", err)
	}
	if scans != 1 {
		t.Errorf("pollLoopWithUpgrade(shutdown during a tick) ran %d scans, want 1 (the initial one): a shutdown must not start another poll scan that still drives the health marker", scans)
	}
}

// TestRun_falls_back_to_polling_when_fsnotify_is_unavailable drives the
// newFSWatcher seam: with the constructor failing, Run must degrade to polling
// rather than abort, which is unreachable on a host where inotify works.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestRun_falls_back_to_polling_when_fsnotify_is_unavailable(t *testing.T) {
	stubFSWatcherUnavailable(t)

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
	stubFSWatcherUnavailable(t)

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
// constructor still failing, the tick must stay in poll mode (stopped=false) and
// still run the polling scan that is then the only live change detection.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestPollTick_stays_in_poll_mode_when_fsnotify_remains_unavailable(t *testing.T) {
	stubFSWatcherUnavailable(t)

	scans := 0
	w := New(t.TempDir(), func(context.Context) { scans++ }, WithFallback(time.Hour))

	upgraded, stopped := w.pollTick(t.Context())
	if upgraded != nil {
		upgraded.Close()
		t.Error("pollTick(fsnotify unavailable) handed back a watcher, want none")
	}
	if stopped {
		t.Error("pollTick(fsnotify unavailable) stopped = true, want false so polling continues")
	}
	if scans != 1 {
		t.Errorf("pollTick(fsnotify unavailable) ran %d scans, want 1", scans)
	}
}

// TestPollTick_does_no_work_when_the_ctx_is_already_cancelled pins pollTick's
// cancelled-tick contract: a tick that fires in the same instant as a shutdown must
// attempt no upgrade and run no scan (which would still drive the health marker), and
// must report stopped=true so the poll loop returns. fsnotify is stubbed UNAVAILABLE so
// the tick runs its cheapest failure path. The composite contract (no scan,
// stopped=true) is also satisfied by the retry arm's own ctx check, which keeps those
// assertions green even with the entry guard deleted; the guard's own effect is that a
// cancelled tick announces no work at all, so the "poll tick" Debug record
// is what actually pins it and is asserted here.
//
// The mid-attempt arms are pinned separately — the rebuild branch by
// TestPollTick_treats_shutdown_during_the_watch_set_rebuild_as_a_stop above, the
// constructor branch by
// TestPollLoopWithUpgrade_returns_when_a_shutdown_interrupts_a_poll_tick.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestPollTick_does_no_work_when_the_ctx_is_already_cancelled(t *testing.T) {
	stubFSWatcherUnavailable(t)
	logs := capture.Default(t)

	scans := 0
	w := New(t.TempDir(), func(context.Context) { scans++ }, WithFallback(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	upgraded, stopped := w.pollTick(ctx)
	if upgraded != nil {
		upgraded.Close()
		t.Error("pollTick(cancelled ctx, fsnotify unavailable) handed back a watcher, want none")
	}
	if !stopped {
		t.Error("pollTick(cancelled ctx, fsnotify unavailable) stopped = false, want true so polling stops")
	}
	if scans != 0 {
		t.Errorf("pollTick(cancelled ctx, fsnotify unavailable) ran %d scans, want 0", scans)
	}
	// The entry guard's own effect: a cancelled tick announces no work at all. The
	// retry arm's ctx check keeps every assertion above green even with the guard
	// deleted, so this record is what actually pins it.
	if n := logs.Count("poll tick"); n != 0 {
		t.Errorf("pollTick(cancelled ctx) logged %d %q records, want 0: the entry guard must return before announcing a tick it never runs; log = %v",
			n, "poll tick", logs.Messages())
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

	if fw, err := w.pollLoopWithUpgrade(ctx); err != nil {
		if fw != nil {
			fw.Close()
		}
		t.Errorf("pollLoopWithUpgrade(ctx cancelled during initial scan) = %v, want nil", err)
	} else if fw != nil {
		fw.Close()
		t.Error("pollLoopWithUpgrade(ctx cancelled during initial scan) handed back a watcher, want none")
	}
	if scans != 1 {
		t.Errorf("pollLoopWithUpgrade(ctx cancelled during initial scan) ran %d scans, want 1", scans)
	}
}

// TestPollLoopWithUpgrade_returns_on_shutdown_while_polling pins that poll mode
// is interruptible at all. Every other shutdown test on this path returns before
// the ticker loop is entered (the pre-scan guard, the during-scan guard, the
// disabled-fallback exit) or leaves through the upgraded watch loop, so nothing
// pinned the loop's own ctx.Done() arm: with it broken a SIGTERM in the degraded
// mode would block until the next poll tick -- six hours on the documented
// cadence -- and the container would be SIGKILLed on every stop.
//
// A one-hour poll interval means no tick can fire, so the ctx.Done() arm is the
// only way out; the fsnotify seam keeps the loop in poll mode instead of
// upgrading away from it.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestPollLoopWithUpgrade_returns_on_shutdown_while_polling(t *testing.T) {
	stubFSWatcherUnavailable(t)

	scans := make(chan struct{}, 4)
	w := New(t.TempDir(), func(context.Context) { scans <- struct{}{} }, WithFallback(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	done := runPollLoop(ctx, w)

	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("poll mode never ran its initial scan")
	}

	cancel()
	select {
	case res := <-done:
		if res.upgraded != nil {
			res.upgraded.Close()
			t.Error("pollLoopWithUpgrade(cancelled while polling) handed back a watcher, want none")
		}
		if res.err != nil {
			t.Errorf("pollLoopWithUpgrade(cancelled while polling) = %v, want nil", res.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pollLoopWithUpgrade did not return after cancellation; a SIGTERM in poll mode would block until the next poll tick and the container would be SIGKILLed on every stop")
	}
	if len(scans) != 0 {
		t.Errorf("pollLoopWithUpgrade ran %d extra scans after cancellation, want none", len(scans))
	}
}

// TestPollTick_closes_the_watcher_it_could_not_give_a_watch_set pins the resource
// release of the poll tick's rebuild-failure branch: a watcher that was
// constructed but could not be given a watch set is closed before the tick stays
// in poll mode. Poll mode re-attempts the upgrade on EVERY fallback tick for as
// long as the degradation lasts, so a watcher left open here leaks an fd and a
// readEvents goroutine per tick -- one every six hours on the documented cadence
// -- and nothing else in the suite would notice.
//
// The seam hands out real watchers and records the one the tick discards, which is
// the only way to observe a watcher the production path never returns; a closed
// watcher refuses Add, exactly as watchMode's close is asserted.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestPollTick_closes_the_watcher_it_could_not_give_a_watch_set(t *testing.T) {
	newTestWatcher(t) // availability probe: skips where inotify is unavailable
	prev := newFSWatcher
	var made *fsnotify.Watcher
	newFSWatcher = func() (*fsnotify.Watcher, error) {
		fw, err := prev()
		made = fw
		return fw, err
	}
	t.Cleanup(func() {
		newFSWatcher = prev
		if made != nil {
			_ = made.Close() // a watcher the tick leaked must not outlive the test
		}
	})
	missingRoot := filepath.Join(t.TempDir(), "missing")
	scans := 0
	w := New(missingRoot, func(context.Context) { scans++ }, WithFallback(time.Hour))

	upgraded, stopped := w.pollTick(t.Context())

	if scans != 1 {
		t.Errorf("pollTick(missing root) ran %d scans, want 1: the tick must still run the safety-net scan that keeps change detection alive", scans)
	}
	if upgraded != nil {
		upgraded.Close()
		t.Fatal("pollTick(missing root) handed back a watcher, want none")
	}
	if stopped {
		t.Fatal("pollTick(missing root) stopped = true, want false so polling continues")
	}
	if made == nil {
		t.Fatal("pollTick constructed no watcher; the rebuild-failure branch was not reached")
	}
	if err := made.Add(t.TempDir()); err == nil {
		t.Error("pollTick left the unattachable watcher open; its fd and readEvents goroutine leak on every poll tick for as long as the degradation lasts")
	}
}

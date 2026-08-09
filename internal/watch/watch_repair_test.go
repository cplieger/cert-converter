package watch

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// TestWatchLoop_runs_the_repair_the_reassert_floor_deferred pins the whole
// deferred-repair contract end to end, through the loop's own select.
//
// The floor (minPreScanResync) exists so a writer to /input cannot drive a
// whole-tree re-assert per event, and that half is pinned by
// TestRunDebouncedScan_floors_the_reassert_cadence. What this pins is the other
// half: the repair the floor declines to run NOW must still run LATER. Dropping
// it means a registration the kernel discarded without an event (IN_UNMOUNT /
// IN_IGNORED, which fsnotify consumes silently) stays out of the watch set until
// something else happens to re-assert -- and with FALLBACK_SCAN_HOURS=0 that used
// to mean the reconciliation floor at the earliest, or never before this change.
//
// The oracle is a registration removed straight on the watcher between two
// debounced scans. The second scan is placed inside the floor without a timing
// window, then the already-armed repair timer is moved to its deadline. That keeps
// this test focused on the loop's select arm; TestScheduleRepair_arms_for_the_
// remainder_of_the_floor owns the timer arithmetic.
func TestWatchLoop_runs_the_repair_the_reassert_floor_deferred(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	dir := filepath.Join(root, "example.com")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	scans := make(chan struct{}, 8)
	// A one-hour debounce and safety net: no event is written under root, and
	// neither timer can fire on this timescale, so the only clock that can restore
	// the watch below is the deferred repair.
	w := New(root, func(context.Context) { scans <- struct{}{} },
		WithDebounce(time.Hour), WithFallback(time.Hour))
	st := newWatchState(w)
	t.Cleanup(st.stop)

	st.runDebouncedScan(t.Context(), watcher)
	if !slices.Contains(watcher.WatchList(), dir) {
		t.Fatalf("watch list after the first debounced scan = %v, want %q: the first scan of a run must re-assert the set", watcher.WatchList(), dir)
	}

	// The kernel-silent drop: fsnotify consumes the IN_IGNORED, so no event
	// announces it and the mirror still claims the directory is watched.
	if err := watcher.Remove(dir); err != nil {
		t.Fatalf("setup: watcher.Remove(%q) = %v, want nil", dir, err)
	}
	// Put the second scan unambiguously inside the floor. No scheduler delay can
	// turn this setup into the past-floor branch before the assertion runs.
	st.lastResync = time.Now()

	st.runDebouncedScan(t.Context(), watcher)

	if watched := watcher.WatchList(); slices.Contains(watched, dir) {
		t.Fatalf("watch list right after a scan inside the %v floor = %v, want %q still dropped: the floor must keep the whole-tree walk off the writer's event cadence",
			minPreScanResync, watched, dir)
	}

	if !st.repairPending {
		t.Fatal("the scan inside the floor left no repair pending")
	}
	// Timer arithmetic is covered separately. Move this positioned state directly
	// to the deadline so this integration test never sleeps for the floor.
	st.lastResync = time.Now().Add(-minPreScanResync)
	st.repairTimer.Reset(0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.runWatchLoop(ctx, watcher, st) }()

	probe := time.NewTicker(time.Millisecond)
	defer probe.Stop()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for !slices.Contains(watcher.WatchList(), dir) {
		select {
		case <-probe.C:
		case <-timeout.C:
			cancel()
			t.Fatalf("the watch on %q was never re-asserted (watch list = %v): the re-assert the floor skipped was dropped rather than deferred", dir, watcher.WatchList())
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runWatchLoop(cancelled ctx) = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runWatchLoop did not return after ctx cancellation")
	}

	if n := len(scans); n != 2 {
		t.Errorf("onChange called %d times, want 2 (the two debounced scans): the deferred repair must re-assert the watch set WITHOUT a certificate scan, or an operator who disabled the periodic rescan pays for a full walk per event window",
			n)
	}
}

// TestScheduleRepair_arms_for_the_remainder_of_the_floor pins the deferral's
// arithmetic, which is what keeps the repair a RATE LIMIT rather than a fresh
// countdown per event: the deferred re-assert is due when the current floor
// interval ends, not a whole interval after the event that deferred it. Arming
// from "now" would let a writer to /input push the repair out indefinitely by
// producing one event per interval — the same writer-controlled amplification the
// floor exists to prevent, inverted.
//
// A second deferral inside the same interval must not move the deadline either,
// which is the pending flag's job.
func TestScheduleRepair_arms_for_the_remainder_of_the_floor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newWatchState(New(absentWatchRoot, func(context.Context) {}, WithFallback(time.Hour)))
		defer st.stop()

		start := time.Now()
		st.lastResync = start
		time.Sleep(20 * time.Second)

		st.scheduleRepair()
		if !st.repairPending {
			t.Fatal("scheduleRepair did not mark a repair pending; a second event in the same interval would re-arm the timer and push the repair out")
		}
		time.Sleep(10 * time.Second)
		st.scheduleRepair() // a second event inside the same interval

		fired := <-st.repairTimer.C
		if want := start.Add(minPreScanResync); !fired.Equal(want) {
			t.Errorf("the deferred repair fired at %v, want %v (the remainder of the floor measured from the last re-assert, not a fresh interval)",
				fired.Sub(start), want.Sub(start))
		}
	})
}

// TestRunDeferredRepair_skips_a_repair_another_reassert_already_covered pins the
// bound on the deferral: whatever the event rate, the walk runs at most once per
// floor interval. A repair waiting behind the floor can be overtaken by any other
// re-assert (a debounced scan past the floor, the periodic safety-net tick), and
// running it anyway would spend a second whole-tree walk — with a WARN per
// unwatchable directory — on a set that was just re-asserted.
//
// The oracle is a registration dropped straight on the watcher AFTER the covering
// re-assert: a repair that runs anyway restores it, a repair that correctly stands
// down leaves it for the next interval.
func TestRunDeferredRepair_skips_a_repair_another_reassert_already_covered(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	dir := filepath.Join(root, "example.com")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	scans := 0
	w := New(root, func(context.Context) { scans++ }, WithFallback(time.Hour))
	st := newWatchState(w)
	t.Cleanup(st.stop)
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs = %v", err)
	}

	// A repair is pending, and another re-assert lands while it waits.
	st.lastResync = time.Now().Add(-minPreScanResync + time.Millisecond)
	st.scheduleRepair()
	st.lastResync = time.Now() // what handleSafetyNetTick / a past-floor scan record

	if err := watcher.Remove(dir); err != nil {
		t.Fatalf("setup: watcher.Remove(%q) = %v, want nil", dir, err)
	}

	st.runDeferredRepair(t.Context(), watcher)

	if watched := watcher.WatchList(); slices.Contains(watched, dir) {
		t.Errorf("watch list after an overtaken repair = %v, want %q still dropped: a repair whose interval another re-assert already covered must stand down, or the floor stops bounding the walk",
			watched, dir)
	}
	if st.repairPending {
		t.Error("runDeferredRepair left the repair pending; the next scan inside the floor would then never defer a fresh one")
	}
	if scans != 0 {
		t.Errorf("runDeferredRepair ran %d certificate scans, want 0: watch repair runs on its own schedule and must not borrow the scan cadence", scans)
	}
}

// TestRunDeferredRepair_skips_the_walk_after_shutdown pins the cancellation
// precedence every arm of watchLoop owes the rest: the select picks a ready case at
// random, so a repair deadline reached in the same instant as a shutdown can win
// over ctx.Done, and the walk would only emit degradation WARNs for a loop that is
// already returning.
func TestRunDeferredRepair_skips_the_walk_after_shutdown(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {}, WithFallback(time.Hour))
	st := newWatchState(w)
	t.Cleanup(st.stop)
	st.lastResync = time.Now().Add(-2 * minPreScanResync)
	st.scheduleRepair()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	st.runDeferredRepair(ctx, watcher)

	if watched := watcher.WatchList(); slices.Contains(watched, root) {
		t.Errorf("watch list after a cancelled repair = %v, want %q unregistered: a shutdown must stop the walk", watched, root)
	}
	if st.repairPending {
		t.Error("runDeferredRepair(cancelled ctx) left the repair pending")
	}
}

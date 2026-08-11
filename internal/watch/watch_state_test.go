package watch

import (
	"context"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/cert-converter/internal/scancadence"
	"github.com/cplieger/slogx/capture"
)

// absentWatchRoot is a path that does not exist, so a watch-set walk over it fails at
// its root before any watcher method is called. The timer tests below use it to drive
// runDebouncedScan with a nil watcher: they pin the debounce and fallback arithmetic,
// and a real fsnotify watcher would park a goroutine in an inotify read that a
// synctest bubble's fake clock cannot advance past.
const absentWatchRoot = "/nonexistent-cert-converter-watch-root"

// TestNewWatchState_arms_the_reconciliation_floor_when_the_fallback_is_disabled
// pins the liveness guarantee FALLBACK_SCAN_HOURS=0/false may NOT remove: the
// loop's periodic safety-net timer is armed in every configuration, on the
// reconciliation floor when the operator switched their own cadence off. Before
// this contract the disabled fallback left the loop holding no clock at all, so a
// silently dropped watch, a directory past the walk's entry budget, and a wedged
// watcher were all permanent and the health marker never went stale.
//
// The other two timers must still start stopped: nothing is pending until an event
// arrives, and nothing is deferred until a scan lands inside the re-assert floor.
func TestNewWatchState_arms_the_reconciliation_floor_when_the_fallback_is_disabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newWatchState(New("/input", func(context.Context) {}, WithDebounce(time.Second), WithFallback(0)))
		defer st.stop()

		if st.safetyNetTimer == nil {
			t.Fatal("newWatchState armed no safety-net timer with WithFallback(0); the loop then holds no clock at all and nothing recovers a dropped watch or refreshes the health marker")
		}

		start := time.Now()
		fired := <-st.safetyNetTimer.C
		if elapsed := fired.Sub(start); elapsed != scancadence.Floor {
			t.Errorf("the safety-net timer fired after %v with the fallback disabled, want exactly the %v reconciliation floor", elapsed, scancadence.Floor)
		}

		select {
		case <-st.debounceTimer.C:
			t.Error("debounce timer fired without any event; newWatchState must leave it stopped")
		case <-st.repairTimer.C:
			t.Error("repair timer fired with nothing deferred; newWatchState must leave it stopped")
		default:
		}
	})
}

// TestRunSafetyNetScan_reconciles_and_re_arms_with_the_fallback_disabled pins the
// scan half of the same guarantee: the floor's tick is a REAL reconciliation (it
// drives onChange, which is what converts a renewal whose event was lost and what
// refreshes the health marker) and it re-arms itself, so the guarantee is standing
// rather than one-shot. Its record names the floor as the trigger, which is how an
// operator confirms both that FALLBACK_SCAN_HOURS=0 took effect and that the app
// still walks the tree.
// Serial (no t.Parallel): it swaps the process-global slog default.
func TestRunSafetyNetScan_reconciles_and_re_arms_with_the_fallback_disabled(t *testing.T) {
	logs := capture.Default(t)
	synctest.Test(t, func(t *testing.T) {
		scans := 0
		st := newWatchState(New(absentWatchRoot, func(context.Context) { scans++ }, WithFallback(0)))
		defer st.stop()

		start := time.Now()
		first := <-st.safetyNetTimer.C
		st.runSafetyNetScan(t.Context())

		if scans != 1 {
			t.Fatalf("the reconciliation tick ran %d scans, want 1: a re-assert without a certificate scan converts nothing and never refreshes the health marker", scans)
		}
		next := <-st.safetyNetTimer.C
		if want := first.Add(scancadence.Floor); !next.Equal(want) {
			t.Errorf("the second reconciliation fired at %v, want %v (the floor must re-arm itself)", next.Sub(start), want.Sub(start))
		}
		if scans != 1 {
			t.Errorf("onChange ran %d times, want 1: only the tick that was serviced may scan", scans)
		}
	})

	rec := requireOneRecord(t, logs, msgScanState)
	assertAttrs(t, "the reconciliation scan record", rec, map[string]string{
		"mode":          "watch",
		"trigger":       triggerReconcile,
		"fallback_scan": "disabled",
		"scan_floor":    scancadence.Floor.String(),
	})
}

// TestSafetyNetCadence_never_exceeds_the_reconciliation_floor pins the one rule
// behind both the loop's cadence and the health probe's staleness deadline: the
// operator's FALLBACK_SCAN_HOURS cadence is used as configured while it is below
// the floor, and the floor covers every other case — the 0/false opt-out, a
// negative interval, and a cadence above the floor (including the 10-year ceiling
// internal/config clamps to, at which the old code armed a timer that would never
// fire in any real container's lifetime).
//
// scancadence.Effective is asserted directly because it IS the rule: main derives
// the probe's max-age from it and this package's timers arm from it, so one table
// covers both. safetyNetTrigger is asserted beside it because it is the only thing
// this package still derives from that cadence — which clock the mode record names.
func TestSafetyNetCadence_never_exceeds_the_reconciliation_floor(t *testing.T) {
	t.Parallel()
	// Strings first, then the durations: govet fieldalignment reads this table too.
	for _, tc := range []struct {
		name        string
		wantTrigger string
		fallback    time.Duration
		want        time.Duration
	}{
		{"the documented default is used as configured", triggerFallback, 6 * time.Hour, 6 * time.Hour},
		{"the 0/false opt-out falls to the floor", triggerReconcile, 0, scancadence.Floor},
		{"a negative interval falls to the floor", triggerReconcile, -time.Second, scancadence.Floor},
		{"a cadence at the floor is the operator's", triggerFallback, scancadence.Floor, scancadence.Floor},
		{"a cadence above the floor is capped", triggerReconcile, 48 * time.Hour, scancadence.Floor},
		{"the config ceiling is capped", triggerReconcile, 87600 * time.Hour, scancadence.Floor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := New("/input", func(context.Context) {}, WithFallback(tc.fallback))
			if got := scancadence.Effective(tc.fallback); got != tc.want {
				t.Errorf("scancadence.Effective(%v) = %v, want %v: the probe's deadline is derived from this and must match the loop's own cadence",
					tc.fallback, got, tc.want)
			}
			if got := w.safetyNetTrigger(); got != tc.wantTrigger {
				t.Errorf("safetyNetTrigger() with WithFallback(%v) = %q, want %q: the record must name which clock ran the scan",
					tc.fallback, got, tc.wantTrigger)
			}
		})
	}
}

// TestWatchState_scheduleScan_does_not_extend_the_debounce_window pins the
// coalescing contract: a burst of events must fire ONE scan at the deadline set
// by the first event. Re-arming on every event would let a continuous event
// stream push the scan out indefinitely, so a renewal mid-burst would never be
// converted.
//
// The root is an absent path, so runDebouncedScan's watch-set re-assert fails at the
// root and returns before it can touch a watcher: this test pins the debounce
// arithmetic, not the re-sync (watch_recv_test.go owns that), and a real fsnotify
// watcher inside a synctest bubble would block the fake clock on an inotify read.
func TestWatchState_scheduleScan_does_not_extend_the_debounce_window(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newWatchState(New(absentWatchRoot, func(context.Context) {}, WithDebounce(2*time.Second)))
		defer st.stop()

		start := time.Now()
		st.scheduleScan()
		if !st.pending {
			t.Fatal("scheduleScan did not mark a scan pending")
		}

		time.Sleep(1500 * time.Millisecond)
		st.scheduleScan() // second event inside the window

		fired := <-st.debounceTimer.C
		if elapsed := fired.Sub(start); elapsed != 2*time.Second {
			t.Errorf("debounce fired %v after the first event, want exactly 2s (a burst must not extend the window)", elapsed)
		}

		st.runDebouncedScan(t.Context(), nil)
		if st.pending {
			t.Error("runDebouncedScan left the pending flag set; the next event would never re-arm the debounce timer")
		}
	})
}

// TestWatchState_scans_re_arm_the_fallback_from_the_last_scan pins the
// safety-net cadence: both a debounced scan and a fallback scan re-arm the
// fallback timer, so the periodic rescan interval is measured from the last
// real scan rather than from process start.
//
// Same absent root as above, for the same reason.
func TestWatchState_scans_re_arm_the_fallback_from_the_last_scan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		scans := 0
		st := newWatchState(New(absentWatchRoot,
			func(context.Context) { scans++ },
			WithDebounce(2*time.Second), WithFallback(6*time.Hour)))
		defer st.stop()

		start := time.Now()

		// A debounced scan at t=2s must push the fallback deadline out to 6h
		// after that scan.
		st.scheduleScan()
		<-st.debounceTimer.C
		st.runDebouncedScan(t.Context(), nil)

		fired := <-st.safetyNetTimer.C
		if want := start.Add(2*time.Second + 6*time.Hour); !fired.Equal(want) {
			t.Errorf("fallback fired at %v, want %v (a real scan must re-arm the fallback interval)", fired.Sub(start), want.Sub(start))
		}

		// The fallback scan itself re-arms on the same interval.
		st.runSafetyNetScan(t.Context())
		next := <-st.safetyNetTimer.C
		if want := fired.Add(6 * time.Hour); !next.Equal(want) {
			t.Errorf("second fallback fired at %v, want %v (the fallback must keep its interval)", next.Sub(start), want.Sub(start))
		}
		if scans != 2 {
			t.Errorf("onChange called %d times, want 2 (one debounced scan plus one fallback scan)", scans)
		}
	})
}

// TestRunDebouncedScan_skips_scan_after_shutdown pins runDebouncedScan's
// cancellation precedence: watchLoop's select has none of its own, so a debounce
// deadline reached in the same instant as shutdown must not start a scan that
// would change health state on the way out.
func TestRunDebouncedScan_skips_scan_after_shutdown(t *testing.T) {
	t.Parallel()
	scans := 0
	w := New(t.TempDir(), func(context.Context) { scans++ }, WithDebounce(time.Hour))
	st := newWatchState(w)
	t.Cleanup(st.stop)
	st.scheduleScan()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	st.runDebouncedScan(ctx, nil)

	if scans != 0 {
		t.Errorf("runDebouncedScan(cancelled ctx) ran %d scans, want 0", scans)
	}
}

// liveForNCtx reports itself live for the first n Err() observations and
// cancelled from then on, which makes "cancellation landed in the middle of a
// helper" deterministic without a sleep or a goroutine race: the helper's own
// ctx.Err() calls are the clock.
type liveForNCtx struct {
	context.Context
	calls *int
	live  int
}

func (c liveForNCtx) Err() error {
	*c.calls++
	if *c.calls <= c.live {
		return nil
	}
	return context.Canceled
}

// TestRunDebouncedScan_skips_the_scan_when_shutdown_cut_the_resync_short pins
// runDebouncedScan's SECOND cancellation guard, the one after the watch-set
// re-assert. Its sibling arm has that half pinned
// (TestHandleSafetyNetTick_skips_the_scan_when_shutdown_cut_the_resync_short);
// here only the entry guard was covered, so the post-re-sync guard could be
// deleted and a shutdown landing mid-re-sync would still start a full /input
// scan whose ScanResult drives the health marker on the way out.
//
// live: 6 is runDebouncedScan's own Err() sequence on this tree: the entry
// guard, then the four observations the confined walk makes over the (empty)
// root — walkWatchDirs' own pre-walk guard, atomicfile.WalkDirInRoot's
// already-cancelled check, then the two the single root callback makes (the
// budget admission gate, exceedsEntryBudget, which honours cancellation before
// charging, and classifyWatchEntry's own guard) — then the one
// WalkDirInRoot makes before reading the root's entries. Cancellation therefore
// lands on reassertWatches' post-root check, so the root's watch is
// re-established and only the scan is suppressed, which is what the watch-list
// assertion distinguishes from an early entry-guard return.
func TestRunDebouncedScan_skips_the_scan_when_shutdown_cut_the_resync_short(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	scans := 0
	w := New(root, func(context.Context) { scans++ }, WithDebounce(time.Hour))
	st := newWatchState(w)
	t.Cleanup(st.stop)
	st.scheduleScan()

	calls := 0
	ctx := liveForNCtx{Context: context.Background(), calls: &calls, live: 6}

	st.runDebouncedScan(ctx, watcher)

	if !slices.Contains(watcher.WatchList(), root) {
		t.Fatalf("the watch-set re-assert never ran (watch list = %v, ctx.Err calls = %d); this test needs the state where shutdown lands AFTER the re-sync started", watcher.WatchList(), calls)
	}
	if scans != 0 {
		t.Errorf("runDebouncedScan ran %d scans after the re-sync was cut short by shutdown, want 0: the loop is about to return and the scan still drives the health marker", scans)
	}
}

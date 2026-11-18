package watch

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/cert-converter/internal/scancadence"
)

// TestWatchState_reports_the_next_fallback_scan pins WithNextScan in watch mode:
// each report is the instant the periodic rescan then fires, measured from the
// last real scan. The absent root keeps fsnotify out of the bubble
// (absentWatchRoot).
func TestWatchState_reports_the_next_fallback_scan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var reports []time.Time
		st := newWatchState(New(absentWatchRoot, func(context.Context, bool) {},
			WithDebounce(time.Second), WithFallback(time.Hour),
			WithNextScan(func(next time.Time) { reports = append(reports, next) })))
		defer st.stop()
		t0 := time.Now()

		time.Sleep(10 * time.Minute)
		st.scheduleScan()
		<-st.debounceTimer.C
		st.runDebouncedScan(t.Context(), nil)

		tick := <-st.safetyNetTimer.C
		st.runSafetyNetScan(t.Context())

		want := []time.Time{
			t0.Add(time.Hour),
			t0.Add(10*time.Minute + time.Second + time.Hour),
			t0.Add(10*time.Minute + time.Second + 2*time.Hour),
		}
		if len(reports) != len(want) {
			t.Fatalf("got %d next-scan reports %v, want %d: loop start, the debounced scan and the fallback scan each arm the rescan",
				len(reports), reports, len(want))
		}
		for i := range want {
			if !reports[i].Equal(want[i]) {
				t.Errorf("report %d = t0+%v, want t0+%v", i, reports[i].Sub(t0), want[i].Sub(t0))
			}
		}
		if !tick.Equal(reports[1]) {
			t.Errorf("the fallback scan fired at t0+%v, but the debounced scan reported t0+%v", tick.Sub(t0), reports[1].Sub(t0))
		}
	})
}

// TestWatchState_reports_the_floor_when_the_fallback_is_disabled pins that the
// reported time is never absent: FALLBACK_SCAN_HOURS=0 still has the
// reconciliation floor as its next guaranteed scan.
func TestWatchState_reports_the_floor_when_the_fallback_is_disabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var reports []time.Time
		t0 := time.Now()
		st := newWatchState(New(absentWatchRoot, func(context.Context, bool) {},
			WithFallback(0), WithNextScan(func(next time.Time) { reports = append(reports, next) })))
		defer st.stop()

		if len(reports) != 1 || !reports[0].Equal(t0.Add(scancadence.Floor)) {
			t.Errorf("reports at loop start = %v, want exactly [t0+%v]", reports, scancadence.Floor)
		}
	})
}

// TestPollLoop_reports_each_tick_plus_the_interval pins WithNextScan in poll
// mode: each report is the instant of the next poll scan, which a ticker keeps
// on its cadence even when a scan runs long.
// Serial (no t.Parallel): it swaps the package-level newFSWatcher seam.
func TestPollLoop_reports_each_tick_plus_the_interval(t *testing.T) {
	stubFSWatcherUnavailable(t)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var reports, scans []time.Time
		w := New(absentWatchRoot, func(context.Context, bool) {
			scans = append(scans, time.Now())
			time.Sleep(10 * time.Minute)
			if len(scans) == 2 {
				cancel()
			}
		}, WithFallback(time.Hour), WithNextScan(func(next time.Time) { reports = append(reports, next) }))
		t0 := time.Now()

		if fw := w.pollUntilUpgrade(ctx); fw != nil {
			fw.Close()
			t.Fatal("pollUntilUpgrade upgraded with fsnotify unavailable")
		}

		want := []time.Time{t0.Add(time.Hour), t0.Add(2 * time.Hour), t0.Add(3 * time.Hour)}
		if len(reports) != len(want) {
			t.Fatalf("got %d next-scan reports %v, want %d: one when polling starts and one per tick", len(reports), reports, len(want))
		}
		for i := range want {
			if !reports[i].Equal(want[i]) {
				t.Errorf("report %d = t0+%v, want t0+%v", i, reports[i].Sub(t0), want[i].Sub(t0))
			}
		}
		for i, at := range scans {
			if !at.Equal(reports[i]) {
				t.Errorf("poll scan %d ran at t0+%v, but the report before it said t0+%v", i, at.Sub(t0), reports[i].Sub(t0))
			}
		}
	})
}

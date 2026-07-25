package watch

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fsnotify/fsnotify"
)

// TestNewWatchState_leaves_nothing_armed_when_fallback_disabled pins the
// disabled-fallback contract: fallbackChan must be nil (a receive on a nil
// channel blocks forever, which is what keeps watchLoop's fallback case from
// firing without a timer) and the debounce timer must start stopped so no scan
// runs before an event arrives.
func TestNewWatchState_leaves_nothing_armed_when_fallback_disabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newWatchState(New("/input", func(context.Context) {}, WithDebounce(time.Second), WithFallback(0)))
		defer st.stop()

		if st.fallbackTimer != nil {
			t.Error("newWatchState armed a fallback timer with WithFallback(0); want none")
		}
		if st.fallbackChan() != nil {
			t.Error("fallbackChan() != nil with the fallback disabled; a non-nil channel makes watchLoop's fallback case reachable")
		}

		time.Sleep(10 * time.Second)
		select {
		case <-st.debounceTimer.C:
			t.Error("debounce timer fired without any event; newWatchState must leave it stopped")
		default:
		}
	})
}

// TestWatchState_scheduleScan_does_not_extend_the_debounce_window pins the
// coalescing contract: a burst of events must fire ONE scan at the deadline set
// by the first event. Re-arming on every event would let a continuous event
// stream push the scan out indefinitely, so a renewal mid-burst would never be
// converted.
func TestWatchState_scheduleScan_does_not_extend_the_debounce_window(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := newWatchState(New("/input", func(context.Context) {}, WithDebounce(2*time.Second)))
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

		st.runDebouncedScan(t.Context())
		if st.pending {
			t.Error("runDebouncedScan left the pending flag set; the next event would never re-arm the debounce timer")
		}
	})
}

// TestWatchState_scans_re_arm_the_fallback_from_the_last_scan pins the
// safety-net cadence: both a debounced scan and a fallback scan re-arm the
// fallback timer, so the periodic rescan interval is measured from the last
// real scan rather than from process start.
func TestWatchState_scans_re_arm_the_fallback_from_the_last_scan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		scans := 0
		st := newWatchState(New("/input",
			func(context.Context) { scans++ },
			WithDebounce(2*time.Second), WithFallback(6*time.Hour)))
		defer st.stop()

		start := time.Now()

		// A debounced scan at t=2s must push the fallback deadline out to 6h
		// after that scan.
		st.scheduleScan()
		<-st.debounceTimer.C
		st.runDebouncedScan(t.Context())

		fired := <-st.fallbackChan()
		if want := start.Add(2*time.Second + 6*time.Hour); !fired.Equal(want) {
			t.Errorf("fallback fired at %v, want %v (a real scan must re-arm the fallback interval)", fired.Sub(start), want.Sub(start))
		}

		// The fallback scan itself re-arms on the same interval.
		st.runFallbackScan(t.Context())
		next := <-st.fallbackChan()
		if want := fired.Add(6 * time.Hour); !next.Equal(want) {
			t.Errorf("second fallback fired at %v, want %v (the fallback must keep its interval)", next.Sub(start), want.Sub(start))
		}
		if scans != 2 {
			t.Errorf("onChange called %d times, want 2 (one debounced scan plus one fallback scan)", scans)
		}
	})
}

// TestWatchState_handleWatcherError_rescans_only_on_overflow pins the recovery
// contract for fsnotify errors: an event-queue overflow dropped events, so a
// rescan must be scheduled to recover a missed renewal, while any other watcher
// error is logged without forcing a scan.
func TestWatchState_handleWatcherError_rescans_only_on_overflow(t *testing.T) {
	t.Parallel()

	overflow := newWatchState(New("/input", func(context.Context) {}))
	defer overflow.stop()
	overflow.handleWatcherError(fsnotify.ErrEventOverflow)
	if !overflow.pending {
		t.Error("handleWatcherError(ErrEventOverflow) did not schedule a scan; dropped events would silently skip a renewal")
	}

	other := newWatchState(New("/input", func(context.Context) {}))
	defer other.stop()
	other.handleWatcherError(errors.New("transient watcher failure"))
	if other.pending {
		t.Error("handleWatcherError(non-overflow error) scheduled a scan; want the error logged only")
	}
}

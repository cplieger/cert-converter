package watch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
	"github.com/fsnotify/fsnotify"
)

// TestHandleEventRecv_closed_channel_stops_the_loop pins the liveness contract
// of the event receive: a closed events channel means the fsnotify watcher is
// dead, so the receive must name that loss (errEventsChannelClosed) and watchLoop
// then returns, restarting the container with a fresh watcher. Returning nil there
// would spin the loop on a dead channel forever with no change detection and a
// still-healthy marker.
func TestHandleEventRecv_closed_channel_stops_the_loop(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {})
	st := newWatchState(w)
	t.Cleanup(st.stop)

	if got := w.handleEventRecv(t.Context(), watcher, st, fsnotify.Event{}, false); got != errEventsChannelClosed {
		t.Errorf("handleEventRecv(ok=false) = %v, want the events-channel-closed loss (%v) so watchLoop exits and the process restarts",
			got, errEventsChannelClosed)
	}
	if st.pending {
		t.Error("handleEventRecv(ok=false) scheduled a scan; a dead watcher must not arm the debounce timer")
	}
}

// TestHandleEventRecv_arms_the_debounce_only_for_interesting_events pins that a
// live receive is classified through handleFsEvent: a cert write arms the
// debounced rescan, an unrelated file does not, and both keep the loop running.
func TestHandleEventRecv_arms_the_debounce_only_for_interesting_events(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()

	for _, tc := range []struct {
		name        string
		file        string
		wantPending bool
	}{
		{"a cert write arms the rescan", "tls.crt", true},
		{"a key write arms the rescan", "tls.key", true},
		{"an unrelated write does not", "notes.txt", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := New(root, func(context.Context) {})
			st := newWatchState(w)
			t.Cleanup(st.stop)

			event := fsnotify.Event{Name: filepath.Join(root, tc.file), Op: fsnotify.Write}
			if got := w.handleEventRecv(t.Context(), watcher, st, event, true); got != nil {
				t.Errorf("handleEventRecv(%s) = %v, want nil (a live event must never stop the loop)", tc.file, got)
			}
			if st.pending != tc.wantPending {
				t.Errorf("handleEventRecv(write %s) pending = %v, want %v", tc.file, st.pending, tc.wantPending)
			}
		})
	}
}

// TestHandleErrorRecv_stops_on_close_and_resyncs_on_overflow pins the error
// receive: a closed errors channel stops the loop, an event-queue overflow both
// forces a rescan and re-attaches the watch set (a dropped directory Create
// would otherwise leave that subtree unwatched for the process's life), and any
// other watcher error is logged without arming a scan.
func TestHandleErrorRecv_stops_on_close_and_resyncs_on_overflow(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	nested := filepath.Join(root, "acme-v02", "example.com")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})

	st := newWatchState(w)
	t.Cleanup(st.stop)
	if got := w.handleErrorRecv(t.Context(), watcher, st, nil, false); got {
		t.Error("handleErrorRecv(ok=false) = true, want false so watchLoop exits and the process restarts")
	}

	overflowState := newWatchState(w)
	t.Cleanup(overflowState.stop)
	if got := w.handleErrorRecv(t.Context(), watcher, overflowState, fsnotify.ErrEventOverflow, true); !got {
		t.Error("handleErrorRecv(ErrEventOverflow) = false, want true (an overflow is recoverable, not fatal)")
	}
	if !overflowState.pending {
		t.Error("handleErrorRecv(ErrEventOverflow) did not schedule a rescan; a renewal in the dropped events would be missed")
	}
	watched := watcher.WatchList()
	if !slices.Contains(watched, nested) {
		t.Errorf("handleErrorRecv(ErrEventOverflow) did not re-sync the watch set; %q missing from %v", nested, watched)
	}

	otherState := newWatchState(w)
	t.Cleanup(otherState.stop)
	if got := w.handleErrorRecv(t.Context(), watcher, otherState, errors.New("transient watcher failure"), true); !got {
		t.Error("handleErrorRecv(non-overflow error) = false, want true (the loop keeps running)")
	}
	if otherState.pending {
		t.Error("handleErrorRecv(non-overflow error) scheduled a scan; want the error logged only")
	}
}

// TestHandleFallbackTick_resyncs_the_watch_set_before_scanning pins the second
// half of the fallback tick: besides firing the safety-net rescan it re-asserts
// the watch set, so a directory whose watcher.Add failed earlier (unreadable, or
// the inotify watch limit exhausted) is picked up again once the condition is
// repaired instead of staying outside the watch set for the process's life.
func TestHandleFallbackTick_resyncs_the_watch_set_before_scanning(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	nested := filepath.Join(root, "acme-v02", "example.com")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	scans := 0
	w := New(root, func(context.Context) { scans++ }, WithFallback(time.Hour))
	st := newWatchState(w)
	t.Cleanup(st.stop)

	w.handleFallbackTick(t.Context(), watcher, st)

	if scans != 1 {
		t.Errorf("handleFallbackTick scans = %d, want 1 (the safety-net rescan must still fire)", scans)
	}
	if watched := watcher.WatchList(); !slices.Contains(watched, nested) {
		t.Errorf("handleFallbackTick did not re-sync the watch set; %q missing from %v", nested, watched)
	}
}

// TestHandleFallbackTick_skips_the_scan_when_shutdown_cut_the_resync_short pins
// the shutdown half of the fallback tick: a re-sync cut short by cancellation
// must not go on to start a full /input scan whose result would still drive the
// health marker while the loop is already returning.
func TestHandleFallbackTick_skips_the_scan_when_shutdown_cut_the_resync_short(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	scans := 0
	w := New(root, func(context.Context) { scans++ }, WithFallback(time.Hour))
	st := newWatchState(w)
	t.Cleanup(st.stop)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w.handleFallbackTick(ctx, watcher, st)

	if scans != 0 {
		t.Errorf("handleFallbackTick(cancelled ctx) ran %d scans, want 0 (the loop is about to return; a shutdown must not start a scan)", scans)
	}
}

// TestHandleErrorRecv_keeps_the_loop_running_when_the_overflow_resync_fails
// pins the liveness half of the overflow recovery: a failed watch-set re-sync
// is warned about and the loop keeps running, because treating it as fatal
// would exit Run and restart the container on a recoverable overflow.
func TestHandleErrorRecv_keeps_the_loop_running_when_the_overflow_resync_fails(t *testing.T) {
	t.Parallel()
	watcher := newClosedTestWatcher(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {})
	st := newWatchState(w)
	t.Cleanup(st.stop)

	if got := w.handleErrorRecv(t.Context(), watcher, st, fsnotify.ErrEventOverflow, true); !got {
		t.Error("handleErrorRecv(overflow, re-sync failing) = false, want true: a failed re-sync is warned about, not fatal to the loop")
	}
	if !st.pending {
		t.Error("handleErrorRecv(overflow, re-sync failing) did not schedule the recovery rescan; a renewal in the dropped events would be missed")
	}
}

// TestHandleErrorRecv_does_not_resync_the_watch_set_for_a_benign_error pins the
// negative half of the recovery contract: only an event-queue overflow warrants
// a full tree re-walk, so a directory created after the watch set was built
// must NOT appear in the watch list after a benign watcher error.
func TestHandleErrorRecv_does_not_resync_the_watch_set_for_a_benign_error(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {})
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs = %v", err)
	}
	st := newWatchState(w)
	t.Cleanup(st.stop)
	late := filepath.Join(root, "late.example.com")
	if err := os.MkdirAll(late, 0o750); err != nil {
		t.Fatal(err)
	}

	if got := w.handleErrorRecv(t.Context(), watcher, st, errors.New("transient watcher failure"), true); !got {
		t.Error("handleErrorRecv(non-overflow error) = false, want true (the loop keeps running)")
	}
	if watched := watcher.WatchList(); slices.Contains(watched, late) {
		t.Errorf("handleErrorRecv(non-overflow error) re-walked the tree and picked up %q; only an event-queue overflow warrants a full re-sync", late)
	}
}

// TestLostOrShutdown_gives_cancellation_precedence pins both halves of the
// channel-closed translation, for every loss this package can reach.
// watchLoop's select has no ctx precedence of its own (Go picks a ready case at
// random), so a SIGTERM arriving in the same instant as an fsnotify fd death can
// take the channel arm: with a live ctx that really is lost change detection and
// must surface the loss ITSELF — the same *LostError value, so the caller can
// tell which loss occurred and reach its remediation — while under an
// already-cancelled ctx it is a clean shutdown and must return nil.
//
// Both halves must be SILENT. The operator-facing announcement is main's, once
// per event; a record emitted here would be a second announcement on the loss
// path and a phantom restart notice on the shutdown path.
// Not parallel: it swaps the process-global slog default.
func TestLostOrShutdown_gives_cancellation_precedence(t *testing.T) {
	for _, lost := range []*LostError{
		errRootWatchRemoved,
		errEventsChannelClosed,
		errErrorsChannelClosed,
		errNoWatchNoFallback,
	} {
		t.Run(lost.Cause, func(t *testing.T) {
			t.Run("a live ctx is lost change detection", func(t *testing.T) {
				logs := capture.Default(t)
				got := lostOrShutdown(t.Context(), lost)
				if !errors.Is(got, ErrWatchLost) {
					t.Errorf("lostOrShutdown(live ctx) = %v, want ErrWatchLost (a watcher that dies while the app must keep running is fatal)", got)
				}
				if got != error(lost) {
					t.Errorf("lostOrShutdown(live ctx) = %v, want the %q loss itself so main can name which loss occurred", got, lost.Cause)
				}
				if !strings.Contains(got.Error(), lost.Cause) {
					t.Errorf("lostOrShutdown(live ctx).Error() = %q, want it to name the cause %q", got.Error(), lost.Cause)
				}
				if logs.Len() != 0 {
					t.Errorf("lostOrShutdown(live ctx) logged %v, want no output: main owns the single operator-facing announcement, so a record here is a second one",
						logs.Messages())
				}
			})
			t.Run("a cancelled ctx is a clean stop", func(t *testing.T) {
				logs := capture.Default(t)
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				if got := lostOrShutdown(cancelled, lost); got != nil {
					t.Errorf("lostOrShutdown(cancelled ctx) = %v, want nil (a channel closing during shutdown is a clean stop, not lost change detection)", got)
				}
				if logs.Len() != 0 {
					t.Errorf("lostOrShutdown(cancelled ctx) logged %v, want no output: a clean shutdown must not claim the process will exit and restart", logs.Messages())
				}
			})
		})
	}
}

// TestLostError_carries_the_remediation_only_where_one_exists pins the split
// that lets main say the right thing per loss: the disabled-fallback case is the
// only operator-fixable one, so it is the only one that names
// FALLBACK_SCAN_HOURS. Dropping that field would silently strip the one
// actionable hint this package has ever given, and adding one to a dead
// fsnotify fd would tell an operator to fix something they did not cause.
func TestLostError_carries_the_remediation_only_where_one_exists(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		lost            *LostError
		wantRemediation bool
	}{
		{errRootWatchRemoved, false},
		{errEventsChannelClosed, false},
		{errErrorsChannelClosed, false},
		{errNoWatchNoFallback, true},
	} {
		t.Run(tc.lost.Cause, func(t *testing.T) {
			t.Parallel()
			if tc.lost.Cause == "" {
				t.Error("a loss with no cause leaves main announcing that change detection is dead without saying which loss ended it")
			}
			if got := tc.lost.Remediation != ""; got != tc.wantRemediation {
				t.Errorf("Remediation = %q, want a remediation: %v", tc.lost.Remediation, tc.wantRemediation)
			}
			if tc.wantRemediation && !strings.Contains(tc.lost.Remediation, "FALLBACK_SCAN_HOURS") {
				t.Errorf("Remediation = %q, want it to name FALLBACK_SCAN_HOURS, the env var that produced this state", tc.lost.Remediation)
			}
		})
	}
}

// TestHandleFallbackTick_runs_the_scan_when_resync_fails pins the safety-net
// half of the fallback tick: when watcher.Add fails while the context is still
// live, the periodic full scan is the only remaining renewal-detection path, so
// a failed watch-set repair must warn and still scan rather than skip the tick.
func TestHandleFallbackTick_runs_the_scan_when_resync_fails(t *testing.T) {
	t.Parallel()
	watcher := newClosedTestWatcher(t)
	scans := 0
	w := New(t.TempDir(), func(context.Context) { scans++ }, WithFallback(time.Hour))
	st := newWatchState(w)
	t.Cleanup(st.stop)

	w.handleFallbackTick(t.Context(), watcher, st)

	if scans != 1 {
		t.Errorf("handleFallbackTick(resync failing) ran %d scans, want 1: a failed watch-set repair must not disable the polling safety net", scans)
	}
}

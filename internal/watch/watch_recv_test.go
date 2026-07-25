package watch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// TestHandleEventRecv_closed_channel_stops_the_loop pins the liveness contract
// of the event receive: a closed events channel means the fsnotify watcher is
// dead, so the loop must report "stop" (Run then returns and the container
// restarts with a fresh watcher). Returning true there would spin the loop on a
// dead channel forever with no change detection and a still-healthy marker.
func TestHandleEventRecv_closed_channel_stops_the_loop(t *testing.T) {
	t.Parallel()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	root := t.TempDir()
	w := New(root, func(context.Context) {})
	st := newWatchState(w)
	t.Cleanup(st.stop)

	if got := w.handleEventRecv(t.Context(), watcher, st, fsnotify.Event{}, false); got {
		t.Error("handleEventRecv(ok=false) = true, want false so watchLoop exits and the process restarts")
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
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
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
			if got := w.handleEventRecv(t.Context(), watcher, st, event, true); !got {
				t.Errorf("handleEventRecv(%s) = false, want true (a live event must never stop the loop)", tc.file)
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
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
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
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
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

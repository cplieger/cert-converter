package watch

import (
	"context"
	"errors"
	"log/slog"
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
	if got := w.handleErrorRecv(t.Context(), watcher, st, nil, false); got != errErrorsChannelClosed {
		t.Errorf("handleErrorRecv(ok=false) = %v, want the errors-channel-closed loss (%v) so watchLoop exits and the process restarts", got, errErrorsChannelClosed)
	}

	overflowState := newWatchState(w)
	t.Cleanup(overflowState.stop)
	if got := w.handleErrorRecv(t.Context(), watcher, overflowState, fsnotify.ErrEventOverflow, true); got != nil {
		t.Errorf("handleErrorRecv(ErrEventOverflow) = %v, want nil (an overflow is recoverable, not fatal)", got)
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
	if got := w.handleErrorRecv(t.Context(), watcher, otherState, errors.New("transient watcher failure"), true); got != nil {
		t.Errorf("handleErrorRecv(non-overflow error) = %v, want nil (the loop keeps running)", got)
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
	// The watch set AS THE SCAN SEES IT: the re-sync must precede the scan, or a
	// renewal landing during a long scan produces no event and waits for the next
	// tick. Asserting the watch list after the tick cannot tell the two orders apart.
	var watchedAtScan []string
	w := New(root, func(context.Context) {
		scans++
		watchedAtScan = watcher.WatchList()
	}, WithFallback(time.Hour))
	st := newWatchState(w)
	t.Cleanup(st.stop)

	w.handleFallbackTick(t.Context(), watcher, st)

	if scans != 1 {
		t.Errorf("handleFallbackTick scans = %d, want 1 (the safety-net rescan must still fire)", scans)
	}
	if !slices.Contains(watchedAtScan, nested) {
		t.Errorf("watch set at scan time = %v, want %q already re-attached: the re-sync must run BEFORE the scan so a change landing during the scan still arrives as an event", watchedAtScan, nested)
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

	if got := w.handleErrorRecv(t.Context(), watcher, st, fsnotify.ErrEventOverflow, true); got != nil {
		t.Errorf("handleErrorRecv(overflow, re-sync failing) = %v, want nil: a failed re-sync is warned about, not fatal to the loop", got)
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

	if got := w.handleErrorRecv(t.Context(), watcher, st, errors.New("transient watcher failure"), true); got != nil {
		t.Errorf("handleErrorRecv(non-overflow error) = %v, want nil (the loop keeps running)", got)
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
// that lets main say the right thing per loss: the two disabled-fallback cases
// are the operator-fixable ones, so they are the two that name
// FALLBACK_SCAN_HOURS. Both are reached ONLY because the periodic rescan was
// switched off — with it enabled, a removed root watch is re-attached in place
// by resyncWatchSet and no watch-set failure ends the loop.
//
// The field is load-bearing, not decoration: main.reportWatchExit attaches the
// remediation attr only where Remediation is non-empty, and the
// CertConverterChangeDetectionDead runbook tells the operator to act on that
// attr, so a loss that leaves it empty ships its actionable half only inside the
// error text. Dropping either field strips that; adding one to a dead fsnotify
// fd would tell an operator to fix something they did not cause.
func TestLostError_carries_the_remediation_only_where_one_exists(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		lost            *LostError
		wantRemediation bool
	}{
		{errRootWatchRemoved, true},
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

// TestHandleWatcherError_warns_with_the_operator_diagnostics pins the two WARN
// records the fsnotify error arm emits. Neither is pinned today: the receive
// tests assert only whether a rescan was armed, so both records could drop to
// Debug, lose their attributes, or change class without any test failing.
//
// The overflow record is the operator's ONLY statement that events were dropped
// (a renewal may have been missed and is covered only by the rescan this arm
// schedules), and the benign record is the only statement that a watcher error
// occurred at all -- so it owes the same triple every other degraded-path site
// in this package owes: which root, whether anything will revisit it
// (fallback_scan; "disabled" means nothing does for the life of the process),
// and the error.
// Not parallel: it swaps the process-global slog default.
func TestHandleWatcherError_warns_with_the_operator_diagnostics(t *testing.T) {
	benign := errors.New("transient watcher failure")

	for _, tc := range []struct {
		name      string
		err       error
		fallback  time.Duration
		msg       string
		wantAttrs map[string]string
	}{
		{
			name:      "an event-queue overflow is announced at WARN with its error",
			err:       fsnotify.ErrEventOverflow,
			fallback:  6 * time.Hour,
			msg:       "fsnotify event queue overflowed",
			wantAttrs: map[string]string{"error": fsnotify.ErrEventOverflow.Error()},
		},
		{
			name:     "a benign watcher error names the root and the rescan cadence",
			err:      benign,
			fallback: 6 * time.Hour,
			msg:      "watcher error",
			wantAttrs: map[string]string{
				"fallback_scan": "6h0m0s",
				"error":         benign.Error(),
			},
		},
		{
			name:     "a benign watcher error reports a disabled rescan as disabled",
			err:      benign,
			fallback: 0,
			msg:      "watcher error",
			wantAttrs: map[string]string{
				"fallback_scan": "disabled",
				"error":         benign.Error(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)
			root := t.TempDir()
			st := newWatchState(New(root, func(context.Context) {}, WithFallback(tc.fallback)))
			t.Cleanup(st.stop)

			st.handleWatcherError(tc.err)

			if n := logs.CountLevel(slog.LevelWarn, tc.msg); n != 1 {
				t.Fatalf("WARN %q logged %d times, want exactly 1; log = %v", tc.msg, n, logs.Messages())
			}
			for key, want := range tc.wantAttrs {
				got, ok := logs.AttrValue(tc.msg, key)
				if !ok {
					t.Errorf("WARN %q carries no %q attribute; an operator cannot act on the error without it", tc.msg, key)
					continue
				}
				if got != want {
					t.Errorf("WARN %q %s = %q, want %q", tc.msg, key, got, want)
				}
			}
			if tc.msg == "watcher error" {
				if got, _ := logs.AttrValue(tc.msg, "root"); got != root {
					t.Errorf("WARN %q root = %q, want %q so the operator knows which tree lost an event", tc.msg, got, root)
				}
			}
		})
	}
}

// TestHandleEventRecv_reattaches_a_recreated_directory pins the half of the
// membership guard that a per-event WatchList scan used to get for free: the
// guard now answers from this package's own mirror of the registration set, so a
// directory whose watch the kernel discarded with the directory itself must be
// forgotten, or its recreation looks "already watched" and is never walked
// again -- every renewal underneath it then waits for the periodic re-sync, and
// never arrives with the fallback disabled.
//
// The oracle is the CHILD of the recreated directory: it was never registered
// before, so it can only appear in the watch list if the Create event actually
// re-walked the subtree, and unlike the parent it cannot be confused with a
// registration the kernel is still dropping asynchronously.
func TestHandleEventRecv_reattaches_a_recreated_directory(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	dir := filepath.Join(root, "example.com")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs(%q) = %v, want nil", root, err)
	}
	st := newWatchState(w)
	t.Cleanup(st.stop)

	if lost := w.handleEventRecv(t.Context(), watcher, st, fsnotify.Event{Name: dir, Op: fsnotify.Remove}, true); lost != nil {
		t.Fatalf("handleEventRecv(Remove %q) = %v, want nil (an ordinary directory removal is not lost change detection)", dir, lost)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "nested")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatal(err)
	}

	if lost := w.handleEventRecv(t.Context(), watcher, st, fsnotify.Event{Name: dir, Op: fsnotify.Create}, true); lost != nil {
		t.Fatalf("handleEventRecv(Create %q) = %v, want nil", dir, lost)
	}

	if watched := watcher.WatchList(); !slices.Contains(watched, child) {
		t.Errorf("watch list after %q was removed and recreated = %v, want %q re-attached: the removed path must be forgotten so its recreation is walked again",
			dir, watched, child)
	}
}

// TestRunDebouncedScan_reasserts_registrations_the_kernel_dropped_silently pins the
// recovery the event-driven path structurally cannot cover.
//
// The membership mirror only forgets a path when fsnotify DELIVERS a Remove or
// Rename for it, and the Linux backend consumes IN_UNMOUNT and IN_IGNORED without
// emitting an event at all (a child filesystem unmount, or any implicit kernel
// removal). The mirror then claims a directory is watched that the kernel has
// dropped, and handlePathEvent's guard skips the subtree re-walk on the strength of
// that claim, so the directory and everything under it stay unwatched. Re-asserting
// the set once per debounced scan recovers them.
//
// The Removes below are made straight on the watcher, leaving the mirror untouched,
// which is exactly the state the filtered kernel events produce.
func TestRunDebouncedScan_reasserts_registrations_the_kernel_dropped_silently(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	dir := filepath.Join(root, "example.com")
	child := filepath.Join(dir, "nested")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {}, WithDebounce(time.Millisecond))
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs(%q) = %v, want nil", root, err)
	}
	st := newWatchState(w)
	t.Cleanup(st.stop)

	for _, path := range []string{dir, child} {
		if err := watcher.Remove(path); err != nil {
			t.Fatalf("setup: watcher.Remove(%q) = %v, want nil", path, err)
		}
	}
	// The mirror still claims both, so the event path skips the re-walk.
	if !w.watchSetHas(dir) {
		t.Fatalf("setup: the mirror forgot %q; this test needs the state where the mirror and the kernel disagree", dir)
	}
	if w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: dir, Op: fsnotify.Chmod}) {
		st.scheduleScan()
	}

	st.runDebouncedScan(t.Context(), watcher)

	watched := watcher.WatchList()
	for _, want := range []string{dir, child} {
		if !slices.Contains(watched, want) {
			t.Errorf("watch list after the debounced scan = %v, want %q re-registered: a registration the kernel dropped without an event is only recovered by re-asserting the set",
				watched, want)
		}
	}
}

// TestRunDebouncedScan_floors_the_reassert_cadence pins minPreScanResync: the
// whole-tree re-assert above is O(directories under the root), re-emits one WARN per
// unwatchable directory, and carries none of the MAX_SCAN_ENTRIES ceiling the scan it
// precedes does, while arming it costs a writer to /input one create+delete per
// debounce window (handleFsEvent's Remove arm schedules a scan for ANY path). Without
// the floor that walk runs on the writer's cadence, which is a writer-controlled CPU
// and log-volume amplifier on the change-detection goroutine.
//
// The oracle is a registration dropped straight on the watcher between two scans, the
// same kernel-silent state the test above recovers: the first scan re-asserts, the
// second one lands inside the floor and must leave it dropped. The scan itself must
// still run both times -- the floor bounds the re-assert, never change detection.
func TestRunDebouncedScan_floors_the_reassert_cadence(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	dir := filepath.Join(root, "example.com")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	scans := 0
	w := New(root, func(context.Context) { scans++ }, WithDebounce(time.Millisecond))
	st := newWatchState(w)
	t.Cleanup(st.stop)

	st.runDebouncedScan(t.Context(), watcher)
	if !slices.Contains(watcher.WatchList(), dir) {
		t.Fatalf("watch list after the first debounced scan = %v, want %q: the first scan of a run must re-assert the set",
			watcher.WatchList(), dir)
	}

	if err := watcher.Remove(dir); err != nil {
		t.Fatalf("setup: watcher.Remove(%q) = %v, want nil", dir, err)
	}

	st.runDebouncedScan(t.Context(), watcher)

	if watched := watcher.WatchList(); slices.Contains(watched, dir) {
		t.Errorf("watch list after a second debounced scan inside %v = %v, want %q still dropped: the whole-tree re-assert must not run on the writer's event cadence",
			minPreScanResync, watched, dir)
	}
	if scans != 2 {
		t.Errorf("onChange called %d times across two debounced scans, want 2: the re-assert floor must bound the walk, not the scan", scans)
	}
}

// TestRecvHelpers_do_no_work_after_cancellation pins the cancellation precedence
// both receive arms owe the rest of the loop: watchLoop's select picks a ready
// case at random, so a queued event or watcher error can still be delivered after
// ctx.Done is ready. The loop exits on its next selection, so a re-attach or a
// scheduled scan can no longer accomplish anything -- but the WARN it logs on the
// way sends an operator to troubleshoot watch degradation in a container that is
// only stopping. Every timer, attach, and channel-loss arm already suppresses
// equivalent work after cancellation; these two must match, so the assertion is
// that NOTHING is logged and no scan is armed.
// Not parallel: it swaps the process-global slog default.
func TestRecvHelpers_do_no_work_after_cancellation(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(ctx context.Context, w *Watcher, watcher *fsnotify.Watcher, st *watchState) *LostError
	}{
		{
			// With the fallback enabled a live context would WARN that the root
			// watch was lost and re-attach the whole watch set.
			name: "a queued root removal is neither announced nor re-attached",
			call: func(ctx context.Context, w *Watcher, watcher *fsnotify.Watcher, st *watchState) *LostError {
				return w.handleEventRecv(ctx, watcher, st, fsnotify.Event{Name: w.root, Op: fsnotify.Remove}, true)
			},
		},
		{
			// A live context would WARN "watcher error" with the rescan cadence.
			name: "a queued watcher error is not announced",
			call: func(ctx context.Context, w *Watcher, watcher *fsnotify.Watcher, st *watchState) *LostError {
				return w.handleErrorRecv(ctx, watcher, st, errors.New("transient watcher failure"), true)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)
			watcher := newTestWatcher(t)
			w := New(t.TempDir(), func(context.Context) {}, WithFallback(6*time.Hour))
			st := newWatchState(w)
			t.Cleanup(st.stop)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			if lost := tc.call(ctx, w, watcher, st); lost != nil {
				t.Errorf("receive on a cancelled context = %v, want nil: a shutdown race is a clean stop, not lost change detection", lost)
			}
			if st.pending {
				t.Error("receive on a cancelled context armed the debounce; the loop is exiting and no scan can run")
			}
			if n := logs.Len(); n != 0 {
				t.Errorf("receive on a cancelled context logged %d record(s) (%v), want none: a shutdown must not look like watch degradation", n, logs.Messages())
			}
		})
	}
}

// TestHandleEventRecv_reattaches_a_directory_recreated_after_a_rename pins the
// Rename half of the forget-before-root-loss step. Its Remove twin
// (TestHandleEventRecv_reattaches_a_recreated_directory) covers only
// event.Has(fsnotify.Remove), so dropping the Rename half leaves the whole suite
// green while a directory renamed away (an operator moving example.com aside,
// or a rotation that renames rather than deletes) stays in the membership
// mirror: when the name is used again the guard reports it already watched, its
// subtree is never walked, and renewals under it are detected only by the
// periodic rescan -- never, with the fallback disabled.
//
// The oracle is the CHILD of the recreated directory: it was never registered
// before, so it can only appear in the watch list if the Create event actually
// re-walked the subtree.
func TestHandleEventRecv_reattaches_a_directory_recreated_after_a_rename(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	dir := filepath.Join(root, "example.com")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs(%q) = %v, want nil", root, err)
	}
	st := newWatchState(w)
	t.Cleanup(st.stop)

	if lost := w.handleEventRecv(t.Context(), watcher, st, fsnotify.Event{Name: dir, Op: fsnotify.Rename}, true); lost != nil {
		t.Fatalf("handleEventRecv(Rename %q) = %v, want nil (an ordinary rename is not lost change detection)", dir, lost)
	}
	if err := os.Rename(dir, filepath.Join(root, "example.com.bak")); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "nested")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatal(err)
	}

	if lost := w.handleEventRecv(t.Context(), watcher, st, fsnotify.Event{Name: dir, Op: fsnotify.Create}, true); lost != nil {
		t.Fatalf("handleEventRecv(Create %q) = %v, want nil", dir, lost)
	}

	if watched := watcher.WatchList(); !slices.Contains(watched, child) {
		t.Errorf("watch list after %q was renamed away and recreated = %v, want %q re-attached: a renamed-away path must be forgotten so its recreation is walked again",
			dir, watched, child)
	}
}

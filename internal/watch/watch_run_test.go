package watch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
	"github.com/fsnotify/fsnotify"
)

// TestRun_scans_once_with_the_watch_set_live pins the attach-then-scan contract of
// Run: after the watch set is registered it performs EXACTLY one scan, then blocks
// until shutdown and returns nil.
//
// Two separate guarantees, both load-bearing. The scan must happen after the watch
// set is live, or a renewal landing in the attach window is missed until the fallback
// tick. And there must be only one: Run owns exactly one post-attach startup scan, so
// /input is not scanned twice on container start, writing the health marker twice and
// emitting a duplicated startup "scan complete" pair.
func TestRun_scans_once_with_the_watch_set_live(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}
	scans := make(chan struct{}, 8)
	// No WithFallback: the periodic rescan is disarmed, so any second scan observed
	// below is a duplicate startup scan rather than a fallback tick.
	w := New(root, func(context.Context) { scans <- struct{}{} }, WithDebounce(20*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("Run did not scan after attaching the watch set; a renewal in the attach window would be missed until the fallback tick")
	}

	// Nothing has changed under root, so a second scan can only be a duplicate.
	select {
	case <-scans:
		cancel()
		t.Fatal("Run scanned twice on startup; the startup scan must happen exactly once")
	case <-time.After(300 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run(cancelled ctx) = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
	if len(scans) != 0 {
		t.Errorf("Run ran %d extra scans, want exactly one attach-then-scan pass", 1+len(scans))
	}
}

// TestRun_treats_a_shutdown_during_the_walk_as_a_clean_stop pins the shutdown
// branch of Run: when cancellation interrupts the watch-set walk, Run must
// return nil without falling back to polling, without starting a scan whose
// result would still drive the health marker, and without a WARN claiming the
// directories could not be watched.
// Not parallel: it swaps the process-global slog default.
func TestRun_treats_a_shutdown_during_the_walk_as_a_clean_stop(t *testing.T) {
	logs := capture.Default(t)

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}
	scans := 0
	w := New(root, func(context.Context) { scans++ }, WithFallback(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := w.Run(ctx); err != nil {
		t.Errorf("Run(cancelled ctx) = %v, want nil (a shutdown mid-walk is not a watch failure)", err)
	}
	if scans != 0 {
		t.Errorf("Run(cancelled ctx) ran %d scans, want 0", scans)
	}
	if logs.Count("failed to watch directories") != 0 {
		t.Errorf("Run(cancelled ctx) logged %v, want no watch-failure WARN: a shutdown mid-walk must not look like a degraded fallback to polling", logs.Messages())
	}
}

// TestScanThenWatch_skips_scan_after_shutdown pins the shutdown guard:
// with a watch set already live but ctx already cancelled, no scan may run
// (it would only log an interrupted scan and touch the health marker on the
// way out) and the helper returns nil.
func TestScanThenWatch_skips_scan_after_shutdown(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	scans := 0
	w := New(t.TempDir(), func(context.Context) { scans++ })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := w.scanThenWatch(ctx, watcher); err != nil {
		t.Errorf("scanThenWatch(cancelled ctx) = %v, want nil", err)
	}
	if scans != 0 {
		t.Errorf("scanThenWatch(cancelled ctx) ran %d scans, want 0", scans)
	}
}

// TestRun_upgrades_from_poll_to_watch_and_keeps_detecting_events pins the
// supervisor's mode transition end to end, the field path that matters most here:
// inotify exhaustion (or an /input not yet mounted) puts Run in poll mode, the
// condition clears without a restart, and the next poll tick must move the
// process into watch mode.
//
// It also pins the log contract across the restructure. The two mode entries
// announce themselves DIFFERENTLY and each exactly once -- the initial attempt
// WARNs that it is degrading, the retry reports the recovery at Info -- so the
// upgrade must not additionally emit the initial path's "fsnotify active" line,
// which is what a naive "make both entries call one announce" refactor would do.
// Not parallel: it swaps the newFSWatcher seam and the process-global slog default.
func TestRun_upgrades_from_poll_to_watch_and_keeps_detecting_events(t *testing.T) {
	logs := capture.Default(t)
	stubFSWatcherFailingOnce(t)

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}
	scanStarted := make(chan struct{}, 4)
	scanMayFinish := make(chan struct{})
	w := New(root, func(ctx context.Context) {
		scanStarted <- struct{}{}
		select {
		case <-scanMayFinish:
		case <-ctx.Done():
		}
	}, WithDebounce(10*time.Millisecond), WithFallback(20*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	select {
	case <-scanStarted:
		scanMayFinish <- struct{}{}
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("Run never ran the initial poll-mode scan")
	}

	select {
	case <-scanStarted:
		// The poll ticker has already returned its watcher, while scanThenWatch
		// is blocked in this callback. Lengthen only watch mode's fallback so
		// the next scan can only be caused by the cert event below.
		w.fallback = time.Hour
		scanMayFinish <- struct{}{}
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("Run never entered watch mode after fsnotify recovered")
	}

	if err := os.WriteFile(filepath.Join(root, "example.com", "tls.crt"), []byte("x"), 0o600); err != nil {
		cancel()
		t.Fatal(err)
	}
	select {
	case <-scanStarted:
		scanMayFinish <- struct{}{}
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("Run did not process a cert event after upgrading from poll to watch mode")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run(cancelled after upgrade) = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}

	if n := logs.CountLevel(slog.LevelWarn, "fsnotify unavailable, using polling"); n != 1 {
		t.Errorf("poll-mode entry logged %d times at WARN, want exactly 1; log = %v", n, logs.Messages())
	}
	if n := logs.Count("fsnotify recovered, upgrading from poll to watch"); n != 1 {
		t.Errorf("upgrade announced %d times, want exactly 1; log = %v", n, logs.Messages())
	}
	if n := logs.Count("fsnotify active"); n != 0 {
		t.Errorf("the upgrade path emitted the initial-attach line %d times, want 0: the recovery is announced by its own record", n)
	}
}

// TestWatchMode_states_the_post_watch_set_sequence_once pins the reason the
// supervisor exists: everything that happens once a watch set is live is stated
// in ONE place, so both mode entries observably behave the same. The two cases
// acquire a watcher through the two different sites -- Run's initial attach and
// poll mode's upgrade handback -- and then assert an identical post-acquisition
// sequence: the watch set is dumped once, exactly one scan runs with the set
// live (attach-then-scan, no duplicate from the acquiring side), the watch loop
// is live afterwards, and the watcher is closed on the way out.
//
// watchMode is the single statement of the post-acquisition sequence, so a second
// statement that scans twice, forgets the watch-set dump, or leaks the watcher fails
// here.
// Not parallel: it swaps the process-global slog default.
func TestWatchMode_states_the_post_watch_set_sequence_once(t *testing.T) {
	for _, tc := range []struct {
		name       string
		acquire    func(ctx context.Context, t *testing.T, w *Watcher) *fsnotify.Watcher
		wantBefore int // scans the acquisition itself performs, before watch mode
	}{
		{
			name: "initial attach",
			acquire: func(ctx context.Context, t *testing.T, w *Watcher) *fsnotify.Watcher {
				fw, stopped := w.attachWatchSet(ctx)
				if stopped || fw == nil {
					t.Fatalf("attachWatchSet = (%v, stopped=%v), want an attached watcher", fw, stopped)
				}
				return fw
			},
			wantBefore: 0,
		},
		{
			name: "poll-mode upgrade",
			acquire: func(ctx context.Context, t *testing.T, w *Watcher) *fsnotify.Watcher {
				// Poll mode's tick interval IS w.fallback, so it must be short here;
				// watch mode below needs it long, or its safety-net rescan would fire
				// on the same cadence and no scan count would be meaningful. Retuning
				// it at the mode boundary is only possible because the modes are now
				// separate calls rather than one nested inside the other.
				w.fallback = 20 * time.Millisecond
				fw, err := w.pollLoopWithUpgrade(ctx)
				if err != nil || fw == nil {
					t.Fatalf("pollLoopWithUpgrade = (%v, %v), want an upgraded watcher", fw, err)
				}
				w.fallback = time.Hour
				return fw
			},
			wantBefore: 1, // poll mode's initial scan
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
				t.Fatal(err)
			}
			scans := make(chan struct{}, 8)
			w := New(root, func(context.Context) { scans <- struct{}{} },
				WithDebounce(20*time.Millisecond), WithFallback(time.Hour))

			ctx, cancel := context.WithCancel(context.Background())
			watcher := tc.acquire(ctx, t, w)
			if n := len(scans); n != tc.wantBefore {
				cancel()
				t.Fatalf("acquisition ran %d scans, want %d", n, tc.wantBefore)
			}
			for range tc.wantBefore {
				<-scans
			}

			done := make(chan error, 1)
			go func() { done <- w.watchMode(ctx, watcher) }()

			select {
			case <-scans:
			case <-time.After(10 * time.Second):
				cancel()
				t.Fatal("watch mode did not scan with the watch set live; a renewal in the attach window would be missed until the fallback tick")
			}
			// The fallback is an hour and nothing changed, so a second scan here could
			// only be the acquiring side stating the sequence a second time.
			select {
			case <-scans:
				cancel()
				t.Fatal("watch mode scanned twice; the attach-then-scan must be stated exactly once")
			case <-time.After(300 * time.Millisecond):
			}
			// Counted HERE, before the cert write below: the attach-then-scan sequence is
			// stated exactly once. Every debounced scan afterwards re-asserts the watch
			// set (recovering a registration the kernel dropped without an event) and
			// refreshes this dump with it, which is a different statement.
			if n := logs.Count("fsnotify watch set"); n != 1 {
				t.Errorf("watch set dumped %d times during acquisition, want exactly 1; log = %v", n, logs.Messages())
			}

			// The watch loop is live: a cert write is detected as an event, not by the
			// (one-hour) safety-net rescan.
			if err := os.WriteFile(filepath.Join(root, "example.com", "tls.crt"), []byte("x"), 0o600); err != nil {
				cancel()
				t.Fatal(err)
			}
			select {
			case <-scans:
			case <-time.After(10 * time.Second):
				cancel()
				t.Fatal("no scan after a cert write; watch mode did not run the watch loop")
			}

			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("watchMode(cancelled ctx) = %v, want nil", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("watchMode did not return after ctx cancellation")
			}

			if n := logs.Count("fsnotify watch set"); n < 1 {
				t.Errorf("watch set never dumped; log = %v", logs.Messages())
			}
			// Close is the one resource release watch mode owns on every exit path.
			// An Add on a live watcher would succeed (and be idempotent).
			if err := watcher.Add(root); err == nil {
				t.Error("watchMode returned without closing the watcher; its fd and readEvents goroutine would outlive the mode")
			}
		})
	}
}

// TestAttachWatchSet_closes_the_watcher_it_could_not_give_a_watch_set pins the
// same release on Run's initial mode selection: a watcher whose watch set could
// not be built is closed HERE rather than handed back, because Run is about to
// enter a long-lived poll mode where that fd and readEvents goroutine would
// survive for the process's whole life. Every watcher this function DOES return is
// closed by watchMode, which is pinned above; the discarded one had no test.
//
// The seam hands out real watchers and records the one the attempt discards, which
// is the only way to observe a watcher the production path never returns; a closed
// watcher refuses Add.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestAttachWatchSet_closes_the_watcher_it_could_not_give_a_watch_set(t *testing.T) {
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
			_ = made.Close() // a watcher the attempt leaked must not outlive the test
		}
	})
	missingRoot := filepath.Join(t.TempDir(), "missing")
	w := New(missingRoot, func(context.Context) {}, WithFallback(time.Hour))

	watcher, stopped := w.attachWatchSet(t.Context())

	if watcher != nil {
		watcher.Close()
		t.Fatal("attachWatchSet(missing root) returned a watcher, want none so Run selects poll mode")
	}
	if stopped {
		t.Fatal("attachWatchSet(missing root) stopped = true, want false: an unwatchable root is a degradation, not a shutdown")
	}
	if made == nil {
		t.Fatal("attachWatchSet constructed no watcher; the watch-set-failure branch was not reached")
	}
	if err := made.Add(t.TempDir()); err == nil {
		t.Error("attachWatchSet handed Run into poll mode with the unattachable watcher still open; its fd and readEvents goroutine would outlive the attempt")
	}
}

// TestRun_reports_a_watch_mode_loss_to_the_caller pins the restart contract at
// Run's boundary: a watcher that dies while watch mode is running must surface
// the loss to the CALLER, not be swallowed or degraded back into poll mode.
// watchLoop's own loss exit is pinned, but nothing pinned that Run's supervisor
// hands it out: with the supervisor looping back to poll mode instead, main
// would never exit non-zero, so the container would keep the last clean scan's
// health marker while nothing detects a renewal -- the silent-healthy state this
// package is built to avoid.
// Not parallel: it swaps the package-level newFSWatcher seam.
func TestRun_reports_a_watch_mode_loss_to_the_caller(t *testing.T) {
	newTestWatcher(t) // availability probe: skips where inotify is unavailable
	prev := newFSWatcher
	made := make(chan *fsnotify.Watcher, 4)
	newFSWatcher = func() (*fsnotify.Watcher, error) {
		fw, err := prev()
		if err == nil {
			made <- fw
		}
		return fw, err
	}
	t.Cleanup(func() { newFSWatcher = prev })

	scanned := make(chan struct{}, 4)
	w := New(t.TempDir(), func(context.Context) { scanned <- struct{}{} },
		WithDebounce(20*time.Millisecond), WithFallback(time.Hour))

	done := make(chan error, 1)
	go func() { done <- w.Run(t.Context()) }()

	// The post-attach scan means watch mode is live, so the close below lands on
	// a running watch loop rather than during the attach.
	select {
	case <-scanned:
	case <-time.After(10 * time.Second):
		t.Fatal("Run never ran the post-attach scan; watch mode was not reached")
	}
	if err := (<-made).Close(); err != nil {
		t.Fatalf("watcher.Close() = %v", err)
	}

	select {
	case err := <-done:
		// Closing the watcher closes BOTH channels and watchLoop's select picks a
		// ready case at random, so either closure loss is correct here; a nil error
		// (the loss swallowed) or a neighbouring cause is not.
		if err != error(errEventsChannelClosed) && err != error(errErrorsChannelClosed) {
			t.Errorf("Run(watcher died in watch mode) = %v, want one of the channel-closure losses (%v / %v) so main exits non-zero and the container restarts with a fresh watcher",
				err, errEventsChannelClosed, errErrorsChannelClosed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the watcher died in watch mode; the process would keep reporting healthy while detecting no renewal")
	}
}

// TestAttachWatchSet_names_the_rescan_cadence_when_it_degrades_to_polling pins
// the fallback_scan attribute on the two WARNs that announce poll mode. It is
// the operator's only statement of whether anything will revisit /input while
// fsnotify is unusable -- "disabled" means nothing does for the life of the
// process -- and the same attribute is already pinned on this package's other
// degraded-path WARNs, so only the mode-entry pair could lose it silently.
// Not parallel: it swaps the process-global slog default and the newFSWatcher seam.
func TestAttachWatchSet_names_the_rescan_cadence_when_it_degrades_to_polling(t *testing.T) {
	for _, tc := range []struct {
		name         string
		msg          string
		unavailable  bool
		fallback     time.Duration
		wantFallback string
	}{
		{"an unusable fsnotify names the cadence", "fsnotify unavailable, using polling", true, 6 * time.Hour, "6h0m0s"},
		{"an unusable fsnotify reports a disabled rescan as disabled", "fsnotify unavailable, using polling", true, 0, "disabled"},
		{"an unwatchable root names the cadence", "failed to watch directories, using polling", false, 6 * time.Hour, "6h0m0s"},
		{"an unwatchable root reports a disabled rescan as disabled", "failed to watch directories, using polling", false, 0, "disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unavailable {
				stubFSWatcherUnavailable(t)
			} else {
				newTestWatcher(t) // availability probe: the root, not fsnotify, must fail here
			}
			logs := capture.Default(t)
			w := New(filepath.Join(t.TempDir(), "missing"), func(context.Context) {}, WithFallback(tc.fallback))

			watcher, stopped := w.attachWatchSet(t.Context())

			if watcher != nil {
				watcher.Close()
				t.Fatal("attachWatchSet returned a watcher, want none so Run selects poll mode")
			}
			if stopped {
				t.Fatal("attachWatchSet stopped = true, want false: an unusable watch set is a degradation, not a shutdown")
			}
			if n := logs.CountLevel(slog.LevelWarn, tc.msg); n != 1 {
				t.Fatalf("WARN %q logged %d times, want exactly 1; log = %v", tc.msg, n, logs.Messages())
			}
			got, ok := logs.AttrValue(tc.msg, "fallback_scan")
			if !ok {
				t.Fatalf("WARN %q carries no fallback_scan attribute; an operator cannot tell whether anything will revisit /input while fsnotify is unusable; log = %v", tc.msg, logs.Messages())
			}
			if got != tc.wantFallback {
				t.Errorf("WARN %q fallback_scan = %q with WithFallback(%v), want %q", tc.msg, got, tc.fallback, tc.wantFallback)
			}
		})
	}
}

// TestTryAttachWatchSet_rebuilds_the_membership_mirror_for_a_new_watcher pins
// the mirror reset every attach performs: each attach constructs a NEW fsnotify
// watcher whose registration set starts empty, so a path recorded for the
// previous, now-closed watcher must not be reported as watched under the new
// one. Without the reset the mirror claims a directory is watched that the new
// watcher never registered, handlePathEvent's membership guard skips the
// subtree re-walk on the strength of that claim, and every renewal underneath
// it is detected only by the periodic rescan -- never, with the fallback
// disabled.
//
// The oracle is a directory that goes away BETWEEN the two attaches, while no
// watch loop is running: no Remove event is ever delivered, so the event path's
// forgetWatch cannot cover it and only the reset can.
func TestTryAttachWatchSet_rebuilds_the_membership_mirror_for_a_new_watcher(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "example.com")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})

	first, stage, err := w.tryAttachWatchSet(t.Context())
	if stage != stageAttached || err != nil {
		t.Fatalf("setup: tryAttachWatchSet = (stage %v, %v), want stageAttached", stage, err)
	}
	if !w.watchSetHas(dir) {
		t.Fatalf("setup: %q is not in the membership mirror after the first attach", dir)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("setup: first.Close() = %v", err)
	}

	// The directory goes away while no watch loop is running, so no Remove event
	// is ever delivered and the event path cannot forget it.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	second, stage, err := w.tryAttachWatchSet(t.Context())
	if stage != stageAttached || err != nil {
		t.Fatalf("tryAttachWatchSet (re-attach) = (stage %v, %v), want stageAttached", stage, err)
	}
	t.Cleanup(func() { _ = second.Close() })

	if w.watchSetHas(dir) {
		t.Errorf("the membership mirror still claims %q is watched after a re-attach that did not register it", dir)
	}

	// The consequence: with the stale claim in place, the recreated directory
	// looks already-watched and its subtree is never walked again.
	child := filepath.Join(dir, "nested")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatal(err)
	}
	if got := w.handleFsEvent(t.Context(), second, fsnotify.Event{Name: dir, Op: fsnotify.Create}); !got {
		t.Error("handleFsEvent(Create of the recreated dir) = false, want true")
	}
	if watched := second.WatchList(); !slices.Contains(watched, child) {
		t.Errorf("watch list = %v, want %q attached: a directory the new watcher never registered must be walked again", watched, child)
	}
}

package watch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
// tick. And there must be only one: Run now owns the startup scan outright, because
// main used to scan before calling Run and the fsnotify path therefore scanned /input
// twice on every container start, writing the health marker twice and emitting a
// duplicated startup "scan complete" pair (deferred finding d-u5c6-1).
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

// TestScanThenWatch_skips_scan_after_shutdown pins the shutdown guard shared by
// both entry points into scanThenWatch: with a watch set already live but ctx
// already cancelled, no scan may run (it would only log an interrupted scan and
// touch the health marker on the way out) and the helper returns nil.
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
	scans := make(chan struct{}, 32)
	w := New(root, func(context.Context) { scans <- struct{}{} },
		WithDebounce(10*time.Millisecond), WithFallback(20*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for !logs.Contains("fsnotify recovered, upgrading from poll to watch") {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("Run never upgraded from poll to watch; log = %v", logs.Messages())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Watch mode's own attach-then-scan, which happens after poll mode has
	// returned: a scan must still arrive once the supervisor switched modes.
	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("no scan after the upgrade; the supervisor did not run watch mode over the watcher poll mode handed back")
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
// Before the restructure that sequence was stated twice (Run and pollTick), so a
// case could pass while its sibling drifted; a second statement that scans twice,
// forgets the watch-set dump, or leaks the watcher now fails here.
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

			if n := logs.Count("fsnotify watch set"); n != 1 {
				t.Errorf("watch set dumped %d times, want exactly 1; log = %v", n, logs.Messages())
			}
			// Close is the one resource release watch mode owns on every exit path.
			// An Add on a live watcher would succeed (and be idempotent).
			if err := watcher.Add(root); err == nil {
				t.Error("watchMode returned without closing the watcher; its fd and readEvents goroutine would outlive the mode")
			}
		})
	}
}

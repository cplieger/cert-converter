package watch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// TestWatchLoop_converts_a_real_cert_write_through_the_debounce is the first
// end-to-end coverage of the select wiring itself: a real inotify Write on a
// cert file inside the watched tree must reach onChange exactly once via the
// debounce timer, and the loop must return nil when the context is cancelled.
// The per-arm helpers are unit-tested individually, but nothing pins that they
// are actually wired into the loop's select.
func TestWatchLoop_converts_a_real_cert_write_through_the_debounce(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)

	root := t.TempDir()
	scans := make(chan struct{}, 8)
	w := New(root, func(context.Context) { scans <- struct{}{} }, WithDebounce(20*time.Millisecond))
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.watchLoop(ctx, watcher) }()

	if err := os.WriteFile(filepath.Join(root, "tls.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("watchLoop never ran a scan after a cert write; the fsnotify event or the debounce arm is not wired into the select")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("watchLoop(cancelled ctx) = %v, want nil (shutdown is not lost change detection)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watchLoop did not return after ctx cancellation")
	}
}

// TestWatchLoop_returns_ErrWatchLost_when_the_watcher_dies pins the liveness
// exit through the loop rather than through the helper: closing the watcher
// closes its Events channel under a live ctx, which must end the loop with
// ErrWatchLost so main exits non-zero and the container restarts with a fresh
// watcher instead of running forever with no change detection.
func TestWatchLoop_returns_ErrWatchLost_when_the_watcher_dies(t *testing.T) {
	t.Parallel()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	root := t.TempDir()
	w := New(root, func(context.Context) {}, WithDebounce(20*time.Millisecond))
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs = %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- w.watchLoop(t.Context(), watcher) }()

	if err := watcher.Close(); err != nil {
		t.Fatalf("watcher.Close() = %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, ErrWatchLost) {
			t.Errorf("watchLoop(dead watcher) = %v, want ErrWatchLost", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watchLoop did not return after the watcher died; the process would keep running with no change detection")
	}
}

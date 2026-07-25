package watch

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

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
	if logged := buf.String(); strings.Contains(logged, "failed to watch directories") {
		t.Errorf("Run(cancelled ctx) logged %q, want no watch-failure WARN: a shutdown mid-walk must not look like a degraded fallback to polling", logged)
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

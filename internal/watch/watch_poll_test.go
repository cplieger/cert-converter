package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
)

// TestPollLoopWithUpgrade_upgrades_to_fsnotify_and_scans_first pins the poll
// mode recovery path: on a tick where fsnotify becomes available again the
// watch set is rebuilt, a scan runs with it already live (attach-then-scan, so a
// renewal during the scan still produces an event), and control hands off to the
// watch loop, which returns nil on shutdown. Runs serially (no t.Parallel): it
// swaps the process-global slog default to read the upgrade log line.
func TestPollLoopWithUpgrade_upgrades_to_fsnotify_and_scans_first(t *testing.T) {
	logs := capture.Default(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}
	scans := make(chan struct{}, 8)
	w := New(root, func(context.Context) { scans <- struct{}{} },
		WithDebounce(20*time.Millisecond), WithFallback(20*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.pollLoopWithUpgrade(ctx) }()

	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("pollLoopWithUpgrade never scanned; neither the poll tick nor the upgrade path ran")
	}

	// Only the upgrade branch logs this, and it logs it before handing off to
	// watchLoop, so the record exists by the time that first scan lands. A scan
	// alone proves nothing here: the poll tick and the watch loop's own fallback
	// tick both scan on the same 20ms interval, so a build that never upgraded
	// would keep feeding this channel forever.
	if !logs.Contains("fsnotify recovered, upgrading from poll to watch") {
		cancel()
		t.Fatalf("pollLoopWithUpgrade scanned but never upgraded; log = %v", logs.Messages())
	}

	// The upgrade handed off to watchLoop, so a real cert write is now detected
	// as an event rather than waiting for the next poll tick.
	if err := os.WriteFile(filepath.Join(root, "example.com", "tls.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-scans:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("no scan after a cert write; pollLoopWithUpgrade did not hand off to the watch loop")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("pollLoopWithUpgrade(cancelled ctx) = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pollLoopWithUpgrade did not return after ctx cancellation")
	}
}

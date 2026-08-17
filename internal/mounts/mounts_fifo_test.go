package mounts

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
)

// TestVerify_refuses_a_fifo_at_a_required_mount_path pins the ONE ordering
// openMount cannot state in code: os.Stat decides the type, and it decides it
// BEFORE os.OpenRoot, because open(2) on a FIFO with no writer blocks and
// os.OpenRoot opens the name before it fstats it. Startup runs before
// signal.NotifyContext and after the marker is unlinked, so a fold of the type
// check into the open's error parks the container with no record, no marker and
// no exit code. A bind-mounted FIFO is the shape openMount's own remediation
// names. Deadline-bounded rather than asserting a duration: it fails closed,
// with a message, and cannot flake into a false pass.
// Serial (no t.Parallel): it swaps the process-global slog default.
func TestVerify_refuses_a_fifo_at_a_required_mount_path(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "input")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported on this platform: %v", err)
	}
	_ = capture.Default(t)

	done := make(chan bool, 1)
	go func() { done <- Verify(Paths{Input: fifo, Output: t.TempDir()}) }()
	select {
	case ready := <-done:
		if ready {
			t.Error("Verify accepted a FIFO at a required mount path")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Verify blocked in open(2) on a FIFO at a required mount path: the type check no longer precedes the open")
	}
}

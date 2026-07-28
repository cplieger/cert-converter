package process

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSourcePathVanished_reports_an_unclassifiable_path_as_steady_state pins
// pathVanished's fallback arm, the one its godoc states and no test reaches: any
// Lstat failure that is NOT ENOENT answers false, so an /input path the scan cannot
// even classify is reported as the steady-state condition (Warn plus the unreadable
// count the documented alert keys on) rather than as the transient renewal race
// (Debug only, health green, no default-level line). Inverting it would leave such a
// certificate producing no PFX forever with nothing naming it.
//
// A regular file standing in for a path component is the reachable non-ENOENT
// failure: the confined Lstat answers ENOTDIR, which satisfies neither fs.ErrNotExist
// nor the surviving-symlink arm.
func TestSourcePathVanished_reports_an_unclassifiable_path_as_steady_state(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s := &source{root: root}

	if s.pathVanished("plain/tls.crt") {
		t.Error("source.pathVanished(path under a non-directory) = true, want false: " +
			"an input the scan cannot even classify is the steady-state condition an operator " +
			"must hear about, not the transient renewal race")
	}
}

func TestSourceReadBounded(t *testing.T) {
	t.Parallel()
	t.Run("reads file within limit through root", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "in.pem"), []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		s := &source{root: root}
		data, err := s.readBoundedLimit(t.Context(), "in.pem", 1024)
		if err != nil {
			t.Fatalf("source.readBoundedLimit: %v", err)
		}
		if !bytes.Equal(data, []byte("hello")) {
			t.Errorf("got %q, want %q", data, "hello")
		}
	})

	t.Run("rejects oversized file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "big.pem"), make([]byte, 2048), 0o644); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		s := &source{root: root}
		if _, err := s.readBoundedLimit(t.Context(), "big.pem", 1024); err == nil {
			t.Error("expected error for oversized file")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		s := &source{root: root}
		// errors.Is, not merely non-nil: noteUnreadableInput splits the transient
		// renewal race from a steady-state unreadable input on exactly
		// errors.Is(err, fs.ErrNotExist) over THIS error. A wrapper anywhere in the
		// confined-read path that drops the chain (a %v instead of a %w) sends every
		// vanished cert down the Warn arm and back into the alerted unreadable count,
		// which is the false page the vanished classification exists to prevent -- and
		// a bare non-nil assertion cannot see it.
		_, err = s.readBoundedLimit(t.Context(), "missing.pem", 1024)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source.readBoundedLimit(nonexistent file) error = %v, want it to satisfy errors.Is(err, fs.ErrNotExist)", err)
		}
	})

	t.Run("confines a symlink escaping the root", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink semantics differ on Windows")
		}
		t.Parallel()
		// The security guarantee under test: a symlink planted in the
		// watched directory that points outside it must not leak the target.
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("top secret"), 0o644); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "leak.pem")); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		s := &source{root: root}
		if _, err := s.readBoundedLimit(t.Context(), "leak.pem", 1024); err == nil {
			t.Fatal("source.readBoundedLimit followed a symlink escaping the root; want a confinement error")
		}
	})

	t.Run("refuses a parent-directory traversal in rel", func(t *testing.T) {
		t.Parallel()
		// The other half of the confinement contract: the read must not escape
		// through a ".." component either, which is why the open goes through
		// the *os.Root instead of filepath.Join + os.Open.
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "secret.pem"), []byte("top secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		dir, err := os.MkdirTemp(outside, "watched")
		if err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		s := &source{root: root}

		data, err := s.readBoundedLimit(t.Context(), "../secret.pem", 1024)
		if err == nil {
			t.Fatalf("source.readBoundedLimit(%q) read %d bytes; want a confinement error", "../secret.pem", len(data))
		}
		if bytes.Contains(data, []byte("top secret")) {
			t.Error("source.readBoundedLimit returned content from outside the root")
		}
	})

	t.Run("rejects a non-regular file without blocking", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("mkfifo is not available on Windows")
		}
		t.Parallel()
		// The guarantee under test: open(2) on a FIFO with no writer blocks
		// forever, and the scan runs on the watch loop's only goroutine, so a
		// FIFO planted in the watched tree must be rejected, not waited on.
		dir := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(dir, "evil.crt"), 0o600); err != nil {
			t.Fatalf("setup: mkfifo: %v", err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		s := &source{root: root}

		done := make(chan error, 1)
		go func() {
			_, readErr := s.readBoundedLimit(t.Context(), "evil.crt", 1024)
			done <- readErr
		}()
		select {
		case readErr := <-done:
			if readErr == nil {
				t.Fatal("source.readBoundedLimit read a FIFO; want a not-a-regular-file error")
			}
			if !strings.Contains(readErr.Error(), "not a regular file") {
				t.Errorf("source.readBoundedLimit(FIFO) error = %q, want it to mention %q",
					readErr.Error(), "not a regular file")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("source.readBoundedLimit blocked on a FIFO; the O_NONBLOCK open regressed")
		}
	})
}

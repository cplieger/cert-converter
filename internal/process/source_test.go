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

	"github.com/cplieger/atomicfile/v2"
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
	s := newInputSource(t, dir)

	if s.pathVanished("plain/tls.crt") {
		t.Error("source.pathVanished(path under a non-directory) = true, want false: " +
			"an input the scan cannot even classify is the steady-state condition an operator " +
			"must hear about, not the transient renewal race")
	}
}

// TestSourcePathAbsent pins the primitive the orphan reap deletes on. Every arm is a
// deletion decision over private key material, and only the first one may answer
// "absent": the re-check runs after a deferral window in which a producer may have
// rewritten the certificate, and any answer the confined Lstat cannot make with
// certainty has to keep the bundle.
func TestSourcePathAbsent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "back.crt"), []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A regular file standing in for a path component: the confined Lstat answers
	// ENOTDIR, the reachable non-ENOENT failure.
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nowhere", filepath.Join(dir, "dangling.crt")); err != nil {
		t.Fatal(err)
	}
	s := newInputSource(t, dir)

	for _, tc := range []struct {
		rel     string
		want    bool
		wantErr bool
		why     string
	}{
		{"missing.crt", true, false, "an ENOENT path is the durable absence the reap needs"},
		{"back.crt", false, false, "a certificate that is present must keep its bundle, which is the case " +
			"pathVanished would have answered true for"},
		{"dangling.crt", false, false, "a symlink whose target is missing is still an entry in the operator's tree"},
		{"plain/tls.crt", false, true, "a path the scan cannot classify is not proof of absence, and the " +
			"failure must reach the caller so the retention is not narrated as a positive observation"},
	} {
		t.Run(tc.rel, func(t *testing.T) {
			t.Parallel()
			got, err := s.pathAbsent(tc.rel)
			if got != tc.want {
				t.Errorf("source.pathAbsent(%q) = %v, want %v: %s", tc.rel, got, tc.want, tc.why)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("source.pathAbsent(%q) error = %v, want error: %v: %s", tc.rel, err, tc.wantErr, tc.why)
			}
		})
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
		s := newInputSource(t, dir)
		data, err := s.readBoundedLimit(t.Context(), "in.pem", 1024)
		if err != nil {
			t.Fatalf("source.readBoundedLimit: %v", err)
		}
		if !bytes.Equal(data, []byte("hello")) {
			t.Errorf("got %q, want %q", data, "hello")
		}
	})

	// maxFileSize (10 MB) is the documented /input bound, and readBoundedLimit's limit
	// parameter exists so that boundary is testable without a 10 MB fixture per case.
	// The bound is INCLUSIVE: a file exactly at the limit must read whole, or a
	// certificate at the documented maximum becomes a conversion failure that flips
	// health -- which a fixture well over the limit can never see.
	t.Run("reads a file exactly at the limit", func(t *testing.T) {
		t.Parallel()
		const limit = 1024
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "exact.pem"), make([]byte, limit), 0o600); err != nil {
			t.Fatal(err)
		}
		s := newInputSource(t, dir)

		data, err := s.readBoundedLimit(t.Context(), "exact.pem", limit)
		if err != nil {
			t.Fatalf("source.readBoundedLimit(file of exactly %d bytes, limit %d) = error %v, want the file read whole: the bound is inclusive",
				limit, limit, err)
		}
		if len(data) != limit {
			t.Errorf("source.readBoundedLimit(file of exactly %d bytes) read %d bytes, want %d", limit, len(data), limit)
		}
	})

	t.Run("refuses a file one byte over the limit", func(t *testing.T) {
		t.Parallel()
		const limit = 1024
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "big.pem"), make([]byte, limit+1), 0o600); err != nil {
			t.Fatal(err)
		}
		s := newInputSource(t, dir)

		// errors.Is on atomicfile's sentinel, not a bare non-nil, for the same reason
		// the missing-file case below argues: a read that failed for any OTHER reason (a
		// rejected path, a file that vanished, a non-regular file) satisfies non-nil
		// while proving nothing about the size bound -- and the bound is what stops one
		// oversized input from spending the scan's only goroutine.
		if _, err := s.readBoundedLimit(t.Context(), "big.pem", limit); !errors.Is(err, atomicfile.ErrFileTooLarge) {
			t.Errorf("source.readBoundedLimit(file of %d bytes, limit %d) error = %v, want it to satisfy errors.Is(err, atomicfile.ErrFileTooLarge)",
				limit+1, limit, err)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		s := newInputSource(t, dir)
		// errors.Is, not merely non-nil: noteUnreadableInput splits the transient
		// renewal race from a steady-state unreadable input on exactly
		// errors.Is(err, fs.ErrNotExist) over THIS error. A wrapper anywhere in the
		// confined-read path that drops the chain (a %v instead of a %w) sends every
		// vanished cert down the Warn arm and back into the alerted unreadable count,
		// which is the false page the vanished classification exists to prevent -- and
		// a bare non-nil assertion cannot see it.
		_, err := s.readBoundedLimit(t.Context(), "missing.pem", 1024)
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
		s := newInputSource(t, dir)
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
		s := newInputSource(t, dir)

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
		s := newInputSource(t, dir)

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

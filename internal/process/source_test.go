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

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/go/filesafe"
)

// TestSourcePathVanished_reports_an_unclassifiable_path_as_steady_state pins
// pathVanished's fallback arm: any Lstat failure that is NOT ENOENT answers false, so
// an /input path the scan cannot even classify is the steady-state condition (Warn
// plus the unreadable count) rather than the transient renewal race (Debug only).
// Inverting it would leave such a certificate producing no PFX with nothing naming
// it. A regular file standing in for a path component makes the confined Lstat
// answer ENOTDIR, which satisfies neither fs.ErrNotExist nor the symlink arm.
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

// TestSourceJudge pins the re-check's judgement of a source or key path, the
// primitive the orphan reap deletes on. Only a path that cannot exist inside the
// input root may read Absent: the re-check runs after a deferral window in which
// a producer may have rewritten the certificate, and any path it cannot resolve
// has to keep the bundle.
func TestSourceJudge(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	dir, outside := filepath.Join(base, "input"), filepath.Join(base, "outside")
	for _, d := range []string{dir, outside, filepath.Join(dir, "a"), filepath.Join(dir, "occupied.crt")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"back.crt", "plain", filepath.Join("a", "site.crt")} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("cert"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{
		"dangling.crt": "nowhere",
		"escaping.crt": filepath.Join(outside, "real.crt"),
		"out":          outside,
		"through.crt":  "out/real.crt",
		"b":            "a",
		"filed.crt":    "plain/real.crt",
	} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	s := newInputSource(t, dir)

	for _, tc := range []struct {
		rel     string
		why     string
		want    verdict
		wantErr bool
	}{
		{rel: "missing.crt", want: verdictAbsent, why: "no entry is the durable absence the reap needs"},
		{rel: "back.crt", want: verdictPresent, why: "a certificate that is present must keep its bundle"},
		{rel: "dangling.crt", want: verdictAbsent, why: "a link to a name missing inside the root is as gone as a deleted file"},
		{rel: "escaping.crt", want: verdictUnproven, wantErr: true, why: "a link out of the root proves nothing"},
		{rel: "through.crt", want: verdictUnproven, wantErr: true, why: "a link through a link out of the root proves nothing"},
		{rel: "b/site.crt", want: verdictAbsent, why: "a path under an alias of a walked directory is not an input"},
		{rel: "plain/tls.crt", want: verdictAbsent, why: "a path through a regular file cannot exist"},
		{rel: "filed.crt", want: verdictAbsent, why: "a link whose target runs through a regular file cannot resolve"},
		{rel: "occupied.crt", want: verdictMismatch, wantErr: true, why: "a directory at a source name proves nothing"},
	} {
		t.Run(tc.rel, func(t *testing.T) {
			t.Parallel()
			got, err := s.judge(tc.rel)
			if got != tc.want {
				t.Errorf("source.judge(%q) = %d, want %d: %s", tc.rel, got, tc.want, tc.why)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("source.judge(%q) error = %v, want error: %v: the reason must reach the caller so a retention is not narrated as a positive observation", tc.rel, err, tc.wantErr)
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
		data, err := s.readBounded(t.Context(), "in.pem")
		if err != nil {
			t.Fatalf("source.readBounded: %v", err)
		}
		if !bytes.Equal(data, []byte("hello")) {
			t.Errorf("got %q, want %q", data, "hello")
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
		_, err := s.readBounded(t.Context(), "missing.pem")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("source.readBounded(nonexistent file) error = %v, want it to satisfy errors.Is(err, fs.ErrNotExist)", err)
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
		if _, err := s.readBounded(t.Context(), "leak.pem"); err == nil {
			t.Fatal("source.readBounded followed a symlink escaping the root; want a confinement error")
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

		data, err := s.readBounded(t.Context(), "../secret.pem")
		if err == nil {
			t.Fatalf("source.readBounded(%q) read %d bytes; want a confinement error", "../secret.pem", len(data))
		}
		if bytes.Contains(data, []byte("top secret")) {
			t.Error("source.readBounded returned content from outside the root")
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
			_, readErr := s.readBounded(t.Context(), "evil.crt")
			done <- readErr
		}()
		select {
		case readErr := <-done:
			if readErr == nil {
				t.Fatal("source.readBounded read a FIFO; want a not-a-regular-file error")
			}
			if !strings.Contains(readErr.Error(), "not a regular file") {
				t.Errorf("source.readBounded(FIFO) error = %q, want it to mention %q",
					readErr.Error(), "not a regular file")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("source.readBounded blocked on a FIFO; the O_NONBLOCK open regressed")
		}
	})

	t.Run("refuses a file above the documented /input cap", func(t *testing.T) {
		t.Parallel()
		// The app-owned half of the read contract: readBounded takes no limit
		// parameter, so the only thing pinning the documented /input cap to the
		// production call is this case. A wiring change to an effectively unbounded
		// limit passes every other subtest here.
		//
		// Sparse: Truncate sets the SIZE filesafe stats off the open handle without
		// allocating convert.MaxInputBytes bytes, so the refusal is observed for the cost of an
		// empty file. The exact-boundary semantics belong to filesafe's own suite.
		dir := t.TempDir()
		f, err := os.Create(filepath.Join(dir, "huge.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(convert.MaxInputBytes + 1); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		s := newInputSource(t, dir)

		data, err := s.readBounded(t.Context(), "huge.pem")
		if !errors.Is(err, filesafe.ErrFileTooLarge) {
			t.Errorf("source.readBounded(a %d-byte file) = %d bytes, error %v; want it to satisfy"+
				" errors.Is(err, filesafe.ErrFileTooLarge): the production call must apply convert.MaxInputBytes (%d)",
				convert.MaxInputBytes+1, len(data), err, convert.MaxInputBytes)
		}
	})
}

func TestSourceReadBundleBoundedUsesBundleSizeDomain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inside := filepath.Join(dir, "inside.pfx")
	f, err := os.Create(inside)
	if err != nil {
		t.Fatalf("setup: create inside.pfx: %v", err)
	}
	if err := f.Truncate(convert.MaxInputBytes + 1); err != nil {
		_ = f.Close()
		t.Fatalf("setup: truncate inside.pfx: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("setup: close inside.pfx: %v", err)
	}
	s := newInputSource(t, dir)
	data, err := s.readBundleBounded(t.Context(), "inside.pfx")
	if err != nil {
		t.Fatalf("source.readBundleBounded(%d-byte bundle) = %v, want nil: output-sized PFX must be valid input", convert.MaxInputBytes+1, err)
	}
	if len(data) != convert.MaxInputBytes+1 {
		t.Errorf("source.readBundleBounded(%d-byte bundle) read %d bytes", convert.MaxInputBytes+1, len(data))
	}

	outside := filepath.Join(dir, "outside.pfx")
	f, err = os.Create(outside)
	if err != nil {
		t.Fatalf("setup: create outside.pfx: %v", err)
	}
	if err := f.Truncate(convert.MaxBundleBytes + 1); err != nil {
		_ = f.Close()
		t.Fatalf("setup: truncate outside.pfx: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("setup: close outside.pfx: %v", err)
	}
	if _, err := s.readBundleBounded(t.Context(), "outside.pfx"); !errors.Is(err, filesafe.ErrFileTooLarge) {
		t.Errorf("source.readBundleBounded(%d-byte bundle) = %v, want ErrFileTooLarge", convert.MaxBundleBytes+1, err)
	}
}

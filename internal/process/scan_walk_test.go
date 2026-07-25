package process

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestScanWalkVisit_classifies_walk_errors pins the /input walk's error triage
// directly, without depending on mode bits: a failure at the root (".") aborts
// the scan so Run reports it and health flips, a failure below the root counts
// one unreadable sub-path and continues so the readable certs still convert, and
// a cancelled context aborts between entries. Collapsing the root case into the
// sub-path case would turn a vanished /input mount into a silently "successful"
// scan; collapsing the sub-path case into the root case would make one
// mis-permissioned cert directory abort every scan.
func TestScanWalkVisit_classifies_walk_errors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")

	t.Run("an error at the root aborts the walk", func(t *testing.T) {
		t.Parallel()
		sw := &scanWalk{seen: make(map[string]struct{})}
		if got := sw.visit(t.Context(), ".", nil, sentinel); !errors.Is(got, sentinel) {
			t.Errorf("visit(\".\", err) = %v, want the walk error so the scan aborts", got)
		}
		if sw.unreadable != 0 {
			t.Errorf("visit(\".\", err) unreadable = %d, want 0 (a root failure is not an unreadable sub-path)", sw.unreadable)
		}
	})

	t.Run("an error below the root is counted and skipped", func(t *testing.T) {
		t.Parallel()
		sw := &scanWalk{seen: make(map[string]struct{})}
		if got := sw.visit(t.Context(), "locked/tls.crt", nil, sentinel); got != nil {
			t.Errorf("visit(\"locked/tls.crt\", err) = %v, want nil so the walk continues", got)
		}
		if sw.unreadable != 1 {
			t.Errorf("visit(sub-path, err) unreadable = %d, want 1", sw.unreadable)
		}
		if len(sw.results) != 0 || len(sw.seen) != 0 {
			t.Errorf("visit(sub-path, err) results/seen = %d/%d, want 0/0 (an unreadable path is not a pair outcome)",
				len(sw.results), len(sw.seen))
		}
	})

	t.Run("a cancelled context aborts the walk", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		sw := &scanWalk{seen: make(map[string]struct{})}
		if got := sw.visit(ctx, "anything.crt", nil, nil); !errors.Is(got, context.Canceled) {
			t.Errorf("visit(cancelled ctx) = %v, want context.Canceled", got)
		}
		if len(sw.seen) != 0 {
			t.Errorf("visit(cancelled ctx) seen = %d, want 0 (no entry may be recorded after cancellation)", len(sw.seen))
		}
	})
}

// TestOutputIsCurrent_regenerates_when_the_output_stat_fails pins the third arm
// of the output-side skip gate. A fingerprint hit whose output Lstat fails for a
// reason other than ENOENT -- an output subdirectory swapped for a symlink out
// of the volume, which the confined root refuses -- must force a reconvert (so
// the write either restores a real PFX or fails the entry and reports
// unhealthy) and must say so distinctly: the return value is identical to the
// "missing" arm, so the log line is the only observable difference and the only
// thing that tells an operator the path was refused rather than absent. Runs
// serially: it swaps slog.Default().
func TestOutputIsCurrent_regenerates_when_the_output_stat_fails(t *testing.T) {
	base := t.TempDir()
	outDir := filepath.Join(base, "out")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{outDir, outside} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "tls.pfx"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(outDir, "swapped")); err != nil {
		t.Fatal(err)
	}
	outHandle, err := os.OpenRoot(outDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outHandle.Close() })

	const (
		certRel     = "swapped/tls.crt"
		pfxRel      = "swapped/tls.pfx"
		fingerprint = "cafebabe"
	)
	sw := &scanWalk{cache: newHashCache(), outHandle: outHandle}
	sw.cache.record(certRel, fingerprint)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if sw.outputIsCurrent(certRel, pfxRel, fingerprint) {
		t.Error("outputIsCurrent(refused output path) = true, want false: an output the confined root refuses to stat must never satisfy the skip gate")
	}
	out := buf.String()
	if !strings.Contains(out, "output PFX stat failed") {
		t.Errorf("outputIsCurrent(refused output path) logged %q, want the distinct stat-failure line (not the missing-output one)", out)
	}
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("outputIsCurrent(refused output path) logged %q, want level WARN", out)
	}
}

// cancelAfterFirstCheck reports "not cancelled" on its first Err() observation
// and "cancelled" on every later one, which is exactly the shape of a SIGTERM
// that lands while a cert is being converted: the walk's entry guard already
// passed, so only the post-conversion re-check can notice it.
type cancelAfterFirstCheck struct{ checks int }

func (*cancelAfterFirstCheck) Deadline() (deadline time.Time, ok bool) { return time.Time{}, false }
func (*cancelAfterFirstCheck) Done() <-chan struct{}                   { return nil }
func (*cancelAfterFirstCheck) Value(any) any                           { return nil }

func (c *cancelAfterFirstCheck) Err() error {
	c.checks++
	if c.checks == 1 {
		return nil
	}
	return context.Canceled
}

// TestScanWalkVisit_cancellation_during_conversion_aborts_the_walk pins the
// second context check in visit. A cancellation that lands mid-conversion turns
// that entry into statusFailed, so without the re-check the walk would finish
// normally and Run would report a "completed" scan whose failed count is really
// a shutdown artifact -- main.go then logs an ERROR and marks the container
// unhealthy on a clean stop. The entry must still be recorded (seen + one
// result) so the cache is not pruned against a partial set.
func TestScanWalkVisit_cancellation_during_conversion_aborts_the_walk(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(certsRoot, "late.crt"), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "late.key"), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	inHandle, err := os.OpenRoot(certsRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inHandle.Close() })
	outHandle, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outHandle.Close() })

	fi, err := os.Lstat(filepath.Join(certsRoot, "late.crt"))
	if err != nil {
		t.Fatal(err)
	}
	sw := &scanWalk{cache: newHashCache(), inHandle: inHandle, outHandle: outHandle, seen: make(map[string]struct{})}

	got := sw.visit(&cancelAfterFirstCheck{}, "late.crt", fs.FileInfoToDirEntry(fi), nil)

	if !errors.Is(got, context.Canceled) {
		t.Errorf("visit(cancelled during conversion) = %v, want context.Canceled so Run reports the shutdown instead of a completed scan", got)
	}
	if len(sw.results) != 1 {
		t.Errorf("visit(cancelled during conversion) results = %d, want 1 (the entry's outcome must still be recorded)", len(sw.results))
	}
	if _, ok := sw.seen["late.crt"]; !ok {
		t.Error("visit(cancelled during conversion) did not record the entry as seen; an unseen entry would be pruned from the cache")
	}
}

// TestNoteUnwalkableSymlink_reports_resolution_outcomes pins both meaningful
// arms of the symlink notice: a link the confined root refuses to resolve is
// the only operator-visible signal that a linked certificate subtree is
// invisible (WARN), while an in-root directory link whose real target the walk
// reaches anyway is merely tracing detail (DEBUG). Runs serially: it swaps
// slog.Default().
func TestNoteUnwalkableSymlink_reports_resolution_outcomes(t *testing.T) {
	base := t.TempDir()
	input := filepath.Join(base, "input")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{input, outside, filepath.Join(input, "target")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"escape": outside, "inside": "target"} {
		if err := os.Symlink(target, filepath.Join(input, name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	sw := &scanWalk{inHandle: root}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for _, tt := range []struct{ name, wantMessage, wantLevel string }{
		{"escape", "skipping symlink that could not be resolved through the input root", "level=WARN"},
		{"inside", "skipping symlinked directory; its target is walked directly", "level=DEBUG"},
	} {
		buf.Reset()
		fi, err := os.Lstat(filepath.Join(input, tt.name))
		if err != nil {
			t.Fatal(err)
		}
		sw.noteUnwalkableSymlink(tt.name, fs.FileInfoToDirEntry(fi))
		out := buf.String()
		if !strings.Contains(out, tt.wantMessage) || !strings.Contains(out, tt.wantLevel) {
			t.Errorf("noteUnwalkableSymlink(%q) logged %q, want message %q at %s", tt.name, out, tt.wantMessage, tt.wantLevel)
		}
	}
}

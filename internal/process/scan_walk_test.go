package process

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
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

	t.Run("an ENOENT below the root is the renewal race, not an unreadable path", func(t *testing.T) {
		t.Parallel()
		sw := &scanWalk{seen: make(map[string]struct{})}
		if got := sw.visit(t.Context(), "renewing", nil, fs.ErrNotExist); got != nil {
			t.Errorf("visit(sub-path, ENOENT) = %v, want nil so the walk continues", got)
		}
		if sw.vanished != 1 {
			t.Errorf("visit(sub-path, ENOENT) vanished = %d, want 1", sw.vanished)
		}
		if sw.unreadable != 0 {
			t.Errorf("visit(sub-path, ENOENT) unreadable = %d, want 0: a directory removed under the walk must not raise the documented unreadable= alert, whose remediation points at /input permissions",
				sw.unreadable)
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

// TestStoreIsCurrent_degrades_when_the_output_cannot_be_inspected pins a DELIBERATE
// reversal. This test previously required an ERROR when the confined root refused to stat
// a prior output, on the reasoning that a refusal is evidence the output tree cannot be
// inspected and should therefore be reported rather than papered over.
//
// The reversal: isCurrent answers exactly one question — "is the file on disk already the
// bundle these inputs produce?" — and "I cannot tell" answers it. Treating it as stale and
// rewriting is both correct and self-healing for the realistic cause, a root-owned .pfx
// left by a deployment that predates the user: mapping. Erroring instead flipped the pair
// to statusFailed and pinned the container unhealthy over something the app can fix itself.
//
// The old objection — that this silently rewrites forever and hides a broken output mount
// — does not hold, and the second half of this test is why: the WRITE goes through the
// same confined root, so a genuinely broken tree fails at the write, which DOES flip
// health. The honest signal moves from the read to the write rather than disappearing.
// Runs serially: it swaps slog.Default().
func TestStoreIsCurrent_degrades_when_the_output_cannot_be_inspected(t *testing.T) {
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
	s := newOutputStore(t, outDir)

	current, _, err := s.isCurrent(t.Context(), "swapped/tls.pfx", &convert.Analysis{}, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("isCurrent(uninspectable output) = %v, want nil: an unreadable prior output is stale, not fatal", err)
	}
	if current {
		t.Error("isCurrent(uninspectable output) = true; a bundle that cannot be inspected must never be reported current")
	}

	// The other half: the tree really is broken, so the rewrite this returns false to
	// authorise must itself fail. That is what keeps health honest.
	if writeErr := s.write(t.Context(), "swapped/tls.pfx", []byte("bundle")); writeErr == nil {
		t.Error("store.write(through a symlink out of the root) = nil error; the confined write must refuse it, or the degrade WOULD hide a broken output mount")
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
	fi, err := os.Lstat(filepath.Join(certsRoot, "late.crt"))
	if err != nil {
		t.Fatal(err)
	}
	sw := &scanWalk{src: &source{root: inHandle}, out: newOutputStore(t, t.TempDir()), seen: make(map[string]struct{})}

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
	sw := &scanWalk{src: &source{root: root}}

	for _, tt := range []struct {
		name, wantMessage string
		wantLevel         slog.Level
	}{
		{"escape", "skipping symlink that could not be resolved through the input root", slog.LevelWarn},
		{"inside", "skipping symlinked directory; its target is walked directly", slog.LevelDebug},
	} {
		// A fresh recorder per case, replacing the buffer reset the text handler needed.
		logs := captureLogs(t)
		fi, err := os.Lstat(filepath.Join(input, tt.name))
		if err != nil {
			t.Fatal(err)
		}
		sw.noteUnwalkableSymlink(tt.name, fs.FileInfoToDirEntry(fi))
		if got := logs.CountLevel(tt.wantLevel, tt.wantMessage); got != 1 {
			t.Errorf("noteUnwalkableSymlink(%q) logged %q, want message %q at %s", tt.name, logs.Messages(), tt.wantMessage, tt.wantLevel)
		}
	}
}

// TestNoteUnwalkableSymlink_stays_silent_where_nothing_is_hidden pins the
// silence half of the symlink notice, which its message assertions cannot cover.
// A dangling link whose target stays inside the root hides no certificates, and
// a symlinked .crt or .key is already classified and logged by convertEntry, so
// neither may produce a second line. The warning suppressed here is the one the
// README's CertConverterInputSymlinkSkipped alert keys on, so a false positive
// pages an operator over a link that costs nothing. The final case is the
// control: an unresolvable non-cert link must still warn, so the test cannot
// pass by silencing everything. Runs serially: it swaps slog.Default().
func TestNoteUnwalkableSymlink_stays_silent_where_nothing_is_hidden(t *testing.T) {
	base := t.TempDir()
	input := filepath.Join(base, "input")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{input, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		// A dangling link whose target stays INSIDE the root: the confined Stat
		// reports ENOENT, which hides nothing, so it must stay silent.
		"dangling": "no-such-target",
		// Escaping links under the pair names: convertEntry owns these, so the
		// notice must not double-report them.
		"tls.crt": filepath.Join(outside, "real.crt"),
		"tls.key": filepath.Join(outside, "real.key"),
		// The control: same escaping target, a name the notice owns.
		"linked-dir": outside,
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(input, name)); err != nil {
			t.Fatal(err)
		}
	}
	inHandle, err := os.OpenRoot(input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inHandle.Close() })
	sw := &scanWalk{src: &source{root: inHandle}}

	entry := func(name string) fs.DirEntry {
		fi, lerr := os.Lstat(filepath.Join(input, name))
		if lerr != nil {
			t.Fatal(lerr)
		}
		return fs.FileInfoToDirEntry(fi)
	}

	for _, name := range []string{"dangling", "tls.crt", "tls.key"} {
		// A fresh recorder per case, replacing the buffer reset the text handler needed.
		logs := captureLogs(t)
		sw.noteUnwalkableSymlink(name, entry(name))
		if logs.Len() != 0 {
			t.Errorf("noteUnwalkableSymlink(%q) logged %q, want no output", name, logs.Messages())
		}
	}

	logs := captureLogs(t)
	sw.noteUnwalkableSymlink("linked-dir", entry("linked-dir"))
	if !logs.Contains("skipping symlink that could not be resolved through the input root") {
		t.Errorf("noteUnwalkableSymlink(%q) logged %q, want the unresolved-symlink warning", "linked-dir", logs.Messages())
	}
}

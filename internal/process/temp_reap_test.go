package process

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTempReapVisit_classifies_walk_errors pins the /output sweep's walk-error
// triage: a failure at the root aborts the sweep (the whole output tree is
// unusable), a failure below the root is counted as one unreadable sub-path and
// skipped so the rest of the tree is still swept, and a cancelled context stops
// the sweep between entries instead of unlinking across a large tree during
// shutdown. Collapsing the root case into the sub-path case would turn a broken
// /output mount into a silently "successful" sweep.
func TestTempReapVisit_classifies_walk_errors(t *testing.T) {
	t.Parallel()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	sentinel := errors.New("boom")

	t.Run("an error at the root aborts the sweep", func(t *testing.T) {
		t.Parallel()
		tr := &tempReap{outHandle: root, cutoff: time.Now()}
		if got := tr.visit(t.Context(), ".", nil, sentinel); !errors.Is(got, sentinel) {
			t.Errorf("visit(\".\", err) = %v, want the walk error so the sweep aborts", got)
		}
		if tr.unreadable != 0 {
			t.Errorf("visit(\".\", err) unreadable = %d, want 0 (a root failure is not an unreadable sub-path)", tr.unreadable)
		}
	})

	t.Run("an error below the root is counted and skipped", func(t *testing.T) {
		t.Parallel()
		tr := &tempReap{outHandle: root, cutoff: time.Now()}
		if got := tr.visit(t.Context(), "sub", nil, sentinel); got != nil {
			t.Errorf("visit(\"sub\", err) = %v, want nil so the sweep continues", got)
		}
		if tr.unreadable != 1 {
			t.Errorf("visit(\"sub\", err) unreadable = %d, want 1", tr.unreadable)
		}
		if tr.failed != 0 || tr.reaped != 0 {
			t.Errorf("visit(\"sub\", err) failed/reaped = %d/%d, want 0/0", tr.failed, tr.reaped)
		}
	})

	t.Run("a cancelled context aborts the sweep", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		tr := &tempReap{outHandle: root, cutoff: time.Now()}
		if got := tr.visit(ctx, "anything", nil, nil); !errors.Is(got, context.Canceled) {
			t.Errorf("visit(cancelled ctx) = %v, want context.Canceled", got)
		}
	})
}

// TestReapStaleTemp_reports_non_benign_failures pins the second return value of
// the per-candidate reaper, which decides whether the sweep's aggregate operator
// warning fires: a candidate that vanished between the readdir and the Lstat is a
// benign race and must NOT be reported, while a candidate the confined root
// refuses to inspect (an output subdirectory swapped for a symlink out of the
// volume) and a stale orphan that cannot be unlinked both must be, because either
// means atomic-write artifacts are accumulating unnoticed. It also asserts the
// confinement itself: nothing outside the output root is ever unlinked.
func TestReapStaleTemp_reports_non_benign_failures(t *testing.T) {
	t.Parallel()

	entryFor := func(t *testing.T, path string) fs.DirEntry {
		t.Helper()
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		return fs.FileInfoToDirEntry(fi)
	}
	old := time.Now().Add(-2 * time.Hour)
	cutoff := time.Now().Add(-staleTempAge)

	t.Run("a vanished candidate is benign", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		present := filepath.Join(dir, ".atomicfile-111.tmp")
		if err := os.WriteFile(present, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		d := entryFor(t, present)
		if err := os.Remove(present); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })

		removed, failed := reapStaleTemp(root, ".atomicfile-111.tmp", d, cutoff)
		if removed || failed {
			t.Errorf("reapStaleTemp(vanished temp) = (%v, %v), want (false, false): a readdir/Lstat race is benign", removed, failed)
		}
	})

	t.Run("a candidate the root refuses to stat is reported", func(t *testing.T) {
		t.Parallel()
		base := t.TempDir()
		dir := filepath.Join(base, "out")
		outside := filepath.Join(base, "outside")
		for _, d := range []string{dir, outside} {
			if err := os.Mkdir(d, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		temp := filepath.Join(outside, ".atomicfile-222.tmp")
		if err := os.WriteFile(temp, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(temp, old, old); err != nil {
			t.Fatal(err)
		}
		d := entryFor(t, temp)
		// An output subdirectory swapped for a symlink out of the volume: the
		// confined Lstat must refuse the escape, and that refusal is a failure
		// to inspect, not a silent skip.
		if err := os.Symlink(outside, filepath.Join(dir, "swapped")); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })

		removed, failed := reapStaleTemp(root, "swapped/.atomicfile-222.tmp", d, cutoff)
		if removed {
			t.Errorf("reapStaleTemp(escaping temp) removed = true, want false")
		}
		if !failed {
			t.Error("reapStaleTemp(escaping temp) failed = false, want true: a confinement or permission refusal must reach the aggregate warning, not only debug")
		}
		if _, statErr := os.Stat(temp); statErr != nil {
			t.Errorf("os.Stat(%q) = %v, want nil: nothing outside the output root may be unlinked", temp, statErr)
		}
	})

	t.Run("an unremovable stale temp is reported", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: mode bits do not block Remove")
		}
		t.Parallel()
		dir := t.TempDir()
		sub := filepath.Join(dir, "sub")
		if err := os.Mkdir(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		temp := filepath.Join(sub, ".atomicfile-333.tmp")
		if err := os.WriteFile(temp, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(temp, old, old); err != nil {
			t.Fatal(err)
		}
		d := entryFor(t, temp)
		if err := os.Chmod(sub, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(sub, 0o750) })
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })

		removed, failed := reapStaleTemp(root, "sub/.atomicfile-333.tmp", d, cutoff)
		if removed {
			t.Errorf("reapStaleTemp(unremovable temp) removed = true, want false")
		}
		if !failed {
			t.Error("reapStaleTemp(unremovable temp) failed = false, want true: an orphan that cannot be unlinked must reach the aggregate warning")
		}
		if _, statErr := os.Stat(temp); statErr != nil {
			t.Errorf("os.Stat(%q) = %v, want nil: the temp must still be there after a failed unlink", temp, statErr)
		}
	})
}

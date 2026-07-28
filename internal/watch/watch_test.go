package watch

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fsnotify/fsnotify"
)

// newTestWatcher returns a live fsnotify watcher, closed at test end, and skips
// the test on a host where inotify is unavailable.
func newTestWatcher(t *testing.T) *fsnotify.Watcher {
	t.Helper()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	return watcher
}

// newClosedTestWatcher returns an already-closed watcher: every watcher.Add on
// it fails, which is how these tests drive the watch-set failure paths.
func newClosedTestWatcher(t *testing.T) *fsnotify.Watcher {
	t.Helper()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("setup: watcher.Close() = %v", err)
	}
	return watcher
}

// TestHandleFsEvent pins the rescan decision for every event class, including
// removed or renamed domain-named directories whose suffix is not certificate-relevant.
func TestHandleFsEvent(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	w := New(root, func(context.Context) {})

	watcher := newTestWatcher(t)
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("addWatchDirs: %v", err)
	}

	// Real paths the Create branch stats.
	domainDir := filepath.Join(root, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	crtFile := filepath.Join(domainDir, "tls.crt")
	if err := os.WriteFile(crtFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	plainFile := filepath.Join(domainDir, "notes.txt")
	if err := os.WriteFile(plainFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A DIRECTORY whose name ends in a cert extension: layout.IsRelevant is a
	// suffix-only classifier, so this is the path that must not be misread as a file.
	// Deliberately NOT under domainDir: the "chmod on a domain directory" case walks
	// domainDir's whole subtree, so a crtDir inside it would already be watched by
	// the time the WatchList assertion runs and the oracle could never fail.
	crtDir := filepath.Join(root, "archive.crt")
	if err := os.MkdirAll(crtDir, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		event fsnotify.Event
		want  bool
	}{
		{"create new directory triggers rescan", fsnotify.Event{Name: domainDir, Op: fsnotify.Create}, true},
		{"create cert file triggers rescan", fsnotify.Event{Name: crtFile, Op: fsnotify.Create}, true},
		{"create non-cert file is ignored", fsnotify.Event{Name: plainFile, Op: fsnotify.Create}, false},
		{"write to cert triggers rescan", fsnotify.Event{Name: crtFile, Op: fsnotify.Write}, true},
		{"write to key triggers rescan", fsnotify.Event{Name: filepath.Join(domainDir, "tls.key"), Op: fsnotify.Write}, true},
		{"write to non-cert is ignored", fsnotify.Event{Name: plainFile, Op: fsnotify.Write}, false},
		{"remove domain-named directory triggers rescan", fsnotify.Event{Name: domainDir, Op: fsnotify.Remove}, true},
		{"remove cert triggers rescan", fsnotify.Event{Name: crtFile, Op: fsnotify.Remove}, true},
		{"rename triggers rescan", fsnotify.Event{Name: filepath.Join(root, "whatever"), Op: fsnotify.Rename}, true},
		{"chmod on a cert triggers rescan", fsnotify.Event{Name: crtFile, Op: fsnotify.Chmod}, true},
		{"chmod on a key triggers rescan", fsnotify.Event{Name: filepath.Join(domainDir, "tls.key"), Op: fsnotify.Chmod}, true},
		{"chmod on a non-cert file is ignored", fsnotify.Event{Name: plainFile, Op: fsnotify.Chmod}, false},
		// A chmod on a DIRECTORY is the permission-repair recovery path --
		// it re-attaches the subtree's watches and rescans, instead of waiting
		// for the fallback tick (never, with the fallback disabled).
		{"chmod on a domain directory rescans", fsnotify.Event{Name: domainDir, Op: fsnotify.Chmod}, true},
		// The directory test runs before the suffix test, so a cert-named DIRECTORY
		// takes the recovery path rather than the file path.
		{"chmod on a cert-named directory rescans", fsnotify.Event{Name: crtDir, Op: fsnotify.Chmod}, true},
		{"chmod on a vanished path is ignored", fsnotify.Event{Name: filepath.Join(root, "gone"), Op: fsnotify.Chmod}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := w.handleFsEvent(t.Context(), watcher, tc.event); got != tc.want {
				t.Errorf("handleFsEvent(%s on %s) = %v, want %v", tc.event.Op, tc.event.Name, got, tc.want)
			}
		})
	}

	// Rescanning is only half of the repaired-directory contract: without the
	// re-attached watch, the immediate scan converts what is on disk now and every
	// later renewal underneath the directory is missed.
	if !slices.Contains(watcher.WatchList(), crtDir) {
		t.Errorf("after a chmod on %s the watch list is %v, want the repaired directory watched", crtDir, watcher.WatchList())
	}
}

// TestHandleFsEvent_rescans_even_when_the_new_subtree_cannot_be_watched pins the
// return value of the Create-directory path when addWatchDirs fails: the event
// must still report true so the debounced rescan converts a cert pair that
// already exists inside the new directory even though its subtree could not be
// watched.
func TestHandleFsEvent_rescans_even_when_the_new_subtree_cannot_be_watched(t *testing.T) {
	t.Parallel()
	watcher := newClosedTestWatcher(t)
	root := t.TempDir()
	newDir := filepath.Join(root, "example.com")
	if err := os.MkdirAll(newDir, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})

	got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: newDir, Op: fsnotify.Create})

	if !got {
		t.Error("handleFsEvent(Create dir, unwatchable) = false, want true: a cert pair already inside the new directory would otherwise wait for the fallback rescan")
	}
}

// TestHandleFsEvent_rescans_when_a_repaired_directory_cannot_be_rewatched pins
// the Chmod twin of the Create-side contract: when the permission-repair arm
// cannot re-attach the subtree's watches, the event must still report true so
// the debounced rescan converts the pair that just became readable. Returning
// false there would leave the repaired directory converting nothing until the
// next fallback tick, and never with the fallback disabled -- the exact
// stuck-unhealthy state the Chmod arm exists to end.
func TestHandleFsEvent_rescans_when_a_repaired_directory_cannot_be_rewatched(t *testing.T) {
	t.Parallel()
	watcher := newClosedTestWatcher(t)
	root := t.TempDir()
	repaired := filepath.Join(root, "example.com")
	if err := os.MkdirAll(repaired, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})

	got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: repaired, Op: fsnotify.Chmod})

	if !got {
		t.Error("handleFsEvent(Chmod dir, unwatchable) = false, want true: the permission repair would otherwise convert nothing until the next fallback tick, and never with the fallback disabled")
	}
}

// TestAddWatchDirs_refuses_a_non_directory_root pins the non-directory-root
// branch: filepath.WalkDir Lstats its root and does not follow it, so a
// regular-file root and a symlinked root each visit exactly one non-directory
// entry. Reporting that is what routes the case into Run's degraded paths (poll
// mode, or ErrWatchLost with the fallback disabled); returning nil would leave Run
// logging "fsnotify active" over an empty watch set, parked in a loop no event can
// reach while the scan keeps the health marker green.
func TestAddWatchDirs_refuses_a_non_directory_root(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	fileRoot := filepath.Join(base, "input")
	if err := os.WriteFile(fileRoot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(base, "linked")
	if err := os.Symlink(realDir, linkRoot); err != nil {
		t.Skipf("symlinks unavailable on this filesystem: %v", err)
	}
	watcher := newTestWatcher(t)

	for _, tc := range []struct {
		root string
		want string
	}{
		{fileRoot, "is not a directory"},
		{linkRoot, "is a symlink"},
	} {
		w := New(tc.root, func(context.Context) {})
		err := w.addWatchDirs(t.Context(), watcher, tc.root)
		if err == nil {
			t.Errorf("addWatchDirs(%q) = nil, want an error: the watch set is %v, so no event could ever arrive", tc.root, watcher.WatchList())
			continue
		}
		// The message is the operator's only signal for this shape: a symlinked
		// /input keeps converting and stays healthy while real-time detection is
		// gone, so the error must name the symlink rather than the generic
		// not-a-directory refusal.
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("addWatchDirs(%q) = %q, want it to name %q so the WARN is self-diagnosing", tc.root, err, tc.want)
		}
	}
}

package watch

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

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

// TestHandleFsEvent is the first unit coverage of the watcher's event
// classifier. It pins the rescan decision per event class, including the
// d-u2-1 regression: a removed/renamed domain-named directory (e.g.
// "example.com") must trigger a rescan even though its ".com" suffix is not a
// cert extension.
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
		// h-f9: a chmod on a DIRECTORY is the permission-repair recovery path --
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

func TestNew_applies_debounce_and_fallback_options(t *testing.T) {
	t.Parallel()
	w := New("/input", func(context.Context) {}, WithDebounce(750*time.Millisecond), WithFallback(3*time.Hour))

	if w.debounce != 750*time.Millisecond {
		t.Errorf("New(WithDebounce(750ms)) debounce = %v, want %v", w.debounce, 750*time.Millisecond)
	}
	if w.fallback != 3*time.Hour {
		t.Errorf("New(WithFallback(3h)) fallback = %v, want %v", w.fallback, 3*time.Hour)
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

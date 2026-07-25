package watch

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/fsnotify/fsnotify"
)

// TestAddWatchDirs_watches_whole_subtree_and_fails_on_missing_root pins the
// watch-set construction: every directory below the root is watched (a
// per-domain Caddy layout nests two levels deep, and an unwatched subdirectory
// means renewals there are only picked up by the fallback rescan), files are
// not watched individually, and a root that cannot be walked is a hard error --
// the signal Run uses to fall back to polling instead of running blind.
func TestAddWatchDirs_watches_whole_subtree_and_fails_on_missing_root(t *testing.T) {
	t.Parallel()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	defer func() { _ = watcher.Close() }()

	root := t.TempDir()
	nested := filepath.Join(root, "acme-v02", "example.com")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(nested, "example.com.crt")
	if err := os.WriteFile(certFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})

	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("addWatchDirs(%q) = %v, want nil", root, err)
	}

	got := watcher.WatchList()
	for _, dir := range []string{root, filepath.Join(root, "acme-v02"), nested} {
		if !slices.Contains(got, dir) {
			t.Errorf("addWatchDirs did not watch %q; watch list = %v", dir, got)
		}
	}
	if slices.Contains(got, certFile) {
		t.Errorf("addWatchDirs added the file %q to the watch list; only directories should be watched", certFile)
	}

	if err := w.addWatchDirs(t.Context(), watcher, filepath.Join(root, "does-not-exist")); err == nil {
		t.Error("addWatchDirs(missing root) = nil, want an error so Run falls back to polling")
	}
}

// TestAddWatchDirs_fails_when_the_root_watch_cannot_be_added pins the second
// fatal case of the watch-set build: the root directory walks fine but the
// watch itself is refused (a closed or exhausted watcher). That must propagate
// as an error, because it is the signal Run uses to fall back to polling; a
// swallowed failure would leave Run believing fsnotify is active while no watch
// exists, so renewals would be detected only by the fallback rescan (or not at
// all when it is disabled).
func TestAddWatchDirs_fails_when_the_root_watch_cannot_be_added(t *testing.T) {
	t.Parallel()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("setup: watcher.Close() = %v", err)
	}
	root := t.TempDir()

	if err := New(root, func(context.Context) {}).addWatchDirs(t.Context(), watcher, root); err == nil {
		t.Error("addWatchDirs(closed watcher) = nil, want an error so Run falls back to polling instead of watching nothing")
	}
}

package watch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
	"github.com/fsnotify/fsnotify"
)

// TestHandleFsEvent_classifies_a_create_it_cannot_stat pins both halves of the
// Create-branch Lstat failure. A vanished path is the expected case (an
// atomic-write temp renamed away before the event was handled) and must stay
// silent while still falling back to the extension check; any other stat error
// means the created path could not be classified at all, which leaves a
// directory outside the watch set until the next fallback re-sync, so it must
// WARN. An ENOTDIR path (a component of the path is a regular file) is the
// portable way to produce that second case without depending on permissions,
// which is untestable as uid 0.
// Not parallel: it swaps the process-global slog default.
func TestHandleFsEvent_classifies_a_create_it_cannot_stat(t *testing.T) {
	watcher := newTestWatcher(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {})

	notADir := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		path     string
		want     bool
		wantWarn bool
	}{
		{"a vanished cert still rescans, silently", filepath.Join(root, "gone.crt"), true, false},
		{"a vanished unrelated file is ignored, silently", filepath.Join(root, "gone.txt"), false, false},
		{"an unclassifiable cert path rescans and warns", filepath.Join(notADir, "tls.crt"), true, true},
		{"an unclassifiable unrelated path is ignored but warns", filepath.Join(notADir, "notes.txt"), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: tc.path, Op: fsnotify.Create})

			if got != tc.want {
				t.Errorf("handleFsEvent(Create %s) = %v, want %v", tc.path, got, tc.want)
			}
			warned := logs.CountLevel(slog.LevelWarn, "cannot classify a created path") > 0
			if warned != tc.wantWarn {
				t.Errorf("handleFsEvent(Create %s) warned = %v, want %v; log = %v", tc.path, warned, tc.wantWarn, logs.Messages())
			}
		})
	}
}

// TestHandleFsEvent_classifies_a_chmod_it_cannot_stat pins both halves of the
// Chmod-branch Lstat failure. Chmod is the documented recovery path for a
// permission repair, so a path that cannot be classified at all must be treated
// as a possible unwatched directory: rescan and WARN, rather than fall through
// to the suffix-only classifier that would silently drop a repaired
// domain-named directory. A vanished path is the one quiet case — the chmod
// target is already gone, so there is nothing left to re-attach. An ENOTDIR
// path (a component of the path is a regular file) produces the
// unclassifiable case without depending on permissions, which is untestable as
// uid 0.
// Not parallel: it swaps the process-global slog default.
func TestHandleFsEvent_classifies_a_chmod_it_cannot_stat(t *testing.T) {
	watcher := newTestWatcher(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {})

	notADir := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		path     string
		want     bool
		wantWarn bool
	}{
		{"a vanished cert still rescans, silently", filepath.Join(root, "gone.crt"), true, false},
		{"a vanished unrelated file is ignored, silently", filepath.Join(root, "gone.txt"), false, false},
		{"an unclassifiable cert path rescans and warns", filepath.Join(notADir, "tls.crt"), true, true},
		{"an unclassifiable unrelated path rescans and warns", filepath.Join(notADir, "notes.txt"), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: tc.path, Op: fsnotify.Chmod})

			if got != tc.want {
				t.Errorf("handleFsEvent(Chmod %s) = %v, want %v", tc.path, got, tc.want)
			}
			warned := logs.CountLevel(slog.LevelWarn, "cannot classify a path whose permissions changed") > 0
			if warned != tc.wantWarn {
				t.Errorf("handleFsEvent(Chmod %s) warned = %v, want %v; log = %v", tc.path, warned, tc.wantWarn, logs.Messages())
			}
		})
	}
}

// TestFallbackStatus_tells_the_operator_whether_anything_will_rescan pins the
// fallback_scan attribute every degraded-path WARN carries. The existing
// classify tests assert only that the WARN fires, so the attribute's value --
// the operator's single statement of when (or whether) the reported path is
// re-scanned -- is unverified, and the boundary that produces "disabled" can
// invert without any test noticing. The disabled case is the load-bearing one:
// nothing re-scans that path for the life of the process, so rendering it as a
// duration would read as a promise the process cannot keep.
// Not parallel: it swaps the process-global slog default.
func TestFallbackStatus_tells_the_operator_whether_anything_will_rescan(t *testing.T) {
	const msg = "cannot classify a path whose permissions changed"

	watcher := newTestWatcher(t)
	root := t.TempDir()
	notADir := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		fallback time.Duration
		want     string
	}{
		{"a disabled fallback is named outright", 0, "disabled"},
		{"a negative interval is disabled too", -time.Second, "disabled"},
		{"an enabled fallback states its cadence", 6 * time.Hour, "6h0m0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)
			w := New(root, func(context.Context) {}, WithFallback(tc.fallback))

			w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: filepath.Join(notADir, "tls.crt"), Op: fsnotify.Chmod})

			got, ok := logs.AttrValue(msg, "fallback_scan")
			if !ok {
				t.Fatalf("no fallback_scan attribute on the degraded-path WARN; log = %v", logs.Messages())
			}
			if got != tc.want {
				t.Errorf("fallback_scan = %q with WithFallback(%v), want %q", got, tc.fallback, tc.want)
			}
		})
	}
}

// TestHandleFsEvent_does_not_watch_through_a_symlinked_directory pins the
// containment invariant both the Create and the Chmod arm rely on: they Lstat
// (never Stat), so a symlink to a directory takes the FILE arm and
// addWatchDirs/watcher.Add never runs on it. Neither addWatchDirs nor the
// scanner's root-confined walk descends a symlinked directory, so watching
// through one would register inotify watches on a tree outside /input whose
// certs can never be converted, silently burning the watch quota. The
// invariant is documented in three comments in watch.go and, before this test,
// asserted nowhere: swapping either Lstat to Stat kept the whole suite green.
func TestHandleFsEvent_does_not_watch_through_a_symlinked_directory(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "escaped"), 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "example.com")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable on this filesystem: %v", err)
	}
	w := New(root, func(context.Context) {})

	for _, op := range []fsnotify.Op{fsnotify.Create, fsnotify.Chmod} {
		if got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: link, Op: op}); got {
			t.Errorf("handleFsEvent(%v on a symlinked dir) = true, want false (the link name is not a cert or key)", op)
		}
	}
	for _, watched := range watcher.WatchList() {
		if watched == link || strings.HasPrefix(watched, outside) {
			t.Errorf("watch registered through a symlink: %q; watch list = %v", watched, watcher.WatchList())
		}
	}
}

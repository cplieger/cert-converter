package watch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

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

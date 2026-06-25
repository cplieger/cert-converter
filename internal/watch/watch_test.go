package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// TestHandleFsEvent is the first unit coverage of the watcher's event
// classifier. It pins the rescan decision per event class, including the
// d-u2-1 regression: a removed/renamed domain-named directory (e.g.
// "example.com") must trigger a rescan even though its ".com" suffix is not a
// cert extension.
func TestHandleFsEvent(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	w := New(root, func(context.Context) {})

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Skipf("fsnotify unavailable: %v", err)
	}
	defer func() { _ = watcher.Close() }()
	if err := w.addWatchDirs(watcher, root); err != nil {
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
		{"chmod only is ignored", fsnotify.Event{Name: crtFile, Op: fsnotify.Chmod}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := w.handleFsEvent(watcher, tc.event); got != tc.want {
				t.Errorf("handleFsEvent(%s on %s) = %v, want %v", tc.event.Op, tc.event.Name, got, tc.want)
			}
		})
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

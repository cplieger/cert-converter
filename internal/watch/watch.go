// Package watch provides filesystem watching with fsnotify and poll fallback.
package watch

import (
	"context"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Runner is the minimal contract main.go depends on.
type Runner interface {
	Run(ctx context.Context)
}

var _ Runner = (*Watcher)(nil)

// Watcher monitors a directory tree for cert/key changes and invokes a callback.
type Watcher struct {
	onChange func(ctx context.Context)
	root     string
	debounce time.Duration
	fallback time.Duration
}

// Option configures a Watcher.
type Option func(*Watcher)

// WithDebounce sets the debounce window for coalescing events.
func WithDebounce(d time.Duration) Option {
	return func(w *Watcher) { w.debounce = d }
}

// WithFallback sets the periodic poll/fallback interval. Zero disables it.
func WithFallback(d time.Duration) Option {
	return func(w *Watcher) { w.fallback = d }
}

// New creates a Watcher for the given root directory.
func New(root string, onChange func(ctx context.Context), opts ...Option) *Watcher {
	w := &Watcher{
		root:     root,
		onChange: onChange,
		debounce: 2 * time.Second,
		fallback: 6 * time.Hour,
	}
	for _, o := range opts {
		o(w)
	}
	return w
}

// Run starts watching. It tries fsnotify first; if unavailable it falls
// back to polling. Blocks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("fsnotify unavailable, using polling with periodic upgrade attempts", "error", err)
		w.pollLoopWithUpgrade(ctx)
		return
	}
	defer watcher.Close()

	if err := w.addWatchDirs(watcher, w.root); err != nil {
		slog.Warn("failed to watch directories, using polling with periodic upgrade attempts", "error", err)
		w.pollLoopWithUpgrade(ctx)
		return
	}

	slog.Info("fsnotify active", "directories", watcher.WatchList())
	w.watchLoop(ctx, watcher)
}

// addWatchDirs recursively adds all directories under root to the watcher.
func (w *Watcher) addWatchDirs(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
}

// handleFsEvent processes a single fsnotify event, adding new directories
// to the watcher and returning true if a cert/key file changed.
func (w *Watcher) handleFsEvent(event fsnotify.Event, watcher *fsnotify.Watcher) bool {
	slog.Debug("fs event", "op", event.Op.String(), "path", event.Name)

	if event.Has(fsnotify.Create) {
		if err := w.addWatchDirs(watcher, event.Name); err != nil {
			slog.Warn("failed to watch new directory subtree", "path", event.Name, "error", err)
		}
	}
	if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
		if walkErr := w.addWatchDirs(watcher, event.Name); walkErr != nil {
			slog.Debug("removed path no longer watchable", "path", event.Name, "error", walkErr)
		}
		return true
	}
	return strings.HasSuffix(event.Name, ".crt") || strings.HasSuffix(event.Name, ".key")
}

// watchLoop uses fsnotify for immediate reaction to cert changes,
// with a periodic full scan as a safety net.
func (w *Watcher) watchLoop(ctx context.Context, watcher *fsnotify.Watcher) {
	var fallbackTimer *time.Timer
	if w.fallback > 0 {
		fallbackTimer = time.NewTimer(w.fallback)
		defer fallbackTimer.Stop()
	}

	var pending bool
	debounceTimer := time.NewTimer(w.debounce)
	debounceTimer.Stop()
	defer debounceTimer.Stop()

	for {
		var fallbackC <-chan time.Time
		if fallbackTimer != nil {
			fallbackC = fallbackTimer.C
		}

		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if w.handleFsEvent(event, watcher) && !pending {
				pending = true
				debounceTimer.Reset(w.debounce)
			}

		case <-debounceTimer.C:
			pending = false
			slog.Info("cert change detected, processing")
			w.onChange(ctx)
			if fallbackTimer != nil {
				fallbackTimer.Reset(w.fallback)
			}

		case <-fallbackC:
			slog.Debug("fallback scan triggered", "interval", w.fallback)
			w.onChange(ctx)
			fallbackTimer.Reset(w.fallback)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("watcher error", "error", err)
		}
	}
}

// pollLoopWithUpgrade polls on the fallback interval and attempts to
// upgrade to fsnotify on every tick.
func (w *Watcher) pollLoopWithUpgrade(ctx context.Context) {
	if w.fallback <= 0 {
		slog.Info("polling disabled and fsnotify unavailable, waiting for shutdown")
		<-ctx.Done()
		return
	}

	ticker := time.NewTicker(w.fallback)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.Debug("poll scan triggered", "interval", w.fallback)
			w.onChange(ctx)
			if fw, err := fsnotify.NewWatcher(); err == nil {
				if addErr := w.addWatchDirs(fw, w.root); addErr == nil {
					slog.Info("fsnotify recovered, upgrading from poll to watch",
						"directories", fw.WatchList())
					w.watchLoop(ctx, fw)
					fw.Close()
					return
				}
				fw.Close()
			}
		}
	}
}

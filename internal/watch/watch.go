// Package watch provides filesystem watching with fsnotify and poll fallback.
package watch

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
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

	if err := w.addWatchDirs(watcher, w.root); err != nil {
		watcher.Close() // release fd + readEvents goroutine before long-lived fallback
		slog.Warn("failed to watch directories, using polling with periodic upgrade attempts", "error", err)
		w.pollLoopWithUpgrade(ctx)
		return
	}
	defer watcher.Close()

	slog.Info("fsnotify active", "directories", watcher.WatchList())
	w.watchLoop(ctx, watcher)
}

// addWatchDirs recursively adds all directories under root to the watcher.
func (w *Watcher) addWatchDirs(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			slog.Warn("skipping unwatchable path", "path", path, "error", err)
			return nil
		}
		if d.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
}

// handleFsEvent processes a single fsnotify event, keeping the watch set in
// sync with directory changes and reporting whether the event warrants a
// rescan. The three event classes are handled distinctly:
//
//   - Create: a new subtree is added to the watcher. A newly created directory
//     triggers a rescan (it may already hold a cert/key pair created before the
//     watch attached); a newly created file triggers one only if it is a cert
//     or key.
//   - Remove/Rename: always triggers a rescan. The path is already gone, so it
//     cannot be stat-ed to tell a cert file from a directory — and a renamed or
//     deleted domain-named directory (e.g. "example.com", whose ".com" suffix
//     fooled the old extension heuristic into skipping it) must still be
//     reflected in the output. A rescan is cheap: the fingerprint cache skips
//     unchanged pairs and prunes vanished ones.
//   - Write: triggers a rescan only for a cert or key file; a metadata-only
//     Chmod or a write to an unrelated file is ignored.
func (w *Watcher) handleFsEvent(watcher *fsnotify.Watcher, event fsnotify.Event) bool {
	slog.Debug("fs event", "op", event.Op.String(), "path", event.Name)
	switch {
	case event.Has(fsnotify.Create):
		if err := w.addWatchDirs(watcher, event.Name); err != nil {
			slog.Warn("failed to watch new directory subtree", "path", event.Name, "error", err)
		}
		if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
			return true
		}
		return isCertFile(event.Name)
	case event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename):
		// event.Name is already gone on Remove/Rename (inotify reports the old
		// name), so there is nothing to add to the watch set: fsnotify drops the
		// watch for a deleted directory itself, and a rename destination inside
		// the tree arrives as its own Create event. addWatchDirs here can only
		// fail, so just rescan.
		return true
	case event.Has(fsnotify.Write):
		return isCertFile(event.Name)
	}
	return false
}

// isCertFile reports whether name is a certificate or private-key file by
// extension — the only inputs cert-converter acts on.
func isCertFile(name string) bool {
	return strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".key")
}

// watchLoop uses fsnotify for immediate reaction to cert changes,
// with a periodic full scan as a safety net.
func (w *Watcher) watchLoop(ctx context.Context, watcher *fsnotify.Watcher) {
	st := newWatchState(w)
	defer st.stop()

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				slog.Warn("fsnotify events channel closed, watcher stopping; process will exit and restart")
				return
			}
			if w.handleFsEvent(watcher, event) {
				st.scheduleScan()
			}

		case <-st.debounceTimer.C:
			st.runDebouncedScan(ctx)

		case <-st.fallbackChan():
			st.runFallbackScan(ctx)

		case err, ok := <-watcher.Errors:
			if !ok {
				slog.Warn("fsnotify errors channel closed, watcher stopping; process will exit and restart")
				return
			}
			st.handleWatcherError(err)
		}
	}
}

// watchState carries the mutable accounting for one watchLoop run: the pending
// debounce flag and the debounce/fallback timers. Hoisting the per-event work
// onto its methods keeps watchLoop's select a flat dispatch table rather than a
// deeply nested switch.
type watchState struct {
	w             *Watcher
	debounceTimer *time.Timer
	fallbackTimer *time.Timer // nil when the periodic fallback rescan is disabled
	pending       bool
}

// newWatchState builds the loop state: a stopped debounce timer (nothing is
// pending until an event arrives) and, when w.fallback > 0, a running fallback
// timer for the periodic safety-net rescan.
func newWatchState(w *Watcher) *watchState {
	st := &watchState{w: w}
	st.debounceTimer = time.NewTimer(w.debounce)
	st.debounceTimer.Stop()
	if w.fallback > 0 {
		st.fallbackTimer = time.NewTimer(w.fallback)
	}
	return st
}

// stop releases both timers when the loop exits.
func (st *watchState) stop() {
	st.debounceTimer.Stop()
	if st.fallbackTimer != nil {
		st.fallbackTimer.Stop()
	}
}

// fallbackChan returns the fallback timer's channel, or nil when the fallback
// is disabled. A receive on a nil channel blocks forever, so the loop's
// fallback case never fires without a fallback timer.
func (st *watchState) fallbackChan() <-chan time.Time {
	if st.fallbackTimer == nil {
		return nil
	}
	return st.fallbackTimer.C
}

// scheduleScan arms the debounce timer to coalesce a burst of events into one
// scan. A scan already pending is left to fire on its existing schedule.
func (st *watchState) scheduleScan() {
	if st.pending {
		return
	}
	st.pending = true
	st.debounceTimer.Reset(st.w.debounce)
}

// runDebouncedScan fires the debounced rescan and re-arms the fallback timer so
// the safety-net interval is measured from the last real scan.
func (st *watchState) runDebouncedScan(ctx context.Context) {
	st.pending = false
	slog.Info("cert change detected, processing")
	st.w.onChange(ctx)
	if st.fallbackTimer != nil {
		st.fallbackTimer.Reset(st.w.fallback)
	}
}

// runFallbackScan fires the periodic safety-net rescan and re-arms its timer.
// It is reached only when fallbackTimer is non-nil (see fallbackChan).
func (st *watchState) runFallbackScan(ctx context.Context) {
	slog.Debug("fallback scan triggered", "interval", st.w.fallback)
	st.w.onChange(ctx)
	st.fallbackTimer.Reset(st.w.fallback)
}

// handleWatcherError reacts to an fsnotify error: an event-queue overflow
// dropped events, so force a rescan to recover any missed renewal; any other
// error is logged and the loop continues.
func (st *watchState) handleWatcherError(err error) {
	if errors.Is(err, fsnotify.ErrEventOverflow) {
		slog.Warn("fsnotify event queue overflowed; events were dropped, forcing a rescan to recover any missed renewal", "error", err)
		st.scheduleScan()
		return
	}
	slog.Warn("watcher error", "error", err)
}

// pollLoopWithUpgrade polls on the fallback interval and attempts to
// upgrade to fsnotify on every tick.
func (w *Watcher) pollLoopWithUpgrade(ctx context.Context) {
	if w.fallback <= 0 {
		slog.Warn("polling disabled and fsnotify unavailable; change detection inactive until restart")
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

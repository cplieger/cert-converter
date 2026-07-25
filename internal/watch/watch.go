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

// WithFallback sets the periodic poll/fallback interval. Zero or a negative duration
// disables it: in fsnotify mode no safety-net rescan is armed, and in poll mode there is
// no interval to poll on, so change detection is inactive until the process restarts.
func WithFallback(d time.Duration) Option {
	return func(w *Watcher) { w.fallback = d }
}

// New creates a Watcher for the given root directory. Timing policy is chosen by
// the composition root (main.go) and injected via WithDebounce/WithFallback;
// config owns the documented FALLBACK_SCAN_HOURS default, so an un-optioned
// Watcher has no debounce window and no fallback rescan.
func New(root string, onChange func(ctx context.Context), opts ...Option) *Watcher {
	w := &Watcher{
		root:     root,
		onChange: onChange,
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

// addWatchDirs recursively adds all directories under root to the watcher. Only
// a failure on root itself is fatal (Run uses it to fall back to polling); a
// directory below root that cannot be watched — unreadable to this UID, or a
// watch descriptor the kernel refuses once fs.inotify.max_user_watches is
// exhausted — is warned about and skipped, exactly as an unreadable sub-path
// is, so one mis-permissioned certificate directory cannot cost the whole tree
// its real-time watch.
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
			addErr := watcher.Add(path)
			if addErr == nil {
				return nil
			}
			if path == root {
				return addErr
			}
			slog.Warn("skipping unwatchable directory; renewals under it are only picked up by the fallback rescan",
				"path", path, "error", addErr)
			return nil
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
		// Only a directory needs watches added. Lstat, for two reasons: a transient
		// file (an atomic-write temp created and renamed away before this event is
		// handled) cannot produce a spurious "failed to watch" WARN from WalkDir
		// failing to lstat a path that is already gone; and a SYMLINK to a directory
		// is not followed. Neither addWatchDirs nor the scanner's filepath.WalkDir
		// descends a symlinked directory, so watching through one would register
		// inotify watches on a tree outside /input whose certs can never be
		// converted — and a symlink to a large tree would burn the watch quota.
		if info, err := os.Lstat(event.Name); err == nil && info.IsDir() {
			if addErr := w.addWatchDirs(watcher, event.Name); addErr != nil {
				slog.Warn("failed to watch new directory subtree", "path", event.Name, "error", addErr)
			}
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
			if !w.handleEventRecv(watcher, st, event, ok) {
				return
			}

		case <-st.debounceTimer.C:
			st.runDebouncedScan(ctx)

		case <-st.fallbackChan():
			st.runFallbackScan(ctx)

		case err, ok := <-watcher.Errors:
			if !w.handleErrorRecv(watcher, st, err, ok) {
				return
			}
		}
	}
}

// handleEventRecv processes one receive from the watcher's event channel and
// reports whether the loop should keep running. A closed channel means the
// watcher is dead, so the loop must exit (the process then restarts); otherwise
// an event classified as interesting arms the debounced rescan.
func (w *Watcher) handleEventRecv(watcher *fsnotify.Watcher, st *watchState, event fsnotify.Event, ok bool) bool {
	if !ok {
		slog.Error("fsnotify events channel closed, watcher stopping; process will exit and restart")
		return false
	}
	if w.handleFsEvent(watcher, event) {
		st.scheduleScan()
	}
	return true
}

// handleErrorRecv processes one receive from the watcher's error channel and
// reports whether the loop should keep running. A closed channel means the
// watcher is dead, so the loop must exit; an event-queue overflow additionally
// re-syncs the watch set.
func (w *Watcher) handleErrorRecv(watcher *fsnotify.Watcher, st *watchState, err error, ok bool) bool {
	if !ok {
		slog.Error("fsnotify errors channel closed, watcher stopping; process will exit and restart")
		return false
	}
	if st.handleWatcherError(err) {
		// The dropped events may have included the Create of a new
		// directory, which would otherwise stay unwatched for the rest of
		// the process's life. watcher.Add is idempotent for a directory
		// already in the watch set, so re-walking the tree only
		// re-attaches what the overflow lost.
		if addErr := w.addWatchDirs(watcher, w.root); addErr != nil {
			slog.Warn("failed to re-sync the watch set after an event-queue overflow", "error", addErr)
		}
	}
	return true
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
// dropped events, so force a rescan to recover any missed renewal and report
// true so the caller also re-syncs the watch set (a dropped directory Create
// would otherwise leave that subtree unwatched until the process restarts); any
// other error is logged, the loop continues, and it reports false.
func (st *watchState) handleWatcherError(err error) bool {
	if errors.Is(err, fsnotify.ErrEventOverflow) {
		slog.Warn("fsnotify event queue overflowed; events were dropped, forcing a rescan to recover any missed renewal", "error", err)
		st.scheduleScan()
		return true
	}
	slog.Warn("watcher error", "error", err)
	return false
}

// pollLoopWithUpgrade polls on the fallback interval and attempts to
// upgrade to fsnotify on every tick. With the fallback disabled (<= 0) there is no
// interval to poll on, so it logs an error once that change detection is inactive and
// blocks until ctx is cancelled.
func (w *Watcher) pollLoopWithUpgrade(ctx context.Context) {
	if w.fallback <= 0 {
		slog.Error("polling disabled and fsnotify unavailable; change detection inactive until restart",
			"remediation", "unset FALLBACK_SCAN_HOURS (or set it above 0) so the periodic rescan covers the missing fsnotify watch")
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
			fw, err := fsnotify.NewWatcher()
			if err != nil {
				slog.Debug("fsnotify still unavailable, staying in poll mode", "error", err)
				continue
			}
			if addErr := w.addWatchDirs(fw, w.root); addErr != nil {
				slog.Debug("fsnotify available but the watch set could not be rebuilt, staying in poll mode",
					"error", addErr)
				fw.Close()
				continue
			}
			slog.Info("fsnotify recovered, upgrading from poll to watch",
				"directories", fw.WatchList())
			w.watchLoop(ctx, fw)
			fw.Close()
			return
		}
	}
}

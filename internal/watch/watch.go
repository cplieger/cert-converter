// Package watch provides filesystem watching with fsnotify and poll fallback.
//
// Paths in this package are AMBIENT: inotify registration takes a path, not a
// directory handle, so there is no *os.Root-confined equivalent of
// watcher.Add. Every filesystem call here is therefore ambient —
// filepath.WalkDir over the watched tree, watcher.Add per directory, and
// handleFsEvent's os.Lstat — unlike every /input and /output touch in
// internal/process, which goes through an *os.Root. That is bounded only
// because nothing here reads file CONTENT: it stats and registers watches, and
// every conversion an event triggers runs through internal/process's
// root-confined scan of the /input *os.Root. Any future read of a watched file
// MUST go through that confined root (convert.ReadBoundedFromRoot); never build
// an ambient path here and read it. See addWatchDirs for the full reasoning.
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

// ErrWatchLost reports that change detection ended for a reason other than
// shutdown: the fsnotify watcher died and cannot be recovered in-process, so
// the caller must exit non-zero for a restart.
var ErrWatchLost = errors.New("change detection lost")

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

// Run starts watching. It tries fsnotify first; if unavailable it falls back to
// polling with periodic upgrade attempts. It normally blocks until ctx is
// cancelled and then returns nil, but it ALSO returns early when the fsnotify
// watcher dies (its Events or Errors channel closes): change detection is then
// gone for good, so it returns ErrWatchLost and the caller must exit non-zero
// for a restart, as main.go does. A closure observed after ctx is already
// cancelled is part of shutdown, not lost change detection, and returns nil.
func (w *Watcher) Run(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("fsnotify unavailable, using polling with periodic upgrade attempts", "error", err)
		return w.pollLoopWithUpgrade(ctx)
	}

	if err := w.addWatchDirs(ctx, watcher, w.root); err != nil {
		watcher.Close() // release fd + readEvents goroutine before long-lived fallback
		if ctx.Err() != nil {
			return nil // shutdown interrupted the walk; not a watch failure
		}
		slog.Warn("failed to watch directories, using polling with periodic upgrade attempts", "error", err)
		return w.pollLoopWithUpgrade(ctx)
	}
	defer watcher.Close()

	slog.Info("fsnotify active", "directory_count", len(watcher.WatchList()))
	if ctx.Err() != nil {
		return nil
	}
	// Attach-then-scan: main's startup scan ran before these watches existed, so
	// a renewal landing in that window produced no event. Scanning once with the
	// watch set live closes it; the fingerprint cache makes the extra scan a
	// no-op when nothing changed, and events arriving during it stay queued and
	// trigger the normal debounced follow-up.
	w.onChange(ctx)
	return w.watchLoop(ctx, watcher)
}

// addWatchDirs recursively adds all directories under root to the watcher. Only
// a failure on root itself is fatal (Run uses it to fall back to polling); a
// directory below root that cannot be watched — unreadable to this UID, or a
// watch descriptor the kernel refuses once fs.inotify.max_user_watches is
// exhausted — is warned about and skipped, exactly as an unreadable sub-path
// is, so one mis-permissioned certificate directory cannot cost the whole tree
// its real-time watch.
//
// Paths here are AMBIENT (filepath.WalkDir plus watcher.Add), unlike every
// /input and /output touch in internal/process, which runs through an *os.Root.
// The divergence is deliberate and bounded: inotify registration takes a path,
// not a directory handle, so there is no root-confined equivalent of
// watcher.Add, and nothing in this package reads file CONTENT — filepath.WalkDir
// stats with Lstat and does not intentionally descend a symlinked directory,
// while handleFsEvent's os.Lstat also skips a symlink visible at inspection.
// The ambient path can still be swapped before watcher.Add; fsnotify does not
// request IN_DONT_FOLLOW, so that race can attach to the replacement target.
// This remains bounded with respect to file content and conversion: this
// package reads no content, and conversion triggered by an event runs only
// through internal/process's root-confined scan. Watch maintenance itself stays
// ambient: a Create event can Lstat and WalkDir beneath event.Name, so a raced
// ancestor can extend registrations into the replacement target and consume
// watch descriptors, but it still cannot make the app read or convert content
// outside the root. Any future read of a watched file must go through
// internal/process's confined root
// (convert.ReadBoundedFromRoot); never build an ambient path here and read it.
//
// The traversal is cancellable: it checks ctx before each entry and returns
// ctx.Err() as soon as the process is shutting down, so a shutdown arriving
// mid-walk over a large input tree is not delayed by the remaining
// registrations. Callers must treat a ctx error as shutdown rather than a watch
// failure (no WARN, no fallback to polling, no follow-up scan).
func (w *Watcher) addWatchDirs(ctx context.Context, watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
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
			slog.Warn("skipping unwatchable directory; renewals under it require a full rescan (periodic fallback if enabled)",
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
func (w *Watcher) handleFsEvent(ctx context.Context, watcher *fsnotify.Watcher, event fsnotify.Event) bool {
	slog.Debug("fs event", "op", event.Op.String(), "path", event.Name)
	switch {
	case event.Has(fsnotify.Create):
		// Only a directory needs watches added. Lstat, for two reasons: a transient
		// file (an atomic-write temp created and renamed away before this event is
		// handled) cannot produce a spurious "failed to watch" WARN from WalkDir
		// failing to lstat a path that is already gone; and a SYMLINK to a directory
		// is not followed. Neither addWatchDirs nor the scanner's root-confined walk
		// (fs.WalkDir over the /input os.Root) descends a symlinked directory, so
		// watching through one would register inotify watches on a tree outside
		// /input whose certs can never be converted — and a symlink to a large tree
		// would burn the watch quota.
		info, err := os.Lstat(event.Name)
		if err != nil {
			// A vanished path is the expected case (an atomic-write temp created and
			// renamed away before this event was handled), so it stays silent. Any
			// other error means the created path could NOT be classified: if it was a
			// directory it is now outside the watch set, and its renewals are covered
			// only by the periodic fallback re-sync (never, with the fallback
			// disabled). That is a degraded state an operator must be able to see.
			if !errors.Is(err, fs.ErrNotExist) {
				slog.Warn("cannot classify a created path; if it is a directory it stays unwatched until the next fallback re-sync",
					"path", event.Name, "error", err)
			}
			return isCertFile(event.Name)
		}
		if info.IsDir() {
			if addErr := w.addWatchDirs(ctx, watcher, event.Name); addErr != nil && ctx.Err() == nil {
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
// with a periodic full scan as a safety net. It returns nil when ctx is
// cancelled and ErrWatchLost when the watcher's Events or Errors channel closes
// under a live ctx, which ends change detection for the life of the process; a
// closure observed after cancellation is a shutdown and also returns nil.
func (w *Watcher) watchLoop(ctx context.Context, watcher *fsnotify.Watcher) error {
	st := newWatchState(w)
	defer st.stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-watcher.Events:
			if !w.handleEventRecv(ctx, watcher, st, event, ok) {
				return lostOrShutdown(ctx, "fsnotify events channel closed, watcher stopping; process will exit and restart")
			}

		case <-st.debounceTimer.C:
			st.runDebouncedScan(ctx)

		case <-st.fallbackChan():
			w.handleFallbackTick(ctx, watcher, st)

		case err, ok := <-watcher.Errors:
			if !w.handleErrorRecv(ctx, watcher, st, err, ok) {
				return lostOrShutdown(ctx, "fsnotify errors channel closed, watcher stopping; process will exit and restart")
			}
		}
	}
}

// lostOrShutdown maps a watcher-death exit to nil when the process is already
// shutting down: an Events/Errors channel closing in the same instant as
// cancellation is a clean stop, not lost change detection, and must not turn a
// SIGTERM into exit 1 with an ERROR claiming there was no shutdown signal.
// watchLoop's select has no ctx precedence of its own (Go picks a ready case at
// random), so the precedence lives here, at the single translation point — and
// so does the operator-facing ERROR for lossMessage, which describes the closed
// channel: logging it in the receive helpers would announce a restart that is
// not happening whenever cancellation wins this check.
func lostOrShutdown(ctx context.Context, lossMessage string) error {
	if ctx.Err() != nil {
		return nil
	}
	slog.Error(lossMessage)
	return ErrWatchLost
}

// handleEventRecv processes one receive from the watcher's event channel and
// reports whether the loop should keep running. A closed channel means the
// watcher is dead, so the loop must exit (the process then restarts); otherwise
// an event classified as interesting arms the debounced rescan. The closure is
// reported by the return value alone: lostOrShutdown owns the ERROR, so a
// closure racing a shutdown stays quiet.
func (w *Watcher) handleEventRecv(ctx context.Context, watcher *fsnotify.Watcher, st *watchState, event fsnotify.Event, ok bool) bool {
	if !ok {
		return false
	}
	if w.handleFsEvent(ctx, watcher, event) {
		st.scheduleScan()
	}
	return true
}

// handleErrorRecv processes one receive from the watcher's error channel and
// reports whether the loop should keep running. A closed channel means the
// watcher is dead, so the loop must exit (lostOrShutdown logs it, if it is a
// genuine loss rather than a shutdown); an event-queue overflow additionally
// re-syncs the watch set.
func (w *Watcher) handleErrorRecv(ctx context.Context, watcher *fsnotify.Watcher, st *watchState, err error, ok bool) bool {
	if !ok {
		return false
	}
	if st.handleWatcherError(err) {
		// The dropped events may have included the Create of a new
		// directory, which would otherwise stay unwatched for the rest of
		// the process's life. watcher.Add is idempotent for a directory
		// already in the watch set, so re-walking the tree only
		// re-attaches what the overflow lost.
		if addErr := w.addWatchDirs(ctx, watcher, w.root); addErr != nil && ctx.Err() == nil {
			slog.Warn("failed to re-sync the watch set after an event-queue overflow", "error", addErr)
		}
	}
	return true
}

// handleFallbackTick runs the periodic safety-net rescan, re-asserting the
// watch set first. addWatchDirs is idempotent for a directory already watched,
// so this only restores what was lost: a directory whose watcher.Add failed
// while it was unreadable (or while fs.inotify.max_user_watches was exhausted)
// and whose condition has since been repaired, or one whose Create event never
// arrived. Without it such a directory stays outside the watch set for the life
// of the process and its renewals are detected only on the fallback cadence.
// Re-attaching before the scan also means a change landing during the scan is
// still reported as an event. A re-sync cut short by shutdown skips the scan
// entirely: the loop is about to return anyway.
func (w *Watcher) handleFallbackTick(ctx context.Context, watcher *fsnotify.Watcher, st *watchState) {
	if addErr := w.addWatchDirs(ctx, watcher, w.root); addErr != nil {
		if ctx.Err() != nil {
			return
		}
		slog.Warn("failed to re-sync the watch set during the periodic fallback scan", "error", addErr)
	}
	st.runFallbackScan(ctx)
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
	slog.Warn("watcher error; the watch loop continues and a change missed because of it is recovered by the periodic fallback rescan (if enabled)",
		"root", st.w.root, "error", err)
	return false
}

// pollLoopWithUpgrade polls on the fallback interval and attempts to
// upgrade to fsnotify on every tick. With the fallback disabled (<= 0) there is no
// interval to poll on, so it logs an error once that change detection is inactive and
// blocks until ctx is cancelled. It returns nil on shutdown and propagates
// ErrWatchLost from the watch loop it upgrades into.
func (w *Watcher) pollLoopWithUpgrade(ctx context.Context) error {
	if w.fallback <= 0 {
		slog.Error("polling disabled and fsnotify unavailable; change detection inactive until restart",
			"remediation", "unset FALLBACK_SCAN_HOURS (or set it above 0) so the periodic rescan covers the missing fsnotify watch")
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(w.fallback)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			slog.Debug("poll scan triggered", "interval", w.fallback)
			fw, err := fsnotify.NewWatcher()
			if err != nil {
				slog.Info("fsnotify still unavailable, staying in poll mode",
					"mode", "poll", "retry_interval", w.fallback, "error", err)
				w.onChange(ctx)
				continue
			}
			if addErr := w.addWatchDirs(ctx, fw, w.root); addErr != nil {
				fw.Close()
				if ctx.Err() != nil {
					return nil // shutdown interrupted the walk; not an upgrade failure
				}
				slog.Info("fsnotify available but the watch set could not be rebuilt, staying in poll mode",
					"mode", "poll", "retry_interval", w.fallback, "error", addErr)
				w.onChange(ctx)
				continue
			}
			slog.Info("fsnotify recovered, upgrading from poll to watch",
				"directory_count", len(fw.WatchList()))
			// Attach-then-scan: this tick's scan runs with the new watch set
			// already live, so a renewal landing during it still produces an
			// event instead of falling into a gap covered by neither mode.
			w.onChange(ctx)
			loopErr := w.watchLoop(ctx, fw)
			fw.Close()
			return loopErr
		}
	}
}

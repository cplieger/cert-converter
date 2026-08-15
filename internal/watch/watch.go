// Package watch provides filesystem watching with fsnotify and poll fallback.
package watch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/scanbudget"
	"github.com/cplieger/cert-converter/internal/scancadence"
	"github.com/fsnotify/fsnotify"
)

// LostError is the SOLE terminal-loss contract of this package: it reports that
// change detection ended for a reason other than shutdown — the fsnotify watcher
// died and cannot be recovered in-process, so the caller must exit non-zero for a
// restart — and it names WHICH loss ended it and, where one exists, the operator
// action that prevents it.
type LostError struct {
	// Cause is the specific loss, phrased to complete the caller's sentence:
	// "change detection is dead: <cause>".
	Cause string
	// Remediation is the operator action that prevents this loss, or empty when
	// there is none to give (a dead fsnotify fd is not a misconfiguration).
	Remediation string
}

// Error renders the terminal-loss prefix plus the specific loss, so a caller that
// only logs the error still names which loss occurred.
func (e *LostError) Error() string { return "change detection lost: " + e.Cause }

// The lost-change-detection conditions this package can reach.
var (
	errRootWatchRemoved = &LostError{
		Cause: "the fsnotify root watch was removed while the periodic rescan is disabled",
		// The Cause still has to name the root Remove/Rename: enabling the rescan
		// restores a recovery mechanism but not a root that is genuinely gone, so the
		// operator needs both facts to tell mount repair from fallback hardening.
		Remediation: "unset FALLBACK_SCAN_HOURS (or set it above 0) so the periodic rescan re-attaches the root " +
			"watch after it is removed; if /input itself is gone, restore the mount",
	}
	errEventsChannelClosed = &LostError{
		Cause: "the fsnotify events channel closed",
	}
	errErrorsChannelClosed = &LostError{
		Cause: "the fsnotify errors channel closed",
	}
	errNoWatchNoFallback = &LostError{
		Cause: "no fsnotify watch could be established and the periodic rescan is disabled",
		Remediation: "unset FALLBACK_SCAN_HOURS (or set it above 0) so the periodic rescan covers the missing " +
			"fsnotify watch; the preceding WARN names why the fsnotify watch is missing",
	}
)

// --- Watcher construction and options ---

// newFSWatcher is the fsnotify construction seam.
var newFSWatcher = fsnotify.NewWatcher

// removeWatch is the kernel-unregistration seam, a package var in the same style
// as newFSWatcher: pruneWatches' stays-charged direction fires only when
// inotify_rm_watch itself fails (EINVAL/EBADF), which no test can produce on a
// healthy host, so a test injects the refusal here.
var removeWatch = func(watcher *fsnotify.Watcher, path string) error {
	return watcher.Remove(path)
}

// Watcher monitors a directory tree for cert/key changes and invokes a callback.
type Watcher struct {
	onChange func(ctx context.Context)

	// watched mirrors the fsnotify registration set, so membership is a map
	// lookup rather than a scan of fsnotify's own list (see watchSetHas).
	watched map[string]struct{}

	root     string
	debounce time.Duration
	fallback time.Duration

	// maxEntries is how many paths ONE watch-set walk may enumerate before it
	// stops registering (scanbudget.Default when non-positive).
	maxEntries int

	// watchedMu guards watched.
	watchedMu sync.Mutex
}

// Option configures a Watcher.
type Option func(*Watcher)

// WithDebounce sets the debounce window for coalescing events.
func WithDebounce(d time.Duration) Option {
	return func(w *Watcher) { w.debounce = d }
}

// WithFallback sets the periodic poll/fallback interval.
func WithFallback(d time.Duration) Option {
	return func(w *Watcher) { w.fallback = d }
}

// WithMaxEntries sets how many paths one watch-set walk may enumerate.
func WithMaxEntries(n int) Option {
	return func(w *Watcher) { w.maxEntries = n }
}

// watchBudgetMsg is the operator-facing half of a watch-set walk that stopped at
// the budget.
const watchBudgetMsg = scanbudget.InputTreeTooLarge + "; stopping the watch-set walk, so directories past the budget are unwatched and renewals under them are covered only by the periodic rescan, health is unaffected"

// coverageAttrs closes a degraded-path record with the two cadences that answer
// the one question such a record raises: will anything revisit what was just lost?
// Both travel together because either alone answers it wrongly — fallback_scan is
// the routine rescan and reads "disabled" when the operator switched it off, while
// scan_floor is the reconciliation floor they cannot switch off, which is what
// revisits the path in exactly that configuration.
func (w *Watcher) coverageAttrs(attrs ...any) []any {
	return append(attrs, scancadence.CoverageAttrs(w.fallback)...)
}

// safetyNetTrigger names the clock behind one safety-net scan for its mode record:
// the operator's configured cadence, or the reconciliation floor standing in for it.
func (w *Watcher) safetyNetTrigger() string {
	if scancadence.Effective(w.fallback) == w.fallback {
		return triggerFallback
	}
	return triggerReconcile
}

// --- The mode record: how change detection reports which mode it is in ---

// detectionMode is the change-detection mode, modelled explicitly because it is
// an operational STATE and not a one-off startup event: poll mode raises renewal
// latency from "immediately" to FALLBACK_SCAN_HOURS for as long as it lasts, and
// health is deliberately blind to it (the marker tracks conversion failures, and
// a poll scan refreshes it exactly like a watch scan does).
type detectionMode string

const (
	modeWatch   detectionMode = "watch"
	modePoll    detectionMode = "poll"
	modeStartup detectionMode = "startup" // previous_mode only, never mode
)

// level maps a mode to the level its records are emitted at, and is the single
// home of the rule that gives the degradation a recurring signal at
// LOG_LEVEL=warn: poll mode is a STANDING degradation, so its records are WARNs,
// while watch mode is the intended state and reports at Info.
func (m detectionMode) level() slog.Level {
	if m == modePoll {
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

// The one message string per scan.
const msgScanState = "change detection scan"

// The trigger attribute's closed set: which clock or event caused this scan.
const (
	triggerAttach    = "attach"    // watch mode's post-attach scan (scanThenWatch)
	triggerEvent     = "event"     // a debounced fsnotify event
	triggerFallback  = "fallback"  // the safety-net rescan on the operator's FALLBACK_SCAN_HOURS cadence
	triggerReconcile = "reconcile" // the safety-net rescan on the reconciliation floor (scancadence.Floor)
	triggerStartup   = "startup"   // poll mode's initial scan
	triggerPoll      = "poll"      // a poll-mode tick scan
)

// The upgrade_stage attribute's closed set, carried by a poll-mode scan record
// alongside the error: WHY the fsnotify upgrade this tick attempted failed.
const (
	upgradeStageConstruct = "fsnotify_unavailable"
	upgradeStageWatchDirs = "watch_set_rebuild_failed"
)

// logModeEntry emits the transition record: change detection has just ENTERED
// mode, coming from previous.
func (w *Watcher) logModeEntry(ctx context.Context, mode, previous detectionMode, msg string, extra ...any) {
	attrs := w.coverageAttrs("mode", string(mode), "previous_mode", string(previous))
	slog.Log(ctx, mode.level(), msg, append(attrs, extra...)...)
}

// logScanState emits the ONE state record every scan carries, naming the mode
// that is live as the scan runs.
func (w *Watcher) logScanState(ctx context.Context, mode detectionMode, trigger string, extra ...any) {
	attrs := w.coverageAttrs("mode", string(mode), "trigger", trigger)
	slog.Log(ctx, mode.level(), msgScanState, append(attrs, extra...)...)
}

// New creates a Watcher for the given root directory.
func New(root string, onChange func(ctx context.Context), opts ...Option) *Watcher {
	// Cleaned here so the field can only ever hold a canonical path: the
	// root-vs-descendant severity policy (handleWatchAddError, classifyWatchEntry,
	// validateWatchRootEntry) is raw string equality against it, and a trailing
	// slash or a "./" prefix would make a refused registration of the ROOT compare
	// unequal and be downgraded to a skipped WARN.
	w := &Watcher{
		root:     filepath.Clean(root),
		onChange: onChange,
		watched:  make(map[string]struct{}),
	}
	for _, o := range opts {
		o(w)
	}
	return w
}

// --- Run: mode supervision ---

// Run starts watching.
func (w *Watcher) Run(ctx context.Context) error {
	watcher, stopped := w.attachWatchSet(ctx)
	if stopped {
		return nil
	}
	if watcher == nil {
		upgraded, pollErr := w.pollLoopWithUpgrade(ctx)
		if upgraded == nil {
			return pollErr // poll mode reached its own terminal answer
		}
		watcher = upgraded
	}
	return w.watchMode(ctx, watcher)
}

// attachWatchSet is Run's initial mode selection: it constructs the fsnotify
// watcher and registers the watch set, announcing the mode it entered either
// way.
func (w *Watcher) attachWatchSet(ctx context.Context) (watcher *fsnotify.Watcher, stopped bool) {
	fw, stage, err := w.tryAttachWatchSet(ctx)
	switch stage {
	case stageStopped:
		return nil, true // shutdown arrived mid-attempt; not a watch failure
	case stageConstruct:
		w.logModeEntry(ctx, modePoll, modeStartup,
			"fsnotify unavailable, using polling with periodic upgrade attempts", "error", err)
		return nil, false
	case stageWatchDirs:
		w.logModeEntry(ctx, modePoll, modeStartup,
			"failed to watch directories, using polling with periodic upgrade attempts", "error", err)
		return nil, false
	case stageAttached:
	}

	w.logModeEntry(ctx, modeWatch, modeStartup, "fsnotify active", "directory_count", len(fw.WatchList()))
	return fw, false
}

// attachStage names the outcome of one attach attempt, so each mode entry can
// phrase its own operator record at its own level while the sequence itself has
// a single home.
type attachStage int

const (
	stageAttached  attachStage = iota // the watch set is live
	stageStopped                      // a shutdown arrived mid-attempt; not a watch failure
	stageConstruct                    // newFSWatcher failed
	stageWatchDirs                    // the watch-set walk failed
)

// tryAttachWatchSet is the construct-then-register sequence both mode entries
// share (Run's initial attach and pollTick's upgrade retry): it releases the
// watcher when the walk fails, so no fd or readEvents goroutine survives into a
// long-lived poll mode, and it reports a shutdown that arrived mid-attempt as
// stageStopped rather than as a degradation.
func (w *Watcher) tryAttachWatchSet(ctx context.Context) (*fsnotify.Watcher, attachStage, error) {
	fw, err := newFSWatcher()
	if err != nil {
		if ctx.Err() != nil {
			return nil, stageStopped, nil
		}
		return nil, stageConstruct, err
	}
	// The new watcher's registration set is empty, so the mirror the per-event
	// membership guard reads must start empty with it.
	w.resetWatchSet()
	if addErr := w.addWatchDirs(ctx, fw, w.root); addErr != nil {
		fw.Close() // release fd + readEvents goroutine before long-lived fallback
		if ctx.Err() != nil {
			return nil, stageStopped, nil
		}
		return nil, stageWatchDirs, addErr
	}
	return fw, stageAttached, nil
}

// watchMode runs one whole watch-mode lifetime over an already-attached watch
// set, and is the ONLY statement of that sequence: dump the watch set, scan with
// it live, run the watch loop, and release the watcher on every exit path.
func (w *Watcher) watchMode(ctx context.Context, watcher *fsnotify.Watcher) error {
	defer watcher.Close()
	logWatchSet(watcher)
	return w.scanThenWatch(ctx, watcher)
}

// logWatchSet emits the watched directories at Debug.
func logWatchSet(watcher *fsnotify.Watcher) {
	// Every name here came from the /input walk, so each one is sanitized for the log
	// (logtext.Path); the registered paths themselves are untouched.
	dirs := watcher.WatchList()
	logged := make([]string, len(dirs))
	for i, dir := range dirs {
		logged[i] = logtext.Path(dir)
	}
	slog.Debug("fsnotify watch set", "directories", logged)
}

// scanThenWatch scans once with the watch set already live and then runs the
// watch loop.
func (w *Watcher) scanThenWatch(ctx context.Context, watcher *fsnotify.Watcher) error {
	if ctx.Err() != nil {
		return nil
	}
	w.logScanState(ctx, modeWatch, triggerAttach)
	w.onChange(ctx)
	return w.watchLoop(ctx, watcher)
}

// --- Watch-set maintenance ---

// addWatchDirs recursively adds all directories under root to the watcher.
func (w *Watcher) addWatchDirs(ctx context.Context, watcher *fsnotify.Watcher, root string) error {
	return w.walkWatchDirs(ctx, root, func(path string) error {
		return w.attachWatch(watcher, root, path)
	})
}

// walkWatchDirs is the ONE traversal both watch-set walks run: the per-walk
// entry budget, its WARN-and-stop, and the shared per-entry policy
// (classifyWatchEntry) are applied here, and only what happens to an admitted
// directory differs per walk -- the registering walk attaches it, the
// rebuild's preflight collects it.
func (w *Watcher) walkWatchDirs(ctx context.Context, root string, register func(path string) error) error {
	// A cancelled walk does no filesystem work, which is what the two syscalls
	// below would otherwise cost on the shutdown path.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	// Cleaned once, so the ambient names the callback rebuilds and every
	// `path == root` comparison below it (classifyWatchEntry, handleWatchAddError,
	// validateWatchRootEntry) are made against one spelling.
	root = filepath.Clean(root)
	// The root's OWN entry is Lstat'ed HERE, and this is the one thing the confined
	// walk cannot express: os.OpenRoot resolves its root, so a symlinked or
	// non-directory /input would arrive at the callback as a resolved directory and
	// the two fatal refusals validateWatchRootEntry words would never fire -- the
	// exec-away case that leaves Run logging "fsnotify active" over an empty watch
	// set while the scan keeps the health marker green.
	fi, statErr := os.Lstat(root)
	if statErr != nil {
		return statErr // a root that cannot be inspected is fatal, as it is today
	}
	if !fi.IsDir() {
		return w.validateWatchRootEntry(root, fs.FileInfoToDirEntry(fi))
	}
	handle, openErr := os.OpenRoot(root)
	if openErr != nil {
		return openErr
	}
	defer func() { _ = handle.Close() }()
	// One Counter per walk, so the operator's ceiling bounds one traversal
	// (scanbudget.Default when nothing was configured): an unbounded walk is not an
	// option, because the tree it enumerates is one this app does not own.
	budget := scanbudget.NewCounter(w.maxEntries)
	// atomicfile owns the traversal mechanics, exactly as internal/process's two
	// walks over the same trees do: fixed 256-entry ReadDir batches, so
	// MAX_SCAN_ENTRIES bounds this walk's MEMORY and not only its entry count; one
	// directory handle open at a time; and O_DIRECTORY|O_NONBLOCK, so a directory
	// replaced by a FIFO between the readdir that classified it and the descent is
	// refused with ENOTDIR instead of blocking this goroutine in open(2) forever.
	return atomicfile.WalkDirInRoot(ctx, handle, func(rel string, d fs.DirEntry, walkErr error) error {
		// fsnotify registers a PATHNAME, not a directory handle (see addWatchDirs),
		// so the ambient name is rebuilt for the registration and the diagnostics;
		// the enumeration itself no longer constructs one.
		path := filepath.Join(root, rel)
		exceeded, err := exceedsEntryBudget(ctx, &budget, walkErr)
		if err != nil {
			return err
		}
		if exceeded {
			w.warnWatchBudget(root, &budget)
			return fs.SkipAll
		}
		// d is nil on this walk's error arm (atomicfile reports a directory it could
		// not open or finish for that directory's OWN path with d nil).
		ok, err := w.classifyWatchEntry(ctx, root, path, d, walkErr)
		if err != nil || !ok {
			return err
		}
		return register(path)
	})
}

// exceedsEntryBudget admits one walk callback: it honours cancellation first, then
// charges the shared Counter for a NORMAL callback only, and reports whether the walk
// has run out of budget.
func exceedsEntryBudget(ctx context.Context, budget *scanbudget.Counter, walkErr error) (bool, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if walkErr != nil {
		return false, nil // The walk is repeating the directory to report its read error.
	}
	return !budget.Charge(), nil
}

// warnWatchBudget emits the entry-ceiling WARN.
func (w *Watcher) warnWatchBudget(root string, budget *scanbudget.Counter) {
	slog.Warn(watchBudgetMsg, w.coverageAttrs(
		"root", logtext.Path(root), "max_entries", budget.Max(),
		"remediation", scanbudget.InputRemediation)...)
}

// classifyWatchEntry applies the per-entry policy BOTH watch-set walks share — the
// event-driven registering walk (addWatchDirs) and the rebuild's preflight
// enumeration (desiredWatchDirs) — and reports whether the entry is a directory the
// walk should register: cancellation first, then the walk-error policy (fatal at the
// root, warn-and-skip below it), then the directory filter.
func (w *Watcher) classifyWatchEntry(
	ctx context.Context, root, path string, d fs.DirEntry, walkErr error,
) (bool, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if walkErr != nil {
		if path == root {
			return false, walkErr
		}
		// A path that disappeared mid-walk is known to be GONE, not unwatchable:
		// the walk lists a directory from its parent's ReadDir and only
		// discovers the deletion when it tries to read it, so an ordinary removal
		// under a churning /input arrives here as ENOENT.
		if errors.Is(walkErr, fs.ErrNotExist) {
			slog.Debug("path disappeared during the watch-set walk",
				"path", logtext.Path(path), "error", logtext.Path(walkErr.Error()))
			return false, nil
		}
		slog.Warn("skipping unwatchable path; renewals under it require a full rescan",
			w.coverageAttrs("path", logtext.Path(path), "error", logtext.Path(walkErr.Error()))...)
		return false, nil
	}
	if !d.IsDir() {
		return false, w.validateWatchRootEntry(path, d)
	}
	return true, nil
}

// attachWatch registers one directory and records it in the membership mirror.
func (w *Watcher) attachWatch(watcher *fsnotify.Watcher, root, path string) error {
	if addErr := watcher.Add(path); addErr != nil {
		return w.handleWatchAddError(root, path, addErr)
	}
	w.recordWatch(path)
	return nil
}

// validateWatchRootEntry applies the non-directory policy for the WATCHER's own
// root: a regular file anywhere else is simply not registered (it is watched
// through its parent), but a non-directory /input is fatal, not a skip.
func (w *Watcher) validateWatchRootEntry(path string, d fs.DirEntry) error {
	if path != w.root {
		return nil
	}
	if d.Type()&fs.ModeSymlink != 0 {
		return fmt.Errorf("watch root %q is a symlink; the watch-set walk Lstats the root and does not descend it, so no directory under the target would be watched - bind-mount the target directory at %q instead", path, path)
	}
	return fmt.Errorf("watch root %q is not a directory", path)
}

// handleWatchAddError applies addWatchDirs' walk-error policy to a failed watch
// REGISTRATION: fatal at the root, warn-and-skip below it.
func (w *Watcher) handleWatchAddError(root, path string, addErr error) error {
	if path == root {
		return addErr
	}
	// Same vanished-path rule as classifyWatchEntry's walk-error arm: a directory
	// the preflight enumerated and that was deleted before reassertWatches got to
	// it fails with ENOENT, which is neither of the two conditions
	// watchAddRemediation names.
	if errors.Is(addErr, fs.ErrNotExist) {
		slog.Debug("directory disappeared before its watch was registered",
			"path", logtext.Path(path), "error", addErr)
		return nil
	}
	slog.Warn("skipping unwatchable directory; renewals under it require a full rescan",
		w.coverageAttrs("path", logtext.Path(path), "error", addErr,
			"remediation", watchAddRemediation)...)
	return nil
}

// watchAddRemediation names the two operator actions a refused registration can call
// for: the directory may be unreadable to this UID, or the per-UID inotify watch quota
// may be exhausted (ENOSPC from inotify_add_watch), which only the host can raise.
const watchAddRemediation = "check that this directory is readable by the UID the container runs as, or raise the host's fs.inotify.max_user_watches if the per-UID inotify watch quota is exhausted"

// watchSetHas reports whether path is already registered with the watcher.
func (w *Watcher) watchSetHas(path string) bool {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	_, ok := w.watched[filepath.Clean(path)]
	return ok
}

// recordWatch notes a registration this package made, so watchSetHas can answer
// from the mirror.
func (w *Watcher) recordWatch(path string) {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	w.watched[filepath.Clean(path)] = struct{}{}
}

// forgetWatch drops a path whose watch is gone.
func (w *Watcher) forgetWatch(path string) {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	delete(w.watched, filepath.Clean(path))
}

// resetWatchSet empties the mirror for a fresh fsnotify watcher.
func (w *Watcher) resetWatchSet() {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	w.watched = make(map[string]struct{})
}

// watchSetSnapshot copies the mirror's paths, so a sweep can iterate them while
// forgetWatch mutates the map underneath it.
func (w *Watcher) watchSetSnapshot() []string {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	paths := make([]string, 0, len(w.watched))
	for path := range w.watched {
		paths = append(paths, path)
	}
	return paths
}

// pruneWatches unregisters every live registration a rebuild's preflight no longer
// wants, which is what keeps the mirror an honest picture of the LIVE registration set
// rather than only of the last walk.
func (w *Watcher) pruneWatches(watcher *fsnotify.Watcher, desired map[string]struct{}) {
	for _, path := range w.watchSetSnapshot() {
		if _, wanted := desired[path]; wanted {
			continue
		}
		if err := removeWatch(watcher, path); err != nil {
			if !errors.Is(err, fsnotify.ErrNonExistentWatch) {
				slog.Warn("failed to unregister a stale fsnotify watch; it stays charged to the live watch set",
					w.coverageAttrs("path", logtext.Path(path), "error", logtext.Path(err.Error()))...)
				continue
			}
			slog.Debug("stale fsnotify registration already gone", "path", logtext.Path(path), "error", logtext.Path(err.Error()))
		}
		w.forgetWatch(path)
	}
}

// --- Event classification ---

// handleFsEvent keeps directory watches current and reports whether an event
// warrants a rescan.
func (w *Watcher) handleFsEvent(ctx context.Context, watcher *fsnotify.Watcher, event fsnotify.Event) bool {
	slog.Debug("fs event", "op", event.Op.String(), "path", logtext.Path(event.Name))
	switch {
	case event.Has(fsnotify.Create):
		// A newly created directory joins the watch set (and triggers a rescan,
		// because it may already hold a pair created before the watch attached); a
		// newly created file is classified by name.
		return w.handlePathEvent(ctx, watcher, event,
			"cannot classify a created path; rescanning because it may be a directory, but if it is one it stays unwatched until the next re-assert of the watch set",
			"failed to watch new directory subtree; renewals under it are covered only by the periodic rescan")
	case event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename):
		// event.Name is already gone on Remove/Rename (inotify reports the old
		// name), so there is nothing to add to the watch set: fsnotify drops the
		// watch for a deleted directory itself, and a rename destination inside
		// the tree arrives as its own Create event.
		return true
	case event.Has(fsnotify.Write):
		return layout.IsRelevant(event.Name)
	case event.Has(fsnotify.Chmod):
		// The recovery path for a permission repair on a cert, on a key, or on a
		// directory the watch set had to skip -- the app's most likely operator
		// error.
		return w.handlePathEvent(ctx, watcher, event,
			"cannot classify a path whose permissions changed; rescanning because it may be an unwatched directory",
			"failed to watch a directory whose permissions changed; renewals under it are covered only by the periodic rescan")
	}
	return false
}

// handlePathEvent is the decision tree the Create and Chmod arms share, and the
// single home of the unclassifiable-path rule: extend the watch set when the
// event's path is a directory, classify a path that is merely GONE by name, and
// conservatively rescan every other stat failure.
func (w *Watcher) handlePathEvent(
	ctx context.Context, watcher *fsnotify.Watcher, event fsnotify.Event, classifyWarning, addWarning string,
) bool {
	info, err := os.Lstat(event.Name)
	if err != nil {
		// A vanished path is known to be gone rather than unclassifiable (an
		// atomic-write temp created and renamed away before this event was
		// handled), so it stays silent and is classified by name: there is nothing
		// left to watch or re-attach.
		if errors.Is(err, fs.ErrNotExist) {
			return layout.IsRelevant(event.Name)
		}
		// Any other error is the unclassifiable-path case, and gets that rule's
		// answer: rescan rather than guess from the suffix, because a domain-named
		// directory ("example.com") reads as an unrelated file to
		// layout.IsRelevant, and a pair already inside it
		// would then wait for the next periodic re-sync.
		slog.Warn(classifyWarning,
			w.coverageAttrs("path", logtext.Path(event.Name), "error", logtext.Path(err.Error()))...)
		return true
	}
	if !info.IsDir() {
		return layout.IsRelevant(event.Name)
	}
	if w.watchSetHas(event.Name) {
		return true // already watched: nothing to re-attach, the debounced rescan covers content
	}
	if addErr := w.addWatchDirs(ctx, watcher, event.Name); addErr != nil && ctx.Err() == nil {
		// The same vanished-path rule classifyWatchEntry's walk-error arm and
		// handleWatchAddError already apply, and the one this function's own Lstat arm
		// above applies to a vanished event path: a directory created and removed again
		// before its subtree could be walked leaves nothing to renew, so the WARN's
		// consequence clause is false and neither action watchAddRemediation names
		// applies to it — the directory is gone, so nothing is unreadable and no inotify
		// slot was ever requested.
		if errors.Is(addErr, fs.ErrNotExist) {
			slog.Debug("directory disappeared before its subtree could be watched",
				"path", logtext.Path(event.Name), "error", logtext.Path(addErr.Error()))
			return true
		}
		slog.Warn(addWarning,
			w.coverageAttrs("path", logtext.Path(event.Name), "error", logtext.Path(addErr.Error()),
				"remediation", watchAddRemediation)...)
	}
	return true
}

// --- Watch loop, its receive arms, and its timer state ---

// watchLoop uses fsnotify for immediate reaction to cert changes,
// with a periodic full scan as a safety net.
func (w *Watcher) watchLoop(ctx context.Context, watcher *fsnotify.Watcher) error {
	st := newWatchState(w)
	defer st.stop()
	return w.runWatchLoop(ctx, watcher, st)
}

// runWatchLoop is watchLoop's select over already-built loop state, split out so
// a test can hand the loop a watchState whose timers it has already positioned
// (an almost-expired re-assert floor, for instance) and observe which arm acts on
// them.
func (w *Watcher) runWatchLoop(ctx context.Context, watcher *fsnotify.Watcher, st *watchState) error {
	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-watcher.Events:
			if lost := w.handleEventRecv(ctx, watcher, st, event, ok); lost != nil {
				return lostOrShutdown(ctx, lost)
			}

		case <-st.debounceTimer.C:
			st.runDebouncedScan(ctx, watcher)

		case <-st.repairTimer.C:
			st.runDeferredRepair(ctx, watcher)

		case <-st.safetyNetTimer.C:
			w.handleSafetyNetTick(ctx, watcher, st)

		case err, ok := <-watcher.Errors:
			if lost := w.handleErrorRecv(ctx, watcher, st, err, ok); lost != nil {
				return lostOrShutdown(ctx, lost)
			}
		}
	}
}

// handleRootWatchLoss reacts to an event that took the watch on the ROOT itself
// away, and reports whether change detection is still live.
func (w *Watcher) handleRootWatchLoss(ctx context.Context, watcher *fsnotify.Watcher, st *watchState, event fsnotify.Event) bool {
	if filepath.Clean(event.Name) != w.root {
		return true
	}
	if !event.Has(fsnotify.Remove) && !event.Has(fsnotify.Rename) {
		return true
	}
	if w.fallback <= 0 {
		return false
	}
	// A root that is genuinely gone surfaces as the WARN below plus the scan error
	// the debounced rescan reports.
	slog.Warn("fsnotify root watch lost; re-attaching the watch set, renewals until it succeeds are covered only by the periodic rescan",
		w.coverageAttrs("root", logtext.Path(w.root), "op", event.Op.String())...)
	st.resync(ctx, watcher,
		"failed to re-attach the watch set after the root watch was lost; renewals are covered only by the periodic rescan")
	return true
}

// lostOrShutdown maps a watcher-death exit to nil when the process is already
// shutting down: an Events/Errors channel closing in the same instant as
// cancellation is a clean stop, not lost change detection, and must not turn a
// SIGTERM into exit 1 with an announcement claiming there was no shutdown
// signal.
func lostOrShutdown(ctx context.Context, lost *LostError) error {
	if ctx.Err() != nil {
		return nil
	}
	return lost
}

// handleEventRecv owns watchLoop's whole event-channel arm: it reports which
// terminal loss that arm observed, or nil while change detection is live.
func (w *Watcher) handleEventRecv(
	ctx context.Context, watcher *fsnotify.Watcher, st *watchState, event fsnotify.Event, ok bool,
) *LostError {
	if !ok {
		return errEventsChannelClosed
	}
	// Cancellation outranks an ordinary event, exactly as it does in every timer,
	// attach, and channel-loss arm of this loop: watchLoop's select picks a ready
	// case at random, so a queued Remove/Rename or Create can still land here after
	// ctx.Done is ready.
	if ctx.Err() != nil {
		return nil
	}
	// Forget before the root-loss handler runs: the kernel drops the watch along
	// with the directory, so an unforgotten path would look watched and never be
	// re-attached if it comes back.
	if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
		w.forgetWatch(event.Name)
	}
	if !w.handleRootWatchLoss(ctx, watcher, st, event) {
		return errRootWatchRemoved
	}
	if w.handleFsEvent(ctx, watcher, event) {
		st.scheduleScan()
	}
	return nil
}

// handleErrorRecv owns watchLoop's whole error-channel arm: it reports which
// terminal loss that arm observed, or nil while change detection is live.
func (w *Watcher) handleErrorRecv(
	ctx context.Context, watcher *fsnotify.Watcher, st *watchState, err error, ok bool,
) *LostError {
	if !ok {
		return errErrorsChannelClosed
	}
	// Same cancellation precedence as handleEventRecv: a queued watcher error
	// selected against a ready ctx.Done would otherwise log a degradation WARN and
	// schedule a re-sync for a loop that is already exiting.
	if ctx.Err() != nil {
		return nil
	}
	if st.handleWatcherError(err) {
		// The dropped events may have included the Create of a new directory, which
		// would otherwise stay unwatched for the rest of the process's life.
		st.resyncOrDefer(ctx, watcher,
			"failed to re-sync the watch set after an event-queue overflow; a directory whose Create was dropped stays unwatched until the next re-sync")
	}
	return nil
}

// handleSafetyNetTick runs the periodic safety-net rescan — the operator's
// FALLBACK_SCAN_HOURS cadence, or the reconciliation floor standing in for it — and
// re-asserts the watch set first.
func (w *Watcher) handleSafetyNetTick(ctx context.Context, watcher *fsnotify.Watcher, st *watchState) {
	// This tick re-asserts the whole set too, so it shares the pre-scan re-assert's
	// clock: a debounced scan landing right behind it has nothing left to recover, a
	// repair deferred earlier finds its interval already covered, and charging every
	// site to one timestamp is what keeps the walk on a cadence this process chose
	// (see minPreScanResync).
	st.resync(ctx, watcher,
		"failed to re-sync the watch set during the periodic safety-net scan; the scan below still runs, so a renewal is not missed")
	// Same stop-request rule as runDebouncedScan, on the success path too: the
	// select has no ctx precedence, so a safety-net deadline reached in the same
	// instant as cancellation can win over ctx.Done.
	if ctx.Err() != nil {
		return
	}
	st.runSafetyNetScan(ctx)
}

// resyncWatchSet re-asserts the watch set over the root (watcher.Add is idempotent,
// so a re-walk only restores what was lost) and, when that fails under a
// live ctx, reports it with the diagnostics every re-sync site owes the
// operator: WHICH root, what will revisit what is now unwatched (the fallback_scan
// and scan_floor pair coverageAttrs carries), and the error.
func (w *Watcher) resyncWatchSet(ctx context.Context, watcher *fsnotify.Watcher, warning string) {
	// A TRANSACTION, in three phases, and the ordering is the whole point: the mirror
	// describes the registrations the kernel is holding, so it may never be emptied while
	// the kernel still holds them -- a mirror emptied ahead of a walk that then fails at
	// the root leaves those descriptors live and unclaimed, so nothing ever unregisters
	// them and the per-event fast path reads their paths as unwatched.
	desired, walkErr := w.desiredWatchDirs(ctx, w.root)
	if walkErr != nil {
		if ctx.Err() == nil {
			slog.Warn(warning, w.coverageAttrs("root", logtext.Path(w.root), "error", walkErr)...)
		}
		return
	}
	// 2.
	w.pruneWatches(watcher, desired)
	// 3.
	if addErr := w.reassertWatches(ctx, watcher, desired); addErr != nil {
		if ctx.Err() == nil {
			slog.Warn(warning, w.coverageAttrs("root", logtext.Path(w.root), "error", addErr)...)
		}
		return
	}
	// Refresh the Debug dump on success: every re-sync exists to RECOVER watches that were
	// missing, so the recovered set - not the set as it stood at attach - is what an operator
	// diagnosing an incomplete watch set needs. The failure half is the WARN above.
	logWatchSet(watcher)
}

// desiredWatchDirs is a rebuild's PREFLIGHT: it enumerates the directories the tree
// wants registered, under the same per-walk entry budget and the same per-entry policy
// as the registering walk (classifyWatchEntry), but it calls neither watcher.Add nor
// recordWatch.
func (w *Watcher) desiredWatchDirs(ctx context.Context, root string) (map[string]struct{}, error) {
	desired := make(map[string]struct{})
	if err := w.walkWatchDirs(ctx, root, func(path string) error {
		desired[filepath.Clean(path)] = struct{}{}
		return nil
	}); err != nil {
		return nil, err
	}
	return desired, nil
}

// reassertWatches registers every path the preflight wants.
func (w *Watcher) reassertWatches(ctx context.Context, watcher *fsnotify.Watcher, desired map[string]struct{}) error {
	// Root first, unconditionally: its refusal is the fatal one
	// (handleWatchAddError), and this runs right after pruneWatches released
	// stale slots — under a nearly spent per-UID quota, map order could hand
	// those freed slots to descendant directories and leave the root, the one
	// watch a silently-dropped registration (IN_IGNORED on unmount/remount)
	// most needs restored, refused for another whole re-sync interval.
	rootPath := w.root
	if err := w.attachWatch(watcher, w.root, rootPath); err != nil {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	for path := range desired {
		if path == rootPath {
			continue
		}
		if err := w.attachWatch(watcher, w.root, path); err != nil {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	return nil
}

// minPreScanResync floors how often a debounced scan may re-assert the WHOLE watch set.
const minPreScanResync = time.Minute

// watchState carries the mutable accounting for one watchLoop run: the pending
// debounce flag and the debounce/safety-net/repair timers.
type watchState struct {
	w              *Watcher
	debounceTimer  *time.Timer
	safetyNetTimer *time.Timer // the periodic rescan: the operator's cadence, or the reconciliation floor
	repairTimer    *time.Timer // stopped unless a re-assert the floor skipped is waiting to run
	lastResync     time.Time   // when the watch set was last re-asserted; floors the pre-scan re-assert
	pending        bool
	repairPending  bool
}

// newWatchState builds the loop state: a stopped debounce timer (nothing is
// pending until an event arrives), a stopped repair timer (nothing has been
// deferred yet), and a running safety-net timer.
func newWatchState(w *Watcher) *watchState {
	st := &watchState{w: w}
	st.debounceTimer = time.NewTimer(w.debounce)
	st.debounceTimer.Stop()
	st.repairTimer = time.NewTimer(minPreScanResync)
	st.repairTimer.Stop()
	st.safetyNetTimer = time.NewTimer(scancadence.Effective(w.fallback))
	return st
}

// stop releases every timer when the loop exits.
func (st *watchState) stop() {
	st.debounceTimer.Stop()
	st.repairTimer.Stop()
	st.safetyNetTimer.Stop()
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

// resync charges the re-assert clock and then re-asserts the whole watch set.
func (st *watchState) resync(ctx context.Context, watcher *fsnotify.Watcher, warning string) {
	st.lastResync = time.Now()
	st.w.resyncWatchSet(ctx, watcher, warning)
}

// scheduleRepair defers the whole-tree re-assert that minPreScanResync just
// declined to run, arming it for the REMAINDER of the floor rather than for a
// fresh interval: the floor bounds how often the walk may run, so the repair is
// due the moment the current interval ends, and a burst inside one interval still
// produces at most one walk.
func (st *watchState) scheduleRepair() {
	if st.repairPending {
		return
	}
	st.repairPending = true
	// A non-positive remainder cannot arise from the caller's guard, and Reset
	// would simply fire on the next loop selection if it did, which is the correct
	// answer anyway.
	st.repairTimer.Reset(minPreScanResync - time.Since(st.lastResync))
}

// resyncOrDefer applies the minPreScanResync floor to one re-assert trigger, and is
// the single spelling of the floor's defer-not-drop rule: past the floor the watch
// set is re-asserted now; inside it the re-assert is deferred to the remainder of the
// interval (scheduleRepair), so a trigger is postponed to a cadence this process chose
// rather than dropped.
func (st *watchState) resyncOrDefer(ctx context.Context, watcher *fsnotify.Watcher, warning string) {
	if time.Since(st.lastResync) >= minPreScanResync {
		st.resync(ctx, watcher, warning)
		return
	}
	st.scheduleRepair()
}

// runDeferredRepair runs the re-assert a debounced scan deferred, and NOTHING else:
// no certificate scan, so watch-set repair runs on its own bounded schedule instead
// of borrowing the scan cadence an operator may have deliberately switched off.
func (st *watchState) runDeferredRepair(ctx context.Context, watcher *fsnotify.Watcher) {
	st.repairPending = false
	// Same cancellation precedence as every other arm: watchLoop's select has none
	// of its own, so a repair deadline reached in the same instant as a shutdown can
	// win over ctx.Done, and the walk would only warn about degradation the loop is
	// about to stop caring about.
	if ctx.Err() != nil {
		return
	}
	if time.Since(st.lastResync) < minPreScanResync {
		return
	}
	st.resync(ctx, watcher,
		"failed to re-assert the watch set on the deferred repair schedule; a registration the kernel dropped without an event stays unwatched until the next re-assert")
}

// runDebouncedScan fires the debounced rescan and re-arms the safety-net timer so
// the periodic interval is measured from the last real scan — which is also what
// makes the reconciliation floor cost an active deployment nothing.
func (st *watchState) runDebouncedScan(ctx context.Context, watcher *fsnotify.Watcher) {
	st.pending = false
	// A stop request must prevent new work on every arm: watchLoop's select has
	// no ctx precedence (Go picks a ready case at random), so a debounce deadline
	// reached in the same instant as cancellation can win over ctx.Done.
	if ctx.Err() != nil {
		return
	}
	st.resyncOrDefer(ctx, watcher,
		"failed to re-assert the watch set before a debounced scan; a registration the kernel dropped without an event stays unwatched until the next re-assert")
	// The re-sync can be cut short by cancellation, and the scan below would then be
	// spurious work for a loop that is already returning.
	if ctx.Err() != nil {
		return
	}
	st.w.logScanState(ctx, modeWatch, triggerEvent)
	st.w.onChange(ctx)
	st.safetyNetTimer.Reset(scancadence.Effective(st.w.fallback))
}

// runSafetyNetScan fires the periodic safety-net rescan and re-arms its timer.
func (st *watchState) runSafetyNetScan(ctx context.Context) {
	st.w.logScanState(ctx, modeWatch, st.w.safetyNetTrigger())
	st.w.onChange(ctx)
	st.safetyNetTimer.Reset(scancadence.Effective(st.w.fallback))
}

// handleWatcherError reacts to an fsnotify error: an event-queue overflow
// dropped events, so force a rescan to recover any missed renewal and report
// true so the caller also re-syncs the watch set (a dropped directory Create
// would otherwise leave that subtree unwatched until the process restarts); any
// other error is logged, the loop continues, and it reports false.
func (st *watchState) handleWatcherError(err error) bool {
	if errors.Is(err, fsnotify.ErrEventOverflow) {
		slog.Warn("fsnotify event queue overflowed; events were dropped, forcing a rescan to recover any missed renewal",
			st.w.coverageAttrs("root", logtext.Path(st.w.root), "error", err)...)
		st.scheduleScan()
		return true
	}
	slog.Warn("watcher error; the watch loop continues and a change missed because of it is covered only by the periodic fallback rescan",
		st.w.coverageAttrs("root", logtext.Path(st.w.root), "error", err)...)
	return false
}

// --- Poll mode ---

// pollLoopWithUpgrade polls on the safety-net interval and attempts to
// upgrade to fsnotify on every tick.
func (w *Watcher) pollLoopWithUpgrade(ctx context.Context) (upgraded *fsnotify.Watcher, err error) {
	// The initial scan: Run owns the first scan in BOTH modes, so main does not scan
	// before calling it.
	if ctx.Err() != nil {
		return nil, nil
	}
	w.logScanState(ctx, modePoll, triggerStartup)
	w.onChange(ctx)

	if w.fallback <= 0 {
		// Shutdown that arrived during the initial scan above is a clean stop, not
		// lost change detection: returning a *LostError here would make main log
		// "change detection is dead" and exit 1 on a normal SIGTERM, firing the
		// CertConverterChangeDetectionDead critical alert for a graceful stop.
		if ctx.Err() != nil {
			return nil, nil
		}
		// Return rather than park: with no fsnotify watch AND no operator-chosen
		// cadence there is nothing to reconcile against, so the floor watch mode runs
		// on would only delay recovery.
		return nil, errNoWatchNoFallback
	}

	return w.pollUntilUpgrade(ctx), nil
}

// pollUntilUpgrade is poll mode's ticker loop: it polls on the safety-net interval
// (the operator's FALLBACK_SCAN_HOURS cadence, capped at the reconciliation floor so
// the floor holds in this mode too) and re-attempts the fsnotify upgrade on every
// tick, returning the upgraded watcher for watch mode to run over, or nil when a
// shutdown ended the mode.
func (w *Watcher) pollUntilUpgrade(ctx context.Context) *fsnotify.Watcher {
	ticker := time.NewTicker(scancadence.Effective(w.fallback))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			fw, stopped := w.pollTick(ctx)
			if stopped {
				return nil
			}
			if fw != nil {
				return fw
			}
		}
	}
}

// pollTick handles one poll-loop tick: it re-attempts the fsnotify upgrade and,
// when that fails, runs the polling scan that keeps change detection alive.
func (w *Watcher) pollTick(ctx context.Context) (upgraded *fsnotify.Watcher, stopped bool) {
	if ctx.Err() != nil {
		return nil, true
	}
	slog.Debug("poll tick", "interval", scancadence.Effective(w.fallback))
	fw, stage, attachErr := w.tryAttachWatchSet(ctx)
	switch stage {
	case stageStopped:
		return nil, true // shutdown interrupted the upgrade attempt; not a poll-mode continuation
	case stageConstruct:
		w.logScanState(ctx, modePoll, triggerPoll,
			"upgrade_stage", upgradeStageConstruct, "error", attachErr)
		w.onChange(ctx)
		return nil, false
	case stageWatchDirs:
		w.logScanState(ctx, modePoll, triggerPoll,
			"upgrade_stage", upgradeStageWatchDirs, "error", attachErr)
		w.onChange(ctx)
		return nil, false
	case stageAttached:
	}
	w.logModeEntry(ctx, modeWatch, modePoll, "fsnotify recovered, upgrading from poll to watch",
		"directory_count", len(fw.WatchList()))
	return fw, false
}

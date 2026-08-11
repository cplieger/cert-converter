// Package watch provides filesystem watching with fsnotify and poll fallback.
//
// Paths this package REGISTERS are ambient, because inotify registers a pathname
// rather than a directory handle, so there is no root-confined equivalent of
// watcher.Add. The ENUMERATION that finds them is confined: walkWatchDirs opens
// the walk root as an *os.Root and streams it through
// atomicfile.WalkDirInRoot, the same primitive internal/process's two walks over
// the same trees use. The invariant that keeps the ambient registration safe:
// this package reads no file CONTENT, so a future read of a watched
// file MUST go through internal/process's confined root
// (source.readBounded, i.e. atomicfile.ReadBoundedInRoot) and never through a
// path built here. See
// addWatchDirs for what the residual exposure of an ambient registration is.
//
// An ERROR is a filesystem-derived string too: the filesystem returns
// *fs.PathError and fsnotify interpolates the path, so every "error" attribute
// whose value can carry a name from the tree is emitted as
// logtext.Path(err.Error()), the same gate the sibling "path" attribute uses.
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
// action that prevents it. Every lost-change-detection return is one of the four
// package-owned *LostError values below, so errors.As(err, &lost) is the caller's
// test for the condition regardless of which loss occurred.
//
// It carries that detail because this package does NOT announce the condition.
// The announcement belongs to the caller that ACTS on it — main exits non-zero
// for a restart, so main states the conclusion, exactly once per event (the
// message the CertConverterChangeDetectionDead alert matches). Authoring it on
// both sides of this boundary is how the wording drifted apart and how such an
// alert quietly stops firing. So the cause and the remediation travel out with
// the error instead of being logged here.
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

// The lost-change-detection conditions this package can reach. Each is returned
// as-is (they are immutable), and the caller distinguishes them by Cause. The two
// disabled-fallback losses are the operator-fixable ones, so they are the two that
// carry a remediation: both are reached ONLY because FALLBACK_SCAN_HOURS was set to
// 0/false, and with the routine rescan enabled neither ends the watch (a removed
// root watch is re-attached in place by resyncWatchSet). Both are LATENCY judgments
// rather than dead ends now that the reconciliation floor covers every mode
// (scancadence.Floor): each names a state where a restart restores real-time detection
// in seconds and the alternative is a wholly unwatched tree until the floor comes
// due, and each is argued at its own site (handleRootWatchLoss,
// pollLoopWithUpgrade). A dead fsnotify channel is not a misconfiguration, so it has
// none to give.
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

// newFSWatcher is the fsnotify construction seam. It is a package var rather
// than a direct call so a test can drive the "fsnotify unavailable" dispatch
// (attachWatchSet's selection of poll mode, pollTick's stay-in-poll) on a host
// where inotify works, in the same style as atomicfile's osChown/fsyncDir seams.
var newFSWatcher = fsnotify.NewWatcher

// removeWatch is the kernel-unregistration seam, a package var in the same style
// as newFSWatcher: pruneWatches' stays-charged direction fires only when
// inotify_rm_watch itself fails (EINVAL/EBADF), which no test can produce on a
// healthy host, so a test injects the refusal here.
var removeWatch = func(watcher *fsnotify.Watcher, path string) error {
	return watcher.Remove(path)
}

// Watcher monitors a directory tree for cert/key changes and invokes a callback.
//
// Field order is govet fieldalignment's: the pointer-bearing fields lead so the
// GC scans 24 bytes rather than the whole struct.
type Watcher struct {
	onChange func(ctx context.Context)

	// watched mirrors the fsnotify registration set, so membership is a map
	// lookup rather than a scan of fsnotify's own list (see watchSetHas). It is a
	// membership CACHE and nothing else: no ceiling is read from it, because the
	// kernel owns the inotify quota (see addWatchDirs). It is
	// mutated only from the goroutine running Run, but a test may drive the
	// event helpers directly while a loop runs, so watchedMu (below) keeps that
	// honest.
	watched map[string]struct{}

	root     string
	debounce time.Duration
	fallback time.Duration

	// maxEntries is how many paths ONE watch-set walk may enumerate before it
	// stops registering (scanbudget.Default when non-positive). It is INJECTED
	// exactly as internal/process.Options.MaxScanEntries is: internal/scanbudget owns
	// MAX_SCAN_ENTRIES' default and ceiling, internal/config owns the variable's name,
	// its parse and its repaired-value diagnostics, and this package stays a leaf both
	// of them configure.
	maxEntries int

	// watchedMu guards watched.
	watchedMu sync.Mutex
}

// Option configures a Watcher.
type Option func(*Watcher)

// WithDebounce sets the debounce window for coalescing events. Zero or a
// negative duration disables coalescing: the timer fires as soon as the loop
// reaches its arm, so a burst is followed by a scan per scheduling round
// rather than one scan per window.
func WithDebounce(d time.Duration) Option {
	return func(w *Watcher) { w.debounce = d }
}

// WithFallback sets the periodic poll/fallback interval. Zero or a negative duration
// disables the ROUTINE rescan: in fsnotify mode the safety-net timer then runs on the
// reconciliation floor instead (scancadence.Floor — slower, and never removable, so
// eventual convergence does not depend on this setting), and in poll mode there is no
// operator-chosen interval at all, so Run reports a *LostError rather than run with
// neither an fsnotify watch nor a cadence its operator asked for.
func WithFallback(d time.Duration) Option {
	return func(w *Watcher) { w.fallback = d }
}

// WithMaxEntries sets how many paths one watch-set walk may enumerate. Zero or a
// negative value uses scanbudget.Default.
func WithMaxEntries(n int) Option {
	return func(w *Watcher) { w.maxEntries = n }
}

// watchBudgetMsg is the operator-facing half of a watch-set walk that stopped at
// the budget. It names the health consequence (none) and what is lost (real-time
// detection under the unwalked remainder) for the same reason the scan's own
// budget WARN does, and it reuses that WARN's matched phrase so one alert rule
// covers both walks over the same tree.
const watchBudgetMsg = scanbudget.InputTreeTooLarge + "; stopping the watch-set walk, so directories past the budget are unwatched and renewals under them are covered only by the periodic rescan, health is unaffected"

// coverageAttrs closes a degraded-path record with the two cadences that answer
// the one question such a record raises: will anything revisit what was just lost?
// Both travel together because either alone answers it wrongly — fallback_scan is
// the routine rescan and reads "disabled" when the operator switched it off, while
// scan_floor is the reconciliation floor they cannot switch off, which is what
// revisits the path in exactly that configuration. Appending rather than prefixing
// keeps each site's own diagnostics (which path, which error) at the front of the
// record.
func (w *Watcher) coverageAttrs(attrs ...any) []any {
	return append(attrs, scancadence.CoverageAttrs(w.fallback)...)
}

// safetyNetTrigger names the clock behind one safety-net scan for its mode record:
// the operator's configured cadence, or the reconciliation floor standing in for it.
// Keeping the two apart in the log is what lets an operator confirm that
// FALLBACK_SCAN_HOURS=0 took effect while still seeing the floor's walk happen.
//
// Derived from scancadence.Effective rather than re-spelling its boundary: the scan
// runs on the operator's clock exactly when the effective interval IS the configured
// fallback (at fallback == scancadence.Floor the two clocks coincide and the operator's
// name wins).
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
// a poll scan refreshes it exactly like a watch scan does). A single startup WARN
// is therefore not enough — a container that has been degraded for a week looks
// identical to a healthy one — so the mode travels on every record this package
// emits about it, as a closed-set attribute an alert rule can key on.
//
// modeWatch and modePoll are the two modes Run supervises and the only values the
// mode attribute takes. modeStartup is not a mode: it is the previous_mode value
// for the process's FIRST mode selection, which has no predecessor.
type detectionMode string

const (
	modeWatch   detectionMode = "watch"
	modePoll    detectionMode = "poll"
	modeStartup detectionMode = "startup" // previous_mode only, never mode
)

// level maps a mode to the level its records are emitted at, and is the single
// home of the rule that gives the degradation a recurring signal at
// LOG_LEVEL=warn: poll mode is a STANDING degradation, so its records are WARNs,
// while watch mode is the intended state and reports at Info. Recovery to watch
// mode is good news and is announced at Info for the same reason.
//
// Deriving the level from the mode rather than from the call site is what keeps a
// new scan or transition site from silently reporting a degraded process at Info.
func (m detectionMode) level() slog.Level {
	if m == modePoll {
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

// The one message string per scan. It is deliberately mode-INDEPENDENT: the mode
// is an attribute, so a log-based alert keys on one line ("change detection
// scan") plus mode="poll" rather than on an enumeration of degradation
// phrasings, and the same query counts scans in either mode. The transition
// records keep their own site-specific messages, because each names WHY the mode
// changed.
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
// alongside the error: WHY the fsnotify upgrade this tick attempted failed. It
// preserves the diagnostic the previous per-tick Info records carried, so raising
// the mode signal to WARN does not cost the reason the process is still degraded.
const (
	upgradeStageConstruct = "fsnotify_unavailable"
	upgradeStageWatchDirs = "watch_set_rebuild_failed"
)

// logModeEntry emits the transition record: change detection has just ENTERED
// mode, coming from previous. Level follows the mode (see detectionMode.level),
// so entering poll mode WARNs and recovering to watch mode reports at Info.
//
// msg stays per-site because each entry names its own cause; the attributes are
// what an alert or a dashboard keys on. extra carries the site's own diagnostics
// (the attach error, the watched-directory count).
func (w *Watcher) logModeEntry(ctx context.Context, mode, previous detectionMode, msg string, extra ...any) {
	attrs := w.coverageAttrs("mode", string(mode), "previous_mode", string(previous))
	slog.Log(ctx, mode.level(), msg, append(attrs, extra...)...)
}

// logScanState emits the ONE state record every scan carries, naming the mode
// that is live as the scan runs. Together with the transition records above it is
// the whole mode signal: the transition says when the state changed, this says
// the state is still current, once per scan, on the mode's own cadence. That is
// what makes a permanently degraded container visible at LOG_LEVEL=warn (a poll
// scan every FALLBACK_SCAN_HOURS is a WARN) while a healthy one adds no warnings
// at all (its scans report at Info).
//
// Every record carries the coverage pair (fallback_scan, scan_floor), so one
// vocabulary answers "what cadence is this process on?" on every record this
// package emits. The one record where scan_floor describes a cadence no walk
// follows is poll mode's initial scan with the routine rescan disabled, which exits
// for a restart immediately afterwards and is announced as such by the caller.
func (w *Watcher) logScanState(ctx context.Context, mode detectionMode, trigger string, extra ...any) {
	attrs := w.coverageAttrs("mode", string(mode), "trigger", trigger)
	slog.Log(ctx, mode.level(), msgScanState, append(attrs, extra...)...)
}

// New creates a Watcher for the given root directory. Timing policy is chosen by
// the composition root (main.go) and injected via WithDebounce/WithFallback;
// config owns the documented FALLBACK_SCAN_HOURS default, so an un-optioned
// Watcher has no debounce window and no fallback rescan.
//
// onChange is REQUIRED. It is not defaulted to a no-op on purpose: a Watcher with no
// callback runs its loops forever and converts nothing while the health marker stays
// set, which is the silent-healthy failure mode this package has already been bitten
// by (see the dead-change-detection path in pollLoopWithUpgrade). A nil callback is a
// wiring bug and should panic at the first scan rather than run indefinitely.
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

// Run starts watching. It supervises two SIBLING change-detection modes and
// blocks until change detection ends.
//
// The mode contract. Watch mode (watchMode) runs whenever an fsnotify watch set
// is live; poll mode (pollLoopWithUpgrade) runs when one could not be
// established. Each mode has exactly ONE exit and neither runs inside the
// other: watch mode returns only the terminal answer (shutdown, or the watcher
// died), while poll mode returns either that same terminal answer or an
// upgraded watcher — and by then it has already released its own ticker, so no
// poll-mode resource outlives the mode. The supervisor below therefore runs at
// most one of each: no watcher means poll mode until it hands one back, and watch
// mode is terminal, so there is no round that returns to polling. Everything that
// happens once a watch set exists
// (dump the set, scan with it live, run the watch loop, close the watcher) is
// stated once, in watchMode, for both mode entries; only the arrival RECORD
// differs per entry, and each entry logs its own.
//
// It normally blocks until ctx is cancelled and then returns nil, but it ALSO
// returns a *LostError early in every state where a restart is the right recovery
// (the LostError values above are the complete set), and the caller must
// then exit non-zero for it, as main.go does: the fsnotify watcher dies
// (its Events or Errors channel closes); the watch on the root itself is removed
// while the routine rescan is disabled, taking the whole watch set with it; or no
// fsnotify watch could be established at all -- its constructor failed, or the
// watch set could not be built on the root -- while the routine rescan is
// disabled, leaving the process with neither a watch nor a cadence its operator
// asked for. A channel closure
// observed after ctx is already cancelled is part of shutdown, not lost change
// detection, and returns nil.
//
// Every other state converges without a restart: watch mode's safety-net timer is
// armed in EVERY configuration (scancadence.Floor), so a partial watch set, a
// registration the kernel dropped silently, and a directory past the registration
// budget are all recovered by a later re-assert rather than left to the next event.
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
// way. It reports (watcher, false) for watch mode, (nil, false) when fsnotify is
// unusable and Run must select poll mode, and (nil, true) when a shutdown
// arrived mid-attempt, which is a clean stop rather than a watch failure and
// must not be reported as one.
//
// Both records are mode TRANSITIONS (logModeEntry), so the level follows the mode
// rather than the call site: entering poll mode WARNs, entering watch mode
// reports at Info. Poll mode's equivalent retry is pollTick, which does not
// re-announce a transition it did not make — while it stays in poll mode the
// signal is the per-scan mode record, at WARN for as long as the degradation
// lasts.
//
// The construct-then-register sequence itself lives in tryAttachWatchSet, the
// single statement of it shared with pollTick; this function is the record half
// only.
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
// stageStopped rather than as a degradation. Stating it once is what keeps a
// lifecycle or containment fix from repairing one mode entry and leaving the
// other leaking or mis-reporting. Every watcher it returns is closed by
// watchMode instead.
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
// it live, run the watch loop, and release the watcher on every exit path. Both
// mode entries reach it through Run's supervisor -- the initial attach and the
// poll-to-watch upgrade -- so the ordering cannot drift between them, and a
// third entry (or a change to the order) is one edit here.
//
// It returns watch mode's single exit: nil on shutdown, a *LostError when the
// watcher died under a live ctx.
func (w *Watcher) watchMode(ctx context.Context, watcher *fsnotify.Watcher) error {
	defer watcher.Close()
	logWatchSet(watcher)
	return w.scanThenWatch(ctx, watcher)
}

// logWatchSet emits the watched directories at Debug.
//
// The default-level records carry only a count: the directory list is unbounded in
// the number of certificate directories. Debug still exposes the set, which is what
// an operator needs to diagnose an INCOMPLETE watch set — a subdirectory whose
// watcher.Add failed, whose renewals are then covered only by the fallback rescan.
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
// watch loop. It is watchMode's body, called from there alone. It preserves the
// attach-then-scan ordering and skips the scan after shutdown.
//
// Attach-then-scan: the scan that preceded this watch set (main's startup scan,
// or the poll tick being upgraded) ran before these watches existed, so a
// renewal landing in that window produced no event. Scanning once with the
// watch set live closes that gap; the fingerprint cache makes the extra scan a
// no-op when nothing changed, and events arriving during it stay queued and
// trigger the normal debounced follow-up. A shutdown that arrives first skips
// the scan: the loop would return immediately anyway, and scanning would only
// log an interrupted scan on the way out.
func (w *Watcher) scanThenWatch(ctx context.Context, watcher *fsnotify.Watcher) error {
	if ctx.Err() != nil {
		return nil
	}
	w.logScanState(ctx, modeWatch, triggerAttach)
	w.onChange(ctx)
	return w.watchLoop(ctx, watcher)
}

// --- Watch-set maintenance ---

// addWatchDirs recursively adds all directories under root to the watcher. Only
// a failure on root itself is fatal (Run uses it to fall back to polling); a
// directory below root that cannot be watched — unreadable to this UID, or a
// watch descriptor the kernel refuses once fs.inotify.max_user_watches is
// exhausted — is warned about and skipped, exactly as an unreadable sub-path
// is, so one mis-permissioned certificate directory cannot cost the whole tree
// its real-time watch.
//
// The ambient-path divergence the package comment points here for is the
// REGISTRATION's alone, and it is deliberate and bounded: inotify registration
// takes a path,
// not a directory handle, so there is no root-confined equivalent of
// watcher.Add, and nothing in this package reads file CONTENT — the enumeration
// runs through atomicfile.WalkDirInRoot over an *os.Root, which never
// constructs an ambient name and never descends a symlinked directory,
// while handleFsEvent's os.Lstat also skips a symlink visible at inspection.
// The ambient path can still be swapped before watcher.Add; fsnotify does not
// request IN_DONT_FOLLOW, so that race can attach to the replacement target.
// This remains bounded with respect to file content and conversion: this
// package reads no content, and conversion triggered by an event runs only
// through internal/process's root-confined scan. Watch maintenance itself stays
// ambient: a Create event can Lstat and walk beneath event.Name, so a raced
// ancestor can extend registrations into the replacement target and consume
// watch descriptors, but it still cannot make the app read or convert content
// outside the root. Every path this package registers is derived from
// the confined walk over the root (attachWatch is the only watcher.Add site) or
// from an event fsnotify named under a path already registered, so a registration
// cannot carry an out-of-root name and cannot compound; a registration that
// escaped through a swapped ancestor still carries an in-root name, so this
// residual (watch descriptors, never content) stands as described above.
//
// The entry ceiling is ONE bound: every walk is capped at maxEntries entries, which
// bounds one traversal's cost over a tree this app does not own — and, because the
// enumeration streams fixed-size ReadDir batches (atomicfile.WalkDirInRoot), that
// ceiling bounds the walk's MEMORY and not only the number of entries it visits.
// It is not a bound on
// the LIVE registration set, and this package deliberately does not impose one — the
// kernel owns fs.inotify.max_user_watches, it is the only party that knows the real
// state of that resource, and it already refuses the registration when the per-UID
// quota is spent. handleWatchAddError is what that refusal reaches: WARN naming the
// directory and skip it below the root (the fallback rescan covers renewals
// underneath), propagate at the root so Run degrades to polling. An app-side ceiling
// calibrated to MAX_SCAN_ENTRIES instead refused two orders of magnitude below a
// modern host's quota. Re-registering a path already in the set is idempotent in the
// kernel and costs no new slot, so a rebuild is never refused by its own existing
// registrations.
//
// The traversal is cancellable: it checks ctx before each entry and returns
// ctx.Err() as soon as the process is shutting down, so a shutdown arriving
// mid-walk over a large input tree is not delayed by the remaining
// registrations. Callers must treat a ctx error as shutdown rather than a watch
// failure (no WARN, no fallback to polling, no follow-up scan).
func (w *Watcher) addWatchDirs(ctx context.Context, watcher *fsnotify.Watcher, root string) error {
	return w.walkWatchDirs(ctx, root, func(path string) error {
		return w.attachWatch(watcher, root, path)
	})
}

// walkWatchDirs is the ONE traversal both watch-set walks run: the per-walk
// entry budget, its WARN-and-stop, and the shared per-entry policy
// (classifyWatchEntry) are applied here, and only what happens to an admitted
// directory differs per walk -- the registering walk attaches it, the
// rebuild's preflight collects it. Stating the wiring once is what
// classifyWatchEntry's doc already promises for the policy itself; this
// extends it to the budget admission, so a fix to the admission order cannot
// repair one walk and leave the other reading the tree by a different rule.
func (w *Watcher) walkWatchDirs(ctx context.Context, root string, register func(path string) error) error {
	// A cancelled walk does no filesystem work, which is what the two syscalls
	// below would otherwise cost on the shutdown path.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	// Cleaned once, so the ambient names the callback rebuilds and every
	// `path == root` comparison below it (classifyWatchEntry, handleWatchAddError,
	// validateWatchRootEntry) are made against one spelling. The mirror already
	// cleans every path it records (recordWatch, watchSetHas).
	root = filepath.Clean(root)
	// The root's OWN entry is Lstat'ed HERE, and this is the one thing the confined
	// walk cannot express: os.OpenRoot resolves its root, so a symlinked or
	// non-directory /input would arrive at the callback as a resolved directory and
	// the two fatal refusals validateWatchRootEntry words would never fire -- the
	// exec-away case that leaves Run logging "fsnotify active" over an empty watch
	// set while the scan keeps the health marker green. filepath.WalkDir got this
	// for free by Lstat-ing its starting point.
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
	// The per-entry policy stays here, which is the same split process.visit keeps.
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
		// classifyWatchEntry returns from its walkErr arm before it reads d, which is
		// what keeps that safe.
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
//
// Charging after the error arm is scanbudget.Counter's documented rule, and this is
// where the watch-set walks obey it. atomicfile.WalkDirInRoot delivers a directory it
// could not read through a SECOND callback for that directory's own path — the one the
// parent
// already charged — so charging above the error arm counts one pathname twice and stops
// both walks below the operator's configured MAX_SCAN_ENTRIES. Cancellation stays first
// so a shutdown arriving exactly at the ceiling propagates ctx.Err() rather than
// emitting the budget WARN and reporting the tree as truncated.
func exceedsEntryBudget(ctx context.Context, budget *scanbudget.Counter, walkErr error) (bool, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if walkErr != nil {
		return false, nil // The walk is repeating the directory to report its read error.
	}
	return !budget.Charge(), nil
}

// warnWatchBudget emits the entry-ceiling WARN. walkWatchDirs returns fs.SkipAll
// in the same frame for both the registering walk and the rebuild's preflight,
// stopping that traversal, so one budget produces exactly one record: the
// remainder is unbounded and the operator action is the same for all of it.
func (w *Watcher) warnWatchBudget(root string, budget *scanbudget.Counter) {
	slog.Warn(watchBudgetMsg, w.coverageAttrs(
		"root", logtext.Path(root), "max_entries", budget.Max(),
		"remediation", scanbudget.InputRemediation)...)
}

// classifyWatchEntry applies the per-entry policy BOTH watch-set walks share — the
// event-driven registering walk (addWatchDirs) and the rebuild's preflight
// enumeration (desiredWatchDirs) — and reports whether the entry is a directory the
// walk should register: cancellation first, then the walk-error policy (fatal at the
// root, warn-and-skip below it), then the directory filter. It is one function
// precisely so a containment or diagnostic fix cannot repair one walk and leave the
// other reading the tree by a different rule.
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
		// under a churning /input arrives here as ENOENT. Nothing is left under it
		// to renew, so the WARN's consequence clause is false, and neither of its
		// operator actions applies. Same rule handlePathEvent's Lstat arm already
		// applies to a vanished event path, and pruneWatches to a registration the
		// kernel confirmed is gone. The Remove/Rename event fsnotify delivers for
		// the same deletion is what schedules the rescan.
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

// attachWatch registers one directory and records it in the membership mirror. It
// imposes no ceiling of its own: the kernel owns fs.inotify.max_user_watches and
// refuses the Add when the per-UID quota is spent, which handleWatchAddError reports
// (see addWatchDirs). Re-adding a path already in the mirror is idempotent in the
// kernel and consumes no further slot, so a rebuild never refuses itself.
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
//
// Keyed on w.root rather than on the walk's root, because both messages below
// describe the MOUNT and prescribe a mount-level remediation. handlePathEvent
// walks an event's own path as a walk root (addWatchDirs' root parameter), so a
// directory that stopped being one between that handler's Lstat and the walk's
// would otherwise be reported as "watch root ... is a symlink" with an
// unachievable "bind-mount the target directory at /input/example.com" - a wrong
// operator signal about an untrusted name, interpolated raw into an error that is
// then emitted as a log attribute. Such an entry has nothing left to register, so
// it is skipped exactly like the regular file it now is; the rescan the event
// already scheduled still covers its content.
//
// The walk Lstats its root and does not follow it, so a bind-mounted file
// or a symlinked /input walks exactly one non-directory entry, registers no
// watches, and would otherwise return nil - leaving Run to log "fsnotify active"
// with an empty watch set and park in a loop no event can reach, while the scan
// (os.OpenRoot DOES follow a symlinked root) keeps the health marker green.
// Reporting it lets Run degrade to polling, or return a *LostError when the
// fallback is disabled too.
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
//
// This is the ONLY place inotify quota exhaustion is reported — the app imposes no
// registration ceiling of its own — so the WARN names raising
// fs.inotify.max_user_watches beside the other reason a directory's watch is refused
// (this UID cannot read it). Below the root it stays health-neutral: neither condition
// is clearable by a restart, and the fallback rescan still covers renewals underneath.
func (w *Watcher) handleWatchAddError(root, path string, addErr error) error {
	if path == root {
		return addErr
	}
	// Same vanished-path rule as classifyWatchEntry's walk-error arm: a directory
	// the preflight enumerated and that was deleted before reassertWatches got to
	// it fails with ENOENT, which is neither of the two conditions
	// watchAddRemediation names. Reporting it as an unwatchable directory sends the
	// operator to chmod a path that no longer exists, or to raise
	// fs.inotify.max_user_watches that was never exhausted.
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

// watchSetHas reports whether path is already registered with the watcher. It
// guards the one piece of unbounded per-event work in this loop: the directory
// arm of handlePathEvent re-walks event.Name's whole subtree on EVERY directory
// Create/Chmod, and that walk is NOT covered by the debounce, which coalesces
// scans rather than watch-set maintenance. A directory already in the watch set
// has nothing to re-attach - it was walked when it was added, anything that
// failed underneath it arrives as its own event, and the periodic re-sync
// restores the rest (a descendant whose Add failed and which gets no event of its
// own waits for a re-assert: the deferred repair, the operator's rescan cadence,
// or at the latest the reconciliation floor).
//
// The answer comes from this package's own mirror of the registration set, not
// from fsnotify.Watcher.WatchList: WatchList locks the watcher and materializes
// every registered pathname on every call, so answering a per-event membership
// question with it makes a burst of N sibling directory creations cost O(N^2)
// path comparisons and allocation in the same synchronous path that drains the
// event channel. A writer to the watched tree controls N, so the guard against
// unbounded walk work must not itself scale with the set it guards.
func (w *Watcher) watchSetHas(path string) bool {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	_, ok := w.watched[filepath.Clean(path)]
	return ok
}

// recordWatch notes a registration this package made, so watchSetHas can answer
// from the mirror. Only a SUCCESSFUL watcher.Add records: a directory whose Add
// failed is not watched, and recording it would suppress the re-attach the
// permission-repair (Chmod) and re-sync paths exist to perform.
func (w *Watcher) recordWatch(path string) {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	w.watched[filepath.Clean(path)] = struct{}{}
}

// forgetWatch drops a path whose watch is gone. The kernel discards the watch
// with the directory itself, so a Remove/Rename that is not forgotten would make
// a recreated directory look watched and never be re-attached, silently missing
// every renewal underneath it.
func (w *Watcher) forgetWatch(path string) {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	delete(w.watched, filepath.Clean(path))
}

// resetWatchSet empties the mirror for a fresh fsnotify watcher. Every attach
// constructs a NEW watcher whose registration set starts empty (Run's initial
// attach and pollTick's upgrade both do), so a path recorded for the previous,
// now-closed watcher must not be reported as watched under the new one.
func (w *Watcher) resetWatchSet() {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	w.watched = make(map[string]struct{})
}

// watchSetSnapshot copies the mirror's paths, so a sweep can iterate them while
// forgetWatch mutates the map underneath it. Taken under the same lock as the rest of
// the mirror's accessors.
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
//
// The kernel keeps a registration until it is removed or its directory disappears, and
// this is the only place that removes one, so without it the app holds descriptors for
// directories the tree no longer wants: a walk the entry budget cut short registers a
// different prefix each time the tree changes, and the registrations the new walk no
// longer reaches stay live while the mirror stops claiming them. Releasing them keeps
// this app's share of the per-UID fs.inotify.max_user_watches quota to what it is
// actually watching, which is the only quota discipline it owes — the kernel refuses an
// Add once the quota is spent (handleWatchAddError), and this app imposes no ceiling of
// its own.
//
// It runs BEFORE the rebuild re-asserts anything (resyncWatchSet), which is what makes
// a replacement directory reachable when the quota is already spent: the stale
// registration's slot is released first, so the Add that wants it is not refused by a
// registration this rebuild is about to drop anyway.
//
// The mirror is only updated for a registration the kernel CONFIRMED is gone — a
// successful Remove, or ErrNonExistentWatch, which means fsnotify already dropped it
// with its directory (reported at Debug: expected, not a degradation). Any other Remove
// error leaves an uncertain descriptor live, so the path stays charged to the mirror and
// the operator is told which one is stuck. Keeping it charged is the cheap direction, and
// the mirror is what keeps the removal RETRYABLE: a charged path the preflight does not
// want is re-tried by every later prune, while forgetting it would leave the descriptor
// live with nothing that ever unregisters it. No ceiling is read from this count, so it
// costs no slot. The one residual is the per-event fast path: a charged path is by
// construction absent from desired, so the re-assert below does NOT re-add it, and if the
// path reappears before the next re-assert, handlePathEvent's membership guard (watchSetHas)
// skips its subtree re-attach -- the rescan that event schedules is unaffected, and the
// registration is restored by the re-assert that follows the reappearance.
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
// warrants a rescan. Remove and Rename always rescan because the old path can
// no longer be inspected. Create and Chmod delegate path classification and
// directory reattachment to handlePathEvent; Write only rescans cert/key paths.
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
		// the tree arrives as its own Create event. addWatchDirs here can only
		// fail, so just rescan.
		return true
	case event.Has(fsnotify.Write):
		return layout.IsRelevant(event.Name)
	case event.Has(fsnotify.Chmod):
		// The recovery path for a permission repair on a cert, on a key, or on a
		// directory the watch set had to skip -- the app's most likely operator
		// error. A pair the scan could not read fails conversion and clears the
		// health marker; the operator fixes it with chmod, and without this arm that
		// chmod schedules nothing, so the container stays unhealthy and the .pfx
		// stays stale until the next periodic tick (six hours on the documented
		// cadence, a day on the reconciliation floor when the routine rescan is off).
		// On a DIRECTORY it is the same recovery one step up: a sub-directory this
		// UID could not read (README: "Fix the directory permissions") has just
		// become readable, so its subtree is re-attached and a rescan runs now --
		// and that outcome is health-neutral (ScanResult.Unreadable), so nothing
		// else would signal the operator that the repair has not taken effect yet.
		// A chmod storm is absorbed by the debounce like a write storm, and the
		// re-attach walk is bounded separately: handlePathEvent skips it for a
		// directory already in the watch set.
		return w.handlePathEvent(ctx, watcher, event,
			"cannot classify a path whose permissions changed; rescanning because it may be an unwatched directory",
			"failed to watch a directory whose permissions changed; renewals under it are covered only by the periodic rescan")
	}
	return false
}

// handlePathEvent is the decision tree the Create and Chmod arms share, and the
// single home of the unclassifiable-path rule: extend the watch set when the
// event's path is a directory, classify a path that is merely GONE by name, and
// conservatively rescan every other stat failure. It reports whether the event
// warrants a rescan. The two arms differ only in the operator messages they pass
// in, so a containment or recovery fix here cannot repair one event class and
// leave the other silently missing renewals.
//
// Lstat, not Stat, for two reasons: a transient file (an atomic-write temp created
// and renamed away before this event is handled) cannot produce a spurious "failed
// to watch" WARN from WalkDir failing to lstat a path that is already gone; and a
// SYMLINK to a directory is not followed. Neither addWatchDirs nor the scanner's
// root-confined walk (fs.WalkDir over the /input os.Root) descends a symlinked
// directory, so watching through one would register inotify watches on a tree
// outside /input whose certs can never be converted — and a symlink to a large tree
// would burn the watch quota.
//
// The directory test comes BEFORE the name classifier because layout.IsRelevant is
// suffix-only: a legitimately nested directory named "archive.crt" would otherwise
// take the file arm, schedule one rescan, and never regain its watches, so every
// later renewal underneath it would be missed.
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
		// would then wait for the next periodic re-sync. The WARN reports the half
		// the rescan does not fix -- the subtree is outside the watch set, so its
		// later renewals are covered only by that periodic re-sync, whose cadence the
		// record names (fallback_scan and scan_floor), which is a state an operator
		// must be able to see.
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
		// slot was ever requested. Both producers reach here as ErrNotExist:
		// walkWatchDirs' own os.Lstat/os.OpenRoot of the walk root, and the root arm of
		// classifyWatchEntry, which returns walkErr above its own ErrNotExist check
		// because the root's refusal is the fatal one.
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
// with a periodic full scan as a safety net. It returns nil when ctx is
// cancelled and a *LostError when the watcher's Events or Errors channel closes
// under a live ctx, which ends change detection for the life of the process; a
// closure observed after cancellation is a shutdown and also returns nil.
func (w *Watcher) watchLoop(ctx context.Context, watcher *fsnotify.Watcher) error {
	st := newWatchState(w)
	defer st.stop()
	return w.runWatchLoop(ctx, watcher, st)
}

// runWatchLoop is watchLoop's select over already-built loop state, split out so
// a test can hand the loop a watchState whose timers it has already positioned
// (an almost-expired re-assert floor, for instance) and observe which arm acts on
// them. watchLoop owns the state's construction and release; nothing else calls
// this.
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
//
// Losing the root watch is not an ordinary path removal: the root's parent is not
// watched, so no Create event can ever announce a replacement, and fsnotify leaves
// both channels open (so watchLoop's closure checks never fire). With the operator's
// routine rescan enabled it is recoverable, and the whole watch set went with the
// root, so re-attach here instead of leaving real-time detection off until the next
// tick — and say so, because nothing else does above Debug.
//
// With the routine rescan disabled it returns false, ending change detection for a
// restart. The reconciliation floor would eventually re-attach the set too, so this
// is a LATENCY choice and not the absence of a mechanism: an exec-away root watch is
// the one loss where the whole set is gone at once, a restart re-attaches it in
// seconds, and the alternative is a tree that is entirely unwatched until the floor
// comes due. Any other event reports true untouched.
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
// signal. watchLoop's select has no ctx precedence of its own (Go picks a ready
// case at random), so the precedence lives here, at the single translation
// point.
//
// It logs nothing, on either branch. The operator-facing ERROR belongs to main,
// which is what acts on the condition (see LostError); emitting one here would
// announce a restart that is not happening whenever cancellation wins this
// check, and a second one when it does not.
func lostOrShutdown(ctx context.Context, lost *LostError) error {
	if ctx.Err() != nil {
		return nil
	}
	return lost
}

// handleEventRecv owns watchLoop's whole event-channel arm: it reports which
// terminal loss that arm observed, or nil while change detection is live. A closed
// channel means the fsnotify watcher is dead (errEventsChannelClosed); an event that
// took the watch on the root away with no way to reattach it ends change detection
// too (errRootWatchRemoved). Otherwise an event classified as interesting arms the
// debounced rescan. Naming the loss here keeps watchLoop a flat dispatch table and
// lets it hand the value straight to lostOrShutdown, which maps it to the terminal
// error (or to a clean stop when it raced a shutdown); main announces it.
func (w *Watcher) handleEventRecv(
	ctx context.Context, watcher *fsnotify.Watcher, st *watchState, event fsnotify.Event, ok bool,
) *LostError {
	if !ok {
		return errEventsChannelClosed
	}
	// Cancellation outranks an ordinary event, exactly as it does in every timer,
	// attach, and channel-loss arm of this loop: watchLoop's select picks a ready
	// case at random, so a queued Remove/Rename or Create can still land here after
	// ctx.Done is ready. The loop exits on its next selection, so the only thing a
	// re-attach or a scheduled scan could produce is a watch-degradation WARN
	// announcing recovery that is not going to happen. The closed-channel taxonomy
	// above stays ahead of it: that is a fact about the watcher, not work to skip.
	if ctx.Err() != nil {
		return nil
	}
	// Forget before the root-loss handler runs: the kernel drops the watch along
	// with the directory, so an unforgotten path would look watched and never be
	// re-attached if it comes back. Doing it here rather than in handleFsEvent's
	// Remove/Rename arm is what lets a successful root re-attach below record the
	// root (and its subtree) again in the same event.
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
// terminal loss that arm observed, or nil while change detection is live. A closed
// channel means the fsnotify watcher is dead (errErrorsChannelClosed); an
// event-queue overflow additionally re-syncs the watch set, on minPreScanResync's
// cadence. Naming the loss here
// rather than at the call site keeps the loss taxonomy in the arm that observes it,
// exactly as handleEventRecv does.
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
		//
		// Floored (resyncOrDefer) for a reason specific to this trigger: an overflow
		// arrives on the ERROR channel, whose rate a writer sets, so an
		// unfloored re-assert here would run the whole-tree walk (and re-emit one WARN
		// per unwatchable directory) on the writer's cadence rather than on one this
		// process chose — which is what minPreScanResync exists to bound. Because the
		// floor defers rather than drops, a dropped Create is still recovered on the
		// floor's own schedule. handleWatcherError has already scheduled the
		// certificate rescan, so renewal recovery is never what the floor delays.
		st.resyncOrDefer(ctx, watcher,
			"failed to re-sync the watch set after an event-queue overflow; a directory whose Create was dropped stays unwatched until the next re-sync")
	}
	return nil
}

// handleSafetyNetTick runs the periodic safety-net rescan — the operator's
// FALLBACK_SCAN_HOURS cadence, or the reconciliation floor standing in for it — and
// re-asserts the watch set first. That restores what was lost: a directory whose
// watcher.Add failed while it was unreadable (or while fs.inotify.max_user_watches was
// exhausted) and whose condition has since been repaired, or one whose Create event
// never arrived. Without it such a directory stays outside the watch set for the life
// of the process and its renewals are detected only on this cadence.
// Re-attaching before the scan also means a change landing during the scan is
// still reported as an event. A stop request skips the scan entirely, whether
// it cut the re-sync short or arrived while the re-sync succeeded: the loop is
// about to return anyway.
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
	// instant as cancellation can win over ctx.Done. The loop is about to
	// return anyway, so a scan started here is pure spurious work.
	if ctx.Err() != nil {
		return
	}
	st.runSafetyNetScan(ctx)
}

// resyncWatchSet re-asserts the watch set over the root (watcher.Add is idempotent,
// so a re-walk only restores what was lost) and, when that fails under a
// live ctx, reports it with the diagnostics every re-sync site owes the
// operator: WHICH root, what will revisit what is now unwatched (the fallback_scan
// and scan_floor pair coverageAttrs carries), and the error. It is the single home
// of those and of the
// shutdown rule -- a walk cut short by cancellation is a clean stop, not a watch
// degradation -- so neither can be changed for one re-sync site and silently left
// wrong at the others. warning names what stays uncovered until the next re-sync.
func (w *Watcher) resyncWatchSet(ctx context.Context, watcher *fsnotify.Watcher, warning string) {
	// A TRANSACTION, in three phases, and the ordering is the whole point: the mirror
	// describes the registrations the kernel is holding, so it may never be emptied while
	// the kernel still holds them -- a mirror emptied ahead of a walk that then fails at
	// the root leaves those descriptors live and unclaimed, so nothing ever unregisters
	// them and the per-event fast path reads their paths as unwatched.
	//
	// 1. PREFLIGHT: enumerate what the tree wants, touching neither the watcher nor the
	//    mirror, so any failure — including cancellation — leaves both exactly as they
	//    were and the next re-sync starts from an honest mirror.
	desired, walkErr := w.desiredWatchDirs(ctx, w.root)
	if walkErr != nil {
		if ctx.Err() == nil {
			slog.Warn(warning, w.coverageAttrs("root", logtext.Path(w.root), "error", walkErr)...)
		}
		return
	}
	// 2. REMOVE, before adding anything: unregister what the preflight no longer wants, so
	//    this app holds descriptors only for what it is actually watching — and so a
	//    replacement directory can take the slot a stale registration was holding when the
	//    per-UID inotify quota is already spent. A removal the kernel refused stays charged
	//    (pruneWatches) so every later prune retries it; phase 3 below does NOT re-add it,
	//    because a charged path the preflight does not want is absent from desired.
	w.pruneWatches(watcher, desired)
	// 3. RE-ASSERT the preflight's set. Add is idempotent, so this restores exactly what
	//    was lost, and it re-adds every desired path regardless of what the mirror claims.
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
// recordWatch. Nothing it does is observable outside its return values, so a failure —
// a fatal root entry, an unreadable root, or shutdown — leaves the live registration set
// and its mirror untouched, which is what lets resyncWatchSet abandon a rebuild without
// having already spent or forgotten anything.
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

// reassertWatches registers every path the preflight wants. It re-asserts from the
// preflight's set rather than walking the tree a second time, so one re-sync enumerates
// the root once, and it Adds every desired path regardless of what the mirror claims:
// Add is idempotent in the kernel, so a path already registered costs no slot, and a
// path the mirror wrongly claims is still watched is repaired here rather than waiting
// for another re-sync. There is no admission ceiling to reach — the kernel refuses an
// Add once the per-UID inotify quota is spent, and handleWatchAddError reports that,
// WARNing and skipping below the root so one refused directory cannot abandon the rest
// of the rebuild (including the root's own watch). The root is re-asserted first, so a
// freed slot cannot be spent on a descendant while the root stays refused.
//
// Cancellable like the walk it replaces, and checked AFTER each registration rather than
// before: the enumeration — the expensive half, and the one that can block on a stranger's
// tree — is the preflight's, so what remains here is a bounded run of one syscall per
// already-known directory, and stopping it before it has re-established anything would
// abandon a registration this rebuild had already removed the stale twin of.
func (w *Watcher) reassertWatches(ctx context.Context, watcher *fsnotify.Watcher, desired map[string]struct{}) error {
	// Root first, unconditionally: its refusal is the fatal one
	// (handleWatchAddError), and this runs right after pruneWatches released
	// stale slots — under a nearly spent per-UID quota, map order could hand
	// those freed slots to descendant directories and leave the root, the one
	// watch a silently-dropped registration (IN_IGNORED on unmount/remount)
	// most needs restored, refused for another whole re-sync interval.
	// The root is always in desired: a preflight whose root errored, is not a
	// directory, or was cut short returns an error instead of a set, and the
	// entry budget cannot refuse the walk's first entry. New cleaned w.root and
	// desiredWatchDirs keys the root as filepath.Clean(w.root), so the loop
	// below skips it by equality.
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

// minPreScanResync floors how often a debounced scan may re-assert the WHOLE watch set. The
// re-assert is O(directories under the root) and re-emits one WARN per unwatchable directory,
// while its trigger costs a writer one create+delete (handleFsEvent's Remove arm always
// schedules a scan), so without a floor the walk runs on the writer's cadence rather than on
// a cadence this process chose. A minute still recovers a silently dropped registration long
// before the safety-net tick would.
//
// The floor DEFERS the re-assert it declines to run: scheduleRepair arms the repair timer
// for the remainder of the interval, so the trigger is postponed to a cadence this process
// chose rather than dropped. Dropping it is what left a registration the kernel discarded
// without an event outside the watch set until something unrelated happened to re-assert —
// with the routine rescan disabled, potentially not before the reconciliation floor.
const minPreScanResync = time.Minute

// watchState carries the mutable accounting for one watchLoop run: the pending
// debounce flag and the debounce/safety-net/repair timers. Hoisting the per-event
// work onto its methods keeps watchLoop's select a flat dispatch table rather than
// a deeply nested switch.
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
//
// The safety-net timer is armed UNCONDITIONALLY, which is the whole of this
// package's liveness guarantee: FALLBACK_SCAN_HOURS=0/false removes the operator's
// own cadence, not the reconciliation floor that stands in for it
// (scancadence.Effective), so there is no configuration in which the loop holds no
// clock at all and change detection depends purely on fsnotify events arriving.
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
// EVERY in-loop re-assert goes through here: minPreScanResync's floor is measured
// from the last walk whichever site ran it, so a site that walks without charging
// the clock is exempt from the floor AND leaves the next debounced scan believing
// no walk has happened, which costs one event two whole-tree walks and two copies
// of every unwatchable-directory WARN.
func (st *watchState) resync(ctx context.Context, watcher *fsnotify.Watcher, warning string) {
	st.lastResync = time.Now()
	st.w.resyncWatchSet(ctx, watcher, warning)
}

// scheduleRepair defers the whole-tree re-assert that minPreScanResync just
// declined to run, arming it for the REMAINDER of the floor rather than for a
// fresh interval: the floor bounds how often the walk may run, so the repair is
// due the moment the current interval ends, and a burst inside one interval still
// produces at most one walk.
//
// Deferring rather than dropping is what keeps the floor a rate limit instead of a
// silent discard. A repair already deferred is left on its existing schedule, so
// the pending flag also keeps a writer from resetting the deadline forward on every
// event.
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
// rather than dropped. Shared by the debounced-scan and event-queue-overflow triggers,
// so the floor is spelled once for both.
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
//
// A repair whose interval another re-assert already covered is skipped rather than
// re-armed: the floor is measured from the last re-assert, so if one landed while
// this repair waited (a debounced scan past the floor, a safety-net tick) there is
// nothing left to restore, and a later event inside the new interval defers a fresh
// one. That is what bounds the walk at one per floor interval however many events
// arrive.
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
// makes the reconciliation floor cost an active deployment nothing. It emits the
// one per-scan mode record (logScanState, trigger="event").
//
// The watch set is re-asserted first, exactly as the safety-net tick does, and for a
// reason the event-driven recovery cannot cover: the watched mirror only forgets a
// path when fsnotify DELIVERS a Remove/Rename for it, and the Linux backend consumes
// IN_UNMOUNT and IN_IGNORED without emitting an event at all. A registration dropped
// that way leaves the mirror claiming the directory is watched, so handlePathEvent's
// membership guard skips the subtree re-walk and its descendants stay unwatched until
// something re-asserts. Re-asserting once per debounced SCAN (not once per event) keeps
// that walk off the per-event path, which is what the membership guard bought — and
// minPreScanResync additionally floors its cadence, so the walk is bounded by the clock
// rather than by a writer's event rate (one create+delete per debounce window arms a scan,
// and the walk carries none of the MAX_SCAN_ENTRIES ceiling the scan it precedes does).
// The zero lastResync means the first debounced scan of a run always re-asserts.
//
// A scan INSIDE the floor defers the re-assert (scheduleRepair) instead of dropping
// it: the repair still happens, on the floor's own schedule and without a
// certificate scan, so watch-set maintenance never depends on another event
// arriving later.
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

// runSafetyNetScan fires the periodic safety-net rescan and re-arms its timer. Its
// per-scan mode record names which clock ran it (safetyNetTrigger: the operator's
// FALLBACK_SCAN_HOURS cadence, or the reconciliation floor), so a deployment that
// switched the routine rescan off can still see the floor's walk happen and confirm
// the setting took effect.
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
// upgrade to fsnotify on every tick. It is one of Run's two modes and has a
// single exit, reported to the supervisor as a pair: a non-nil watcher means the
// upgrade succeeded and watch mode takes over from here, while a nil watcher
// means change detection is over for this mode -- nil error on shutdown, or
// a *LostError with the routine rescan disabled (fallback <= 0), where the process
// holds neither an fsnotify watch nor a cadence its operator asked for, so after
// the initial scan it returns rather than parking, and the caller must exit
// non-zero for a restart. The returned error carries the FALLBACK_SCAN_HOURS
// remediation for the caller to announce.
//
// That exit is deliberately NOT replaced by the reconciliation floor watch mode
// runs on. The floor exists so a process holding a partial or silently-dropped
// watch set still converges; here there is no watch set at all, so the only
// question is cadence, and exiting is the stronger answer: main drops the health
// marker on the way out (nothing reports healthy while converting nothing), the
// restart retries the fsnotify attach immediately rather than a whole floor later,
// and inotify exhaustion is usually transient. Reconciling once a day in-process
// would trade a prompt recovery of real-time detection for a slower one.
//
// Returning the upgraded watcher instead of running the watch loop is what keeps
// poll mode's resources out of watch mode's lifetime: the ticker in
// pollUntilUpgrade is stopped by its own defer as this mode returns, i.e. before
// watch mode begins, rather than living on unread until the process exits.
func (w *Watcher) pollLoopWithUpgrade(ctx context.Context) (upgraded *fsnotify.Watcher, err error) {
	// The initial scan: Run owns the first scan in BOTH modes, so main does not scan
	// before calling it. It runs before the fallback check on purpose: when polling is
	// disabled AND fsnotify is unavailable this function exits for a restart, and
	// converting whatever is already on disk once before doing so is the only useful
	// work the process can perform.
	if ctx.Err() != nil {
		return nil, nil
	}
	w.logScanState(ctx, modePoll, triggerStartup)
	w.onChange(ctx)

	if w.fallback <= 0 {
		// Shutdown that arrived during the initial scan above is a clean stop, not
		// lost change detection: returning a *LostError here would make main log
		// "change detection is dead" and exit 1 on a normal SIGTERM, firing the
		// CertConverterChangeDetectionDead critical alert for a graceful stop. Same
		// cancellation precedence lostOrShutdown applies at the other loss point.
		if ctx.Err() != nil {
			return nil, nil
		}
		// Return rather than park: with no fsnotify watch AND no operator-chosen
		// cadence there is nothing to reconcile against, so the floor watch mode runs
		// on would only delay recovery. errNoWatchNoFallback reaches main's non-zero exit,
		// which is the right answer because inotify exhaustion is usually transient,
		// and it carries the FALLBACK_SCAN_HOURS remediation main announces. main's
		// deferred marker cleanup means nothing reports healthy on the way out.
		return nil, errNoWatchNoFallback
	}

	return w.pollUntilUpgrade(ctx), nil
}

// pollUntilUpgrade is poll mode's ticker loop: it polls on the safety-net interval
// (the operator's FALLBACK_SCAN_HOURS cadence, capped at the reconciliation floor so
// the floor holds in this mode too) and re-attempts the fsnotify upgrade on every
// tick, returning the upgraded watcher for watch mode to run over, or nil when a
// shutdown ended the mode.
//
// It OWNS the ticker, and that ownership is the point of the mode split: the
// ticker's Stop runs as this returns, so it is released before watch mode begins
// rather than firing for watch mode's whole lifetime into a receiver nobody
// selects on, with its Stop deferred until process exit.
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
// when that fails, runs the polling scan that keeps change detection alive. It
// hands the attached watcher back for the supervisor to run watch mode over --
// it does NOT run the watch loop itself -- and reports stopped=true when a
// shutdown interrupted the attempt, so the poll loop returns instead of treating
// it as a degraded upgrade failure. A nil watcher with stopped=false means stay
// in poll mode.
//
// The record is the per-scan mode record (logScanState), so a failed retry is
// reported at WARN with mode="poll": staying in poll mode is not a NEW
// degradation, but it is a standing one, and the whole point of the mode model is
// that it stays visible at LOG_LEVEL=warn for as long as it lasts. The
// upgrade_stage and error attributes carry which half of the upgrade failed. The
// construct-then-register sequence itself is tryAttachWatchSet, shared with
// attachWatchSet; this function owns only the poll-mode record and the polling
// scan that follows a failed upgrade. A tick that UPGRADES logs the transition
// instead and no scan record, because it runs no scan (watch mode's
// attach-then-scan does).
//
// The cancellation guard is here rather than in the caller's select because this
// function owns the stopped outcome: a tick that fires in the same instant as a
// shutdown must do no work at all -- no upgrade attempt, no scan driving the health
// marker -- and every caller already reads stopped=true as "end poll mode". The
// Debug line follows the guard so a cancelled tick announces no tick it never ran.
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

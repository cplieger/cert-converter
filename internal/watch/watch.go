// Package watch provides filesystem watching with fsnotify and poll fallback.
//
// Paths here are AMBIENT, unlike every /input and /output touch in
// internal/process, which goes through an *os.Root. The invariant that keeps
// that safe: this package reads no file CONTENT, so a future read of a watched
// file MUST go through internal/process's confined root
// (source.readBounded, i.e. atomicfile.ReadBoundedInRoot) and never through a
// path built here. See
// addWatchDirs for why no confined equivalent exists and what the residual
// exposure is.
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

	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/fsnotify/fsnotify"
)

// ErrWatchLost reports that change detection ended for a reason other than
// shutdown: the fsnotify watcher died and cannot be recovered in-process, so
// the caller must exit non-zero for a restart. Every lost-change-detection
// return is a *LostError wrapping this sentinel, so errors.Is(err,
// ErrWatchLost) is the caller's test for the condition regardless of which
// loss occurred.
var ErrWatchLost = errors.New("change detection lost")

// LostError is the concrete error behind every ErrWatchLost return: it names
// WHICH loss ended change detection and, where one exists, the operator action
// that prevents it.
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

// Error renders the sentinel plus the specific loss, so a caller that only logs
// the error still names which loss occurred.
func (e *LostError) Error() string { return ErrWatchLost.Error() + ": " + e.Cause }

// Unwrap reports ErrWatchLost so errors.Is keeps identifying the condition
// without the caller having to know the concrete type.
func (e *LostError) Unwrap() error { return ErrWatchLost }

// The lost-change-detection conditions this package can reach. Each is returned
// as-is (they are immutable), and the caller distinguishes them by Cause. The two
// disabled-fallback losses are the operator-fixable ones, so they are the two that
// carry a remediation: both are reached ONLY because FALLBACK_SCAN_HOURS was set to
// 0/false, and with the routine rescan enabled neither ends the watch (a removed
// root watch is re-attached in place by resyncWatchSet). Both are LATENCY judgments
// rather than dead ends now that the reconciliation floor covers every mode
// (reconcileFloor): each names a state where a restart restores real-time detection
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

// Watcher monitors a directory tree for cert/key changes and invokes a callback.
//
// Field order is govet fieldalignment's: the pointer-bearing fields lead so the
// GC scans 24 bytes rather than the whole struct.
type Watcher struct {
	onChange func(ctx context.Context)

	// watched mirrors the fsnotify registration set, so membership is a map
	// lookup rather than a scan of fsnotify's own list (see watchSetHas). It is
	// mutated only from the goroutine running Run, but a test may drive the
	// event helpers directly while a loop runs, so watchedMu (below) keeps that
	// honest.
	watched map[string]struct{}

	root     string
	debounce time.Duration
	fallback time.Duration

	// maxEntries is how many paths ONE watch-set walk may enumerate before it
	// stops registering (fallbackWatchEntries when non-positive). It is INJECTED
	// exactly as internal/process.Options.MaxScanEntries is: internal/config owns
	// MAX_SCAN_ENTRIES' name, default, ceiling and repaired-value diagnostics, and
	// this package stays a leaf that package configures.
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
// reconciliation floor instead (reconcileFloor — slower, and never removable, so
// eventual convergence does not depend on this setting), and in poll mode there is no
// operator-chosen interval at all, so Run reports ErrWatchLost rather than run with
// neither an fsnotify watch nor a cadence its operator asked for.
func WithFallback(d time.Duration) Option {
	return func(w *Watcher) { w.fallback = d }
}

// WithMaxEntries sets how many paths one watch-set walk may enumerate. Zero or a
// negative value uses fallbackWatchEntries.
func WithMaxEntries(n int) Option {
	return func(w *Watcher) { w.maxEntries = n }
}

// fallbackWatchEntries guards a Watcher constructed without a budget (a caller
// that never wired one, and this package's own tests). It matches
// internal/config's MAX_SCAN_ENTRIES default so an un-wired Watcher walks like a
// default-configured one.
const fallbackWatchEntries = 10000

// watchBudgetMsg is the operator-facing half of a watch-set walk that stopped at
// the budget. It names the health consequence (none) and what is lost (real-time
// detection under the unwalked remainder) for the same reason the scan's own
// budget WARN does, and it reuses that WARN's matched phrase so one alert rule
// covers both walks over the same tree.
const watchBudgetMsg = "the /input tree holds more entries than one scan will enumerate; stopping the watch-set walk, so directories past the budget are unwatched and renewals under them are covered only by the periodic rescan, health is unaffected"

// watchBudgetRemediation names both ways out, exactly as the scan's does: a mount
// pointed at the wrong tree, or a legitimately large certificate directory.
const watchBudgetRemediation = "check that /input is mounted at the certificate directory and holds nothing else, or raise MAX_SCAN_ENTRIES if the tree is legitimately this large"

// reconcileFloor is the longest this app will go without a FULL reconciliation of
// the input tree — a whole-tree watch-set re-assert followed by a certificate scan
// — in ANY configuration, including FALLBACK_SCAN_HOURS=0/false.
//
// It is a floor, not a cadence: every scan re-arms the timer that enforces it,
// exactly as the configured fallback interval is re-armed, so a deployment whose
// fsnotify events arrive normally never pays for a reconciliation walk at all. Only
// a process that has gone a whole floor without scanning reaches it.
//
// Why it exists. fsnotify events are a LATENCY optimisation here, not the liveness
// mechanism: registrations are deliberately BOUNDED (addWatchDirs caps both the walk
// and the live set, because the inotify quota is shared per UID), the kernel discards
// watches without emitting an event at all (IN_UNMOUNT/IN_IGNORED), and a descriptor
// the kernel refused is only recovered by a re-assert. An app that notices change
// ONLY through events therefore has states in which it converts nothing indefinitely.
// This floor is what makes eventual convergence a property of the app rather than of
// its configuration, and it is what gives the health marker a guaranteed refresh
// cadence in every mode (MarkerRefreshFloor), so a wedged loop can be restarted even
// with the routine rescan switched off.
//
// Why 24h and not the documented 6h default. An operator who sets
// FALLBACK_SCAN_HOURS=0 is escaping periodic full walks — usually because /input is a
// network mount where they are expensive — so re-enabling the default cadence under
// another name would overrule the choice this setting exists to offer. The floor costs
// them ONE walk per day of inactivity, a quarter of the default cadence's, and the
// certificate timescale is what makes a day cheap: an ACME issuer renews a 90-day
// certificate about 30 days before it expires (Caddy at two thirds of the lifetime),
// so a renewal whose event was lost has weeks of slack before anything downstream
// serves an expired chain, and a day of added latency spends a rounding error of it.
const reconcileFloor = 24 * time.Hour

// safetyNetIntervalFor reports the periodic safety-net scan's interval for a
// configured fallback value: the operator's cadence while they chose one below the
// floor, and the reconciliation floor otherwise — which covers the 0/false opt-out,
// a negative value, and a cadence above the floor (including the 10-year ceiling
// internal/config clamps to, at which no rescan would ever have arrived).
//
// One timer serves both, because they are the same mechanism — a full re-assert plus
// a full scan — differing only in who chose the number. safetyNetTrigger reports which
// one did, so the two never become indistinguishable in the log.
func safetyNetIntervalFor(fallback time.Duration) time.Duration {
	if fallback > 0 && fallback < reconcileFloor {
		return fallback
	}
	return reconcileFloor
}

// MarkerRefreshFloor reports how often the health marker is guaranteed to be
// refreshed under a given FALLBACK_SCAN_HOURS interval (non-positive = the
// 0/false opt-out). Every safety-net scan calls the caller's onChange, and that is
// what writes the marker, so this is the cadence a probe staleness deadline must be
// derived from — the composition root's `health` subcommand arms
// health.WithMaxAge from it.
//
// It lives here rather than in internal/config because the number is this package's
// timer policy and not a configured value: config owns FALLBACK_SCAN_HOURS' name,
// default, ceiling and diagnostics, and this package deliberately does not import it.
func MarkerRefreshFloor(fallback time.Duration) time.Duration {
	return safetyNetIntervalFor(fallback)
}

// FallbackLabel renders a periodic-rescan interval for an operator-facing log
// record. A non-positive interval is reported as "disabled" rather than as a
// bare "0s": that value is the operator's confirmation that
// FALLBACK_SCAN_HOURS=0/false took effect, i.e. that no ROUTINE rescan runs on
// their cadence. It does NOT mean nothing rescans — the reconciliation floor
// still does, and the probe's staleness deadline is derived from that floor
// (MarkerRefreshFloor), which is why every record carrying this label also
// carries scan_floor. It is exported so the composition root's startup line and
// this package's degraded-path WARNs render the shared fallback_scan attribute
// identically.
func FallbackLabel(d time.Duration) string {
	if d <= 0 {
		return "disabled"
	}
	return d.String()
}

// coverageAttrs closes a degraded-path record with the two cadences that answer
// the one question such a record raises: will anything revisit what was just lost?
// Both travel together because either alone answers it wrongly — fallback_scan is
// the routine rescan and reads "disabled" when the operator switched it off, while
// scan_floor is the reconciliation floor they cannot switch off, which is what
// revisits the path in exactly that configuration. Appending rather than prefixing
// keeps each site's own diagnostics (which path, which error) at the front of the
// record.
func (w *Watcher) coverageAttrs(attrs ...any) []any {
	return append(attrs,
		// fallback_scan answers only "is the operator's own cadence running?", so
		// FallbackLabel renders a non-positive interval as "disabled"; scan_floor beside
		// it is what keeps that from reading as "nothing will ever revisit this".
		"fallback_scan", FallbackLabel(w.fallback),
		"scan_floor", w.safetyNetInterval().String())
}

// safetyNetInterval is this Watcher's periodic safety-net cadence; see
// safetyNetIntervalFor for the rule and reconcileFloor for why a floor exists.
func (w *Watcher) safetyNetInterval() time.Duration {
	return safetyNetIntervalFor(w.fallback)
}

// safetyNetTrigger names the clock behind one safety-net scan for its mode record:
// the operator's configured cadence, or the reconciliation floor standing in for it.
// Keeping the two apart in the log is what lets an operator confirm that
// FALLBACK_SCAN_HOURS=0 took effect while still seeing the floor's walk happen.
func (w *Watcher) safetyNetTrigger() string {
	if w.fallback > 0 && w.fallback <= reconcileFloor {
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
	triggerReconcile = "reconcile" // the safety-net rescan on the reconciliation floor (reconcileFloor)
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
// It replaces this package's previous per-scan announcements rather than joining
// them: two records per scan would double the log volume of the healthy path and
// leave the mode discoverable in only one of them.
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
	w := &Watcher{
		root:     root,
		onChange: onChange,
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
// poll-mode resource outlives the mode. The supervisor below therefore picks a
// mode per round: a watcher in hand means watch mode, no watcher means poll
// until it hands one back. Everything that happens once a watch set exists
// (dump the set, scan with it live, run the watch loop, close the watcher) is
// stated once, in watchMode, for both mode entries; only the arrival RECORD
// differs per entry, and each entry logs its own.
//
// It normally blocks until ctx is cancelled and then returns nil, but it ALSO
// returns ErrWatchLost early in every state where a restart is the right recovery
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
// armed in EVERY configuration (reconcileFloor), so a partial watch set, a
// registration the kernel dropped silently, and a directory past the registration
// budget are all recovered by a later re-assert rather than left to the next event.
func (w *Watcher) Run(ctx context.Context) error {
	watcher, stopped := w.attachWatchSet(ctx)
	if stopped {
		return nil
	}
	for {
		if watcher != nil {
			return w.watchMode(ctx, watcher)
		}
		upgraded, pollErr := w.pollLoopWithUpgrade(ctx)
		if upgraded == nil {
			return pollErr // poll mode reached its own terminal answer
		}
		watcher = upgraded
	}
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
// It returns watch mode's single exit: nil on shutdown, ErrWatchLost when the
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
	slog.Debug("fsnotify watch set", "directories", watcher.WatchList())
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
// The ambient-path divergence the package comment points here for is deliberate
// and bounded: inotify registration takes a path,
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
// outside the root. Every path this package registers is derived from
// filepath.WalkDir over the root (visitWatchPath is the only watcher.Add site) or
// from an event fsnotify named under a path already registered, so a registration
// cannot carry an out-of-root name and cannot compound; a registration that
// escaped through a swapped ancestor still carries an in-root name, so this
// residual (watch descriptors, never content) stands as described above.
//
// The entry ceiling is TWO bounds, not one. Every walk is capped at maxEntries
// entries, which bounds one traversal's cost; and the LIVE registration set is capped
// at the same number across calls, which is the host-resource bound the per-walk cap
// alone does not give. addWatchDirs runs again for every directory Create/Chmod
// (handlePathEvent), so a writer creating directories one at a time under an
// already-watched parent hands each call a fresh per-walk budget it never exhausts,
// and the registration set would grow until the per-UID
// fs.inotify.max_user_instances/max_user_watches quota is spent — taking unrelated
// same-UID consumers down with it. Re-registering a path already in the set is
// idempotent in the kernel and costs no new slot, so a rebuild is never refused by
// its own existing registrations.
//
// The traversal is cancellable: it checks ctx before each entry and returns
// ctx.Err() as soon as the process is shutting down, so a shutdown arriving
// mid-walk over a large input tree is not delayed by the remaining
// registrations. Callers must treat a ctx error as shutdown rather than a watch
// failure (no WARN, no fallback to polling, no follow-up scan).
func (w *Watcher) addWatchDirs(ctx context.Context, watcher *fsnotify.Watcher, root string) error {
	budget := &watchSetBudget{max: w.maxEntries, root: root}
	if budget.max <= 0 {
		budget.max = fallbackWatchEntries
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if !budget.spendEntry() {
			w.warnWatchBudget(budget)
			return fs.SkipAll
		}
		return w.visitWatchPath(ctx, watcher, budget, path, d, walkErr)
	})
}

// watchSetBudget is one walk's share of the two entry ceilings addWatchDirs applies:
// how many paths this traversal may visit, and — read through the Watcher's own
// registration mirror — how large the live watch set may grow. It also carries the
// once-per-walk guard for the budget WARN, whose remainder is unbounded and whose
// operator action is the same for all of it.
type watchSetBudget struct {
	root    string
	max     int
	visited int
	warned  bool
}

// spendEntry charges one enumerated path and reports whether it is within budget.
func (b *watchSetBudget) spendEntry() bool {
	b.visited++
	return b.visited <= b.max
}

// warnWatchBudget emits the budget WARN at most once per walk.
func (w *Watcher) warnWatchBudget(budget *watchSetBudget) {
	if budget.warned {
		return
	}
	budget.warned = true
	slog.Warn(watchBudgetMsg, w.coverageAttrs(
		"root", budget.root, "max_entries", budget.max,
		"remediation", watchBudgetRemediation)...)
}

// visitWatchPath handles one entry of addWatchDirs' traversal: it honours
// cancellation first, then applies the walk-error policy (fatal at the root,
// warn-and-skip below it), and registers a watch for every directory. Only
// directories are registered; a regular file is watched through its parent
// directory.
//
// A NEW registration is refused once the live watch set is at the budget (see
// addWatchDirs): that is the bound the per-walk count cannot express, because each
// event-driven call starts a fresh count.
func (w *Watcher) visitWatchPath(
	ctx context.Context, watcher *fsnotify.Watcher, budget *watchSetBudget, path string, d fs.DirEntry, walkErr error,
) error {
	root := budget.root
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if walkErr != nil {
		if path == root {
			return walkErr
		}
		slog.Warn("skipping unwatchable path; renewals under it require a full rescan",
			w.coverageAttrs("path", path, "error", walkErr)...)
		return nil
	}
	if !d.IsDir() {
		return validateWatchRootEntry(root, path, d)
	}
	// Already registered: re-adding is idempotent in the kernel and consumes no
	// further slot, so a rebuild never refuses itself.
	if !w.watchSetHas(path) && w.watchSetSize() >= budget.max {
		w.warnWatchBudget(budget)
		return fs.SkipAll
	}
	if addErr := watcher.Add(path); addErr != nil {
		return w.handleWatchAddError(root, path, addErr)
	}
	w.recordWatch(path)
	return nil
}

// validateWatchRootEntry applies the non-directory policy: a regular file below
// the root is simply not registered (it is watched through its parent), but a
// non-directory ROOT is fatal, not a skip.
//
// filepath.WalkDir Lstats its root and does not follow it, so a bind-mounted file
// or a symlinked /input walks exactly one non-directory entry, registers no
// watches, and would otherwise return nil - leaving Run to log "fsnotify active"
// with an empty watch set and park in a loop no event can reach, while the scan
// (os.OpenRoot DOES follow a symlinked root) keeps the health marker green.
// Reporting it lets Run degrade to polling, or return ErrWatchLost when the
// fallback is disabled too.
func validateWatchRootEntry(root, path string, d fs.DirEntry) error {
	if path != root {
		return nil
	}
	if d.Type()&fs.ModeSymlink != 0 {
		return fmt.Errorf("watch root %q is a symlink; the watch-set walk Lstats the root and does not descend it, so no directory under the target would be watched - bind-mount the target directory at %s instead", path, path)
	}
	return fmt.Errorf("watch root %q is not a directory", path)
}

// handleWatchAddError applies addWatchDirs' walk-error policy to a failed watch
// REGISTRATION: fatal at the root, warn-and-skip below it.
func (w *Watcher) handleWatchAddError(root, path string, addErr error) error {
	if path == root {
		return addErr
	}
	slog.Warn("skipping unwatchable directory; renewals under it require a full rescan",
		w.coverageAttrs("path", path, "error", addErr)...)
	return nil
}

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

// watchSetSize reports how many registrations the mirror holds, which is the live
// watch set addWatchDirs bounds across calls. Read under the same lock as
// watchSetHas, because a Remove/Rename handler can forget a path concurrently.
func (w *Watcher) watchSetSize() int {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	return len(w.watched)
}

// recordWatch notes a registration this package made, so watchSetHas can answer
// from the mirror. Only a SUCCESSFUL watcher.Add records: a directory whose Add
// failed is not watched, and recording it would suppress the re-attach the
// permission-repair (Chmod) and re-sync paths exist to perform.
func (w *Watcher) recordWatch(path string) {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	if w.watched == nil {
		w.watched = make(map[string]struct{})
	}
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

// takeWatchSet empties the mirror and returns what it held, so a REBUILD over a
// live watcher can unregister the paths it does not re-establish. resetWatchSet is
// the attach-time twin: a brand-new watcher's kernel registration set is already
// empty, so there is nothing to unregister and nothing to hand back.
func (w *Watcher) takeWatchSet() map[string]struct{} {
	w.watchedMu.Lock()
	defer w.watchedMu.Unlock()
	previous := w.watched
	w.watched = make(map[string]struct{})
	return previous
}

// pruneWatches unregisters every path a rebuild did not re-establish, which is what
// makes the mirror an honest count of the LIVE registration set rather than only of
// the last walk.
//
// The kernel keeps a registration until it is removed or its directory disappears,
// and this is the only place that removes one, so without it the live set grows past
// the ceiling addWatchDirs documents: a walk the entry budget cut short registers a
// different prefix each time the tree changes, and the registrations the new walk no
// longer reaches stay live while watchSetSize stops counting them. That ceiling is a
// share of the per-UID fs.inotify.max_user_watches quota, so overrunning it is paid
// by unrelated same-UID consumers.
//
// Best-effort by design: a path whose directory is already gone has no registration
// left to remove, so a failure here is expected rather than a degradation and is
// reported at Debug only.
func (w *Watcher) pruneWatches(watcher *fsnotify.Watcher, stale map[string]struct{}) {
	for path := range stale {
		if w.watchSetHas(path) {
			continue
		}
		if err := watcher.Remove(path); err != nil {
			slog.Debug("stale fsnotify registration already gone", "path", path, "error", err)
		}
	}
}

// --- Event classification ---

// handleFsEvent keeps directory watches current and reports whether an event
// warrants a rescan. Remove and Rename always rescan because the old path can
// no longer be inspected. Create and Chmod delegate path classification and
// directory reattachment to handlePathEvent; Write only rescans cert/key paths.
func (w *Watcher) handleFsEvent(ctx context.Context, watcher *fsnotify.Watcher, event fsnotify.Event) bool {
	slog.Debug("fs event", "op", event.Op.String(), "path", event.Name)
	switch {
	case event.Has(fsnotify.Create):
		return w.handleCreate(ctx, watcher, event)
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
		return w.handleChmod(ctx, watcher, event)
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
			w.coverageAttrs("path", event.Name, "error", err)...)
		return true
	}
	if !info.IsDir() {
		return layout.IsRelevant(event.Name)
	}
	if w.watchSetHas(event.Name) {
		return true // already watched: nothing to re-attach, the debounced rescan covers content
	}
	if addErr := w.addWatchDirs(ctx, watcher, event.Name); addErr != nil && ctx.Err() == nil {
		slog.Warn(addWarning,
			w.coverageAttrs("path", event.Name, "error", addErr)...)
	}
	return true
}

// handleCreate is handleFsEvent's Create arm: a newly created directory joins the
// watch set (and triggers a rescan, because it may already hold a pair created
// before the watch attached), and a newly created file is classified by name.
func (w *Watcher) handleCreate(ctx context.Context, watcher *fsnotify.Watcher, event fsnotify.Event) bool {
	return w.handlePathEvent(ctx, watcher, event,
		"cannot classify a created path; rescanning because it may be a directory, but if it is one it stays unwatched until the next re-assert of the watch set",
		"failed to watch new directory subtree; renewals under it are covered only by the periodic rescan")
}

// handleChmod is handleFsEvent's Chmod arm: the recovery path for a permission
// repair on a cert, on a key, or on a directory the watch set had to skip.
//
// A chmod on a DIRECTORY is that same recovery one step up: an /input
// sub-directory the watch set had to skip because this UID could not read it
// (README: "Fix the directory permissions") has just become readable, so its
// subtree is re-attached and a rescan runs now instead of at the next periodic
// tick. Unlike the file case this outcome is
// health-neutral (ScanResult.Unreadable), so nothing else signals the operator
// that the repair has not taken effect yet.
//
// A chmod on a cert or key IS conversion-relevant, and this arm is the recovery
// path for the app's most likely operator error: a pair the scan could not read
// fails conversion and clears the health marker; the operator fixes it with
// chmod; without this arm that chmod schedules nothing, so the container stays
// unhealthy and the .pfx stays stale until the next periodic tick -- six hours on
// the documented cadence, and a day on the reconciliation floor when the routine
// rescan is switched off.
//
// Scoped to the naming contract, so a chmod on an unrelated file still schedules
// nothing. A chmod storm is absorbed by the debounce, exactly as a write storm
// is, and /input is a certificate directory rather than a busy tree. The debounce
// coalesces SCANS only, so the directory arm's re-attach walk is bounded
// separately: handlePathEvent skips it for a directory already in the watch set
// (watchSetHas), leaving the walk for the skipped-directory recovery this arm is
// here for.
func (w *Watcher) handleChmod(ctx context.Context, watcher *fsnotify.Watcher, event fsnotify.Event) bool {
	return w.handlePathEvent(ctx, watcher, event,
		"cannot classify a path whose permissions changed; rescanning because it may be an unwatched directory",
		"failed to watch a directory whose permissions changed; renewals under it are covered only by the periodic rescan")
}

// --- Watch loop, its receive arms, and its timer state ---

// watchLoop uses fsnotify for immediate reaction to cert changes,
// with a periodic full scan as a safety net. It returns nil when ctx is
// cancelled and ErrWatchLost when the watcher's Events or Errors channel closes
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
	if filepath.Clean(event.Name) != filepath.Clean(w.root) {
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
		w.coverageAttrs("root", w.root, "op", event.Op.String())...)
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
// event-queue overflow additionally re-syncs the watch set. Naming the loss here
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
		st.resync(ctx, watcher,
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
	// Rebuild rather than append: the walk below re-records every directory it registers, so
	// starting from empty makes the mirror exactly the set this walk established. That prunes a
	// path the tree no longer has - the mirror otherwise only forgets on a DELIVERED
	// Remove/Rename, and the queue overflow that drops those deliveries is the same condition
	// that routes here, so without this the map grows with churn for the process's life. A walk
	// cut short below leaves the mirror emptier than the kernel's set, which errs toward one
	// extra subtree walk on a later event (the safe direction this mirror already documents),
	// never toward claiming an unwatched directory is watched.
	stale := w.takeWatchSet()
	if addErr := w.addWatchDirs(ctx, watcher, w.root); addErr != nil {
		if ctx.Err() == nil {
			slog.Warn(warning, w.coverageAttrs("root", w.root, "error", addErr)...)
		}
		return
	}
	// Unregister what this walk did not re-establish, so the mirror the LIVE-set ceiling is
	// read from (visitWatchPath's watchSetSize test) counts the kernel's registrations rather
	// than only this walk's. Only on the success path: a walk that failed at the root proves
	// nothing about which registrations are still wanted, and dropping them all there would
	// unwatch a tree this process cannot currently re-walk.
	w.pruneWatches(watcher, stale)
	// Refresh the Debug dump on success: every re-sync exists to RECOVER watches that were
	// missing, so the recovered set - not the set as it stood at attach - is what an operator
	// diagnosing an incomplete watch set needs. The failure half is the WARN above.
	logWatchSet(watcher)
}

// watchState carries the mutable accounting for one watchLoop run: the pending
// debounce flag and the debounce/safety-net/repair timers. Hoisting the per-event
// work onto its methods keeps watchLoop's select a flat dispatch table rather than
// a deeply nested switch.
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
// (safetyNetInterval), so there is no configuration in which the loop holds no
// clock at all and change detection depends purely on fsnotify events arriving.
func newWatchState(w *Watcher) *watchState {
	st := &watchState{w: w}
	st.debounceTimer = time.NewTimer(w.debounce)
	st.debounceTimer.Stop()
	st.repairTimer = time.NewTimer(minPreScanResync)
	st.repairTimer.Stop()
	st.safetyNetTimer = time.NewTimer(w.safetyNetInterval())
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
// makes the reconciliation floor cost an active deployment nothing. Its per-scan
// mode record (logScanState, trigger="event") replaces the previous "cert change
// detected, processing" line: one record per scan, carrying the mode, rather than
// an announcement that said nothing about the state the process is in.
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
	if time.Since(st.lastResync) >= minPreScanResync {
		st.resync(ctx, watcher,
			"failed to re-assert the watch set before a debounced scan; a registration the kernel dropped without an event stays unwatched until the next re-assert")
		// The re-sync can be cut short by cancellation, and the scan below would then be
		// spurious work for a loop that is already returning.
		if ctx.Err() != nil {
			return
		}
	} else {
		st.scheduleRepair()
	}
	st.w.logScanState(ctx, modeWatch, triggerEvent)
	st.w.onChange(ctx)
	st.safetyNetTimer.Reset(st.w.safetyNetInterval())
}

// runSafetyNetScan fires the periodic safety-net rescan and re-arms its timer. Its
// per-scan mode record names which clock ran it (safetyNetTrigger: the operator's
// FALLBACK_SCAN_HOURS cadence, or the reconciliation floor), so a deployment that
// switched the routine rescan off can still see the floor's walk happen and confirm
// the setting took effect.
func (st *watchState) runSafetyNetScan(ctx context.Context) {
	st.w.logScanState(ctx, modeWatch, st.w.safetyNetTrigger())
	st.w.onChange(ctx)
	st.safetyNetTimer.Reset(st.w.safetyNetInterval())
}

// handleWatcherError reacts to an fsnotify error: an event-queue overflow
// dropped events, so force a rescan to recover any missed renewal and report
// true so the caller also re-syncs the watch set (a dropped directory Create
// would otherwise leave that subtree unwatched until the process restarts); any
// other error is logged, the loop continues, and it reports false.
func (st *watchState) handleWatcherError(err error) bool {
	if errors.Is(err, fsnotify.ErrEventOverflow) {
		slog.Warn("fsnotify event queue overflowed; events were dropped, forcing a rescan to recover any missed renewal",
			st.w.coverageAttrs("root", st.w.root, "error", err)...)
		st.scheduleScan()
		return true
	}
	slog.Warn("watcher error; the watch loop continues and a change missed because of it is covered only by the periodic fallback rescan",
		st.w.coverageAttrs("root", st.w.root, "error", err)...)
	return false
}

// --- Poll mode ---

// pollLoopWithUpgrade polls on the safety-net interval and attempts to
// upgrade to fsnotify on every tick. It is one of Run's two modes and has a
// single exit, reported to the supervisor as a pair: a non-nil watcher means the
// upgrade succeeded and watch mode takes over from here, while a nil watcher
// means change detection is over for this mode -- nil error on shutdown, or
// ErrWatchLost with the routine rescan disabled (fallback <= 0), where the process
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
		// lost change detection: returning ErrWatchLost here would make main log
		// "change detection is dead" and exit 1 on a normal SIGTERM, firing the
		// CertConverterChangeDetectionDead critical alert for a graceful stop. Same
		// cancellation precedence lostOrShutdown applies at the other loss point.
		if ctx.Err() != nil {
			return nil, nil
		}
		// Return rather than park: with no fsnotify watch AND no operator-chosen
		// cadence there is nothing to reconcile against, so the floor watch mode runs
		// on would only delay recovery. ErrWatchLost reaches main's non-zero exit,
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
	ticker := time.NewTicker(w.safetyNetInterval())
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
	slog.Debug("poll tick", "interval", w.safetyNetInterval())
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

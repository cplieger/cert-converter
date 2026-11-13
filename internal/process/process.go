// Package process provides the certificate scanning and conversion orchestration.
package process

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/mounts"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/scanbudget"
	"github.com/cplieger/go/filesafe"
)

// ScanResult carries per-source outcome summary counts from a scan run. A scan
// whose /input walk did not finish reports the per-path counts and the reap and
// layout flags at least as the previous scan did, and any scan that did not cover
// the tree keeps NoSources and AllExcluded unless its own sources disprove them.
type ScanResult struct {
	// Removed counts artifacts deleted because their source is gone.
	Removed    int
	Total      int
	Converted  int
	Unchanged  int
	Orphan     int
	Failed     int
	Unreadable int
	// Unresolved counts input symlinks not named like an input that the confined
	// root could not resolve.
	Unresolved int
	// Vanished counts /input files this scan saw evidence of and then could not find:
	// a cert or key that existed at readdir and was gone by the bounded read, and a
	// sibling .key that a previous scan of this process read whole and that is gone by
	// this scan's stat (noteMissingKey).
	Vanished int
	// Unwritable counts prior artifacts this app could not replace, where it never
	// proved the bytes on disk wrong and no restart can clear what refused the
	// write, so the artifact is left in place and health is unaffected.
	Unwritable int
	// Collided counts flat-layout sources whose output name another source also
	// claims, a standing collision's claimants the scan could not reach included;
	// none of them was converted, and the container goes unhealthy until the
	// operator resolves the ambiguity.
	Collided int
	// Ignored counts PFX/P12 files skipped because PFX input was not explicitly
	// enabled. They preserve pre-feature behavior and do not make the input
	// enumeration safe for orphan deletion.
	Ignored int
	// Excluded counts sources INPUT_EXCLUDE_PATHS declared are not this app's to
	// convert. They are enumerated and register no artifact, so what they
	// produced earlier is an orphan candidate; health is unaffected.
	Excluded int
	Outcome  Outcome
	// NoSources reports a complete enumeration that found nothing to convert: no
	// source at all, or only PEM certificates that lack their key.
	NoSources bool
	// AllExcluded reports a complete enumeration whose every source
	// INPUT_EXCLUDE_PATHS covers.
	AllExcluded bool
	// OrphanRemovalDisabled reports a scan that could not prove any /output
	// artifact orphaned, so OUTPUT_LIFECYCLE removed nothing.
	OrphanRemovalDisabled bool
	// PreviousLayoutRetained reports a sync scan that kept artifacts laid out for
	// the other OUTPUT_LAYOUT.
	PreviousLayoutRetained bool
	// CleanupDegraded is the latest stale-temp sweep's verdict: some temp could not
	// be removed or inspected. The sweep runs at most hourly, so a scan that did
	// not sweep carries the previous sweep's verdict.
	CleanupDegraded bool
}

// Outcome is how a scan ended. The zero value is a scan that covered the tree.
type Outcome int

// The scan outcomes.
const (
	OutcomeComplete Outcome = iota
	// OutcomeAborted is a scan that ended early on an error other than shutdown.
	OutcomeAborted
	// OutcomeBudgetStopped is a scan that stopped at the /input entry budget and
	// converted only what it enumerated before the stop.
	OutcomeBudgetStopped
)

// String names the outcome as the metrics label and the docs spell it.
func (o Outcome) String() string {
	switch o {
	case OutcomeAborted:
		return "aborted"
	case OutcomeBudgetStopped:
		return "budget_stopped"
	default:
		return "complete"
	}
}

// carryUnproven raises the conditions a scan that did not enumerate the whole
// tree cannot prove gone to the previous report's values. With enumerated, the
// walk finished and only the whole-tree verdicts carry; a whole-tree verdict
// this scan's own sources disprove does not.
func (r *ScanResult) carryUnproven(prev *ScanResult, enumerated bool) {
	r.NoSources = r.NoSources || (prev.NoSources && r.Total <= r.Orphan)
	r.AllExcluded = r.AllExcluded || (prev.AllExcluded && r.Excluded == r.Total)
	if enumerated {
		return
	}
	r.Orphan = max(r.Orphan, prev.Orphan)
	r.Failed = max(r.Failed, prev.Failed)
	r.Unreadable = max(r.Unreadable, prev.Unreadable)
	r.Unresolved = max(r.Unresolved, prev.Unresolved)
	r.Unwritable = max(r.Unwritable, prev.Unwritable)
	// A scan that got as far as the claim ledger counts its own collisions
	// (claimLedger); only an aborted one may not have.
	if r.Outcome == OutcomeAborted {
		r.Collided = max(r.Collided, prev.Collided)
	}
	r.OrphanRemovalDisabled = r.OrphanRemovalDisabled || prev.OrphanRemovalDisabled
	r.PreviousLayoutRetained = r.PreviousLayoutRetained || prev.PreviousLayoutRetained
}

// conversionsClean reports whether nothing this scan did leaves the output tree in a
// state this app is still trying to repair. A collision counts: the contested
// path's content is ambiguous, so no deletion may rest on this scan's view.
func (r *ScanResult) conversionsClean() bool {
	return r.Failed == 0 && r.Unwritable == 0 && r.Collided == 0
}

// durablyEnumerated reports whether every DURABLE veto on the input enumeration is
// clear: nothing under /input was unreadable and no symlink was unresolvable.
func (r *ScanResult) durablyEnumerated() bool {
	return r.Unreadable == 0 && r.Unresolved == 0
}

// inputFullyEnumerated reports whether nothing prevented this scan from observing
// every /input path.
func (r *ScanResult) inputFullyEnumerated() bool {
	return r.durablyEnumerated() && r.Vanished == 0
}

// Scan-level sentinels: the reported entry-budget stop and the destructive
// mount-alias configuration refusal.
var (
	errScanBudgetExceeded = errors.New("input tree exceeds the per-scan entry budget")
	errAliasedRoots       = errors.New("input and output roots resolve to the same directory")
)

// scanBudgetMsg is the operator-facing half of that abort.
const scanBudgetMsg = scanbudget.InputTreeTooLarge + "; stopping this scan without converting or removing anything further, health is unaffected"

// Options carries the process-lifetime scan configuration the composition root
// chooses once at startup: confined roots, input and output passwords, output
// formats and layout, and the PKCS#12 encoder profile.
type Options struct {
	Encoder       convert.EncoderType
	Lifecycle     outputpolicy.Lifecycle
	Layout        outputpolicy.Layout
	CertsRoot     string
	OutRoot       string
	Password      string
	InputPassword string
	// Exclude names input paths that are enumerated but never converted.
	Exclude layout.ExcludeSet
	// MaxScanEntries is how many entries one scan may enumerate in EACH mounted tree
	// before it refuses that tree (scanbudget.Default when non-positive): the /input
	// walk (scanWalk.budget) and the /output orphan walk (outputWalk.budget)
	// each get the same ceiling, applied per tree rather than shared, because both are
	// mounts this app does not own and either one can be made large by whoever can write
	// to it.
	MaxScanEntries int
	// Formats is the set of artifact families every source emits.
	Formats outputpolicy.Formats
	// FormatsExplicit distinguishes the legacy unset PFX default from an operator
	// who deliberately selected a format set. An explicit selection lets sync
	// clean artifacts produced by a previously enabled format.
	FormatsExplicit bool
	// LayoutExplicit is the layout mirror of FormatsExplicit: an explicit
	// OUTPUT_LAYOUT lets sync clean artifacts laid out for the other layout,
	// while the unset default leaves them in place and reports them.
	LayoutExplicit bool
	// InputPasswordReady is false unless a non-blank value or the explicit
	// empty-password opt-in was set.
	InputPasswordReady bool
}

// Scanner walks a certificate directory, resolves PEM pairs and PKCS#12
// bundles into one identity model, and updates every configured output format.
type Scanner struct {
	// lastSweep is when this process last swept /output for stale temps. It lives here
	// rather than on store because store is rebuilt per Run.
	lastSweep    time.Time
	observations *observationLog
	standing     *standing
	// claims is the flat ownership record: every flat output stem's claimants as
	// the last scan that ran the claim ledger left them (claimLedger), and its
	// owner. claimsPersisted is its last stored encoding.
	claims          map[string]stemClaim
	claimsPersisted []byte
	opts            Options
	// lastReported is the previous scan's result, what an incomplete scan carries.
	lastReported ScanResult
	// cleanupDegraded carries the last sweep's verdict to the scans between sweeps.
	cleanupDegraded bool
	// claimsLoaded is whether the flat ownership record was read (loadClaims).
	claimsLoaded bool
}

// sweepClock is indirected for the same reason waitBeforeReap is: a test cannot
// move an hour otherwise.
var sweepClock = time.Now

// New constructs a Scanner with the given process-lifetime scan configuration.
// The zero values keep their unset-env meaning: no enabled format means PFX
// only, and no layout means the default layout.
func New(opts *Options) *Scanner {
	normalized := *opts
	if !normalized.Formats.PFX && !normalized.Formats.PEM {
		normalized.Formats = outputpolicy.DefaultFormats()
	}
	if normalized.Layout == "" {
		normalized.Layout = outputpolicy.DefaultLayout()
	}
	if normalized.InputPasswordReady && normalized.InputPassword == "" {
		normalized.InputPasswordReady = false
	}
	return &Scanner{
		opts:         normalized,
		observations: newObservationLog(normalized.MaxScanEntries),
		standing:     newStanding(),
		claims:       make(map[string]stemClaim),
	}
}

func openScanRoots(inputPath, outputPath string) (input, output *os.Root, err error) {
	input, err = os.OpenRoot(inputPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open input root %q: %w", inputPath, err)
	}
	output, err = os.OpenRoot(outputPath)
	if err != nil {
		_ = input.Close()
		return nil, nil, fmt.Errorf("open output root %q: %w", outputPath, err)
	}
	overlaps, err := mounts.Overlap(inputPath, outputPath)
	if err != nil {
		_ = output.Close()
		_ = input.Close()
		return nil, nil, fmt.Errorf("compare input and output roots: %w", err)
	}
	if overlaps {
		_ = output.Close()
		_ = input.Close()
		return nil, nil, fmt.Errorf("%w: mount physically separate directory trees at /input and /output", errAliasedRoots)
	}
	return input, output, nil
}

// Run walks the configured input root, converts each selected source into the
// configured output formats, and returns per-source counts plus any walk-level
// error.
func (s *Scanner) Run(ctx context.Context) (ScanResult, error) {
	s.standing.beginScan()
	inHandle, outHandle, err := openScanRoots(s.opts.CertsRoot, s.opts.OutRoot)
	if err != nil {
		result := ScanResult{Outcome: OutcomeAborted, CleanupDegraded: s.cleanupDegraded}
		result.carryUnproven(&s.lastReported, false)
		s.lastReported = result
		return result, err
	}
	defer func() { _ = inHandle.Close() }()
	defer func() { _ = outHandle.Close() }()

	cleanupFormats := s.opts.Formats
	if s.opts.FormatsExplicit {
		cleanupFormats = outputpolicy.Formats{PFX: true, PEM: true}
	}
	out := &store{root: outHandle, standing: s.standing, maxEntries: s.opts.MaxScanEntries, formats: cleanupFormats}
	if now := sweepClock(); s.lastSweep.IsZero() || now.Sub(s.lastSweep) >= staleTempAge {
		// A temp is only a candidate once it is staleTempAge old, so sweeping more
		// often than that re-walks the whole output tree to find nothing new.
		s.lastSweep = now
		if degraded, swept := out.sweepStaleTemps(ctx); swept {
			s.cleanupDegraded = degraded
		}
	}

	flat := s.opts.Layout == outputpolicy.LayoutFlat
	if flat && !s.claimsLoaded {
		s.loadClaims(ctx, out)
	}
	owners := s.ownersSnapshot()
	sw := &scanWalk{
		src:                &source{root: inHandle},
		out:                out,
		observations:       s.observations,
		standing:           s.standing,
		claims:             s.claims,
		bundleBudget:       convert.NewBundleWorkBudget(),
		password:           s.opts.Password,
		inputPassword:      s.opts.InputPassword,
		inputPasswordReady: s.opts.InputPasswordReady,
		enc:                s.opts.Encoder,
		formats:            s.opts.Formats,
		layoutMode:         s.opts.Layout,
		exclude:            s.opts.Exclude,
		seen:               make(map[string]struct{}),
		expected:           make(map[string]struct{}),
		budget:             scanbudget.NewCounter(s.opts.MaxScanEntries),
	}
	// Protect the wholeness this walk establishes from the observation log's own
	// eviction: an eviction's victim is arbitrary, so without this window a pair markWhole
	// read earlier in THIS scan could lose the evidence noteMissingKey classifies a
	// replaced key with, and the veto that covers the eviction (evictedWholeness) is
	// spent by the end of this scan. Closed on every exit path.
	s.observations.beginScan()
	defer s.observations.endScan()
	// Enumerate the input tree THROUGH the root handle, exactly as the
	// /output stale-temp sweep does: every step is an openat-relative
	// syscall and every path handed downstream is root-relative, so no
	// ambient absolute path exists for a later read to reach for.
	walkErr := sw.finish(ctx, filesafe.WalkDirInRoot(ctx, inHandle, func(rel string, d fs.DirEntry, err error) error {
		return sw.visit(ctx, rel, d, err)
	}))
	// Before reconcile, whose confirmation wait a shutdown can cut short.
	if flat {
		s.persistClaims(ctx, out)
	}
	// A tree over the entry budget is REPORTED, not failed.
	budgetExceeded := errors.Is(walkErr, errScanBudgetExceeded)

	result := countResults(sw.results, sw.unreadable, sw.unresolved, sw.vanished)
	result.Collided += sw.contested
	result.Failed += sw.unreachedFailures()
	result.Ignored = sw.ignored
	rc := reapContext{
		// The scan's counts are carried whole rather than copied field-by-field:
		// result.Unreadable (not sw.unreadable) is what the veto needs, because it also
		// carries the per-entry statusUnreadable count.
		result:        result,
		walkCompleted: walkErr == nil,
		shutdown:      walkErr != nil && IsShutdown(walkErr),
		// The observation log's ceiling can force it to drop the "this pair was once
		// read whole" evidence noteMissingKey depends on, and the loss is silent at the
		// point of use: a key that goes missing afterwards is classified as an ordinary
		// orphan (health-neutral, NOT reap-vetoing) instead of the transient
		// statusVanished (reap-vetoing), so the scan would go on to delete unrelated
		// leftover outputs on an input reading it can no longer justify.
		evidenceEvicted: s.observations.takeEvictedWholeness(),
	}
	// Prune observation state for pairs that are gone, but ONLY when the walk
	// proved the enumeration complete and only for paths it reached: a pair
	// hidden behind an unreadable sub-path or an unresolved symlink would be
	// forgotten and re-warn on the next clean scan.
	if rc.walkEnumerationComplete() {
		s.observations.forget(sw.keepObserved)
	}
	rp := &reaper{
		src: sw.src, out: out, mode: s.opts.Lifecycle, formats: s.opts.Formats,
		layoutMode: s.opts.Layout, layoutExplicit: s.opts.LayoutExplicit,
		exclude:            s.opts.Exclude,
		maxEntries:         s.opts.MaxScanEntries,
		owners:             owners,
		inputPasswordReady: s.opts.InputPasswordReady,
	}
	if !flat {
		rp.unreached = sw.reach.outputHidden
	}
	removed, reconcileErr := rp.reconcile(ctx, sw.expected, &rc)
	result.Removed = removed
	// A shutdown that arrives after the input walk completed cancels reconciliation
	// instead, and that scan is NOT complete: without folding the error in, the
	// caller would log "scan complete" and mark the container healthy on a scan that
	// stopped halfway through the output tree.
	if walkErr == nil {
		walkErr = reconcileErr
	}

	s.reportVerdict(&result, out, sw, walkErr)
	if budgetExceeded {
		return result, nil
	}
	return result, walkErr
}

// reportVerdict derives the scan's verdicts from what the walk, the reaper and
// the last sweep found, then logs the standing conditions that changed. Only a
// scan that ran to the end can prove a per-path condition gone, and only for a
// subject it reached (scanReach.input).
func (s *Scanner) reportVerdict(result *ScanResult, out *store, sw *scanWalk, walkErr error) {
	result.Outcome = outcomeOf(walkErr)
	result.OrphanRemovalDisabled = out.reapDisabled
	result.PreviousLayoutRetained = out.otherLayoutKept
	result.CleanupDegraded = s.cleanupDegraded
	enumerated := walkErr == nil
	wholeTree := sw.readWholeTree(result, walkErr)
	if wholeTree {
		coverage := wholeTreeCoverageOf(result)
		result.NoSources = coverage == coverageNoSource || coverage == coverageAllOrphan
		result.AllExcluded = coverage == coverageAllExcluded
	}
	logInputCoverageWarnings(s.standing, result, walkErr, wholeTree)
	if !wholeTree {
		result.carryUnproven(&s.lastReported, enumerated)
	}
	s.lastReported = *result
	if walkErr != nil {
		return
	}
	inputReached := func(subject string, _ []string) bool { return sw.reach.input(subject) }
	judged := func(subject string, _ []string) bool { return sw.reach.judged(subject) }
	s.standing.clearUnseen(condUnresolvedSymlink, false, judged)
	s.standing.clearUnseen(condDanglingSource, false, judged)
	// The aggregate unreadable_paths condition reports the clear; its per-path
	// detail goes quietly.
	s.standing.clearUnseen(condUnreadablePath, true, inputReached)
	s.standing.clearUnseen(condConversionFailed, false, inputReached)
	s.standing.clearUnseen(condUnwritable, false, func(subject string, sources []string) bool {
		return wholeTree || sw.reach.output(subject) || sw.gone(sources)
	})
	if wholeTree {
		out.clearUnmanaged(sw.expected)
	}
}

// outcomeOf classifies the error a scan ended with.
func outcomeOf(walkErr error) Outcome {
	switch {
	case walkErr == nil:
		return OutcomeComplete
	case errors.Is(walkErr, errScanBudgetExceeded):
		return OutcomeBudgetStopped
	default:
		return OutcomeAborted
	}
}

// scanWalk carries the read-only conversion parameters and mutable accounting
// for one Scanner.Run input-tree walk.
type scanWalk struct {
	src  *source
	out  *store
	seen map[string]struct{}
	// expected is every artifact path the enabled formats derive from the sources
	// this walk saw, registered at enumeration time so a source whose conversion
	// later fails still protects its artifacts from the orphan reaper.
	expected map[string]struct{}
	// failed is whether each source that failed in this walk was news, so every
	// failure of one source in one scan shares the first one's level.
	failed map[string]bool
	reach  scanReach
	// pendingSources defers flat-layout conversion until every source name is
	// known, so output-name collisions are arbitrated before any artifact is
	// published.
	pendingSources []string
	observations   *observationLog
	standing       *standing
	claims         map[string]stemClaim
	// facts is every /input entry this walk judged, so each path is judged once
	// per scan and every reader of it agrees.
	facts map[string]entryFacts
	// unproven is every source whose own entry or key resolved to the wrong kind:
	// it claims its stem and is never read.
	unproven      map[string]struct{}
	bundleBudget  *convert.BundleWorkBudget
	enc           convert.EncoderType
	layoutMode    outputpolicy.Layout
	exclude       layout.ExcludeSet
	password      string
	inputPassword string
	results       []conversionStatus
	// budget is this walk's entry ceiling and its charge counter, injected from
	// Options.MaxScanEntries.
	budget     scanbudget.Counter
	unreadable int
	ignored    int
	// vanished counts paths the walk enumerated and then could not find: the
	// directory half of the renewal race whose file half readPair classifies as
	// statusVanished.
	vanished int
	// unresolved counts input symlinks the confined root could not resolve.
	unresolved int
	// contested counts the claimants of standing collisions this scan could not
	// reach (claimLedger).
	contested int
	// unreachedClaims counts every stored flat claimant this scan could not reach.
	unreachedClaims int
	formats         outputpolicy.Formats
	// inputPasswordReady is false unless a non-blank password or the explicit
	// empty-password opt-in was configured.
	inputPasswordReady bool
}

// visit is the walk's per-entry callback (filesafe.WalkDirInRoot).
func (sw *scanWalk) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		sw.reach.withdraw(rel)
		if rel == "." {
			return err
		}
		// An ENOENT below the root is the WALK's half of the renewal race the
		// read side classifies as statusVanished.
		if errors.Is(err, fs.ErrNotExist) {
			slog.Debug("skipping path that vanished during the scan", "path", logtext.Path(rel), "error", logtext.Path(err.Error()))
			sw.vanished++
			return nil
		}
		slog.Debug("skipping unreadable path", "path", logtext.Path(rel), "error", logtext.Path(err.Error()))
		sw.unreadable++
		return nil
	}
	// Charged once per enumerated path, before anything is read or remembered,
	// so the budget bounds the walk's own state rather than trailing it.
	if !sw.budget.Charge() {
		sw.reach.stop(rel)
		slog.Warn(scanBudgetMsg,
			"path", logtext.Path(rel), "entries", sw.budget.Count(), "limit", sw.budget.Max(),
			"remediation", scanbudget.InputRemediation)
		return fmt.Errorf("%w: stopped at %d entries (%s)", errScanBudgetExceeded, sw.budget.Count(), rel)
	}
	if d.IsDir() {
		// Withdrawn by the error call above if its listing fails.
		sw.reach.enterDir(rel)
	}
	sw.noteUnwalkableSymlink(rel, d)
	if layout.IsKey(rel) {
		sw.judgeKeyLink(rel)
		return nil
	}
	if !layout.IsSource(rel) {
		return nil
	}
	// Ahead of the judgement: both decide from the path alone, so an excluded or
	// disabled-bundle name counts the same whatever a link there points at.
	if sw.excludeSource(rel) || sw.ignoreDisabledBundle(rel) {
		return nil
	}
	return sw.claimSource(ctx, rel, d)
}

// entry returns the facts about the entry rel the walk listed as d, following a
// link once.
func (sw *scanWalk) entry(rel string, d fs.DirEntry) entryFacts {
	if f, judged := sw.facts[rel]; judged {
		return f
	}
	var f entryFacts
	switch {
	case d.Type()&fs.ModeSymlink != 0:
		f = sw.src.linkFacts(rel)
	default:
		f = entryFacts{shape: shapeOfMode(d.Type())}
	}
	sw.remember(rel, f)
	return f
}

// leaf returns the facts about rel, a path in a directory this walk lists,
// whether or not the walk has reached its entry yet.
func (sw *scanWalk) leaf(rel string) entryFacts {
	if f, judged := sw.facts[rel]; judged {
		return f
	}
	f := sw.src.leafFacts(rel)
	sw.remember(rel, f)
	return f
}

func (sw *scanWalk) remember(rel string, f entryFacts) {
	if sw.facts == nil {
		sw.facts = make(map[string]entryFacts)
	}
	sw.facts[rel] = f
}

// claimSource judges the source rel, and for a certificate its key. A source
// that cannot exist claims nothing; one of the wrong kind claims its stem and is
// never read; any other claims and converts.
func (sw *scanWalk) claimSource(ctx context.Context, rel string, d fs.DirEntry) error {
	switch v := judgeFacts(sw.entry(rel, d), roleFile); {
	case v == verdictAbsent:
		sw.reportDanglingLink(rel)
		return nil
	case v == verdictMismatch:
		sw.claimMismatched(rel, rel)
		return nil
	case v == verdictPresent && layout.IsCert(rel) && judgeFacts(sw.leaf(layout.KeyFor(rel)), roleFile) == verdictMismatch:
		sw.claimMismatched(rel, layout.KeyFor(rel))
		return nil
	}
	if sw.layoutMode == outputpolicy.LayoutFlat {
		sw.pendingSources = append(sw.pendingSources, rel)
		return nil
	}
	_, err := sw.processSource(ctx, rel)
	return err
}

// mismatchMsg reports an input path that is not a regular file where a source
// or key is expected.
const mismatchMsg = "skipping source: an input path is not a regular file"

// claimMismatched holds the source rel, whose entry at at resolved to the wrong
// kind. It proves nothing about rel, so rel keeps its stem, its artifacts stay
// expected and reaping stays vetoed, and one standing warning names at.
func (sw *scanWalk) claimMismatched(rel, at string) {
	sw.unreadable++
	level, attrs := sw.standing.reportPath(condUnreadablePath, at)
	if at != rel {
		attrs = append(attrs, "source", logtext.Path(rel))
	}
	slog.Log(context.Background(), level, mismatchMsg, append(attrs, "remediation", "replace it with a regular file")...)
	if sw.unproven == nil {
		sw.unproven = make(map[string]struct{})
	}
	sw.unproven[rel] = struct{}{}
	if sw.layoutMode == outputpolicy.LayoutFlat {
		sw.pendingSources = append(sw.pendingSources, rel)
		return
	}
	sw.holdUnproven(rel)
}

// holdUnproven keeps an unread source's claim: its artifacts stay expected and
// what this process knows about it stands.
func (sw *scanWalk) holdUnproven(rel string) {
	sw.seen[rel] = struct{}{}
	sw.reach.noteSource(rel, statusUnreadable, sw.registerExpected(rel))
}

// danglingSourceMsg reports a source or key link whose target does not exist.
const danglingSourceMsg = "skipping source: the symlink's target does not exist inside /input, so it counts as deleted"

// danglingSourceRemediation names both ways out, and when sync reaps.
const danglingSourceRemediation = "restore the link's target or remove the link; under OUTPUT_LIFECYCLE=sync the stem's artifacts " +
	"are removed only once no source or private key of the stem remains in /input and another source keeps the input tree non-empty"

// reportDanglingLink reports the link rel, judged Absent, as a standing
// condition. A regular file judged Absent raced the walk and says nothing.
func (sw *scanWalk) reportDanglingLink(rel string) {
	f := sw.facts[rel]
	if !f.linked {
		return
	}
	level, attrs := sw.standing.reportPath(condDanglingSource, rel)
	if target, err := sw.src.root.Readlink(rel); err == nil {
		attrs = append(attrs, "target", logtext.Path(target))
	}
	slog.Log(context.Background(), level, danglingSourceMsg,
		append(attrs, "remediation", danglingSourceRemediation)...)
}

// judgeKeyLink reports a key link that leads nowhere. Nothing else would: the
// key is no source, and its pair reads it only while the certificate converts.
func (sw *scanWalk) judgeKeyLink(rel string) {
	if !sw.facts[rel].linked || (!sw.exclude.Empty() && sw.exclude.Excludes(rel)) {
		return
	}
	if judgeFacts(sw.facts[rel], roleFile) == verdictAbsent {
		sw.reportDanglingLink(rel)
	}
}

// ignoreDisabledBundle skips a PKCS#12 source while bundle input is off, which
// preserves the behavior of every deployment that predates PFX input.
func (sw *scanWalk) ignoreDisabledBundle(rel string) bool {
	if !layout.IsBundle(rel) || sw.inputPasswordReady {
		return false
	}
	sw.ignored++
	slog.Debug("skipping bundle: PFX input is not enabled",
		"path", logtext.Path(rel),
		"remediation", "set INPUT_PFX_PASSWORD or point INPUT_PFX_PASSWORD_FILE at a secret")
	return true
}

// excludeSource resolves one enumerated source against INPUT_EXCLUDE_PATHS. An
// excluded source is counted and then dropped: nothing about it is read,
// decoded or written, and it registers NO expected artifact, so what it produced
// earlier becomes an ordinary orphan candidate under OUTPUT_LIFECYCLE, as for a
// format switched off (FormatsExplicit) or a layout changed (LayoutExplicit).
// Only sync deletes (resolveReap).
func (sw *scanWalk) excludeSource(rel string) bool {
	if sw.exclude.Empty() || !sw.exclude.Excludes(rel) {
		return false
	}
	sw.results = append(sw.results, statusExcluded)
	slog.Debug("skipping excluded source", "path", logtext.Path(rel),
		"remediation", "remove the path from INPUT_EXCLUDE_PATHS to convert it again")
	return true
}

// processSource applies source precedence, registers lifecycle expectations and
// converts one source. Mirror layout calls it during the walk; flat layout calls
// it only after collision arbitration. A shadowed bundle returns statusUnset.
func (sw *scanWalk) processSource(ctx context.Context, rel string) (conversionStatus, error) {
	if layout.IsBundle(rel) && sw.bundleShadowed(rel) {
		return statusUnset, nil
	}
	sw.seen[rel] = struct{}{}
	artifacts := sw.registerExpected(rel)
	convertSource := sw.convertEntry
	if layout.IsBundle(rel) {
		convertSource = sw.convertBundle
	}
	outcome := convertSource(ctx, rel)
	sw.reach.noteSource(rel, outcome, artifacts)
	sw.results = append(sw.results, outcome)
	// A cancellation during conversion already became a per-source outcome, but
	// the walk itself must still stop so the scan is never reported complete.
	return outcome, ctx.Err()
}

// flatClaim is one flat output stem and the sources that claim it.
type flatClaim struct {
	stem    string
	sources []string
}

// groupFlatClaims groups sources by flat output stem, in the order of each
// stem's first source once sorted. Sorting a clone keeps the order stable on
// every filesystem and leaves the walk's retained order untouched.
func groupFlatClaims(sources []string) []flatClaim {
	sorted := slices.Clone(sources)
	slices.Sort(sorted)
	at := make(map[string]int, len(sorted))
	var claims []flatClaim
	for _, rel := range sorted {
		stem := layout.FlatStem(layout.SourceStem(rel))
		i, claimed := at[stem]
		if !claimed {
			i = len(claims)
			at[stem] = i
			claims = append(claims, flatClaim{stem: stem})
		}
		claims[i].sources = append(claims[i].sources, rel)
	}
	return claims
}

// stemLedger is one flat output stem's claimants: those this scan saw claim it,
// and the stored ones the scan did not reach.
// A stem two or more claimants hold converts none of them: arbitrating by name,
// age or expiry would silently publish one operator input as another's artifact.
type stemLedger struct {
	stem      string
	seen      []string
	unreached []string
}

// stands reports whether the stem's collision holds.
func (l *stemLedger) stands() bool { return len(l.seen)+len(l.unreached) > 1 }

// members returns every claimant, sorted, in a new slice.
func (l *stemLedger) members() []string {
	members := slices.Concat(l.seen, l.unreached)
	slices.Sort(members)
	return members
}

// claimLedger returns this scan's ledger of every flat stem named in claims or
// held by the stored ledger, and stores it for the next scan. A stored claimant
// leaves when the scan reached it and did not see it claim the stem, or at once
// when INPUT_EXCLUDE_PATHS covers it: being out of reach never removes one. An
// owner that left its stem's ledger is no longer its owner.
func (sw *scanWalk) claimLedger(claims []flatClaim) []stemLedger {
	unclaimed := maps.Clone(sw.claims)
	ledgers := make([]stemLedger, 0, len(claims)+len(unclaimed))
	for _, claim := range claims {
		ledgers = append(ledgers, stemLedger{stem: claim.stem, seen: claim.sources, unreached: sw.outOfReach(sw.claims[claim.stem].Members, claim.sources)})
		delete(unclaimed, claim.stem)
	}
	for _, stem := range slices.Sorted(maps.Keys(unclaimed)) {
		ledgers = append(ledgers, stemLedger{stem: stem, unreached: sw.outOfReach(unclaimed[stem].Members, nil)})
	}
	updated := make(map[string]stemClaim, len(ledgers))
	for i := range ledgers {
		members := ledgers[i].members()
		if len(members) == 0 {
			continue
		}
		owner := sw.claims[ledgers[i].stem].Owner
		if !slices.Contains(members, owner) {
			owner = ""
		}
		updated[ledgers[i].stem] = stemClaim{Owner: owner, Members: members}
	}
	clear(sw.claims)
	maps.Copy(sw.claims, updated)
	return ledgers
}

// own records rel as the owner of stem: its conversion wrote or verified the
// stem's artifacts.
func (sw *scanWalk) own(stem, rel string) {
	claim := sw.claims[stem]
	claim.Owner = rel
	sw.claims[stem] = claim
}

// outOfReach returns the claimants among held that this scan neither saw in
// seen nor reached, and that INPUT_EXCLUDE_PATHS does not cover.
func (sw *scanWalk) outOfReach(held, seen []string) []string {
	var unreached []string
	for _, rel := range held {
		if !slices.Contains(seen, rel) && !sw.reach.input(rel) && (sw.exclude.Empty() || !sw.exclude.Excludes(rel)) {
			unreached = append(unreached, rel)
		}
	}
	return unreached
}

// collisionMsg is the ERROR record for a flat output-name collision.
const collisionMsg = "output name collision: several inputs produce the same output path, so none of them is converted"

// allExcludedMsg is the report for a scan whose every source is covered by
// INPUT_EXCLUDE_PATHS.
const allExcludedMsg = "every certificate source under the input root is excluded; no output artifacts are being produced"

// collisionRemediation names both ways out of a flat collision.
const collisionRemediation = "rename one input directory so the colliding sources differ in their last directory-plus-name, " +
	"or set OUTPUT_LAYOUT=mirror to keep every source's full path under /output"

// processFlatSources resolves the deferred flat batch: certificates that are
// not pairs resolve as orphans exactly as mirror resolves them, shadowed bundle
// spellings drop, every remaining output name is arbitrated, and sources whose
// name is unambiguous convert. Colliding sources fail loudly: none converts,
// the container goes unhealthy, and the record carries the shared stem, the
// claimant count and a bounded sample of the claimants so the operator can
// resolve the ambiguity.
func (sw *scanWalk) processFlatSources(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	candidates, err := sw.flatCandidates(ctx)
	if err != nil {
		return err
	}
	ledgers := sw.claimLedger(groupFlatClaims(candidates))
	if err := sw.recordCollisions(ctx, ledgers); err != nil {
		return err
	}
	for i := range ledgers {
		ledger := &ledgers[i]
		// An unreached claimant may still be there, so its artifacts are not orphans.
		for _, rel := range ledger.unreached {
			sw.registerExpected(rel)
		}
		sw.unreachedClaims += len(ledger.unreached)
		if ledger.stands() || len(ledger.seen) != 1 {
			continue
		}
		if err := sw.convertSole(ctx, ledger.stem, ledger.seen[0]); err != nil {
			return err
		}
	}
	return nil
}

// convertSole converts rel, the only claimant of stem, and makes it the stem's
// owner once its artifacts are written or found current. A source of the wrong
// kind is held instead: it cannot be read.
func (sw *scanWalk) convertSole(ctx context.Context, stem, rel string) error {
	if _, held := sw.unproven[rel]; held {
		sw.holdUnproven(rel)
		return nil
	}
	outcome, err := sw.processSource(ctx, rel)
	if outcome == statusConverted || outcome == statusUnchanged {
		sw.own(stem, rel)
	}
	return err
}

// flatCandidates returns the deferred sources that claim a flat output stem:
// shadowed bundle spellings drop, and orphan certificates resolve as mirror
// resolves them.
func (sw *scanWalk) flatCandidates(ctx context.Context) ([]string, error) {
	candidates := make([]string, 0, len(sw.pendingSources))
	for _, rel := range sw.pendingSources {
		if _, held := sw.unproven[rel]; held {
			candidates = append(candidates, rel)
			continue
		}
		if layout.IsBundle(rel) && sw.bundleShadowed(rel) {
			continue
		}
		orphan, err := sw.resolveFlatOrphanCert(ctx, rel)
		if err != nil {
			return nil, err
		}
		if !orphan {
			candidates = append(candidates, rel)
		}
	}
	return candidates, nil
}

// recordCollisions reports each standing ledger, records its seen claimants'
// outcomes and artifact claims, counts its unreached claimants in contested, and
// clears the collision of every stem whose ledger holds fewer than two.
func (sw *scanWalk) recordCollisions(ctx context.Context, ledgers []stemLedger) error {
	for i := range ledgers {
		if err := ctx.Err(); err != nil {
			return err
		}
		ledger := &ledgers[i]
		key := standingKey{kind: condCollision, subject: ledger.stem}
		if !ledger.stands() {
			sw.standing.clear(key)
			continue
		}
		members := ledger.members()
		if !sw.standing.report(key, len(members)) {
			slog.Debug(collisionMsg, "output_stem", logtext.Path(ledger.stem), "count", len(members))
		} else {
			slog.Error(collisionMsg,
				attrCondition, condCollision, "output_stem", logtext.Path(ledger.stem),
				"count", len(members),
				"sources", logtext.CapJoin(members, maxLoggedOrphanBytes),
				"remediation", collisionRemediation)
		}
		for _, rel := range ledger.seen {
			// A collided source still CLAIMS its artifacts: the inputs exist, so
			// the orphan reaper must keep whatever is at the contested path while
			// the operator resolves the ambiguity.
			sw.seen[rel] = struct{}{}
			sw.registerExpected(rel)
			sw.results = append(sw.results, statusCollided)
		}
		sw.contested += len(ledger.unreached)
	}
	return nil
}

// keepObserved reports whether the scan saw the source rel or did not reach it.
func (sw *scanWalk) keepObserved(rel string) bool {
	_, seen := sw.seen[rel]
	return seen || !sw.reach.input(rel)
}

// gone reports whether the scan proved every one of sources absent: it reached
// each one's directory and did not see it.
func (sw *scanWalk) gone(sources []string) bool {
	for _, rel := range sources {
		if _, seen := sw.seen[rel]; seen || !sw.reach.input(rel) {
			return false
		}
	}
	return len(sources) > 0
}

// readWholeTree reports whether the scan, ended by walkErr, read every /input
// path: none the counts in result name, and none behind a link whose input name
// kept it out of them that hides something stored.
func (sw *scanWalk) readWholeTree(result *ScanResult, walkErr error) bool {
	if walkErr != nil || !result.inputFullyEnumerated() || sw.unreachedClaims > 0 {
		return false
	}
	return !slices.ContainsFunc(sw.reach.links, sw.hides)
}

// hides reports whether something this process stores lies strictly under the
// /input path link: a flat claimant, the subject of a per-path /input condition
// or a source of an unwritable artifact, or, in the mirror layout, an /output
// directory at the link's own path. A link at a source position covers only its
// own stem, whose own record reports it, so it hides nothing.
func (sw *scanWalk) hides(link string) bool {
	under := func(rel string) bool { return strings.HasPrefix(rel, link+"/") }
	for _, claim := range sw.claims {
		if slices.ContainsFunc(claim.Members, under) {
			return true
		}
	}
	if sw.standing.anyHolds(func(key standingKey, sources []string) bool {
		switch key.kind {
		case condConversionFailed, condUnreadablePath:
			return under(key.subject)
		case condUnwritable:
			return slices.ContainsFunc(sources, under)
		default:
			return false
		}
	}) {
		return true
	}
	return sw.layoutMode != outputpolicy.LayoutFlat && sw.out.holdsDir(link)
}

// unresolvedLinkMsg reports a symlink the scan cannot resolve.
const unresolvedLinkMsg = "skipping symlink that could not be resolved through the input root; anything it points to, including certificates under a linked directory, is not scanned"

// reportUnresolvedLink logs the standing unresolved_symlink condition for rel.
func (sw *scanWalk) reportUnresolvedLink(rel string) {
	level, attrs := sw.standing.reportPath(condUnresolvedSymlink, rel)
	if err := sw.facts[rel].err; err != nil {
		attrs = append(attrs, "error", logtext.Path(err.Error()))
	}
	slog.Log(context.Background(), level, unresolvedLinkMsg,
		append(attrs, "remediation", "mount that certificate path into /input directly instead of linking to it, or fix the permissions on the link target")...)
}

// finish runs what follows a walk that enumerated the tree, or the prefix a
// budget stop left, and returns the scan's error: a shutdown or root error
// converts nothing. Flat conversion runs on everything enumerated, matching
// mirror's availability: an unreadable sub-path skips its sources, never the
// tree's. claimLedger owns how a collision is arbitrated.
func (sw *scanWalk) finish(ctx context.Context, walkErr error) error {
	if walkErr != nil && !errors.Is(walkErr, errScanBudgetExceeded) {
		return walkErr
	}
	if sw.layoutMode == outputpolicy.LayoutFlat {
		if err := sw.processFlatSources(ctx); err != nil {
			walkErr = err
		}
	}
	sw.reportHidingLinks()
	return walkErr
}

// reportHidingLinks reports each unresolvable link named like an input that
// hides something stored, once the ledger is known. A link whose own read
// already reported it this scan gets no second line.
func (sw *scanWalk) reportHidingLinks() {
	for _, rel := range sw.reach.links {
		if layout.IsRelevant(rel) && sw.hides(rel) &&
			!sw.standing.reported(standingKey{kind: condUnreadablePath, subject: rel}) {
			sw.reportUnresolvedLink(rel)
		}
	}
}

// unreachedFailures counts the standing conversion failures this scan did not
// reach: nothing has shown them fixed, so they keep counting.
func (sw *scanWalk) unreachedFailures() int {
	return sw.standing.countUnseen(condConversionFailed, func(subject string) bool { return !sw.reach.input(subject) })
}

// resolveFlatOrphanCert filters one arbitration candidate: a certificate whose
// sibling key is Absent is not a pair, so it cannot claim an output stem;
// letting it into arbitration would have a stray orphan certificate suppress a
// valid same-stem source. It resolves through processSource instead, counting
// statusOrphan exactly as the mirror walk does. A key the scan cannot judge
// Absent keeps the certificate in arbitration: converting against an
// unanswerable precedence question is worse than refusing loudly.
func (sw *scanWalk) resolveFlatOrphanCert(ctx context.Context, rel string) (bool, error) {
	if !layout.IsCert(rel) || judgeFacts(sw.leaf(layout.KeyFor(rel)), roleFile) != verdictAbsent {
		return false, nil
	}
	_, err := sw.processSource(ctx, rel)
	return true, err
}

// noteUnwalkableSymlink judges a symlink the walk enumerated, which it never
// descends, as a directory on the way to what may lie under it. One the scan
// cannot resolve keeps what is under it unreached; unless its name makes it an
// input it is also warned about and counted, and an input-named one is
// reported once the ledger is known (reportHidingLinks). An alias of an in-root
// directory is traced at Debug: the walk reaches its target directly.
func (sw *scanWalk) noteUnwalkableSymlink(rel string, d fs.DirEntry) {
	if d.Type()&fs.ModeSymlink == 0 {
		return
	}
	switch judgeFacts(sw.entry(rel, d), roleDir) {
	case verdictUnproven:
		sw.reach.enterLink(rel)
		if layout.IsRelevant(rel) {
			return
		}
		sw.unresolved++
		sw.reportUnresolvedLink(rel)
	case verdictAlias:
		slog.Debug("skipping symlinked directory; its target is walked directly", "path", logtext.Path(rel))
	default:
	}
}

// bundleShadowed reports whether a bundle source yields to a sibling that
// outranks it (layout.ShadowingSiblings).
func (sw *scanWalk) bundleShadowed(rel string) bool {
	for _, sibling := range layout.ShadowingSiblings(rel) {
		if sw.siblingOutranks(sibling) {
			return noteShadowedBundle(rel, sibling)
		}
	}
	return false
}

// siblingOutranks answers whether one shadowing sibling outranks the bundle. An
// EXCLUDED sibling never does: precedence is decided among the sources this app
// will actually convert, or excluding one half of a stem would silently strand
// the other. A PEM certificate outranks a bundle only when its key is not
// Absent: an orphaned certificate is not a pair and must not strand a usable
// bundle. A sibling the scan cannot judge Absent outranks, because converting
// two sources of one stem would have them overwrite one artifact set.
func (sw *scanWalk) siblingOutranks(sibling string) bool {
	switch {
	case !sw.exclude.Empty() && sw.exclude.Excludes(sibling):
		return false
	case judgeFacts(sw.leaf(sibling), roleFile) == verdictAbsent:
		return false
	case !layout.IsCert(sibling):
		return true
	}
	return judgeFacts(sw.leaf(layout.KeyFor(sibling)), roleFile) != verdictAbsent
}

func noteShadowedBundle(rel, sibling string) bool {
	slog.Debug("skipping bundle: a sibling source with the same stem takes precedence",
		"path", logtext.Path(rel), "sibling", logtext.Path(sibling))
	return true
}

// registerExpected records every artifact path the enabled formats derive from
// rel, at enumeration time, whatever its conversion later resolves to, and
// returns them.
func (sw *scanWalk) registerExpected(rel string) []string {
	outStem := layout.SourceStem(rel)
	if sw.layoutMode == outputpolicy.LayoutFlat {
		outStem = layout.FlatStem(outStem)
	}
	artifacts := layout.ArtifactsFor(outStem, sw.formats)
	for _, artifact := range artifacts {
		sw.expected[artifact] = struct{}{}
	}
	return artifacts
}

// --- Logging policy ---

// logInputCoverageWarnings names the health-neutral outcomes that produce no
// output artifacts, for the whole input tree or for some PEM pairs, and that
// summary counts alone cannot distinguish from a healthy steady state. Each is a
// standing condition, logged when it appears, changes or clears. wholeTree is
// whether the scan read every /input path, the proof a whole-tree claim needs.
func logInputCoverageWarnings(st *standing, result *ScanResult, walkErr error, wholeTree bool) {
	budgetStopped := errors.Is(walkErr, errScanBudgetExceeded)
	if walkErr != nil && !budgetStopped {
		return
	}
	// A claim about the WHOLE TREE ("no pair at all", "every certificate") needs a
	// complete enumeration; a claim about the paths this scan read does not. Only a
	// complete scan can prove a condition gone.
	complete := walkErr == nil && wholeTree
	if st.track(standingKey{kind: condUnreadablePaths}, result.Unreadable, walkErr == nil) {
		slog.Warn("some /input paths were unreadable and were skipped; health is unaffected unless a skipped path had a standing conversion failure",
			attrCondition, condUnreadablePaths, "unreadable", result.Unreadable,
			// inputPermRemediation, not a permission-only hint of its own: the count
			// aggregates every unreadable shape this package classifies, and only some
			// of them are permission problems.
			"remediation", inputPermRemediation)
	}
	orphans := result.Orphan
	if complete {
		coverage := wholeTreeCoverageOf(result)
		logWholeTreeCoverage(st, result, coverage)
		if coverage != coveragePartialOrphan {
			orphans = 0
		}
	}
	if st.track(standingKey{kind: condOrphanCertificates}, orphans, complete) {
		slog.Warn("some PEM certificates under the input root are missing their sibling .key; those files do not form PEM sources",
			attrCondition, condOrphanCertificates, "orphan", result.Orphan, "total", result.Total,
			"remediation", "name each private key <name>.key beside its <name>.crt, provide a PFX/P12 bundle with the same stem, or remove the orphan certificate")
	}
}

// treeCoverage is what a complete enumeration found to convert.
type treeCoverage int

const (
	coverageConvertible treeCoverage = iota
	coverageAllExcluded
	coverageIgnoredOnly
	coverageNoSource
	coverageAllOrphan
	coveragePartialOrphan
)

// wholeTreeCoverageOf classifies a COMPLETE enumeration's counts. The caller owns
// the completeness proof: a partial walk cannot claim anything about the whole tree.
func wholeTreeCoverageOf(result *ScanResult) treeCoverage {
	switch {
	case result.Total > 0 && result.Excluded == result.Total:
		return coverageAllExcluded
	case result.Total == 0 && result.Ignored > 0:
		return coverageIgnoredOnly
	case result.Total == 0:
		return coverageNoSource
	case result.Orphan == result.Total:
		return coverageAllOrphan
	case result.Orphan > 0:
		return coveragePartialOrphan
	default:
		return coverageConvertible
	}
}

// logWholeTreeCoverage tracks the outcomes only a COMPLETE enumeration can
// claim: a tree whose every source is excluded, one holding no source, and one
// where every PEM certificate lacks its sibling key.
func logWholeTreeCoverage(st *standing, result *ScanResult, coverage treeCoverage) {
	if coverage == coverageIgnoredOnly {
		slog.Debug("PFX/P12 files were ignored because bundle input is not enabled",
			"ignored", result.Ignored,
			"remediation", "set INPUT_PFX_PASSWORD to enable PFX input")
	}
	if st.track(standingKey{kind: condAllExcluded}, countIf(coverage == coverageAllExcluded, result.Excluded), true) {
		slog.Warn(allExcludedMsg,
			attrCondition, condAllExcluded, "excluded", result.Excluded,
			"remediation", "narrow INPUT_EXCLUDE_PATHS, or point /input at the directory holding the certificates you want converted")
	}
	if st.track(standingKey{kind: condNoSources}, countIf(coverage == coverageNoSource, 1), true) {
		slog.Warn("no certificate sources found under the input root; no output artifacts are being produced",
			attrCondition, condNoSources,
			"remediation", "check that the /input mount points at a directory containing PEM pairs or PFX/P12 bundles")
	}
	if st.track(standingKey{kind: condAllOrphan}, countIf(coverage == coverageAllOrphan, result.Orphan), true) {
		slog.Warn("every PEM certificate under the input root is missing its sibling .key; no output artifacts are being produced",
			attrCondition, condAllOrphan, "orphan", result.Orphan,
			"remediation", "name each private key <name>.key beside its <name>.crt, provide a PFX/P12 bundle instead, or remove the orphan certificate")
	}
}

// countIf is n when the condition holds and 0 when it does not.
func countIf(holds bool, n int) int {
	if holds {
		return n
	}
	return 0
}

// IsShutdown reports whether err is the process shutting down (context
// cancellation or a deadline) rather than an operator-actionable failure.
func IsShutdown(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// failEntry records one per-entry failure: it logs the failure and returns the
// failed status for the caller to propagate.
func failEntry(logPath, msg string, err error, extra ...any) conversionStatus {
	attrs := failureAttrs(logPath, err, extra)
	if IsShutdown(err) {
		slog.Debug(msg+" (shutdown)", attrs...)
	} else {
		slog.Error(msg, attrs...)
	}
	return statusFailed
}

func failureAttrs(logPath string, err error, extra []any) []any {
	return append([]any{"path", logtext.Path(logPath), "error", logtext.Path(err.Error())}, extra...)
}

// conversionFailedMsg reports a source that could not be converted.
const conversionFailedMsg = "conversion failed"

// failSource records a source's conversion failure as a standing condition keyed
// by cause, a stable description of what failed: ERROR when the failure is new or
// its cause changed, Debug while it holds.
func (sw *scanWalk) failSource(rel, cause string, err error, extra ...any) conversionStatus {
	if IsShutdown(err) {
		return failEntry(rel, conversionFailedMsg, err, extra...)
	}
	news, decided := sw.failed[rel]
	if !decided {
		news = sw.standing.reportState(standingKey{kind: condConversionFailed, subject: rel}, 1, cause)
		if sw.failed == nil {
			sw.failed = make(map[string]bool)
		}
		sw.failed[rel] = news
	}
	level := slog.LevelDebug
	if news {
		level = slog.LevelError
	}
	slog.Log(context.Background(), level, conversionFailedMsg,
		append([]any{attrCondition, condConversionFailed}, failureAttrs(rel, err, extra)...)...)
	return statusFailed
}

// --- Per-entry conversion ---

// pairInputs carries the cert and key PEM bytes readPair read through the
// confined input root, so one return value covers both inputs of a pair.
type pairInputs struct {
	certPEM []byte
	keyPEM  []byte
}

// pairFingerprint identifies the exact cert/key input bytes.
func pairFingerprint(certPEM, keyPEM []byte) [sha256.Size]byte {
	certSum := sha256.Sum256(certPEM)
	keySum := sha256.Sum256(keyPEM)
	var pair [2 * sha256.Size]byte
	copy(pair[:sha256.Size], certSum[:])
	copy(pair[sha256.Size:], keySum[:])
	return sha256.Sum256(pair[:])
}

// observationLog de-duplicates the per-pair observation WARNs across scans: an
// odd-but-convertible input is named on the scan that introduced it and stays
// silent on every later fsnotify event and fallback tick.
type observationLog struct {
	seen map[string][sha256.Size]byte
	// whole holds the paths this process has read as a COMPLETE pair.
	whole map[string]struct{}
	// activeWhole holds the paths whose wholeness this SCAN established, and exists
	// only for the duration of one input walk (beginScan / endScan).
	activeWhole map[string]struct{}
	// maxPairs is the injected ceiling (Options.MaxScanEntries); non-positive means
	// scanbudget.Default. Resolved through maxObservedPairs.
	maxPairs int
	// evictedWholeness counts wholeness entries reserveWhole had to drop since the last
	// take.
	evictedWholeness int
}

// newObservationLog builds an empty log whose EACH of two sets — the signatures
// (seen) and the wholeness evidence (whole) — is bounded at maxPairs entries
// independently, so the log's process-lifetime ceiling is twice maxPairs.
func newObservationLog(maxPairs int) *observationLog {
	return &observationLog{
		seen:     make(map[string][sha256.Size]byte),
		whole:    make(map[string]struct{}),
		maxPairs: maxPairs,
	}
}

// beginScan opens the window in which wholeness established by this walk is protected
// from eviction.
func (o *observationLog) beginScan() {
	o.activeWhole = make(map[string]struct{})
}

// endScan closes that window: outside a walk no path is protected, so a later scan's
// eviction is free to take any victim it needs.
func (o *observationLog) endScan() {
	o.activeWhole = nil
}

// canEvict reports whether victim may be dropped: a pair this scan already read whole
// is never evicted — dropping it spends evidence the CURRENT scan established, and the
// veto that covers the eviction is reset before the scan that would need it.
func (o *observationLog) canEvict(victim string) bool {
	_, observedThisScan := o.activeWhole[victim]
	return !observedThisScan
}

// markWhole records the structural fact that this process read both inputs for rel.
func (o *observationLog) markWhole(rel string) {
	if o.activeWhole != nil {
		o.activeWhole[rel] = struct{}{}
	}
	o.reserveWhole(rel)
	o.whole[rel] = struct{}{}
}

// observationSignature identifies both the input bytes and the observations
// Analyse currently derives from them.
func observationSignature(input [sha256.Size]byte, observations []convert.Observation) [sha256.Size]byte {
	data := append([]byte{}, input[:]...)
	for _, observation := range observations {
		kind := sha256.Sum256([]byte(observation.Kind))
		detail := sha256.Sum256([]byte(observation.Detail))
		data = append(data, kind[:]...)
		data = append(data, detail[:]...)
	}
	return sha256.Sum256(data)
}

// note records the pair's signature and emits its observations when that
// signature differs from the last one observed for that path.
func (o *observationLog) note(rel string, fp [sha256.Size]byte, obs []convert.Observation) {
	current := observationSignature(fp, obs)
	previous, ok := o.seen[rel]
	// markWhole first: it protects rel in activeWhole and reserves the wholeness half it
	// populates.
	o.markWhole(rel)
	o.reserveSeen(rel)
	o.seen[rel] = current
	if !ok || previous != current {
		logConversionObservations(rel, obs)
	}
}

// record commits the signature without re-emitting: the conversion path has
// already logged the observations unconditionally.
func (o *observationLog) record(rel string, fp [sha256.Size]byte, obs []convert.Observation) {
	// One reservation per half, each made where its slot is taken, exactly as in note.
	o.markWhole(rel)
	o.reserveSeen(rel)
	o.seen[rel] = observationSignature(fp, obs)
}

// maxObservedPairs bounds this log's process-lifetime size.
func (o *observationLog) maxObservedPairs() int {
	return scanbudget.Effective(o.maxPairs)
}

// reserveWhole makes room in the WHOLENESS half for a path it does not already hold,
// evicting one remembered pair when that half is full.
func (o *observationLog) reserveWhole(rel string) {
	if _, known := o.whole[rel]; !known && len(o.whole) >= o.maxObservedPairs() {
		o.evictFrom(maps.Keys(o.whole))
	}
}

// reserveSeen makes room in the SIGNATURE half for a path it does not already hold.
func (o *observationLog) reserveSeen(rel string) {
	if _, known := o.seen[rel]; !known && len(o.seen) >= o.maxObservedPairs() {
		o.evictFrom(maps.Keys(o.seen))
	}
}

// evictFrom drops one remembered pair from BOTH halves, taking its victim from
// candidates — the half that is full — and never a pair this scan already read whole
// (canEvict).
func (o *observationLog) evictFrom(candidates iter.Seq[string]) {
	for victim := range candidates {
		if !o.canEvict(victim) {
			continue
		}
		delete(o.seen, victim)
		o.dropWholeness(victim)
		return
	}
}

// dropWholeness removes one path's wholeness evidence and counts the loss when there
// was any to lose.
func (o *observationLog) dropWholeness(rel string) {
	if _, held := o.whole[rel]; !held {
		return
	}
	delete(o.whole, rel)
	o.evictedWholeness++
}

// takeEvictedWholeness reports how many pairs have lost their wholeness evidence to
// the ceiling since the last call, and resets the counter.
func (o *observationLog) takeEvictedWholeness() int {
	n := o.evictedWholeness
	o.evictedWholeness = 0
	return n
}

// completedPair reports whether this process has already read rel's pair whole, which
// is what noteMissingKey reads as "this certificate HAD its sibling key".
func (o *observationLog) completedPair(rel string) bool {
	_, remembered := o.whole[rel]
	return remembered
}

// forgetPair spends the wholeness evidence for one pair, spending the single scan of
// grace completedPair grants: the scan that reports a vanished key forgets that the pair
// was ever read whole, so a key that is STILL missing on the next scan — one fsnotify
// event or one fallback tick later — has no memory behind it and is reported as the
// genuine orphan it is.
func (o *observationLog) forgetPair(rel string) {
	delete(o.whole, rel)
}

// forget drops entries for paths keep rejects, the pairs a COMPLETE walk
// proved gone, so a pair that comes back is reported once again.
func (o *observationLog) forget(keep func(rel string) bool) {
	for rel := range o.seen {
		if !keep(rel) {
			delete(o.seen, rel)
		}
	}
	for rel := range o.whole {
		if !keep(rel) {
			delete(o.whole, rel)
		}
	}
}

// inputPermRemediation is the one remediation hint every /input-side WARN in this
// package carries -- the per-path cert and key lines AND the once-per-scan unreadable
// aggregate -- and the mirror of store.go's outputPermRemediation: they all name the
// SAME operator action for the same root cause, so an operator who sees the cert-side
// line, the key-side line and the aggregate in one scan must not read three variants
// of it.
const inputPermRemediation = "check /input permissions and that the container runs as a UID that can read it, and that each certificate path is a regular file inside the mount, not a directory or a symlink out of it"

// readPair reads one pair through the input source, after judging its sibling
// key: an Absent key is an orphan or a vanish (noteMissingKey), and an Unproven
// one is unreadable, which also blocks orphan reaping.
func (sw *scanWalk) readPair(ctx context.Context, rel, keyRel string) (pairInputs, conversionStatus) {
	switch key := sw.leaf(keyRel); judgeFacts(key, roleFile) {
	case verdictAbsent:
		return pairInputs{}, sw.noteMissingKey(rel, keyRel)
	case verdictUnproven:
		level, attrs := sw.standing.reportPath(condUnreadablePath, keyRel)
		slog.Log(context.Background(), level, "skipping cert: cannot stat sibling key",
			append(attrs, "source", logtext.Path(rel),
				"error", logtext.Path(key.err.Error()), "remediation", inputPermRemediation)...)
		return pairInputs{}, statusUnreadable
	}

	certPEM, err := sw.src.readBounded(ctx, rel)
	if err != nil {
		return pairInputs{}, sw.noteUnreadableInput(rel, rel, "certificate", err)
	}
	keyPEM, err := sw.src.readBounded(ctx, keyRel)
	if err != nil {
		return pairInputs{}, sw.noteUnreadableInput(rel, keyRel, "private key", err)
	}
	return pairInputs{certPEM: certPEM, keyPEM: keyPEM}, statusUnset
}

// noteMissingKey classifies a sibling .key that is not there at the stat and returns the
// outcome, with its diagnosis already logged.
func (sw *scanWalk) noteMissingKey(rel, keyRel string) conversionStatus {
	if sw.observations.completedPair(rel) && sw.src.pathVanished(keyRel) {
		sw.observations.forgetPair(rel)
		// Byte-identical to the read side's vanish line for the same condition on the
		// same pair, so an operator correlating one renewal does not meet two
		// vocabularies for it.
		slog.Debug("skipping cert: private key vanished during the scan", "path", logtext.Path(rel))
		return statusVanished
	}
	// A genuine orphan: the certificate has no sibling key at all.
	slog.Debug("skipping cert without matching key", "path", logtext.Path(rel))
	return statusOrphan
}

// noteUnreadableInput logs a failed read of an /input file and returns the outcome it
// diagnosed, so the classification and its diagnostic cannot drift apart.
func (sw *scanWalk) noteUnreadableInput(logRel, inputRel, what string, err error) conversionStatus {
	if IsShutdown(err) {
		// A cancelled read is the shutdown itself, not an unreadable path: the Warn
		// below would tell a reader a mount that is fine needs fixing.
		slog.Debug("skipping cert: "+what+" read interrupted by shutdown", "path", logtext.Path(logRel), "error", logtext.Path(err.Error()))
		return statusUnreadable
	}
	if errors.Is(err, fs.ErrNotExist) && sw.src.pathVanished(inputRel) {
		slog.Debug("skipping cert: "+what+" vanished during the scan", "path", logtext.Path(logRel), "error", logtext.Path(err.Error()))
		return statusVanished
	}
	level, attrs := sw.standing.reportPath(condUnreadablePath, inputRel)
	if logRel != inputRel {
		attrs = append(attrs, "source", logtext.Path(logRel))
	}
	slog.Log(context.Background(), level, "skipping cert: cannot read "+what,
		append(attrs, "error", logtext.Path(err.Error()), "remediation", inputPermRemediation)...)
	return statusUnreadable
}

// convertEntry resolves the outcome for one .crt entry under certsRoot.
func (sw *scanWalk) convertEntry(ctx context.Context, rel string) conversionStatus {
	// Both sibling names come from layout, so this package and internal/watch
	// derive the pairing rule from one place.
	keyRel := layout.KeyFor(rel)

	inputs, outcome := sw.readPair(ctx, rel, keyRel)
	if outcome != statusUnset {
		return outcome
	}
	certPEM, keyPEM := inputs.certPEM, inputs.keyPEM
	sw.observations.markWhole(rel)
	fingerprint := pairFingerprint(certPEM, keyPEM)

	// Resolve the pair before consulting the output: currency asks "is the file
	// on disk the bundle these inputs produce?", which needs that bundle known first.
	analysis, err := convert.Analyse(ctx, certPEM, keyPEM)
	if err != nil {
		return sw.failSource(rel, err.Error(), err)
	}
	return sw.emit(ctx, rel, &emission{
		analysis:     analysis,
		observations: analysis.Observations(),
		fingerprint:  fingerprint,
		// The pair's own bytes ARE the PEM artifacts: passthrough, verbatim.
		certPEM: certPEM,
		keyPEM:  keyPEM,
	})
}

var errInputPasswordNotConfigured = errors.New("PFX input reached conversion without an input password; set INPUT_PFX_PASSWORD or point INPUT_PFX_PASSWORD_FILE at a secret")

// convertBundle resolves the outcome for one PKCS#12 source under certsRoot.
func (sw *scanWalk) convertBundle(ctx context.Context, rel string) conversionStatus {
	if !sw.inputPasswordReady {
		return sw.failSource(rel, errInputPasswordNotConfigured.Error(), errInputPasswordNotConfigured)
	}
	data, err := sw.src.readBundleBounded(ctx, rel)
	if err != nil {
		return sw.noteUnreadableInput(rel, rel, "bundle", err)
	}
	fingerprint := pairFingerprint(data, nil)
	analysis, err := convert.AnalyseBundleWithBudget(ctx, data, sw.inputPassword, sw.bundleBudget)
	if err != nil {
		return sw.failSource(rel, err.Error(), err)
	}
	return sw.emit(ctx, rel, &emission{
		analysis:     analysis,
		observations: analysis.Observations(),
		fingerprint:  fingerprint,
		// PEM artifacts are rendered from the analysis on demand (pemBytes).
		pemFromAnalysis: true,
	})
}

// emission carries one analysed source into artifact planning: the analysis, its
// findings, the input fingerprint the observation log keys on, and the PEM
// artifact bytes (a pair's own bytes verbatim, or rendered from the analysis for
// a bundle).
type emission struct {
	observations    []convert.Observation
	certPEM         []byte
	keyPEM          []byte
	analysis        convert.Analysis
	fingerprint     [sha256.Size]byte
	pemFromAnalysis bool
}

// pemBytes returns the PEM artifacts' bytes, rendering them from the analysis
// once for a bundle source.
func (em *emission) pemBytes() (certPEM, keyPEM []byte, err error) {
	if em.certPEM == nil && em.pemFromAnalysis {
		em.certPEM, em.keyPEM, err = em.analysis.EncodePEM()
		if err != nil {
			return nil, nil, err
		}
	}
	return em.certPEM, em.keyPEM, nil
}

// emit writes every enabled artifact for one analysed source and resolves the
// entry's single outcome, folding the per-artifact results and applying the
// once-per-entry observation bookkeeping.
func (sw *scanWalk) emit(ctx context.Context, rel string, em *emission) conversionStatus {
	outStem := layout.SourceStem(rel)
	if sw.layoutMode == outputpolicy.LayoutFlat {
		outStem = layout.FlatStem(outStem)
	}
	statuses := make([]conversionStatus, 0, 3)
	if sw.formats.PFX {
		statuses = append(statuses, sw.emitPFX(ctx, rel, layout.PFXOutFor(outStem), em))
	}
	if sw.formats.PEM {
		certPEM, keyPEM, err := em.pemBytes()
		if err != nil {
			statuses = append(statuses, sw.failSource(rel, err.Error(), err))
		} else {
			statuses = append(statuses,
				sw.emitRaw(ctx, rel, layout.CertOutFor(outStem), certPEM),
				sw.emitRaw(ctx, rel, layout.KeyOutFor(outStem), keyPEM))
		}
	}
	outcome := foldStatuses(statuses)
	if outcome == statusFailed && !slices.Contains(statuses, statusFailed) {
		sw.failSource(rel, errPartialPublication.Error(), errPartialPublication)
	}
	switch outcome {
	case statusFailed:
		if sw.failed[rel] {
			logConversionObservations(rel, em.observations)
		}
	case statusUnwritable:
		// An artifact on disk this app never proved wrong, behind a refusal no
		// restart clears: re-analysed every scan for as long as the operator
		// leaves /output as it is.
		sw.observations.note(rel, em.fingerprint, em.observations)
	case statusConverted:
		logConversionObservations(rel, em.observations)
		sw.observations.record(rel, em.fingerprint, em.observations)
	default:
		// observationLog.note owns the once-per-change rule for a semantically
		// equivalent input edit that leaves every artifact on disk unchanged.
		sw.observations.note(rel, em.fingerprint, em.observations)
		slog.Debug("skipping unchanged source", "path", logtext.Path(rel))
	}
	return outcome
}

var errPartialPublication = errors.New("one output artifact was updated while another could not be replaced; the output set may contain mismatched certificate material")

// foldStatuses resolves one source outcome from its artifacts. Any ordinary
// failure fails the source. A successful write combined with an unwritable
// sibling is also a failure because the output set changed only partly. With no
// write, an unwritable artifact remains health-neutral; one write makes the
// source converted; all-current is unchanged.
func foldStatuses(statuses []conversionStatus) conversionStatus {
	var converted, unwritable bool
	for _, st := range statuses {
		switch st {
		case statusFailed:
			return statusFailed
		case statusUnwritable:
			unwritable = true
		case statusConverted:
			converted = true
		default:
		}
	}
	if converted && unwritable {
		return statusFailed
	}
	if converted {
		return statusConverted
	}
	if unwritable {
		return statusUnwritable
	}
	return statusUnchanged
}

// emitPFX resolves one source's PKCS#12 artifact: current, rewritten, refused, or
// failed, with each arm's diagnostic emitted here.
func (sw *scanWalk) emitPFX(ctx context.Context, rel, pfxRel string, em *emission) conversionStatus {
	state, err := sw.out.inspect(ctx, pfxRel, em.analysis, sw.enc, sw.password)
	if err != nil {
		// A cancellation, and nothing else: inspect resolves every other
		// question about the bytes on disk into contentUnverified or
		// contentVerifiedStale itself.
		return failEntry(rel, "failed to inspect existing pfx", err)
	}
	if state.upToDate() {
		return statusUnchanged
	}
	slog.Debug("converting source", "path", logtext.Path(rel), "output_path", logtext.Path(pfxRel))
	pfxData, err := em.analysis.Encode(sw.enc, sw.password)
	if err != nil {
		return sw.failSource(rel, err.Error(), err)
	}
	writeErr := sw.out.write(ctx, pfxRel, pfxData)
	// The one derivation, after the write, from what the bundle on disk was
	// and how the write itself ended.
	outcome := writeOutcome(state, writeErr)
	if writeErr != nil {
		sw.reportWriteFailure(rel, pfxRel, writeErr, outcome)
	}
	if outcome == statusConverted {
		slog.Info("wrote pfx", "path", logtext.Path(pfxRel))
	}
	return outcome
}

// emitRaw resolves one byte-exact artifact (the PEM format's two): currency is a
// byte comparison, everything else mirrors emitPFX.
func (sw *scanWalk) emitRaw(ctx context.Context, rel, outRel string, data []byte) conversionStatus {
	state, err := sw.out.inspectRaw(ctx, outRel, data)
	if err != nil {
		return failEntry(rel, "failed to inspect existing output", err)
	}
	if state.upToDate() {
		return statusUnchanged
	}
	writeErr := sw.out.writePEM(ctx, outRel, data)
	outcome := writeOutcome(state, writeErr)
	if writeErr != nil {
		sw.reportWriteFailure(rel, outRel, writeErr, outcome)
	}
	if outcome == statusConverted {
		slog.Info("wrote pem", "path", logtext.Path(outRel))
	}
	return outcome
}

// writeOutcome derives one entry's conversionStatus, and it is the ONLY place that
// derivation happens.
func writeOutcome(state contentState, writeErr writeRefusal) conversionStatus {
	switch {
	case writeErr == nil:
		return statusConverted
	case state.artifactNotProvenWrong() && !writeErr.cause().restartCanClear():
		return statusUnwritable
	default:
		return statusFailed
	}
}

// unreplaceableArtifactMsg reports a health-neutral write refusal: a prior
// artifact this app could not VERIFY at all, whose replacing write a
// steady-state /output condition refused. It is a standing condition per output
// path.
const unreplaceableArtifactMsg = "prior output could not be replaced and the /output condition that refused the write is not one a restart clears; whatever is at the output path is left as found, health is unaffected"

// reportWriteFailure logs a failed artifact write in the register the derived
// outcome calls for.
func (sw *scanWalk) reportWriteFailure(logRel, outputRel string, err writeRefusal, outcome conversionStatus) {
	if outcome == statusUnwritable {
		if !sw.standing.reportFor(standingKey{kind: condUnwritable, subject: outputRel}, 1, []string{logRel}) {
			slog.Debug(unreplaceableArtifactMsg, "output_path", logtext.Path(outputRel))
			return
		}
		// "unverified" is the only content fact that reaches this record:
		// writeOutcome grants statusUnwritable solely via artifactNotProvenWrong,
		// whose allowlist is exactly contentUnverified.
		slog.Warn(unreplaceableArtifactMsg,
			attrCondition, condUnwritable, "path", logtext.Path(logRel), "output_path", logtext.Path(outputRel), "error", logtext.Path(err.Error()),
			"content", "unverified", "remediation", err.cause().remediation())
		return
	}
	// failSource is called for its log; the statusFailed it returns is the value
	// writeOutcome already derived, so this keeps one derivation. The cause names
	// the artifact and the refusal class, not the error text, which can carry a
	// temp file's random name.
	sw.failSource(logRel, fmt.Sprintf("write %s: %d", outputRel, err.cause()), err,
		"output_path", logtext.Path(outputRel), "remediation", err.cause().remediation())
}

// logConversionObservations surfaces Analyse's non-fatal findings about a pair's
// input.
func logConversionObservations(rel string, observations []convert.Observation) {
	for _, o := range observations {
		attrs := []any{"path", logtext.Path(rel), "kind", string(o.Kind), "detail", o.Detail}
		switch o.Kind.Class() {
		case convert.ObservationClassQuiet:
			slog.Debug("cert input observation", attrs...)
		case convert.ObservationClassInfo:
			slog.Info("cert input observation", attrs...)
		default:
			// ObservationClassWarning, and any class this app does not know:
			// reported loudly rather than dropped.
			slog.Warn("cert input observation", attrs...)
		}
	}
}

// countResults derives summary counts from typed results.
func countResults(results []conversionStatus, walkUnreadable, walkUnresolved, walkVanished int) ScanResult {
	var counts [statusCount]int
	for _, r := range results {
		counts[r]++ // every outcome, including a future one, lands somewhere
	}
	return ScanResult{
		Total:      len(results),
		Converted:  counts[statusConverted],
		Unchanged:  counts[statusUnchanged],
		Orphan:     counts[statusOrphan],
		Failed:     counts[statusFailed],
		Unreadable: walkUnreadable + counts[statusUnreadable],
		Unresolved: walkUnresolved,
		Vanished:   walkVanished + counts[statusVanished],
		Unwritable: counts[statusUnwritable],
		Collided:   counts[statusCollided],
		Excluded:   counts[statusExcluded],
	}
}

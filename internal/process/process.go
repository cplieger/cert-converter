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
	"time"

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/mounts"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/scanbudget"
)

// ScanResult carries per-source outcome summary counts from a scan run.
type ScanResult struct {
	// Removed counts artifacts deleted because their source is gone.
	Removed    int
	Total      int
	Converted  int
	Unchanged  int
	Orphan     int
	Failed     int
	Unreadable int
	// Unresolved counts input symlinks the confined root could not resolve.
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
	// claims; none of them was converted, and the container goes unhealthy until
	// the operator resolves the ambiguity.
	Collided int
	// Ignored counts PFX/P12 files skipped because PFX input was not explicitly
	// enabled. They preserve pre-feature behavior and do not make the input
	// enumeration safe for orphan deletion.
	Ignored int
	// Excluded counts sources INPUT_EXCLUDE_PATHS declared are not this app's to
	// convert. They are enumerated and still protect their artifacts from the
	// orphan reaper; only the conversion is skipped, so health is unaffected.
	Excluded int
}

// summaryAttrs is the ONE list of the scan-summary attributes, in the order
// logScanOutcome emits them; the README's alerting section keys Loki rules on these
// names, so both the names and the order are the operator-visible contract.
var summaryAttrs = []struct {
	of   func(*ScanResult) int
	name string
}{
	{name: "total", of: func(r *ScanResult) int { return r.Total }},
	{name: "converted", of: func(r *ScanResult) int { return r.Converted }},
	{name: "unchanged", of: func(r *ScanResult) int { return r.Unchanged }},
	{name: "orphan", of: func(r *ScanResult) int { return r.Orphan }},
	{name: "unreadable", of: func(r *ScanResult) int { return r.Unreadable }},
	{name: "unresolved", of: func(r *ScanResult) int { return r.Unresolved }},
	{name: "vanished", of: func(r *ScanResult) int { return r.Vanished }},
	{name: "unwritable", of: func(r *ScanResult) int { return r.Unwritable }},
	{name: "collided", of: func(r *ScanResult) int { return r.Collided }},
	{name: "excluded", of: func(r *ScanResult) int { return r.Excluded }},
	{name: "ignored", of: func(r *ScanResult) int { return r.Ignored }},
	{name: "removed", of: func(r *ScanResult) int { return r.Removed }},
	{name: "failed", of: func(r *ScanResult) int { return r.Failed }},
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

// scanBudgetSummaryMsg is the end-of-scan summary line for a walk the entry budget
// stopped.
const scanBudgetSummaryMsg = "scan stopped at the /input entry budget"

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
	observations *observationLog
	// lastSweep is when this process last swept /output for stale temps. It lives here
	// rather than on store because store is rebuilt per Run.
	lastSweep time.Time
	opts      Options
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
	inHandle, outHandle, err := openScanRoots(s.opts.CertsRoot, s.opts.OutRoot)
	if err != nil {
		return ScanResult{}, failScan(ctx, err)
	}
	defer func() { _ = inHandle.Close() }()
	defer func() { _ = outHandle.Close() }()

	cleanupFormats := s.opts.Formats
	if s.opts.FormatsExplicit {
		cleanupFormats = outputpolicy.Formats{PFX: true, PEM: true}
	}
	out := &store{root: outHandle, maxEntries: s.opts.MaxScanEntries, formats: cleanupFormats}
	if now := sweepClock(); s.lastSweep.IsZero() || now.Sub(s.lastSweep) >= staleTempAge {
		// A temp is only a candidate once it is staleTempAge old, so sweeping more
		// often than that re-walks the whole output tree to find nothing new.
		s.lastSweep = now
		out.sweepStaleTemps(ctx)
	}

	sw := &scanWalk{
		src:                &source{root: inHandle},
		out:                out,
		observations:       s.observations,
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
	walkErr := atomicfile.WalkDirInRoot(ctx, inHandle, func(rel string, d fs.DirEntry, err error) error {
		return sw.visit(ctx, rel, d, err)
	})
	// Flat conversion runs on everything the walk enumerated, matching mirror's
	// availability: an unreadable sub-path skips ITS sources, never the tree's.
	// Collisions are arbitrated among the enumerated sources only — a source
	// hidden behind an unreadable path is caught by the first complete scan, and
	// conversion is idempotent, so partial visibility cannot flap artifacts.
	// A budget stop converts the enumerated prefix, exactly as mirror converts
	// inline until the stop; a shutdown or root error converts nothing.
	if s.opts.Layout == outputpolicy.LayoutFlat && (walkErr == nil || errors.Is(walkErr, errScanBudgetExceeded)) {
		if flatErr := sw.processFlatSources(ctx); flatErr != nil {
			walkErr = flatErr
		}
	}
	// A tree over the entry budget is REPORTED, not failed.
	budgetExceeded := errors.Is(walkErr, errScanBudgetExceeded)

	result := countResults(sw.results, sw.unreadable, sw.unresolved, sw.vanished)
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
	// proved the enumeration complete: an aborted walk, an unreadable sub-path or
	// an unresolved symlink means `seen` is not the whole input tree, so a pair
	// hidden behind it would be forgotten and re-warn on the next clean scan.
	if rc.walkEnumerationComplete() {
		s.observations.forget(sw.seen)
	}
	rp := &reaper{
		src: sw.src, out: out, mode: s.opts.Lifecycle, formats: s.opts.Formats,
		layoutMode: s.opts.Layout, layoutExplicit: s.opts.LayoutExplicit,
		maxEntries: s.opts.MaxScanEntries,
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

	logScanOutcome(ctx, &result, walkErr)
	if budgetExceeded {
		return result, nil
	}
	return result, walkErr
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
	// pendingSources defers flat-layout conversion until every source name is
	// known, so output-name collisions are arbitrated before any artifact is
	// published.
	pendingSources []string
	observations   *observationLog
	bundleBudget   *convert.BundleWorkBudget
	enc            convert.EncoderType
	layoutMode     outputpolicy.Layout
	exclude        layout.ExcludeSet
	password       string
	inputPassword  string
	results        []conversionStatus
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
	formats    outputpolicy.Formats
	// inputPasswordReady is false unless a non-blank password or the explicit
	// empty-password opt-in was configured.
	inputPasswordReady bool
}

// visit is the walk's per-entry callback (atomicfile.WalkDirInRoot).
func (sw *scanWalk) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
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
		slog.Warn(scanBudgetMsg,
			"path", logtext.Path(rel), "entries", sw.budget.Count(), "limit", sw.budget.Max(),
			"remediation", scanbudget.InputRemediation)
		return fmt.Errorf("%w: stopped at %d entries (%s)", errScanBudgetExceeded, sw.budget.Count(), rel)
	}
	if d.IsDir() {
		sw.noteSourceShapedDir(rel)
		return nil
	}
	if !layout.IsSource(rel) {
		sw.noteUnwalkableSymlink(rel, d)
		return nil
	}
	// Ahead of every other classification: an excluded source is enumerated and
	// still claims its artifacts, so orphan reconciliation keeps protecting
	// them, but nothing about it is read, decoded or written.
	if sw.excludeSource(rel) {
		return nil
	}
	if sw.ignoreDisabledBundle(rel) {
		return nil
	}
	if sw.layoutMode == outputpolicy.LayoutFlat {
		sw.pendingSources = append(sw.pendingSources, rel)
		return nil
	}
	if err := sw.processSource(ctx, rel); err != nil {
		return err
	}
	return nil
}

// noteSourceShapedDir classifies a directory occupying a source path: an input
// the scan cannot read. Counting it as unreadable keeps it health-neutral while
// blocking orphan reaping, so sync never deletes the still-live artifacts of an
// input path that still exists in an unusable shape.
func (sw *scanWalk) noteSourceShapedDir(rel string) {
	if !layout.IsSource(rel) {
		return
	}
	slog.Debug("skipping source: input path is a directory",
		"path", logtext.Path(rel),
		"remediation", "replace the directory with a regular file")
	sw.unreadable++
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
// excluded source is recorded as seen and registers the artifacts it WOULD
// produce, so those artifacts never become orphan candidates: the operator said
// "not mine to convert", not "delete what is already there", and a mistyped
// exclusion must not become a deletion.
//
// The registration is not the only thing standing between an excluded artifact
// and an unlink — the post-delay re-check spares it too, because the source is
// still on disk — but it is what keeps the artifact out of the candidate set at
// all, so a scan with exclusions does not spend the 30s confirmation deferral
// and announce candidates it will always refuse. Do not delete it as redundant.
func (sw *scanWalk) excludeSource(rel string) bool {
	if sw.exclude.Empty() || !sw.exclude.Excludes(rel) {
		return false
	}
	sw.seen[rel] = struct{}{}
	sw.registerExpected(rel)
	sw.results = append(sw.results, statusExcluded)
	slog.Debug("skipping excluded source", "path", logtext.Path(rel),
		"remediation", "remove the path from INPUT_EXCLUDE_PATHS to convert it again")
	return true
}

// processSource applies source precedence, registers lifecycle expectations and
// converts one source. Mirror layout calls it during the walk; flat layout calls
// it only after collision arbitration.
func (sw *scanWalk) processSource(ctx context.Context, rel string) error {
	if layout.IsBundle(rel) && sw.bundleShadowed(rel) {
		return nil
	}
	sw.seen[rel] = struct{}{}
	sw.registerExpected(rel)
	convertSource := sw.convertEntry
	if layout.IsBundle(rel) {
		convertSource = sw.convertBundle
	}
	sw.results = append(sw.results, convertSource(ctx, rel))
	// A cancellation during conversion already became a per-source outcome, but
	// the walk itself must still stop so the scan is never reported complete.
	return ctx.Err()
}

// flatCollision names one group of sources whose flat output name is the same:
// the shared output stem and every source that claims it.
type flatCollision struct {
	stem    string
	sources []string
}

// selectFlatSources partitions sources by flat output stem: a stem exactly one
// source claims converts, a stem several sources claim converts NOTHING.
// Arbitrating between colliding sources — by name, by age, by expiry — would
// silently publish one operator input as another's artifact, so ambiguity is an
// error the operator resolves, not a tie this app breaks. Sorting a clone keeps
// the report order stable on every filesystem and leaves the walk's retained
// order untouched.
func selectFlatSources(sources []string) (unique []string, collisions []flatCollision) {
	sorted := slices.Clone(sources)
	slices.Sort(sorted)
	claims := make(map[string][]string, len(sorted))
	stems := make([]string, 0, len(sorted))
	for _, rel := range sorted {
		stem := layout.FlatStem(layout.SourceStem(rel))
		if _, claimed := claims[stem]; !claimed {
			stems = append(stems, stem)
		}
		claims[stem] = append(claims[stem], rel)
	}
	for _, stem := range stems {
		group := claims[stem]
		if len(group) == 1 {
			unique = append(unique, group[0])
			continue
		}
		collisions = append(collisions, flatCollision{stem: stem, sources: group})
	}
	return unique, collisions
}

// collisionMsg is the ERROR record for a flat output-name collision; the
// published CertConverterOutputNameCollision alert matches on a substring of it.
const collisionMsg = "output name collision: several inputs produce the same output path, so none of them is converted"

// allExcludedMsg is the report for a scan whose every source is covered by
// INPUT_EXCLUDE_PATHS; the published CertConverterEverySourceExcluded alert
// matches on a substring of it.
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
	candidates := make([]string, 0, len(sw.pendingSources))
	for _, rel := range sw.pendingSources {
		if layout.IsBundle(rel) && sw.bundleShadowed(rel) {
			continue
		}
		orphan, err := sw.resolveFlatOrphanCert(ctx, rel)
		if err != nil {
			return err
		}
		if orphan {
			continue
		}
		candidates = append(candidates, rel)
	}
	unique, collisions := selectFlatSources(candidates)
	if err := sw.recordCollisions(ctx, collisions); err != nil {
		return err
	}
	for _, rel := range unique {
		if err := sw.processSource(ctx, rel); err != nil {
			return err
		}
	}
	return nil
}

// recordCollisions reports each collision group and records its members'
// outcomes and artifact claims.
func (sw *scanWalk) recordCollisions(ctx context.Context, collisions []flatCollision) error {
	for _, collision := range collisions {
		if err := ctx.Err(); err != nil {
			return err
		}
		slog.Error(collisionMsg,
			"output_stem", logtext.Path(collision.stem),
			"count", len(collision.sources),
			"sources", logtext.CapJoin(collision.sources, maxLoggedOrphanBytes),
			"remediation", collisionRemediation)
		for _, rel := range collision.sources {
			// A collided source still CLAIMS its artifacts: the inputs exist, so
			// the orphan reaper must keep whatever is at the contested path while
			// the operator resolves the ambiguity.
			sw.seen[rel] = struct{}{}
			sw.registerExpected(rel)
			sw.results = append(sw.results, statusCollided)
		}
	}
	return nil
}

// resolveFlatOrphanCert filters one arbitration candidate: a certificate whose
// sibling key is provably absent is not a pair, so it cannot claim an output
// stem — letting it into arbitration would have a stray orphan certificate
// suppress a valid same-stem source. It resolves through processSource instead,
// counting statusOrphan exactly as the mirror walk does. A sibling stat that
// answers nothing keeps the certificate in arbitration: converting against an
// unanswerable precedence question is worse than refusing loudly.
func (sw *scanWalk) resolveFlatOrphanCert(ctx context.Context, rel string) (bool, error) {
	if !layout.IsCert(rel) {
		return false, nil
	}
	keyAbsent, keyErr := sw.src.pathAbsent(layout.KeyFor(rel))
	if keyErr != nil || !keyAbsent {
		return false, nil
	}
	return true, sw.processSource(ctx, rel)
}

// noteUnwalkableSymlink reports a symlink under the input root that the walk
// cannot follow.
func (sw *scanWalk) noteUnwalkableSymlink(rel string, d fs.DirEntry) {
	if d.Type()&fs.ModeSymlink == 0 || layout.IsRelevant(rel) {
		return
	}
	fi, err := sw.src.stat(rel)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		sw.unresolved++
		slog.Warn("skipping symlink that could not be resolved through the input root; anything it points to, including certificates under a linked directory, is not scanned",
			"path", logtext.Path(rel), "error", logtext.Path(err.Error()),
			"remediation", "mount that certificate path into /input directly instead of linking to it, or fix the permissions on the link target")
	case err == nil && fi.IsDir():
		slog.Debug("skipping symlinked directory; its target is walked directly", "path", logtext.Path(rel))
	}
}

// bundleShadowed reports whether a bundle source yields to a sibling that
// outranks it (layout.ShadowingSiblings). Precedence must be decidable, so an
// unanswerable sibling stat yields — converting two sources of one stem would
// have them overwrite one artifact set in a single scan.
func (sw *scanWalk) bundleShadowed(rel string) bool {
	for _, sibling := range layout.ShadowingSiblings(rel) {
		outranks, decidable := sw.siblingOutranks(sibling)
		if !decidable || outranks {
			return noteShadowedBundle(rel, sibling)
		}
	}
	return false
}

// siblingOutranks answers whether one shadowing sibling actually outranks the
// bundle, and whether that question could be answered at all. An EXCLUDED
// sibling never outranks anything — precedence is decided among the sources this
// app will actually convert, or excluding one half of a stem would silently
// strand the other. A PEM certificate outranks a bundle only when its sibling
// key exists too: an orphaned certificate is not a pair and must not strand a
// usable bundle source.
func (sw *scanWalk) siblingOutranks(sibling string) (outranks, decidable bool) {
	if !sw.exclude.Empty() && sw.exclude.Excludes(sibling) {
		return false, true
	}
	absent, err := sw.src.pathAbsent(sibling)
	switch {
	case err != nil:
		return false, false
	case absent:
		return false, true
	case !layout.IsCert(sibling):
		return true, true
	}
	keyAbsent, keyErr := sw.src.pathAbsent(layout.KeyFor(sibling))
	if keyErr != nil {
		return false, false
	}
	return !keyAbsent, true
}

func noteShadowedBundle(rel, sibling string) bool {
	slog.Debug("skipping bundle: a sibling source with the same stem takes precedence",
		"path", logtext.Path(rel), "sibling", logtext.Path(sibling))
	return true
}

// registerExpected records every artifact path the enabled formats derive from
// rel, at enumeration time, whatever its conversion later resolves to.
func (sw *scanWalk) registerExpected(rel string) {
	outStem := layout.SourceStem(rel)
	if sw.layoutMode == outputpolicy.LayoutFlat {
		outStem = layout.FlatStem(outStem)
	}
	for _, artifact := range layout.ArtifactsFor(outStem, sw.formats) {
		sw.expected[artifact] = struct{}{}
	}
}

// --- Logging policy ---

// failScan reports a scan that ended before the walk began: a certs or output
// root that could not be opened as an *os.Root.
func failScan(ctx context.Context, err error) error {
	logScanOutcome(ctx, &ScanResult{}, err)
	return err
}

// logScanOutcome emits the end-of-scan summary.
func logScanOutcome(ctx context.Context, result *ScanResult, walkErr error) {
	level, msg := slog.LevelInfo, "scan complete"
	if walkErr != nil {
		level, msg = slog.LevelWarn, "scan aborted before completion"
		switch {
		case IsShutdown(walkErr):
			level, msg = slog.LevelDebug, "scan cancelled during shutdown"
		case errors.Is(walkErr, errScanBudgetExceeded):
			level, msg = slog.LevelWarn, scanBudgetSummaryMsg
		}
	}
	attrs := make([]any, 0, 2+2*len(summaryAttrs))
	if walkErr != nil {
		// The walk error names a path in two shapes — an *fs.PathError from the
		// filesystem, and the entry-budget stop's own wrap — so the summary's error
		// attribute passes the same gate its count attributes' sibling `path` does.
		attrs = append(attrs, "error", logtext.Path(walkErr.Error()))
	}
	for _, a := range summaryAttrs {
		attrs = append(attrs, a.name, a.of(result))
	}
	slog.Log(ctx, level, msg, attrs...)
	logInputCoverageWarnings(result, walkErr)
}

// logInputCoverageWarnings names the health-neutral outcomes that produce no
// output artifacts — for the whole input tree, or for one PEM pair — and that
// summary counts alone cannot distinguish from a healthy steady state: an input
// tree the scan could not fully read, one holding no source at all, one where
// every PEM certificate lacks its sibling .key, and one where only some do.
func logInputCoverageWarnings(result *ScanResult, walkErr error) {
	// A typed stop reason, not a string match: errScanBudgetExceeded already exists as
	// its own sentinel precisely so the budget stop can be told from an unreadable root
	// or a cancellation, and Run wraps it with the entry count rather than replacing it.
	budgetStopped := errors.Is(walkErr, errScanBudgetExceeded)
	if walkErr != nil && !budgetStopped {
		return
	}
	if result.Unreadable > 0 {
		// Message byte-identical to the one the composition root emitted: README's
		// Alerting section tells an operator at LOG_LEVEL=warn to alert on this exact
		// line, so its wording is a contract regardless of which package renders it.
		slog.Warn("some /input paths were unreadable and were skipped; health is unaffected",
			"unreadable", result.Unreadable,
			// inputPermRemediation, not a permission-only hint of its own: the count
			// aggregates every unreadable shape this package classifies, and only some
			// of them are permission problems.
			"remediation", inputPermRemediation)
	}
	// Each arm is gated by the evidence IT needs, which is the rule here rather than an
	// exception: a claim about the WHOLE TREE ("no pair at all", "every certificate")
	// needs a complete enumeration, while a claim about the PATHS THIS SCAN READ needs
	// only those paths.
	if walkErr == nil && result.inputFullyEnumerated() {
		logWholeTreeCoverageWarning(result)
		return
	}
	if result.Orphan > 0 {
		// The ONE arm that needs no whole-tree proof.
		slog.Warn("some PEM certificates under the input root are missing their sibling .key; those files do not form PEM sources",
			"orphan", result.Orphan, "total", result.Total,
			"remediation", "name each private key <name>.key beside its <name>.crt, provide a PFX/P12 bundle with the same stem, or remove the orphan certificate")
	}
}

// logWholeTreeCoverageWarning names the health-neutral outcomes that only a
// COMPLETE enumeration can claim: a tree whose every source is excluded, one
// holding nothing convertible, and one where every or some PEM certificate
// lacks its sibling key.
func logWholeTreeCoverageWarning(result *ScanResult) {
	switch {
	case result.Total > 0 && result.Excluded == result.Total:
		// Every source found is excluded, so the scan produced nothing while
		// reporting no failure: indistinguishable from a healthy steady state in
		// the counts, and the signature of an over-broad INPUT_EXCLUDE_PATHS.
		slog.Warn(allExcludedMsg,
			"excluded", result.Excluded,
			"remediation", "narrow INPUT_EXCLUDE_PATHS, or point /input at the directory holding the certificates you want converted")
	case result.Total == 0 && result.Ignored > 0:
		slog.Debug("PFX/P12 files were ignored because bundle input is not enabled",
			"ignored", result.Ignored,
			"remediation", "set INPUT_PFX_PASSWORD to enable PFX input")
	case result.Total == 0:
		// A completed scan that visited no source at all is indistinguishable
		// from a healthy steady state in the summary counts (failed=0 keeps the
		// marker set, and the README's Loki rules match on failed/unreadable or
		// on the absence of "scan complete"), yet it is the signature of a wrong
		// or vanished /input mount: no artifact is produced and nothing fires.
		// Name it.
		slog.Warn("no certificate sources found under the input root; no output artifacts are being produced",
			"remediation", "check that the /input mount points at a directory containing PEM pairs or PFX/P12 bundles")
	case result.Orphan == result.Total:
		// Every .crt under /input lacks its sibling .key, so the scan
		// completed with failed=0 and produced nothing at all.
		slog.Warn("every PEM certificate under the input root is missing its sibling .key; no output artifacts are being produced",
			"orphan", result.Orphan,
			"remediation", "name each private key <name>.key beside its <name>.crt, provide a PFX/P12 bundle instead, or remove the orphan certificate")
	case result.Orphan > 0:
		slog.Warn("some PEM certificates under the input root are missing their sibling .key; those files do not form PEM sources",
			"orphan", result.Orphan, "total", result.Total,
			"remediation", "name each private key <name>.key beside its <name>.crt, provide a PFX/P12 bundle with the same stem, or remove the orphan certificate")
	}
}

// IsShutdown reports whether err is the process shutting down (context
// cancellation or a deadline) rather than an operator-actionable failure.
func IsShutdown(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// failEntry records one per-entry failure: it logs the failure and returns the
// failed status for the caller to propagate.
func failEntry(logPath, msg string, err error, extra ...any) conversionStatus {
	attrs := append([]any{"path", logtext.Path(logPath), "error", logtext.Path(err.Error())}, extra...)
	if IsShutdown(err) {
		slog.Debug(msg+" (shutdown)", attrs...)
	} else {
		slog.Error(msg, attrs...)
	}
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

// forget drops entries for paths a COMPLETE walk did not see, so a pair that
// comes back is reported once again.
func (o *observationLog) forget(seen map[string]struct{}) {
	for rel := range o.seen {
		if _, ok := seen[rel]; !ok {
			delete(o.seen, rel)
		}
	}
	for rel := range o.whole {
		if _, ok := seen[rel]; !ok {
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

// readPair resolves and reads the input side of one .crt entry: it classifies
// the sibling .key (a key that is not there is a health-neutral statusOrphan, or the
// transient statusVanished when this process had already read the pair whole — see
// noteMissingKey; a non-ENOENT stat failure is statusUnreadable instead, because the
// key is there and cannot be read — health-neutral too, but it also blocks orphan
// reaping, which an orphan does not) and then performs both bounded reads through the
// input source, so every /input byte is read once from within the confined root.
func (sw *scanWalk) readPair(ctx context.Context, rel, keyRel string) (pairInputs, conversionStatus) {
	if _, statErr := sw.src.stat(keyRel); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return pairInputs{}, sw.noteMissingKey(rel, keyRel)
		}
		// A non-ENOENT stat failure (a sibling key that is a symlink the *os.Root
		// refuses because it escapes /input, or a permission/IO error) is NOT a
		// genuine "no key" orphan — the key is there and cannot be read.
		slog.Warn("skipping cert: cannot stat sibling key", "path", logtext.Path(rel), "error", logtext.Path(statErr.Error()),
			"remediation", inputPermRemediation)
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
		// A cancelled read is the shutdown itself, not an unreadable path — the
		// Warn below is what the README recommends alerting on, so emitting it
		// for a normal SIGTERM would page an operator for a mount that is fine.
		slog.Debug("skipping cert: "+what+" read interrupted by shutdown", "path", logtext.Path(logRel), "error", logtext.Path(err.Error()))
		return statusUnreadable
	}
	if errors.Is(err, fs.ErrNotExist) && sw.src.pathVanished(inputRel) {
		slog.Debug("skipping cert: "+what+" vanished during the scan", "path", logtext.Path(logRel), "error", logtext.Path(err.Error()))
		return statusVanished
	}
	slog.Warn("skipping cert: cannot read "+what,
		"path", logtext.Path(logRel), "error", logtext.Path(err.Error()),
		"remediation", inputPermRemediation)
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
		return failEntry(rel, "conversion failed", err)
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
		return failEntry(rel, "conversion failed", errInputPasswordNotConfigured)
	}
	data, err := sw.src.readBundleBounded(ctx, rel)
	if err != nil {
		return sw.noteUnreadableInput(rel, rel, "bundle", err)
	}
	fingerprint := pairFingerprint(data, nil)
	analysis, err := convert.AnalyseBundleWithBudget(ctx, data, sw.inputPassword, sw.bundleBudget)
	if err != nil {
		return failEntry(rel, "conversion failed", err)
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
			statuses = append(statuses, failEntry(rel, "conversion failed", err))
		} else {
			statuses = append(statuses,
				sw.emitRaw(ctx, rel, layout.CertOutFor(outStem), certPEM),
				sw.emitRaw(ctx, rel, layout.KeyOutFor(outStem), keyPEM))
		}
	}
	outcome := foldStatuses(statuses)
	if outcome == statusFailed && !slices.Contains(statuses, statusFailed) {
		failEntry(rel, "conversion failed", errPartialPublication)
	}
	switch outcome {
	case statusFailed:
		logConversionObservations(rel, em.observations)
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
		return failEntry(rel, "conversion failed", err)
	}
	writeErr := sw.out.write(ctx, pfxRel, pfxData)
	// The one derivation, after the write, from what the bundle on disk was
	// and how the write itself ended.
	outcome := writeOutcome(state, writeErr)
	if writeErr != nil {
		reportWriteFailure(rel, pfxRel, writeErr, outcome)
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
		reportWriteFailure(rel, outRel, writeErr, outcome)
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

// unreplaceableArtifactMsg is the standing WARN for a health-neutral write
// refusal: a prior artifact this app could not VERIFY at all, whose replacing
// write a steady-state /output condition refused.
const unreplaceableArtifactMsg = "prior output could not be replaced and the /output condition that refused the write is not one a restart clears; whatever is at the output path is left as found, health is unaffected"

// reportWriteFailure logs a failed artifact write in the register the derived
// outcome calls for.
func reportWriteFailure(logRel, outputRel string, err writeRefusal, outcome conversionStatus) {
	if outcome == statusUnwritable {
		// "unverified" is the only content fact that reaches this record:
		// writeOutcome grants statusUnwritable solely via artifactNotProvenWrong,
		// whose allowlist is exactly contentUnverified.
		slog.Warn(unreplaceableArtifactMsg,
			"path", logtext.Path(logRel), "output_path", logtext.Path(outputRel), "error", logtext.Path(err.Error()),
			"content", "unverified", "remediation", err.cause().remediation())
		return
	}
	// failEntry is called for its log; the statusFailed it returns is the value
	// writeOutcome already derived, so this keeps one derivation.
	failEntry(logRel, "conversion failed", err, "output_path", logtext.Path(outputRel),
		"remediation", err.cause().remediation())
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

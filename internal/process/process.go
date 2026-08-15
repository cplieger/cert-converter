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

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/scanbudget"
)

// ScanResult carries per-pair outcome summary counts from a scan run.
type ScanResult struct {
	// Removed counts outputs deleted because their input pair is gone.
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
	// Unwritable counts prior bundles this app could not replace, where it never proved the
	// bundle on disk wrong and no restart can clear what refused the write
	// (statusUnwritable, whose doc comment states the promise in full).
	Unwritable int
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
	{name: "removed", of: func(r *ScanResult) int { return r.Removed }},
	{name: "failed", of: func(r *ScanResult) int { return r.Failed }},
}

// conversionsClean reports whether nothing this scan did leaves the output tree in a
// state this app is still trying to repair.
func (r *ScanResult) conversionsClean() bool {
	return r.Failed == 0 && r.Unwritable == 0
}

// durablyEnumerated reports whether every DURABLE veto on the input enumeration is
// clear: nothing under /input was unreadable and no symlink was unresolvable.
func (r *ScanResult) durablyEnumerated() bool {
	return r.Unreadable == 0 && r.Unresolved == 0
}

// inputFullyEnumerated reports whether nothing prevented this scan from observing
// every /input path: no unreadable path, no unresolved symlink, nothing that vanished
// mid-walk.
func (r *ScanResult) inputFullyEnumerated() bool {
	return r.durablyEnumerated() && r.Vanished == 0
}

// unreplaceableOnly reports whether the only conversionsClean member this scan is
// still failing is a REPLACEMENT THE VOLUME REFUSED rather than a failed conversion.
func (r *ScanResult) unreplaceableOnly() bool {
	return r.Failed == 0 && r.Unwritable > 0
}

// The per-scan entry budget bounds how many /input entries ONE scan enumerates.

// errScanBudgetExceeded marks the abort above.
var errScanBudgetExceeded = errors.New("input tree exceeds the per-scan entry budget")

// scanBudgetMsg is the operator-facing half of that abort.
const scanBudgetMsg = scanbudget.InputTreeTooLarge + "; stopping this scan without converting or removing anything further, health is unaffected"

// scanBudgetSummaryMsg is the end-of-scan summary line for a walk the entry budget
// stopped.
const scanBudgetSummaryMsg = "scan stopped at the /input entry budget"

// budgetTruncatedCoverage marks a coverage count that came from a scan the entry budget
// stopped early: the number is what this scan REACHED, not what the tree holds.
const budgetTruncatedCoverage = "partial: the scan stopped at the /input entry budget, so this counts only the paths it reached"

// Options carries the process-lifetime scan configuration the composition root
// chooses once at startup: the confined input and output roots, the password
// embedded in generated PFX files, and the PKCS#12 encoder profile.
type Options struct {
	Encoder   convert.EncoderType
	Lifecycle outputpolicy.Lifecycle
	CertsRoot string
	OutRoot   string
	Password  string
	// MaxScanEntries is how many entries one scan may enumerate in EACH mounted tree
	// before it refuses that tree (scanbudget.Default when non-positive): the /input
	// walk (scanWalk.budget) and the /output orphan walk (outputWalk.budget)
	// each get the same ceiling, applied per tree rather than shared, because both are
	// mounts this app does not own and either one can be made large by whoever can write
	// to it.
	MaxScanEntries int
}

// Scanner walks a certificate directory, decides which cert/key pairs are out of
// date by reading the bundle already on disk, and dispatches their conversion to
// PFX format.
type Scanner struct {
	observations *observationLog
	opts         Options
}

// New constructs a Scanner with the given process-lifetime scan configuration.
func New(opts *Options) *Scanner {
	return &Scanner{
		opts:         *opts,
		observations: newObservationLog(opts.MaxScanEntries),
	}
}

// Run walks the configured certs root, converts changed .crt/.key pairs to PFX
// in the configured output root, and returns a ScanResult with outcome counts
// plus any walk-level error.
func (s *Scanner) Run(ctx context.Context) (ScanResult, error) {
	certsRoot, outRoot := s.opts.CertsRoot, s.opts.OutRoot
	inHandle, err := os.OpenRoot(certsRoot)
	if err != nil {
		return ScanResult{}, failScan(ctx, fmt.Errorf("open input root %q: %w", certsRoot, err))
	}
	defer func() { _ = inHandle.Close() }()

	outHandle, err := os.OpenRoot(outRoot)
	if err != nil {
		return ScanResult{}, failScan(ctx, fmt.Errorf("open output root %q: %w", outRoot, err))
	}
	defer func() { _ = outHandle.Close() }()

	out := &store{root: outHandle, maxEntries: s.opts.MaxScanEntries}
	out.sweepStaleTemps(ctx)

	sw := &scanWalk{
		src:          &source{root: inHandle},
		out:          out,
		observations: s.observations,
		password:     s.opts.Password,
		enc:          s.opts.Encoder,
		seen:         make(map[string]struct{}),
		budget:       scanbudget.NewCounter(s.opts.MaxScanEntries),
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
	// A tree over the entry budget is REPORTED, not failed.
	budgetExceeded := errors.Is(walkErr, errScanBudgetExceeded)

	result := countResults(sw.results, sw.unreadable, sw.unresolved, sw.vanished)
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
	rp := &reaper{src: sw.src, out: out, mode: s.opts.Lifecycle, observations: s.observations}
	removed, reconcileErr := rp.reconcile(ctx, sw.seen, &rc)
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

// scanWalk carries the read-only conversion parameters and the mutable
// accounting for one Scanner.Run tree walk: the per-pair results, the count of
// unreadable sub-paths, and the set of cert paths seen (the input enumeration
// reaper.reconcile checks the output tree against).
type scanWalk struct {
	src          *source
	out          *store
	seen         map[string]struct{}
	observations *observationLog
	enc          convert.EncoderType
	password     string
	results      []conversionStatus
	unreadable   int
	// vanished counts paths the walk enumerated and then could not find: the
	// directory half of the renewal race whose file half readPair classifies as
	// statusVanished. countResults folds it into ScanResult.Vanished.
	vanished int
	// unresolved counts input symlinks the confined root could not resolve.
	unresolved int
	// budget is this walk's entry ceiling and its charge counter, injected from
	// Options.MaxScanEntries.
	budget scanbudget.Counter
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
		// An ENOENT below the root is the WALK's half of the renewal race the read
		// side already classifies as statusVanished.
		if errors.Is(err, fs.ErrNotExist) {
			slog.Debug("skipping path that vanished during the scan", "path", logtext.Path(rel), "error", logtext.Path(err.Error()))
			sw.vanished++
			return nil
		}
		// Debug, not Warn: this is the per-path half of a two-level contract shared
		// with the /output sweep.
		slog.Debug("skipping unreadable path", "path", logtext.Path(rel), "error", logtext.Path(err.Error()))
		sw.unreadable++
		return nil
	}
	// Charged once per ENUMERATED path, and before anything is read or remembered, so
	// the budget bounds the walk's own state rather than trailing it.
	if !sw.budget.Charge() {
		slog.Warn(scanBudgetMsg,
			"path", logtext.Path(rel), "entries", sw.budget.Count(), "limit", sw.budget.Max(),
			"remediation", scanbudget.InputRemediation)
		// The returned error stays RAW, the rule for every error this app hands back
		// (l-p1): the stopping path is sanitized where the record is EMITTED, by
		// logScanOutcome's `error` attribute, so the app has one gate home and a caller
		// inspecting this error still sees the path the walk actually stopped at.
		return fmt.Errorf("%w: stopped at %d entries (%s)", errScanBudgetExceeded, sw.budget.Count(), rel)
	}
	if d.IsDir() {
		// A directory occupying a <name>.crt path is a certificate the scan cannot
		// read, not an ordinary directory: counting it as unreadable keeps it
		// health-neutral (a restart cannot clear it) while blocking orphan reaping,
		// so sync reconciliation never deletes the still-live <name>.pfx of an input
		// path that still exists in an unusable shape.
		if layout.IsCert(rel) {
			slog.Debug("skipping cert: certificate path is a directory",
				"path", logtext.Path(rel),
				"remediation", "replace the directory with a regular <name>.crt file")
			sw.unreadable++
		}
		return nil
	}
	if !layout.IsCert(rel) {
		sw.noteUnwalkableSymlink(rel, d)
		return nil
	}
	sw.seen[rel] = struct{}{}
	sw.results = append(sw.results, sw.convertEntry(ctx, rel))
	// A cancellation that landed *during* the conversion above already turned that
	// entry into a shutdown artifact, but not always the same one: an interrupted
	// /input read is statusUnreadable (noteUnreadableInput routes a cancelled read
	// there, health-neutral, and reserves statusVanished for an ENOENT race), while an
	// interrupted prior-bundle read or atomic write is statusFailed.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
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
		// The error is the only evidence of the cause here (a target outside the
		// root, or an unreadable component inside it), so name the consequence and
		// let the error carry the cause.
		sw.unresolved++
		slog.Warn("skipping symlink that could not be resolved through the input root; anything it points to, including certificates under a linked directory, is not scanned",
			"path", logtext.Path(rel), "error", logtext.Path(err.Error()),
			"remediation", "mount that certificate path into /input directly instead of linking to it, or fix the permissions on the link target")
	case err == nil && fi.IsDir():
		// The target is inside the root, so the walk reaches those
		// certificates through the real directory; nothing is missed.
		slog.Debug("skipping symlinked directory; its target is walked directly", "path", logtext.Path(rel))
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

// logInputCoverageWarnings names the health-neutral outcomes that produce no PFX --
// for the whole input tree, or for one certificate in it -- and that the summary
// counts alone cannot distinguish from a healthy steady state: an input tree the scan
// could not fully read, one holding no certificate pair at all, one whose every
// certificate lacks its sibling .key, and one where only some of them do.
func logInputCoverageWarnings(result *ScanResult, walkErr error) {
	// A typed stop reason, not a string match: errScanBudgetExceeded already exists as
	// its own sentinel precisely so the budget stop can be told from an unreadable root
	// or a cancellation, and Run wraps it with the entry count rather than replacing it.
	budgetStopped := errors.Is(walkErr, errScanBudgetExceeded)
	if walkErr != nil && !budgetStopped {
		return
	}
	// Extra attribute for the truncated case only, appended to the per-path arms.
	var observed []any
	if budgetStopped {
		observed = []any{"coverage", budgetTruncatedCoverage}
	}
	if result.Unreadable > 0 {
		// Message byte-identical to the one the composition root emitted: README's
		// Alerting section tells an operator at LOG_LEVEL=warn to alert on this exact
		// line, so its wording is a contract regardless of which package renders it.
		slog.Warn("some /input paths were unreadable and were skipped; health is unaffected",
			append([]any{
				"unreadable", result.Unreadable,
				// inputPermRemediation, not a permission-only hint of its own: the count
				// aggregates every unreadable shape this package classifies, and only some
				// of them are permission problems.
				"remediation", inputPermRemediation,
			}, observed...)...)
	}
	// Each arm is gated by the evidence IT needs, which is the rule here rather than an
	// exception: a claim about the WHOLE TREE ("no pair at all", "every certificate")
	// needs a complete enumeration, while a claim about the PATHS THIS SCAN READ needs
	// only those paths.
	fullyEnumerated := walkErr == nil && result.inputFullyEnumerated()
	switch {
	case fullyEnumerated && result.Total == 0:
		// A completed scan that visited no .crt at all is indistinguishable from
		// a healthy steady state in the summary counts (failed=0 keeps the marker
		// set, and the README's Loki rules match on failed/unreadable or on the
		// absence of "scan complete"), yet it is the signature of a wrong or
		// vanished /input mount: no PFX is produced and nothing fires. Name it.
		slog.Warn("no certificate pairs found under the input root; no PFX output is being produced",
			"remediation", "check that the /input mount points at the PEM certificate directory")
	case fullyEnumerated && result.Orphan == result.Total:
		// Every .crt under /input lacks its sibling .key, so the scan
		// completed with failed=0 and produced nothing at all.
		slog.Warn("every certificate under the input root is missing its sibling .key; no PFX output is being produced",
			"orphan", result.Orphan,
			"remediation", "name each private key <name>.key beside its <name>.crt (Caddy's layout)")
	case result.Orphan > 0:
		// Some, not all — and the ONE arm here that needs no whole-tree proof.
		slog.Warn("some certificates under the input root are missing their sibling .key; those produce no PFX and any existing bundle for them goes stale",
			append([]any{
				"orphan", result.Orphan, "total", result.Total,
				"remediation", "name each private key <name>.key beside its <name>.crt (Caddy's layout), or remove the certificate from /input",
			}, observed...)...)
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
	// loneKeys holds the paths this log has already reported for a retained bundle:
	// the CERT path when a sibling key is still there while the certificate is gone,
	// and the KEY path when that key could not be inspected at all
	// (reaper.keyStillPresent keys the two reports on different paths so they retire
	// independently).
	loneKeys map[string]struct{}
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

// newObservationLog builds an empty log whose EACH of three sets — the signatures
// (seen), the wholeness evidence (whole) and the lone-key reports (loneKeys) — is
// bounded at maxPairs entries independently, so the log's process-lifetime ceiling is
// three times maxPairs rather than two.
func newObservationLog(maxPairs int) *observationLog {
	return &observationLog{
		seen:     make(map[string][sha256.Size]byte),
		whole:    make(map[string]struct{}),
		loneKeys: make(map[string]struct{}),
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
	// A pair that reads whole is not a lone key any more, so the next time it becomes
	// one it is reported again.
	o.clearLoneKey(rel)
	o.clearLoneKey(layout.KeyFor(rel))
}

// markLoneKey records that rel's bundle is being retained because a sibling key is
// still present while the certificate is gone, and reports whether that is NEW — i.e.
// whether the condition has to be logged on this scan.
func (o *observationLog) markLoneKey(rel string) bool {
	if _, reported := o.loneKeys[rel]; reported {
		return false
	}
	if len(o.loneKeys) >= o.maxObservedPairs() {
		return true
	}
	o.loneKeys[rel] = struct{}{}
	return true
}

// clearLoneKey retires the lone-key report for rel: the pair read whole again, or the
// leftover key is gone, so the retention this report described no longer holds.
func (o *observationLog) clearLoneKey(rel string) {
	delete(o.loneKeys, rel)
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

// noteUnreadableInput logs a failed read of an /input file and RETURNS the outcome it
// diagnosed, so the classification and its diagnostic cannot drift apart: Debug plus
// statusUnreadable when the read was cancelled by shutdown, Debug plus the transient
// statusVanished when the file simply vanished, and Warn plus statusUnreadable
// otherwise -- the last matching readPair's sibling-key stat.
func (sw *scanWalk) noteUnreadableInput(logRel, inputRel, what string, err error) conversionStatus {
	if IsShutdown(err) {
		// A cancelled read is the shutdown itself, not an unreadable path: the WARN
		// below is the message the README recommends alerting on, so emitting it for
		// a normal SIGTERM would page an operator for a mount that is fine.
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
	// derive the pairing rule from one place instead of two copies that can drift.
	keyRel := layout.KeyFor(rel)

	inputs, outcome := sw.readPair(ctx, rel, keyRel)
	if outcome != statusUnset {
		return outcome
	}
	certPEM, keyPEM := inputs.certPEM, inputs.keyPEM
	sw.observations.markWhole(rel)
	fingerprint := pairFingerprint(certPEM, keyPEM)

	pfxRel := layout.OutputFor(rel)

	// Resolve the pair BEFORE consulting the output: currency is now "is the file
	// on disk the bundle these inputs produce?", which cannot be asked until the
	// bundle those inputs produce is known.
	analysis, err := convert.Analyse(ctx, certPEM, keyPEM)
	if err != nil {
		return failEntry(rel, "conversion failed", err)
	}
	observations := analysis.Observations()
	state, err := sw.out.inspect(ctx, pfxRel, analysis, sw.enc, sw.password)
	if err != nil {
		// A cancellation, and nothing else: inspect resolves every question about the bytes
		// on disk into a content FACT itself — contentUnverified for the ones it could not
		// compare (a bundle it could not stat or pin, one above the readable bound, a read
		// failure that settles nothing, a refused preflight) and contentVerifiedStale for
		// the ones it could (nothing there, a non-regular occupant, a profile mismatch, a
		// bundle that will not decode with the configured password).
		return failEntry(rel, "failed to inspect existing pfx", err)
	}
	if state.upToDate() {
		// The observations describe the INPUT, so a semantically equivalent input
		// edit still has to be named once even though the bundle on disk stays
		// correct; observationLog.note owns that once-per-change rule.
		sw.observations.note(rel, fingerprint, observations)
		slog.Debug("skipping unchanged cert pair", "path", logtext.Path(rel))
		return statusUnchanged
	}

	slog.Debug("converting cert pair", "path", logtext.Path(rel))
	pfxData, err := analysis.Encode(sw.enc, sw.password)
	if err != nil {
		logConversionObservations(rel, observations)
		return failEntry(rel, "conversion failed", err)
	}
	writeErr := sw.out.write(ctx, pfxRel, pfxData)
	// The one derivation, after the write, from the two facts this entry resolved: what
	// the bundle on disk was, and how the write itself ended.
	outcome = writeOutcome(state, writeErr)
	if writeErr != nil {
		reportWriteFailure(rel, pfxRel, writeErr, outcome)
	}
	if outcome == statusUnwritable {
		// The bundle on disk is one this app never proved wrong and the refusal is steady
		// state (no restart clears it), so the observations describe an input that will be
		// re-analysed on every scan for as long as the operator leaves /output as it is.
		sw.observations.note(rel, fingerprint, observations)
		return outcome
	}
	logConversionObservations(rel, observations)
	if outcome == statusFailed {
		return outcome
	}
	sw.observations.record(rel, fingerprint, observations)

	slog.Info("wrote pfx", "path", logtext.Path(pfxRel))
	return outcome
}

// writeOutcome derives one entry's conversionStatus, and it is the ONLY place that
// derivation happens.
func writeOutcome(state contentState, writeErr writeRefusal) conversionStatus {
	switch {
	case writeErr == nil:
		return statusConverted
	case state.bundleNotProvenWrong() && !writeErr.cause().restartCanClear():
		return statusUnwritable
	default:
		return statusFailed
	}
}

// unreplaceableBundleMsg is the standing WARN for a health-neutral write refusal: a prior
// bundle this app could not VERIFY at all (above the readable bound, unreadable,
// un-stat-able, or refused by the codec's preflight) whose replacing write a steady-state
// /output condition refused.
const unreplaceableBundleMsg = "prior pfx could not be replaced and the /output condition that refused the write is not one a restart clears; leaving the existing bundle in place, health is unaffected"

// reportWriteFailure logs a failed PFX write in the register the DERIVED outcome calls
// for.
func reportWriteFailure(logRel, pfxRel string, err writeRefusal, outcome conversionStatus) {
	if outcome == statusUnwritable {
		// "unverified" is the only content fact that can reach this record:
		// writeOutcome grants statusUnwritable solely via bundleNotProvenWrong,
		// whose allowlist is exactly contentUnverified.
		slog.Warn(unreplaceableBundleMsg,
			"path", logtext.Path(logRel), "output_path", logtext.Path(pfxRel), "error", logtext.Path(err.Error()),
			"content", "unverified", "remediation", err.cause().remediation())
		return
	}
	// failEntry is called for its LOG: the statusFailed it returns is the same value
	// writeOutcome already derived, and taking it from there keeps one derivation.
	failEntry(logRel, "conversion failed", err, "output_path", logtext.Path(pfxRel),
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
			// ObservationClassWarning, and any class this app does not know: reported
			// loudly rather than dropped — the same safe direction convert takes for an
			// unclassified kind, and the reason Warning needs no case of its own.
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
	}
}

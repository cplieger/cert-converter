// Package process provides the certificate scanning and conversion orchestration.
package process

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/scanbudget"
)

// ScanResult carries per-pair outcome summary counts from a scan run.
type ScanResult struct {
	// Removed counts outputs deleted because their input pair is gone. It is
	// reported for visibility only and never affects health: a reap is the
	// operator's configured intent, not a failure.
	Removed    int
	Total      int
	Converted  int
	Unchanged  int
	Orphan     int
	Failed     int
	Unreadable int
	// Unresolved counts input symlinks the confined root could not resolve.
	// Deliberately a SEPARATE field, never folded into Unreadable: the
	// README's Loki rules match on the `unreadable=` log attribute, and
	// conflating the two would change that operator-visible signal. Kept on
	// ScanResult so both coverage dimensions have one accumulator.
	Unresolved int
	// Vanished counts /input files this scan saw evidence of and then could not find:
	// a cert or key that existed at readdir and was gone by the bounded read, and a
	// sibling .key that a previous scan of this process read whole and that is gone by
	// this scan's stat (noteMissingKey). Both are the ordinary renewal race, one
	// observed a moment later than the other. Deliberately a SEPARATE field, never
	// folded into Unreadable, for the same reason as Unresolved: the README's Loki
	// rules match on the `unreadable=` attribute and carry a permissions
	// remediation, which is the wrong diagnosis for a transient replacement that the
	// next scan converts. It is health-neutral, and like Unreadable it still blocks
	// orphan reaping.
	Vanished int
	// Unwritable counts prior bundles this app could not replace, where it never proved the
	// bundle on disk wrong and no restart can clear what refused the write
	// (statusUnwritable, whose doc comment states the promise in full). Health-neutral for
	// the same reason Unreadable is — no restart grants the UID a permission it does not
	// have, frees a full volume or remounts a read-only one — and a SEPARATE field for the
	// same reason as the two above: `unreadable=` carries an /input remediation and drives
	// the documented alert, while this condition is entirely on the /output side. It blocks
	// orphan reaping like every other outcome that left a bundle this app is not satisfied
	// with (conversionsClean).
	Unwritable int
}

// summaryAttrs is the ONE list of the scan-summary attributes, in the order
// logScanOutcome emits them; the README's alerting section keys Loki rules on these
// names, so both the names and the order are the operator-visible contract. It sits
// beside ScanResult because it IS the reporting half of that struct: a counter added
// above without a row here never reaches the only operator-visible summary, and the
// omission is not a compile error.
//
// Field order is pointer-region packing (govet fieldalignment), not narrative order:
// the func pointer leads so the string's pointer+len sit behind it. Each row is
// written keyed so the operator-visible name still reads first.
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
// state this app is still trying to repair. It is the ONE spelling of the reap veto
// that is about the OUTPUT rather than the input enumeration: Failed is the obvious
// member, and Unwritable joins it because a bundle the volume refused to let this app
// replace is one it wanted to replace and could not — deleting other bundles on
// the strength of that same volume is exactly what the Failed veto refuses. Health
// deliberately does NOT ask this question; it asks Failed alone
// (main.healthyAfterScan), because a restart can clear one and never the other.
// Pointer receiver like its two siblings below: ScanResult reached gocritic's
// hugeParam threshold when Unwritable was added, and a read-only predicate is the
// wrong place to copy 80 bytes.
func (r *ScanResult) conversionsClean() bool {
	return r.Failed == 0 && r.Unwritable == 0
}

// durablyEnumerated reports whether every DURABLE veto on the input enumeration is
// clear: nothing under /input was unreadable and no symlink was unresolvable. It is
// the ONE spelling of that veto set, kept on the type that owns the counters, so a
// new durable coverage dimension cannot be added to one asker and missed in another.
// Vanished is deliberately excluded: it is the transient renewal race, and the two
// predicates that differ only in their Vanished term compose this one.
func (r *ScanResult) durablyEnumerated() bool {
	return r.Unreadable == 0 && r.Unresolved == 0
}

// inputFullyEnumerated reports whether nothing prevented this scan from observing
// every /input path: no unreadable path, no unresolved symlink, nothing that vanished
// mid-walk. It is the ONE spelling of that veto set — reapContext.enumerationClean
// and logInputCoverageWarnings both ask this question, so a new coverage dimension
// cannot be added to one of them and missed in the other.
func (r *ScanResult) inputFullyEnumerated() bool {
	return r.durablyEnumerated() && r.Vanished == 0
}

// The per-scan entry budget bounds how many /input entries ONE scan enumerates. Its
// value and its non-positive-means-default rule live in internal/scanbudget; what
// follows is why the bound exists at all.
//
// The per-file and per-PEM-block caps bound what one certificate costs; nothing
// bounded how MANY the walk would take on. /input is a mounted tree this app does not
// own, and every entry the walk accepts costs cumulative memory that outlives the
// entry: a `seen` key per certificate, a conversionStatus per result, and an
// observation-log entry per pair. A producer (or anything else with write access to the
// host side of that mount) that plants a very large inventory therefore drives the
// daemon into an OOM kill, which stops conversion for every certificate — a denial of
// the app's only job, from the one boundary it deliberately does not trust.
//
// The operator-facing budget is MAX_SCAN_ENTRIES, and it is INJECTED
// (Options.MaxScanEntries) rather than read here: internal/config owns the variable's
// name, its default, its ceiling and every diagnostic for a repaired value, and this
// package stays a leaf that package configures. Importing internal/config from the
// scanner would invert that direction and give the silent `health` subcommand a path
// into the scan machinery.
//
// The floor under a Scanner constructed without a budget is scanbudget.Default, the same
// number internal/config hands the operator, from the one home both packages read.

// errScanBudgetExceeded marks the abort above. It is its own sentinel so the walk's
// own callers (and a test) can tell a refused-because-too-large tree from an
// unreadable one.
//
// It is deliberately NOT returned to Run's caller: see Run, where it is swallowed
// after the summary is logged. A tree bigger than the budget is not restart-clearable,
// so it must not flip health — the same reading this app already gives every /input
// path it could not read.
var errScanBudgetExceeded = errors.New("input tree exceeds the per-scan entry budget")

// scanBudgetMsg is the operator-facing half of that abort. It names the health
// consequence for the same reason the unreadable aggregate does: "stopping this scan"
// otherwise reads as a failure an operator would expect a restart to clear.
const scanBudgetMsg = "the /input tree holds more entries than one scan will enumerate; stopping this scan without converting or removing anything further, health is unaffected"

// scanBudgetRemediation is that WARN's operator action. It names BOTH ways out,
// because the budget cannot tell them apart: a mount pointed at the wrong tree (the
// tripwire this bound exists for) and a legitimately large certificate directory that
// simply needs a higher ceiling.
const scanBudgetRemediation = "check that /input is mounted at the certificate directory and holds nothing else, or raise MAX_SCAN_ENTRIES if the tree is legitimately this large"

// scanBudgetSummaryMsg is the end-of-scan summary line for a walk the entry budget
// stopped. It is deliberately NOT "scan aborted before completion": that message is
// the README's CertConverterScanAborted signal, documented as an /input root that
// could not be walked on a container that has gone unhealthy, and this abort is
// neither — the root walked fine and Run swallows the error, so health is untouched.
// CertConverterInputTreeTooLarge (which matches scanBudgetMsg) stays this condition's
// signal; this line only stops it from also raising the wrong one.
const scanBudgetSummaryMsg = "scan stopped at the /input entry budget"

// budgetTruncatedCoverage marks a coverage count that came from a scan the entry budget
// stopped early: the number is what this scan REACHED, not what the tree holds. It is an
// added ATTRIBUTE rather than a reworded message, because the README publishes those
// message substrings as Loki matchers (CertConverterInputPathUnreachable keys on the
// unreadable line), so a record's fields may grow while its wording may not.
const budgetTruncatedCoverage = "partial: the scan stopped at the /input entry budget, so this counts only the paths it reached"

// Options carries the process-lifetime scan configuration the composition root
// chooses once at startup: the confined input and output roots, the password
// embedded in generated PFX files, and the PKCS#12 encoder profile. The encoder
// is carried as the app-owned convert.EncoderType name, not as a go-pkcs12
// value, so the vendor type stays confined to internal/convert. These values
// never vary between Run calls, so they are injected at construction rather
// than re-supplied per scan.
type Options struct {
	Encoder   convert.EncoderType
	Lifecycle outputpolicy.Lifecycle
	CertsRoot string
	OutRoot   string
	Password  string
	// MaxScanEntries is how many entries one scan may enumerate in EACH mounted tree
	// before it refuses that tree (scanbudget.Default when non-positive): the /input
	// walk (scanWalk.maxEntries) and the /output orphan walk (outputWalk.maxEntries)
	// each get the same ceiling, applied per tree rather than shared, because both are
	// mounts this app does not own and either one can be made large by whoever can write
	// to it. It is INJECTED rather than read from internal/config here: that package owns
	// MAX_SCAN_ENTRIES' name, default, ceiling and repaired-value diagnostics, and the
	// composition root wires its Config.MaxScanEntries into this field. It also bounds
	// the observation log, whose size a scan's enumeration is what drives
	// (observationLog.maxObservedPairs).
	MaxScanEntries int
}

// Scanner walks a certificate directory, decides which cert/key pairs are out of
// date by reading the bundle already on disk, and dispatches their conversion to
// PFX format.
//
// A Scanner's input-observation cache and output tree require Run to be called from a
// single goroutine. The cache is a plain map, so two concurrent scans is a fatal
// "concurrent map writes" throw, not merely wasted work; and on the output tree they
// would both read the same prior bundle, both would decide it is stale, and both
// would rewrite it with fresh KDF salts (churning mtimes and re-replicating
// downstream), and one scan's orphan reap could race the other's write of the same
// path. main.go does this (initial scan, then the watcher's synchronous onChange
// callback).
type Scanner struct {
	observations *observationLog
	opts         Options
}

// New constructs a Scanner with the given process-lifetime scan configuration.
// The options are taken by pointer only because the struct is large enough that
// copying it is wasteful (gocritic hugeParam); New does not retain the pointer's
// identity, it copies the value into the Scanner.
func New(opts *Options) *Scanner {
	return &Scanner{
		opts:         *opts,
		observations: newObservationLog(opts.MaxScanEntries),
	}
}

// Run walks the configured certs root, converts changed .crt/.key pairs to PFX
// in the configured output root, and returns a ScanResult with outcome counts
// plus any walk-level error. Every
// /input read is confined to certsRoot through an *os.Root, so a symlink in the
// watched tree cannot redirect a read outside it, and every /output stat,
// directory creation and PFX write is confined to outRoot the same way, so a
// symlink planted there cannot redirect the private-key-bearing PFX outside the
// mounted volume. A certsRoot or outRoot that cannot be opened as a root is a
// hard error (the caller marks the container unhealthy).
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
		maxEntries:   s.opts.MaxScanEntries,
	}
	// Protect the wholeness this walk establishes from the observation log's own
	// eviction: reserve's victim is arbitrary, so without this window a pair markWhole
	// read earlier in THIS scan could lose the evidence noteMissingKey classifies a
	// replaced key with, and the veto that covers the eviction (evictedWholeness) is
	// spent by the end of this scan. Closed on every exit path.
	s.observations.beginScan()
	defer s.observations.endScan()
	// Enumerate the input tree THROUGH the root handle, exactly as the
	// /output stale-temp sweep does: every step is an openat-relative
	// syscall and every path handed downstream is root-relative, so no
	// ambient absolute path exists for a later read to reach for.
	//
	// atomicfile owns the traversal mechanics (streaming ReadDir batches, one
	// directory handle at a time, O_DIRECTORY so a planted FIFO is refused rather
	// than blocking this goroutine, no descent into a symlinked directory). The
	// per-entry policy — the budget, the classification, the diagnostics — is
	// sw.visit's, and the walk is the same one store.listOutputs uses, so the two
	// mounts cannot drift apart in how much of a stranger's tree they take on.
	walkErr := atomicfile.WalkDirInRoot(ctx, inHandle, func(rel string, d fs.DirEntry, err error) error {
		return sw.visit(ctx, rel, d, err)
	})
	// A tree over the entry budget is REPORTED, not failed. It stops the walk (so
	// `seen` is a prefix of the tree and every whole-tree claim below stays vetoed),
	// visit has already emitted scanBudgetMsg at WARN with the remediation, and the
	// summary names the abort — but the error is not carried past this point, because
	// nothing about a too-large /input is clearable by restarting the container. That
	// is the same reading this app gives every /input path it could not read
	// (main.healthyAfterScan asks Failed alone), and it is why the budget's own
	// diagnostic has to carry the operator action: no other signal follows.
	budgetExceeded := errors.Is(walkErr, errScanBudgetExceeded)

	result := countResults(sw.results, sw.unreadable, sw.unresolved, sw.vanished)
	rc := reapContext{
		// The scan's counts are carried whole rather than copied field-by-field:
		// result.Unreadable (not sw.unreadable) is what the veto needs, because it also
		// carries the per-entry statusUnreadable count. That term is about the TREE, not
		// about the unreadable pair's own bundle — visit records every .crt in `seen`
		// before dispatching it, so a cert whose read failed still matches its .pfx and
		// is never an orphan candidate. What it vetoes is the claim behind every reap: a
		// scan that could not READ part of /input has not enumerated the tree completely
		// in the README's sense ("no unreadable path"), so no output under it can be
		// proven orphaned. A cert that vanished mid-walk leaves the same hole in `seen`,
		// so it vetoes reaping too — but transiently: the next scan sees the replacement
		// and reconciles then.
		result:        result,
		walkCompleted: walkErr == nil,
		shutdown:      walkErr != nil && IsShutdown(walkErr),
		// The observation log's ceiling can force it to drop the "this pair was once
		// read whole" evidence noteMissingKey depends on, and the loss is silent at the
		// point of use: a key that goes missing afterwards is classified as an ordinary
		// orphan (health-neutral, NOT reap-vetoing) instead of the transient
		// statusVanished (reap-vetoing), so the scan would go on to delete unrelated
		// leftover outputs on an input reading it can no longer justify. Taken (and
		// reset) once per scan so the veto covers exactly the scan whose evidence was
		// spent; a later scan that re-reads the pair whole re-establishes it.
		evidenceEvicted: s.observations.takeEvictedWholeness(),
	}
	// Prune observation state for pairs that are gone, but ONLY when the walk
	// proved the enumeration complete: an aborted walk, an unreadable sub-path or
	// an unresolved symlink means `seen` is not the whole input tree, so a pair
	// hidden behind it would be forgotten and re-warn on the next clean scan.
	// result.Total is deliberately NOT part of this gate (unlike enumeratedInput): a
	// clean walk that found nothing proves every remembered pair is gone. Nor is
	// evidenceComplete: an eviction does not make the enumeration partial, and gating
	// the prune on it would let ceiling pressure disable the one mechanism that
	// relieves it — an evicted live path is unknown again next scan, evicts again, and
	// the log stays pinned at its ceiling with orphan reaping off until a restart.
	// forget only drops paths absent from `seen`, so it cannot spend evidence for any
	// pair this scan observed, and rc was built before this point, so the reap veto
	// for this scan is unaffected. Eviction obeys the same rule for the same reason
	// (observationLog.canEvict): neither pruning nor the ceiling may drop wholeness a
	// pair of the active scan established.
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
// reaper.reconcile checks the output tree against). The one exception is
// observations, which is process-lifetime state owned by the Scanner and shared
// with the walk, not per-run accounting: it survives across scans by design.
// Hoisting the per-entry callback onto this struct keeps Scanner.Run flat.
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
	// unresolved counts input symlinks the confined root could not resolve. Each
	// one may hide certificates, so `seen` is NOT a complete enumeration of the
	// input tree afterwards. countResults folds it into ScanResult.Unresolved.
	unresolved int
	// entries counts every path this walk has been handed, including directories and
	// entries it could not read. It is the accounting behind the entry budget: the cap is
	// about how much of an untrusted tree one scan takes on, so it counts what the walk
	// TOUCHED rather than what it converted.
	entries int
	// maxEntries is this walk's entry budget, injected from Options.MaxScanEntries.
	// Non-positive means "use scanbudget.Default" (scanbudget.Effective), so a scanWalk
	// assembled without one — the package's own focused tests do this — is bounded
	// rather than unbounded.
	maxEntries int
}

// visit is the walk's per-entry callback (atomicfile.WalkDirInRoot). The context is
// checked before and after each
// entry: a walk error at the root ("."), or a cancelled context, aborts the
// walk; an error below the root marks one unreadable sub-path and continues.
// Every path is root-relative (the walk runs through the *os.Root). Directories
// and non-.crt files convert nothing; a directory whose name is a certificate
// path is counted as one unreadable sub-path, and any other non-.crt entry is
// only inspected by noteUnwalkableSymlink, which reports a symlink the walk
// cannot follow. Every .crt entry is recorded as seen and dispatched to
// convertEntry.
func (sw *scanWalk) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if rel == "." {
			return err
		}
		// An ENOENT below the root is the WALK's half of the renewal race the read
		// side already classifies as statusVanished. Only real directories are ever
		// ReadDir-ed: the walk queues a subdirectory on the DIRENT type
		// (entry.IsDir(), which is false for a symlink), so it never descends a
		// link -- and the only way a path it just enumerated answers ENOENT is that it
		// was removed under the walk;
		// there is no surviving-symlink reading to rule out here, which is why this
		// arm needs no src.pathVanished second observation. Counting it as
		// unreadable raised the documented `unreadable=` alert, whose remediation
		// points at /input permissions, for a directory that is merely being
		// replaced. Health-neutral and reap-vetoing either way.
		if errors.Is(err, fs.ErrNotExist) {
			slog.Debug("skipping path that vanished during the scan", "path", rel, "error", err)
			sw.vanished++
			return nil
		}
		// Debug, not Warn: this is the per-path half of a two-level contract shared
		// with the /output sweep. An unreadable sub-path is a steady-state
		// permissions/UID misconfiguration the app deliberately tolerates, and it
		// recurs on EVERY scan (each debounced fsnotify event and each fallback
		// tick) — so naming every one at the default level put N lines plus an
		// aggregate into the log forever for a condition the operator already knows
		// about. The aggregate Warn in logInputCoverageWarnings carries the signal and
		// the remediation hint; LOG_LEVEL=debug names the individual paths.
		slog.Debug("skipping unreadable path", "path", rel, "error", err)
		sw.unreadable++
		return nil
	}
	// Charged once per ENUMERATED path, and before anything is read or remembered, so
	// the budget bounds the walk's own state rather than trailing it. Deliberately
	// below the error arm above: the walk reports a directory it could not open or
	// finish reading through visit for that directory's OWN path, which was already
	// charged when its parent enumerated it, so charging there counted one path twice
	// and enforced the operator's MAX_SCAN_ENTRIES below its configured value. The
	// root's failed Stat is the only error visit for an uncharged path, and it returns
	// without converting anything. Returning an error aborts the walk, which is what
	// keeps `seen` from being read as a complete enumeration downstream.
	sw.entries++
	if budget := scanbudget.Effective(sw.maxEntries); sw.entries > budget {
		slog.Warn(scanBudgetMsg,
			"path", rel, "entries", sw.entries, "limit", budget,
			"remediation", scanBudgetRemediation)
		return fmt.Errorf("%w: stopped at %d entries (%s)", errScanBudgetExceeded, sw.entries, rel)
	}
	if d.IsDir() {
		// A directory occupying a <name>.crt path is a certificate the scan cannot
		// read, not an ordinary directory: counting it as unreadable keeps it
		// health-neutral (a restart cannot clear it) while blocking orphan reaping,
		// so sync reconciliation never deletes the still-live <name>.pfx of an input
		// path that still exists in an unusable shape. The walk continues into it so
		// genuinely nested certificate entries are still discovered.
		//
		// Debug for the reason the unreadable-sub-path arm above states in full: this
		// is the same shape of steady-state layout mistake, recurring on EVERY scan
		// until an operator moves the directory, and the unreadable count incremented
		// here is what raises the aggregate Warn in logInputCoverageWarnings on this
		// same scan. Naming the path at the default level too would emit both halves of
		// that two-level contract as Warn for one condition.
		if layout.IsCert(rel) {
			slog.Debug("skipping cert: certificate path is a directory",
				"path", rel,
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
	// interrupted prior-bundle read or atomic write is statusFailed. Re-check here so
	// the walk aborts and Run reports the cancellation, instead of returning a
	// "completed" scan whose unreadable, vanished or failed count is really that
	// artifact.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// noteUnwalkableSymlink reports a symlink under the input root that the walk
// cannot follow. The walk never descends a symlinked directory (it queues a
// subdirectory only on the dirent type, which is never a directory for a
// symlink), and a link
// the confined handle cannot resolve at all (a target outside the root, or an
// unreadable component of an in-root target) tells us nothing about what it
// points to, so every certificate beneath such a link is invisible to the
// scan: it is counted in nothing, no PFX is produced, and health stays green.
// An /input populated with symlinks to other certificate directories would
// otherwise fail silently. The .crt/.key pair names are excluded because
// convertEntry already classifies and logs those (an unreadable .crt fails the
// entry, a sibling .key that cannot be stat-ed is a warned orphan), so warning
// here as well would double-report one condition. A dangling link (ENOENT)
// hides nothing and stays silent.
func (sw *scanWalk) noteUnwalkableSymlink(rel string, d fs.DirEntry) {
	if d.Type()&fs.ModeSymlink == 0 || layout.IsRelevant(rel) {
		return
	}
	fi, err := sw.src.stat(rel)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		// The error is the only evidence of the cause here (a target outside the
		// root, or an unreadable component inside it), so name the consequence and
		// let the error carry the cause. The target's type is unknown on this arm
		// (fi is unusable when err != nil), so the message covers a linked file as
		// well as a linked directory.
		// The walk KNOWS it is blind here, which is exactly the state that must
		// block orphan reaping: a certificate behind this link still exists but
		// will not appear in `seen`.
		sw.unresolved++
		slog.Warn("skipping symlink that could not be resolved through the input root; anything it points to, including certificates under a linked directory, is not scanned",
			"path", rel, "error", err,
			"remediation", "mount that certificate path into /input directly instead of linking to it, or fix the permissions on the link target")
	case err == nil && fi.IsDir():
		// The target is inside the root, so the walk reaches those
		// certificates through the real directory; nothing is missed.
		slog.Debug("skipping symlinked directory; its target is walked directly", "path", rel)
	}
}

// --- Logging policy ---

// failScan reports a scan that ended before the walk began: a certs or output
// root that could not be opened as an *os.Root. It routes the error through
// logScanOutcome so the "scan aborted before completion" record — the one the
// README's CertConverterScanAborted rule matches — is emitted for an unusable
// root too, not only for a walk that aborted at ".". The counts it logs are all
// zero, which is accurate: nothing was visited. logInputCoverageWarnings
// self-vetoes on a non-nil walk error, so no coverage WARN is emitted alongside
// it. The error is returned unchanged so the caller pairs it with a zero
// ScanResult at the return site.
func failScan(ctx context.Context, err error) error {
	logScanOutcome(ctx, &ScanResult{}, err)
	return err
}

// logScanOutcome emits the end-of-scan summary. A completed walk logs at Info;
// a walk aborted by shutdown (context cancellation or deadline) logs at Debug;
// any other abort logs at Warn so an operator sees the partial scan and its
// error. The count attributes are identical in all three cases (the README's Loki
// alert matches on them), so they are built once. Every count is named here,
// including the ones deliberately kept out of Unreadable; ScanResult's field
// comments carry why each is separate.
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
		attrs = append(attrs, "error", walkErr)
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
//
// This is the single home for EVERY default-level /input-coverage diagnostic. The
// unreadable aggregate used to be rendered by the composition root instead, from the
// exported count, which split one taxonomy across two packages: a change to the
// classification here silently changed what that WARN covered, with no compile-time
// or structural signal. main keeps only healthyAfterScan, the health boundary.
//
// Every message is gated by the evidence THAT message needs, which is the rule this
// function is organised around rather than a per-arm exception:
//
//   - A walk that stopped for an ARBITRARY reason claims nothing: it observed a prefix
//     of the tree chosen by whatever failed, and a shutdown-cancelled walk stopped at an
//     instant unrelated to the tree's contents. Both stay silent here.
//   - The ENTRY-BUDGET stop is the exception, and it is a typed one
//     (errScanBudgetExceeded): the scan stopped because the tree is larger than the
//     budget, having read every path it visited normally. Its per-path counts are
//     therefore observations, not casualties of the stop, and they are the counts the
//     operator most needs — the budget WARN says the tree is too large, and without
//     these the same operator is not told that specific certificates in the part that
//     WAS read were unreadable or missing their key. They carry the coverage attribute
//     so the number reads as "what this scan reached" rather than as a whole-tree total.
//   - The WHOLE-TREE arms ("no certificate pair at all", "every certificate lacks its
//     key") need a complete enumeration: a completed walk with no unreadable path, no
//     unresolved symlink, nothing that vanished mid-scan. Run deliberately continues past
//     an unreadable sub-path, so a partial enumeration cannot know what lies beneath it,
//     and a cert (or the key pairing with one) replaced during the walk was not observed
//     whole. Neither "no pair exists" nor "every certificate" is a claim such a scan can
//     make — least of all one the budget truncated, which is precisely a scan that did
//     not see the whole tree.
//   - The PER-PATH arms (unreadable paths, "some certificates are missing their sibling
//     .key") need only their own counts, because those are proven path by path: an
//     unreadable path was refused when this scan touched it, and a sibling key is stat-ed
//     directly through the confined root with only ENOENT becoming statusOrphan. A hole
//     elsewhere in the tree — or a budget stop further along it — cannot make an observed
//     missing key unobserved.
//
// Orphan REAPING keeps the full whole-tree gate (reapContext.enumerationClean): a
// deletion rests on the claim that no input for a bundle exists ANYWHERE in the tree,
// which is a whole-tree claim, unlike naming the orphans this scan actually saw.
func logInputCoverageWarnings(result *ScanResult, walkErr error) {
	// A typed stop reason, not a string match: errScanBudgetExceeded already exists as
	// its own sentinel precisely so the budget stop can be told from an unreadable root
	// or a cancellation, and Run wraps it with the entry count rather than replacing it.
	budgetStopped := errors.Is(walkErr, errScanBudgetExceeded)
	if walkErr != nil && !budgetStopped {
		return
	}
	// Extra attribute for the truncated case only, appended to the per-path arms. The
	// MESSAGES are untouched: the README publishes their substrings as Loki matchers
	// (CertConverterInputPathUnreachable keys on the unreadable line), so the wording is
	// a contract and only a record's fields may grow.
	var observed []any
	if budgetStopped {
		observed = []any{"coverage", budgetTruncatedCoverage}
	}
	if result.Unreadable > 0 {
		// Message byte-identical to the one the composition root emitted: README's
		// Alerting section tells an operator at LOG_LEVEL=warn to alert on this exact
		// line, so its wording is a contract regardless of which package renders it.
		// Health is deliberately unaffected (see main.healthyAfterScan): nothing the
		// scan merely could not READ is clearable by a restart.
		slog.Warn("some /input paths were unreadable and were skipped; health is unaffected",
			append([]any{
				"unreadable", result.Unreadable,
				// inputPermRemediation, not a permission-only hint of its own: the count
				// aggregates every unreadable shape this package classifies, and only some
				// of them are permission problems. A directory occupying a <name>.crt path
				// is a LAYOUT mistake whose per-path Debug line names the right action, so
				// an aggregate that said only "fix /input permissions or run as a UID that
				// can read it" sent the operator to re-check permissions that were already
				// correct. Sharing the package's one /input-side hint keeps the aggregate
				// and the per-path lines from prescribing two different actions for one
				// condition.
				"remediation", inputPermRemediation,
			}, observed...)...)
	}
	// Each arm is gated by the evidence IT needs, which is the rule here rather than an
	// exception: a claim about the WHOLE TREE ("no pair at all", "every certificate")
	// needs a complete enumeration, while a claim about the PATHS THIS SCAN READ needs
	// only those paths. Folding the second kind behind the whole-tree gate silenced a
	// proven fact because of an unrelated hole elsewhere in the tree.
	//
	// walkErr == nil is part of the whole-tree gate rather than of the function's own
	// entry condition: a budget-truncated scan reaches the arms below, and it is exactly
	// a scan that cannot speak for the whole tree.
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
		// completed with failed=0 and produced nothing at all. The summary counts
		// carry orphan, but no README Loki rule keys on it and the
		// per-cert reason is Debug-only, so this steady-state naming
		// misconfiguration (a key extension that is not .key) is silent at
		// the default level, exactly like the Total==0 case above. Name it.
		slog.Warn("every certificate under the input root is missing its sibling .key; no PFX output is being produced",
			"orphan", result.Orphan,
			"remediation", "name each private key <name>.key beside its <name>.crt (Caddy's layout)")
	case result.Orphan > 0:
		// Some, not all — and the ONE arm here that needs no whole-tree proof. Every
		// counted orphan is proven per path: readPair stats the sibling .key directly
		// through the confined root and only an ENOENT becomes statusOrphan (a key that
		// is there and unreadable is statusUnreadable, and a key this process had already
		// read whole is the transient statusVanished), so "these certificates have no
		// sibling .key" is a fact about paths this scan read, not an inference from the
		// tree being complete. An unreadable path, an unresolved symlink or a renewal
		// elsewhere in the tree cannot make it untrue, and gating it on them silenced it
		// for as long as any unrelated hole stood.
		//
		// It is also the arm that catches the all-orphan shape on an INCOMPLETE
		// enumeration: "every certificate" is then unprovable, "some" still holds.
		//
		// The pairs that DO have their key still convert, so the scan
		// completes with failed=0 and the summary's orphan count is the only trace at
		// the default level. An orphaned .crt is also recorded as seen, so its
		// existing bundle is never reaped either: it keeps being served, indefinitely
		// stale, with nothing naming it. The per-cert path stays Debug; this is the
		// once-per-scan aggregate.
		slog.Warn("some certificates under the input root are missing their sibling .key; those produce no PFX and any existing bundle for them goes stale",
			append([]any{
				"orphan", result.Orphan, "total", result.Total,
				"remediation", "name each private key <name>.key beside its <name>.crt (Caddy's layout), or remove the certificate from /input",
			}, observed...)...)
	}
}

// IsShutdown reports whether err is the process shutting down (context
// cancellation or a deadline) rather than an operator-actionable failure. It is
// the single decision behind every Debug-instead-of-Warn/Error downgrade in
// this package AND behind the composition root's choice to leave the health
// marker untouched on a shutdown, so the walk-level, sweep-level, per-entry and
// health-marker decisions cannot drift apart. Exported for the composition
// root; Run returns the walk error unwrapped, so main classifies the same value
// this package does.
func IsShutdown(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// failEntry records one per-entry failure: it logs the failure and returns the
// failed status for the caller to propagate. A failure caused by shutdown
// (context cancellation or deadline) logs at Debug -- it is not an operator
// actionable conversion error -- while every real failure logs at Error, the same
// split logScanOutcome applies to the walk-level error. Callers may pass extra
// slog key/value pairs (a remediation hint, the output path) for failures whose
// cause is not evident from the input path alone.
//
// It carries no rollback obligation: currency is derived from the output file
// itself, so a failed entry leaves the previous bundle (or nothing) at the output
// path and the next scan reaches the same verdict and retries the pair.
func failEntry(logPath, msg string, err error, extra ...any) conversionStatus {
	attrs := append([]any{"path", logPath, "error", err}, extra...)
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

// pairFingerprint identifies the exact cert/key input bytes. Each side is
// hashed separately before combining, so moving bytes across the boundary is
// still detected. It controls diagnostic emission only; output-derived currency
// remains the authority for whether a PFX needs rewriting.
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
// silent on every later fsnotify event and fallback tick. It maps each cert path
// to a signature of the last input bytes AND the observations derived from them,
// and is NEVER consulted for currency, which store.inspect derives from the
// bundle on disk. It is process-lifetime state held by the Scanner, so a restart
// re-reports each pair exactly once.
//
// The map is plain, so it inherits Scanner's single-goroutine Run contract.
//
// It carries a SECOND, structural fact that readPair's missing-key classifier
// depends on, in its own `whole` set: a path is in that set only if this process read
// that pair WHOLE — cert and sibling key both — because markWhole is called immediately
// after readPair succeeds. That MEMBERSHIP is the one piece of in-process evidence that a
// key which is missing now was there before (completedPair). It is a separate field
// precisely because it is spent on a different schedule than the signature: forgetPair
// spends the wholeness, never the de-duplication.
type observationLog struct {
	seen map[string][sha256.Size]byte
	// whole holds the paths this process has read as a COMPLETE pair. It is the
	// structural half of the log, kept separate from `seen` because the two are spent
	// differently: forgetPair spends one scan of missing-key grace, which must not
	// also reset the WARN de-duplication for input bytes that never changed.
	whole map[string]struct{}
	// loneKeys holds the cert paths this log has already reported as retaining an
	// output because a sibling KEY is still there while the certificate is gone
	// (reaper.reapConfirmed). A THIRD set for a third spending schedule: it is cleared
	// when the pair reads whole again (markWhole) or when the bundle is finally deleted
	// (clearLoneKey), and — unlike `seen` and `whole` — it is deliberately NOT pruned by
	// forget, whose gate is membership in the scan's cert enumeration. A lone key's
	// certificate is by definition absent from that enumeration, so pruning it there
	// would re-report the same unchanged condition on every scan.
	loneKeys map[string]struct{}
	// activeWhole holds the paths whose wholeness this SCAN established, and exists
	// only for the duration of one input walk (beginScan / endScan). Eviction skips
	// them: reserve's victim is otherwise arbitrary, so a pair markWhole read earlier
	// in the SAME scan could lose its evidence, and the counter that vetoes reaping for
	// the evicting scan (evictedWholeness) is reset before a later scan needs that
	// evidence — at which point a replaced key reads as an ordinary orphan and the reap
	// gate treats the enumeration as complete. A nil map means no walk is in progress,
	// and then nothing is protected.
	activeWhole map[string]struct{}
	// maxPairs is the injected ceiling (Options.MaxScanEntries); non-positive means
	// scanbudget.Default. Resolved through maxObservedPairs.
	maxPairs int
	// evictedWholeness counts wholeness entries reserve had to drop since the last
	// take. It is the log's own report that it can no longer answer completedPair for
	// some pair it once knew — evidence noteMissingKey needs — and Scanner.Run turns it
	// into a reap veto for that scan (reapContext.evidenceEvicted). Without it the loss
	// is silent exactly where it matters: a missing key reads as an ordinary orphan,
	// which does not veto reaping, so the scan deletes other bundles on an input reading
	// it can no longer defend.
	evictedWholeness int
}

// newObservationLog builds an empty log whose EACH of three sets — the signatures
// (seen), the wholeness evidence (whole) and the lone-key reports (loneKeys) — is
// bounded at maxPairs entries independently, so the log's process-lifetime ceiling is
// three times maxPairs rather than two. A non-positive maxPairs means
// scanbudget.Default: an unbounded log is not an option this constructor offers,
// because /input path churn is what fills it.
func newObservationLog(maxPairs int) *observationLog {
	return &observationLog{
		seen:     make(map[string][sha256.Size]byte),
		whole:    make(map[string]struct{}),
		loneKeys: make(map[string]struct{}),
		maxPairs: maxPairs,
	}
}

// beginScan opens the window in which wholeness established by this walk is protected
// from eviction. Paired with endScan through a defer in Scanner.Run, so the protection
// never outlives the walk that needs it.
func (o *observationLog) beginScan() {
	o.activeWhole = make(map[string]struct{})
}

// endScan closes that window: outside a walk no path is protected, so a later scan's
// reserve is free to take any victim it needs.
func (o *observationLog) endScan() {
	o.activeWhole = nil
}

// canEvict reports whether victim may be dropped: a pair this scan already read whole
// is never evicted — dropping it spends evidence the CURRENT scan established, and the
// veto that covers the eviction is reset before the scan that would need it. The path
// being reserved is never a candidate at all: reserve hunts victims only in a map that
// does not contain it, and markWhole protects it in activeWhole before reserving.
func (o *observationLog) canEvict(victim string) bool {
	_, observedThisScan := o.activeWhole[victim]
	return !observedThisScan
}

// markWhole records the structural fact that this process read both inputs for rel.
// It is called at the readPair success boundary, independently of analysis, currency,
// encoding, and output-write outcomes — so it is reached for pairs that never get as
// far as note or record (an analysis failure, an encode failure, a failed write), and
// it therefore has to reserve against the same ceiling they do rather than trusting
// their reservations to bound it. note and record route their reservation THROUGH this
// one — a single pass makes room for the wholeness entry and the signature both — so
// this reserve is the only one either of them performs.
//
// The path is recorded as observed-this-scan BEFORE reserving, so the reservation this
// call performs cannot pick it — or any earlier pair of the same walk — as its victim.
func (o *observationLog) markWhole(rel string) {
	if o.activeWhole != nil {
		o.activeWhole[rel] = struct{}{}
	}
	o.reserve(rel)
	o.whole[rel] = struct{}{}
	// A pair that reads whole is not a lone key any more, so the next time it becomes
	// one it is reported again. This is the "per change, not per scan" half of the
	// lone-key report: the state is remembered until the state itself changes.
	o.clearLoneKey(rel)
}

// markLoneKey records that rel's bundle is being retained because a sibling key is
// still present while the certificate is gone, and reports whether that is NEW — i.e.
// whether the condition has to be logged on this scan. Once reported it stays silent
// until markWhole sees the pair whole again or clearLoneKey retires it because the
// leftover key went.
//
// A full log answers true every time rather than remembering: this set is bounded by
// the same ceiling as the rest of the log, and re-reporting a retained private-key
// bundle is the loud direction. It does NOT route through reserve, because reserve's
// eviction spends the wholeness evidence a reap veto now rests on — a diagnostic
// de-duplication set must not be able to trigger that.
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
// Analyse currently derives from them. Not every observation is a property of the
// bytes alone: the validity-window ones (expired, not-yet-valid, chain cert out of
// window) also depend on the scan time, so keying de-duplication on the input
// fingerprint alone would suppress a cert crossing NotAfter forever while the
// daemon stays up. Hashing each field separately keeps the variable-length
// kind/detail boundary unambiguous.
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
// signature differs from the last one observed for that path. The observations
// describe the INPUT as read on this scan, so a semantically equivalent input
// edit (a reordered chain, an appended duplicate cert, a second key) still has to
// be named once even though the bundle on disk stays correct — and so does a
// newly derived expiry, whose bytes never changed. Keying the emission on the
// signature reports each one on the scan that introduced it, which is what
// unconditional logging would turn into noise.
func (o *observationLog) note(rel string, fp [sha256.Size]byte, obs []convert.Observation) {
	current := observationSignature(fp, obs)
	previous, ok := o.seen[rel]
	// markWhole first: its reserve makes room for BOTH entries this call commits, and
	// markWhole has already protected rel in activeWhole — and reserve only hunts victims
	// in maps that do not contain rel — so the reservation cannot evict what it is making
	// room for.
	o.markWhole(rel)
	o.seen[rel] = current
	if !ok || previous != current {
		logConversionObservations(rel, obs)
	}
}

// record commits the signature without re-emitting: the conversion path has
// already logged the observations unconditionally.
func (o *observationLog) record(rel string, fp [sha256.Size]byte, obs []convert.Observation) {
	// One reservation covers both halves, exactly as in note.
	o.markWhole(rel)
	o.seen[rel] = observationSignature(fp, obs)
}

// maxObservedPairs bounds this log's process-lifetime size.
//
// forget only prunes when a walk PROVED the enumeration complete, so a deployment whose
// scans keep ending incomplete — an unreadable sub-path, an unresolved symlink, a
// certificate replaced mid-scan — never reclaims the entries of paths that are gone.
// Under path churn from a tree this app does not own, that grows process-lifetime state
// with nothing to stop it. The bound IS the scan entry budget: a scan cannot
// legitimately observe more pairs than it is allowed to enumerate in the first place,
// which is why the budget is injected into this log too rather than derived a second
// time from anything else.
func (o *observationLog) maxObservedPairs() int {
	return scanbudget.Effective(o.maxPairs)
}

// reserve makes room for a path this log has not seen before, evicting one remembered
// pair when it is full.
//
// Eviction spends the signature freely — the evicted pair re-emits its observation WARN
// once, and no currency decision reads this log at all, since store.inspect derives
// currency from the bundle on disk. What it must NOT spend silently is the WHOLENESS
// evidence: dropping it makes completedPair answer false, and that answer is what
// downgrades a later missing key from the reap-vetoing statusVanished to the ordinary
// statusOrphan, which authorises deleting unrelated leftover bundles on this scan. So
// every wholeness entry dropped is COUNTED (evictedWholeness) and Scanner.Run turns the
// count into a reap veto for that scan: the reap gate fails closed on the loss instead
// of reading it as proof.
//
// The victim is arbitrary (map iteration order) rather than least-recently-used: every
// entry is worth exactly one deduplicated WARN, so ordering machinery would buy nothing
// at a bound this size.
func (o *observationLog) reserve(rel string) {
	// BOTH halves are checked because they are WRITTEN independently: markWhole is
	// reached at the readPair success boundary, on pairs that never get as far as note
	// or record, so a `seen`-only ceiling would leave the structural half growing for
	// the process lifetime.
	if _, known := o.seen[rel]; !known && len(o.seen) >= o.maxObservedPairs() {
		o.evictOne()
	}
	if _, known := o.whole[rel]; !known && len(o.whole) >= o.maxObservedPairs() {
		o.evictWholeness()
	}
}

// evictOne drops one remembered pair from BOTH halves, never a pair this scan already
// read whole (canEvict); the reserved path is excluded by reserve's own membership gate,
// which only hunts victims in a map that does not contain it. So an eviction can never
// leave the two halves out of step and can never spend evidence the active scan
// established. It is reserve's SIGNATURE arm, so it takes its victim from `seen`, and
// it normally finds one: reserve calls it only when len(seen) >= maxObservedPairs()
// (never 0, since the fallback is scanbudget.Default) and only for a path that is
// absent from `seen`, while the paths protected for the active scan are a strict subset
// of the entries charged to that same scan-entry ceiling. If every candidate IS
// protected, the log holds one entry over the ceiling for the rest of the walk rather
// than dropping evidence the scan is about to need. A
// wholeness-only entry — what a pair that read whole and then failed analysis, encoding
// or its write leaves behind — is evicted by evictWholeness, which reserve's own second
// arm calls.
func (o *observationLog) evictOne() {
	for victim := range o.seen {
		if !o.canEvict(victim) {
			continue
		}
		delete(o.seen, victim)
		o.dropWholeness(victim)
		return
	}
}

// evictWholeness makes room in the WHOLENESS half specifically, dropping a victim that
// actually holds wholeness and dropping that victim's signature with it so the two
// halves stay in step. Like evictOne it skips any pair the active scan read whole
// (canEvict); the reserved path is excluded by reserve's membership gate.
//
// evictOne cannot serve this call: its signature-first victim may hold no wholeness at
// all (a pair forgetPair spent, which keeps its signature), and then the half that was
// full is not reduced — so `whole` grows past the ceiling while an unrelated pair's
// de-duplication is spent for nothing and re-emits its observation WARN on the next
// scan. Every drop here is counted by dropWholeness, which is what makes the reap veto
// fail closed on a loss that previously went unrecorded.
func (o *observationLog) evictWholeness() {
	for victim := range o.whole {
		if !o.canEvict(victim) {
			continue
		}
		delete(o.seen, victim)
		o.dropWholeness(victim)
		return
	}
}

// dropWholeness removes one path's wholeness evidence and counts the loss when there
// was any to lose. Counting here rather than at the two call sites above is what makes
// the accounting exact: the signature half is evicted alongside paths the wholeness half
// never held, and counting those would veto a reap for evidence that never existed.
func (o *observationLog) dropWholeness(rel string) {
	if _, held := o.whole[rel]; !held {
		return
	}
	delete(o.whole, rel)
	o.evictedWholeness++
}

// takeEvictedWholeness reports how many pairs have lost their wholeness evidence to
// the ceiling since the last call, and resets the counter.
//
// Read once per scan by Scanner.Run, which turns a non-zero answer into that scan's
// reap veto. It RESETS because the veto's scope is the scan whose evidence was spent: a
// later scan that reads the pair whole again re-establishes the evidence through
// markWhole, and a later scan that finds the key still missing has the same no-memory
// position as a pair this process never read whole — the documented, loud direction.
func (o *observationLog) takeEvictedWholeness() int {
	n := o.evictedWholeness
	o.evictedWholeness = 0
	return n
}

// completedPair reports whether this process has already read rel's pair whole, which
// is what noteMissingKey reads as "this certificate HAD its sibling key".
//
// A false answer is the safe direction, and it is deliberately the answer for every
// pair this process never got through: a first scan after a restart, a cert whose PEM
// does not parse, a key that was already missing when the daemon started. All of them
// keep the default-level missing-key diagnostic they have today, because no memory
// exists to suppress it.
func (o *observationLog) completedPair(rel string) bool {
	_, remembered := o.whole[rel]
	return remembered
}

// forgetPair spends the wholeness evidence for one pair, spending the single scan of
// grace completedPair grants: the scan that reports a vanished key forgets that the pair
// was ever read whole, so a key that is STILL missing on the next scan — one fsnotify
// event or one fallback tick later — has no memory behind it and is reported as the
// genuine orphan it is. The observation signature in `seen` deliberately SURVIVES: the
// input bytes did not change, so a re-read of the same pair must not re-emit its
// observation WARN. It is the per-path sibling of forget, which prunes every path a
// COMPLETE walk did not see.
func (o *observationLog) forgetPair(rel string) {
	delete(o.whole, rel)
}

// forget drops entries for paths a COMPLETE walk did not see, so a pair that
// comes back is reported once again. Callers must gate this on a complete
// enumeration: with a partial one, a pair hidden behind an unreadable sub-path
// or an unresolved symlink would be forgotten and re-warn on the next clean
// scan.
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
//
// It names all three shapes the unreadable count aggregates, not permissions alone: a
// permission or UID problem, a path that is not a regular file (a directory occupying
// a <name>.crt path, a FIFO), and a symlink whose target escapes the mount. The
// aggregate previously offered permission/UID advice only, which sent an operator with
// a layout mistake to re-check permissions that were already correct.
const inputPermRemediation = "check /input permissions and that the container runs as a UID that can read it, and that each certificate path is a regular file inside the mount, not a directory or a symlink out of it"

// readPair resolves and reads the input side of one .crt entry: it classifies
// the sibling .key (a key that is not there is a health-neutral statusOrphan, or the
// transient statusVanished when this process had already read the pair whole — see
// noteMissingKey; a non-ENOENT stat failure is statusUnreadable instead, because the
// key is there and cannot be read — health-neutral too, but it also blocks orphan
// reaping, which an orphan does not) and then performs both bounded reads through the
// input source, so every /input byte is read once from within the confined root.
//
// The returned conversionStatus is statusUnset on success and, on failure, the
// outcome convertEntry must propagate for that entry, with the failure already
// logged. statusUnset is not an outcome, so it doubles as the success signal: a
// status propagated from a successful read can never be mistaken for a
// conversion, and no second return value can disagree with it.
func (sw *scanWalk) readPair(ctx context.Context, rel, keyRel string) (pairInputs, conversionStatus) {
	if _, statErr := sw.src.stat(keyRel); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return pairInputs{}, sw.noteMissingKey(rel, keyRel)
		}
		// A non-ENOENT stat failure (a sibling key that is a symlink the *os.Root
		// refuses because it escapes /input, or a permission/IO error) is NOT a
		// genuine "no key" orphan — the key is there and cannot be read. Reporting it
		// as an orphan misdescribed it in the scan summary and in the all-orphan
		// diagnostic, so it is statusUnreadable, the same outcome the two bounded
		// reads below produce for the same class of condition. Health-neutral either
		// way; the message is unchanged because an alert rule keys on it.
		slog.Warn("skipping cert: cannot stat sibling key", "path", rel, "error", statErr,
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
//
// One ENOENT, two conditions. The STEADY STATE is a key that was never named
// <name>.key beside its <name>.crt: no PFX is produced, any existing bundle goes
// indefinitely stale, and logInputCoverageWarnings' once-per-scan aggregate is the only
// default-level trace of it — so that case stays statusOrphan and keeps that WARN and
// its rename remediation. The TRANSIENT is a key being replaced while the scan reads
// the tree: the same renewal window the cert and key READS classify as statusVanished,
// where naming a misnamed key would tell an operator to rename files that are correct.
//
// One ENOENT cannot separate them, so this needs a second observation, and the only
// honest one available in-process is memory: observationLog holds an entry for a pair
// only once this process has read that pair WHOLE, so its presence is evidence the key
// was there (completedPair). The memory is SPENT on use, which is what keeps the
// genuine case loud — see forgetPair — and a pair this process never read whole has no
// memory at all, so every shape that is missing its key from the start keeps today's
// default-level diagnostic.
//
// src.pathVanished is the read side's primitive, asked here for the question its
// second arm was written for. Its answers all read correctly for a stat that just
// returned ENOENT: the key path is GONE (the replacement has not landed yet), or it is
// a non-symlink again (it landed between this stat and that Lstat) — either way the
// tree moved under the scan; against a SURVIVING symlink whose target does not exist,
// which is the steady-state certbot live/ -> archive/ shape and stays an orphan. Any
// other Lstat failure answers false there, so a key the scan cannot even classify
// stays an orphan too: no arm that fails to prove a replacement takes the quieter
// reading.
//
// statusVanished rather than a count of its own, because it is the same condition the
// read side already named: health-neutral, out of the documented unreadable= alert and
// its permissions remediation, Debug-only per path, and — for this one scan — a veto on
// both the orphan aggregate (ScanResult.inputFullyEnumerated) and the reap, exactly as
// a vanished cert is. This pair's OWN bundle was never at risk either way: visit
// records the .crt in `seen` before dispatching it, so it is not an orphan candidate,
// and the next scan sees the replacement and reconciles the rest.
func (sw *scanWalk) noteMissingKey(rel, keyRel string) conversionStatus {
	if sw.observations.completedPair(rel) && sw.src.pathVanished(keyRel) {
		sw.observations.forgetPair(rel)
		// Byte-identical to the read side's vanish line for the same condition on the
		// same pair, so an operator correlating one renewal does not meet two
		// vocabularies for it.
		slog.Debug("skipping cert: private key vanished during the scan", "path", rel)
		return statusVanished
	}
	// A genuine orphan: the certificate has no sibling key at all.
	slog.Debug("skipping cert without matching key", "path", rel)
	return statusOrphan
}

// noteUnreadableInput logs a failed read of an /input file and RETURNS the outcome it
// diagnosed, so the classification and its diagnostic cannot drift apart: Debug plus
// statusUnreadable when the read was cancelled by shutdown, Debug plus the transient
// statusVanished when the file simply vanished, and Warn plus statusUnreadable
// otherwise -- the last matching readPair's sibling-key stat. Both outcomes are
// health-neutral.
//
// logRel is the .crt path every per-entry log line names (so the cert-side and the
// key-side line of one pair are attributable to the same entry); inputRel is the path
// the failed read actually used, which is what the ENOENT arm re-examines.
//
// Every OPERATOR-ACTIONABLE reason a read fails here is a steady-state condition a
// restart cannot clear. A confinement refusal in particular cannot be identified by
// sentinel — os.Root reports "path escapes from parent", which matches none of
// fs.ErrPermission, fs.ErrNotExist, fs.ErrInvalid, syscall.ELOOP or syscall.EXDEV — so
// classifying per-error would mean matching on Go's error text. Treating every
// non-ENOENT read failure alike avoids that entirely and makes the two reads of a pair
// agree, which was the actual defect: the sibling key's stat failure was already
// health-neutral while the cert's read failure flipped the container unhealthy.
//
// ENOENT alone is not enough to call the entry a benign race. It IS one when the path
// itself is gone — the entry existed at readdir and was gone by the read (a renewal
// replacing a file, an atomic-write temp) — so that stays at Debug AND out of the
// Unreadable count: folding it in raised the documented unreadable-path alert, with its
// permissions remediation, on the ordinary renewal this daemon exists to process. It
// becomes statusVanished instead, which the next scan clears. But the SAME ENOENT comes
// back on every scan from a symlink that is still there and points at a target that is
// not (the certbot live/ -> archive/ layout with only live/ mounted, or a link left
// behind by a removed cert): that is a steady-state operator-actionable condition, and
// reporting it as a transient race would leave a certificate producing no PFX forever
// with no default-level signal anywhere. sw.src.pathVanished separates the two.
//
// The pair is still not converted either way, so both outcomes block orphan reaping:
// an input tree the scan could not fully read cannot prove an output is orphaned.
func (sw *scanWalk) noteUnreadableInput(logRel, inputRel, what string, err error) conversionStatus {
	if IsShutdown(err) {
		// A cancelled read is the shutdown itself, not an unreadable path: the WARN
		// below is the message the README recommends alerting on, so emitting it for
		// a normal SIGTERM would page an operator for a mount that is fine.
		slog.Debug("skipping cert: "+what+" read interrupted by shutdown", "path", logRel, "error", err)
		return statusUnreadable
	}
	if errors.Is(err, fs.ErrNotExist) && sw.src.pathVanished(inputRel) {
		slog.Debug("skipping cert: "+what+" vanished during the scan", "path", logRel, "error", err)
		return statusVanished
	}
	slog.Warn("skipping cert: cannot read "+what,
		"path", logRel, "error", err,
		"remediation", inputPermRemediation)
	return statusUnreadable
}

// convertEntry resolves the outcome for one .crt entry under certsRoot. It
// reads the cert and its sibling .key exactly once through the input source,
// analyses the pair, and either skips it (the bundle on disk is already the one
// these inputs produce) or converts and writes it (it is not, whether because the
// inputs changed, the output went missing or was replaced, or the encoder profile
// or password changed). Every output touch — the prior-bundle read, the directory
// creation and the atomic write — is confined to the store's root, so a symlink
// planted under the output tree cannot redirect the private-key-bearing PFX
// outside it. The only thing recorded on success is the pair's observation
// signature (input fingerprint plus the observations derived from it), which gates
// one-shot input diagnostics and never currency, so every failure path
// leaves the pair due for a retry without needing a rollback. All per-cert logs
// use the certsRoot-relative path for a stable, non-leaky identifier.
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
	// bundle those inputs produce is known. Observations describe the INPUT, so
	// they are logged either way — a reordered bundle or a multi-key file is the
	// same operator-visible fact whether or not a write follows.
	analysis, err := convert.Analyse(ctx, certPEM, keyPEM)
	if err != nil {
		return failEntry(rel, "conversion failed", err)
	}
	observations := analysis.Observations()
	state, err := sw.out.inspect(ctx, pfxRel, analysis, sw.enc, sw.password)
	if err != nil {
		// A cancellation, and nothing else: inspect resolves every "I cannot tell what
		// is on disk" outcome (an unreadable, oversized, non-regular or undecodable
		// bundle, a lax directory) into a content FACT itself, and its only two error
		// returns are the prior-bundle read that raced a cancellation and
		// contentFromCurrency's pre-verdict context check. failEntry logs it at Debug,
		// and visit's post-conversion context check turns it into the walk-level
		// cancellation the caller reports, so this entry's statusFailed never reaches the
		// health marker.
		return failEntry(rel, "failed to inspect existing pfx", err)
	}
	if state.upToDate() {
		// The observations describe the INPUT, so a semantically equivalent input
		// edit still has to be named once even though the bundle on disk stays
		// correct; observationLog.note owns that once-per-change rule.
		sw.observations.note(rel, fingerprint, observations)
		slog.Debug("skipping unchanged cert pair", "path", rel)
		return statusUnchanged
	}

	slog.Debug("converting cert pair", "path", rel)
	pfxData, err := convert.Encode(analysis, sw.enc, sw.password)
	if err != nil {
		logConversionObservations(rel, observations)
		return failEntry(rel, "conversion failed", err)
	}
	writeErr := sw.out.write(ctx, pfxRel, pfxData)
	// The one derivation, after the write, from the three facts this entry resolved:
	// what the bundle on disk was, whether its mode was laxer than policy, and how the
	// write itself ended. Nothing below re-decides it; the logging and the observation
	// bookkeeping only read the outcome.
	outcome = writeOutcome(state, writeErr)
	if writeErr != nil {
		reportWriteFailure(rel, pfxRel, state, writeErr, outcome)
	}
	if outcome == statusUnwritable {
		// The bundle on disk is one this app never proved wrong and the refusal is steady
		// state (no restart clears it), so the observations describe an input that will be
		// re-analysed on every scan for as long as the operator leaves /output as it is.
		// note emits them once per CHANGE and commits the signature, exactly as the
		// unchanged path does: re-emitting per attempt is reserved for statusFailed, where
		// the bundle those inputs produce is genuinely not on disk. That is why the
		// emission waits for the write outcome instead of running before it — a
		// persistently foreign-owned bundle is non-current on every scan, so an
		// unconditional emission there repeated the input WARN on every scan forever.
		// The standing per-scan WARN for the condition itself is reportWriteFailure's.
		sw.observations.note(rel, fingerprint, observations)
		return outcome
	}
	logConversionObservations(rel, observations)
	if outcome == statusFailed {
		return outcome
	}
	sw.observations.record(rel, fingerprint, observations)

	slog.Info("wrote pfx", "path", pfxRel)
	return outcome
}

// writeOutcome derives one entry's conversionStatus, and it is the ONLY place that
// derivation happens. Its inputs are the two facts this scan resolved independently:
// what this app learned about the bundle already on disk (state.content), and — when the
// write failed — whether a restart could clear that failure (restartCanClearWrite). The
// bundle's MODE is not one of them: a lax mode is reported and acted on nowhere, so it can
// neither schedule a write nor reach health. Deriving the status once, after the write, is
// what replaced threading a staleness cause into the failure handler: each fact arrives
// unmodified, so a fix to one of them cannot overwrite another on the way here.
//
// The default is unchanged and stays the loud one: a PFX this app could not write is a
// conversion failure, counted in ScanResult.Failed, and health goes unhealthy — right,
// because the bundle those inputs produce is not on disk. Two independent things must
// BOTH hold before the health-neutral outcome is granted instead:
//
//  1. This app never proved the bundle on disk wrong (bundleState.bundleNotProvenWrong):
//     it could not read the bytes at all. A bundle it DID compare and find stale — a
//     renewal behind, a rotated password, an absent or non-regular output path — stays a
//     conversion failure whatever refused the write, because the operator is being served
//     the wrong bundle and that has to be loud (the README's /output contract). A bundle
//     it compared and MATCHED never reaches here at all: convertEntry returns at
//     `if state.upToDate()` before the write.
//  2. No restart can clear what refused the write (restartCanClearWrite): a permission
//     denial, a read-only mount, a full volume, an exhausted quota.
//
// Together those two are exactly the condition health exists to exclude: restarting the
// container cannot change the outcome, so restarting is the wrong answer and Failed is the
// wrong count — the same mistake statusUnreadable exists to avoid on the /input side. The
// condition is not silence: it carries a standing WARN once per scan and it still blocks
// orphan reaping (ScanResult.conversionsClean).
func writeOutcome(state bundleState, writeErr error) conversionStatus {
	switch {
	case writeErr == nil:
		return statusConverted
	case state.bundleNotProvenWrong() && !restartCanClearWrite(writeErr):
		return statusUnwritable
	default:
		return statusFailed
	}
}

// unreplaceableBundleMsg is the standing WARN for a health-neutral write refusal: a prior
// bundle this app could not VERIFY at all (above the readable bound, unreadable,
// un-stat-able, or refused by the codec's preflight) whose replacing write a steady-state
// /output condition refused.
//
// It is now the ONLY such message. The second one described a rewrite that carried no new
// bytes because only the mode was wrong, and no such rewrite happens any more: a lax mode
// is reported and never written over, so the refusal it named cannot arise. It promises
// nothing about the bytes on disk, deliberately, because nothing compared them. The record
// carries a `content` attribute naming which fact the app actually had, so an operator
// reading this line knows what the bundle left in place was.
const unreplaceableBundleMsg = "prior pfx could not be replaced and the /output condition that refused the write is not one a restart clears; leaving the existing bundle in place, health is unaffected"

// outputVolumeRemediation is the remediation for a write the VOLUME refused rather than
// ownership: this app may write /output, but the filesystem will not take the bytes.
// Deliberately not outputPermRemediation — chowning /output frees no space and does not
// remount it read-write, and an operator sent after the wrong cause reads the WARN as
// noise.
const outputVolumeRemediation = "check /output for free space, a quota and a read-only mount"

// reportWriteFailure logs a failed PFX write in the register the DERIVED outcome calls
// for. It decides nothing — writeOutcome already did — so the count and the log can never
// disagree about an entry, which is what the previous shape risked by classifying inside
// the logger.
//
// The WARN is emitted once per bundle per scan, because the entry is written at most once
// per scan: there is no retry loop behind it.
func reportWriteFailure(logRel, pfxRel string, state bundleState, err error, outcome conversionStatus) {
	if outcome == statusUnwritable {
		slog.Warn(unreplaceableBundleMsg,
			"path", logRel, "output_path", pfxRel, "error", err,
			"content", state.content.String(), "remediation", unwritableRemediation(err))
		return
	}
	// failEntry is called for its LOG: the statusFailed it returns is the same value
	// writeOutcome already derived, and taking it from there keeps one derivation.
	// The message is unchanged (an operator's log query keys on it); the remediation names
	// the two steady-state output-side causes.
	failEntry(logRel, "conversion failed", err, "output_path", pfxRel,
		"remediation", "check /output ownership and permissions for the UID in user:, "+
			"and that no symlink is planted at the output path")
}

// unwritableRemediation names the operator action that clears a health-neutral write
// refusal. One axis rather than the two this used to pick over: with only one standing
// message left, what remains is WHAT REFUSED the replacement — ownership, or the volume —
// and an operator sent after the wrong cause reads the WARN as noise.
func unwritableRemediation(err error) string {
	if isPermissionRefusal(err) {
		return outputPermRemediation
	}
	return outputVolumeRemediation
}

// logConversionObservations surfaces Analyse's non-fatal findings about a pair's
// input. Every one of them is a CONVERTIBLE condition, so none flips health:
// health tracks conversion failures, and these all converted.
//
// The level comes from the kind's own convert.ObservationClass, which is minted where
// the kinds are minted, mapped here onto this app's log vocabulary: Quiet (a benign
// assembly artefact) is Debug, Info (a true fact about the input with nothing to act
// on, such as a chain that stops at an absent trust anchor — the documented Caddy
// fullchain shape) is Info, and Warning (something the operator probably did not
// intend, or that a consumer will reject) is Warn. Three levels rather than the old
// noise/not-noise boolean, which had no room for the middle case and reported it as a
// problem the operator was expected to fix.
//
// Observations are emitted on the conversion path, and on the unchanged path only
// when the pair's observation signature (input bytes plus the observations derived
// from them) differs from the last one observed, which is what keeps them from
// becoming noise: an odd-but-convertible input, or a newly derived expiry over
// unchanged bytes, is reported on the scan that introduced it rather than on every
// scan for the life of the deployment.
// A pair that keeps FAILING re-emits per attempt, matching how the failure itself is
// logged.
// Detail is already bounded by convert, so it needs no further truncation here.
func logConversionObservations(rel string, observations []convert.Observation) {
	for _, o := range observations {
		attrs := []any{"path", rel, "kind", string(o.Kind), "detail", o.Detail}
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
//
// walkUnreadable (sub-paths the walk could not enter) and per-entry statusUnreadable
// (a cert or key the scan could not read) are folded into one Unreadable count on
// purpose: both mean "an /input path this app could not read", both carry the same
// operator remediation, both are health-neutral, and both must block orphan reaping.
//
// statusVanished and statusUnwritable each keep their own count instead; see
// ScanResult's field comments for why.
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

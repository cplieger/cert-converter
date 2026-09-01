package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/scanbudget"
)

// reaper reconciles output artifacts with one scan's expected artifact set.
type reaper struct {
	src  *source
	out  *store
	mode outputpolicy.Lifecycle
	// layoutMode selects the post-delay source re-check: the mirror layout
	// derives a candidate's sources from its name and stats them, while the flat
	// layout re-enumerates /input fresh per candidate (flatInventory).
	layoutMode outputpolicy.Layout
	// exclude is the scan's INPUT_EXCLUDE_PATHS set. The post-delay re-check
	// honours it too: a source that is present but out of scope must read as
	// absent, or sync could never reconcile away the artifacts of a path the
	// operator just excluded.
	exclude layout.ExcludeSet
	// maxEntries bounds the flat re-check's own /input enumeration, same ceiling
	// as every other walk in this app.
	maxEntries int
	formats    outputpolicy.Formats
	// layoutExplicit gates cleanup of the OTHER layout's artifacts: only an
	// operator who deliberately chose a layout has asked for its predecessor's
	// tree to be reconciled away.
	layoutExplicit bool
}

// reapContext is everything the gate needs to decide whether `seen` can be
// trusted as a COMPLETE enumeration of the input tree.
type reapContext struct {
	// result is the scan's own outcome counts, carried whole so a new coverage
	// dimension cannot go missing from a field-by-field copy.
	result ScanResult
	// evidenceEvicted counts pairs whose "read whole" evidence the observation
	// log's ceiling dropped during this scan (observationLog.reserveWhole).
	evidenceEvicted int
	walkCompleted   bool
	// shutdown is true when the walk ended because the process is stopping, which
	// is not an operator-actionable incomplete enumeration.
	shutdown bool
}

// walkEnumerationComplete reports whether nothing PREVENTED the walk from observing
// every /input path: the walk ran to the end and no path was unreadable, unresolved
// or replaced under it.
func (r *reapContext) walkEnumerationComplete() bool {
	return r.walkCompleted && r.result.inputFullyEnumerated()
}

// enumeratedInput reports whether `seen` can be trusted as a COMPLETE enumeration of
// the input tree: nothing prevented the walk from observing every /input path, nothing
// spent the in-process evidence this scan's own classifications rest on, and the walk
// found a pair to compare the output tree against.
func (r *reapContext) enumeratedInput() bool {
	return r.walkEnumerationComplete() && r.evidenceEvicted == 0 && r.result.Total > 0
}

// reapDisabledPhrase is the substring the README's CertConverterOrphanRemovalDisabled Loki
// rule matches.
const reapDisabledPhrase = "orphan removal is disabled for this scan"

// logIncompleteInputEnumeration reports why orphan reconciliation is skipped when
// the input enumeration is incomplete.
func logIncompleteInputEnumeration(rc *reapContext) {
	if rc.shutdown {
		slog.Debug("skipping orphan reconciliation; scan cancelled during shutdown")
		return
	}
	slog.Warn(reapDisabledPhrase+": this scan cannot prove any /output artifact is orphaned",
		"walk_completed", rc.walkCompleted, "unreadable", rc.result.Unreadable,
		"unresolved", rc.result.Unresolved, "vanished", rc.result.Vanished,
		"total", rc.result.Total,
		// Covers all four enumeratedInput terms: an incomplete walk, a path the
		// walk could not read or resolve, an empty /input tree (total=0, its own
		// WARN above), and wholeness evidence the observation log's ceiling
		// evicted (also fixed by MAX_SCAN_ENTRIES).
		"remediation", "check the /input mount and the unreadable-path warnings above; "+
			"if the scan stopped at the entry budget, raise MAX_SCAN_ENTRIES and the container's "+
			"memory limit together, because one scan's memory grows with the total length of the "+
			"paths it enumerates")
}

// reconcile compares the output tree against the artifact set this scan expects
// and, in sync mode, deletes the artifacts that no longer have an input.
func (rp *reaper) reconcile(ctx context.Context, expected map[string]struct{}, rc *reapContext) (int, error) {
	if rp.mode == outputpolicy.LifecycleKeep {
		// Keep neither deletes nor reports, so return before the output walk.
		return 0, nil
	}
	if !rc.enumeratedInput() {
		logIncompleteInputEnumeration(rc)
		return 0, nil
	}
	outputs, walkSafe, err := rp.out.listOutputs(ctx)
	if err != nil {
		if IsShutdown(err) {
			slog.Debug("orphan enumeration cancelled during shutdown", "error", logtext.Path(err.Error()))
			return 0, err
		}
		if errors.Is(err, errOutputBudgetExceeded) {
			// A SIZE condition, not a permission one: the generic WARN below
			// points at /output ownership, which is the wrong diagnosis for a
			// tree simply larger than one scan will enumerate.
			slog.Warn(outputBudgetMsg,
				"error", logtext.Path(err.Error()), "dir", logtext.Path(rp.out.root.Name()),
				"remediation", outputBudgetRemediation)
			return 0, nil
		}
		slog.Warn("could not enumerate output orphans; "+reapDisabledPhrase,
			"error", logtext.Path(err.Error()), "dir", logtext.Path(rp.out.root.Name()),
			"remediation", outputPermRemediation)
		return 0, nil
	}
	orphaned := orphansOf(outputs, expected)
	if len(orphaned) == 0 {
		return 0, nil
	}

	// !rc.enumeratedInput() above already answered the enumeration half of the
	// reap-safety question; resolveReap reads the remainder off this scan's own
	// output-work result.
	if !resolveReap(rp.mode, &rc.result, walkSafe) {
		rp.reportRetainedOrphans(orphaned, walkSafe)
		return 0, nil
	}

	return rp.reapConfirmed(ctx, orphaned)
}

// reportRetainedOrphans is reconcile's no-deletion arm: the orphans are named and
// kept because OUTPUT_LIFECYCLE forbids a deletion for this scan.
func (rp *reaper) reportRetainedOrphans(orphaned []string, walkSafe bool) {
	msg := "output artifacts have no matching input"
	// Reaching this line in sync mode means orphan removal is OFF for this scan —
	// the condition CertConverterOrphanRemovalDisabled matches, and the
	// README's OUTPUT_LIFECYCLE row promises this phrase for every failed proof term.
	if rp.mode == outputpolicy.LifecycleSync {
		msg += "; " + reapDisabledPhrase
	}
	inaction, remediation := retentionProse(rp.mode, walkSafe)
	slog.Warn(msg,
		"count", len(orphaned), "paths", sampleOrphanPaths(orphaned),
		"action", inaction,
		"remediation", remediation)
	// keyStillPresent owns the half-deleted-pair record; with no deletion to gate,
	// its answer is the report itself. The sources are re-resolved before that
	// record fires: `expected` was filled by the input walk before the /output walk,
	// so it cannot itself prove the sources are gone by now. Only the mirror
	// layout can derive a candidate's sources from its name.
	if walkSafe && rp.layoutMode != outputpolicy.LayoutFlat {
		for _, rel := range orphaned {
			stem := layout.OutputStem(rel)
			absent, err := rp.sourcesAbsent(stem)
			// Silent on error: an unreadable /input path proves neither half of
			// the claim, and the aggregate WARN above already named this candidate.
			if err != nil || !absent {
				continue
			}
			rp.keyStillPresent(rel, layout.CertFor(stem))
		}
	}
}

// sourcesAbsent reports whether EVERY input that would produce artifacts at stem
// is gone; one present source, or one unanswerable stat, keeps the candidate. An
// EXCLUDED source reads as absent: the operator declared it out of scope, so it
// is not a source this app produces artifacts from.
func (rp *reaper) sourcesAbsent(stem string) (bool, error) {
	for _, src := range layout.SourceCandidates(stem) {
		if !rp.exclude.Empty() && rp.exclude.Excludes(src) {
			continue
		}
		absent, err := rp.src.pathAbsent(src)
		if err != nil {
			return false, err
		}
		if !absent {
			return false, nil
		}
	}
	return true, nil
}

// orphansOf selects, from the output tree's own enumeration, the artifacts this
// scan does not expect any seen source to produce — in walk order.
func orphansOf(outputs []string, expected map[string]struct{}) []string {
	var orphaned []string
	for _, rel := range outputs {
		if _, ok := expected[rel]; !ok {
			orphaned = append(orphaned, rel)
		}
	}
	return orphaned
}

// reapConfirmed is the deletion half of reconcile: wait reapDeferral ONCE for the
// whole batch, then re-check each candidate's INPUT evidence immediately before
// deleting it — per-candidate stats under the mirror layout, a fresh /input
// enumeration per candidate under the flat layout.
func (rp *reaper) reapConfirmed(ctx context.Context, orphaned []string) (int, error) {
	slog.Info(reapRecheckMsg,
		"count", len(orphaned), "recheck_in", reapDeferral.String())
	if err := waitBeforeReap(ctx, reapDeferral); err != nil {
		slog.Debug("orphan removal abandoned during shutdown before the confirming re-check",
			"candidates", len(orphaned), "error", logtext.Path(err.Error()))
		return 0, err
	}
	return rp.removeConfirmed(ctx, orphaned)
}

// flatRecheckIncompleteMsg reports a confirming /input re-enumeration that could
// not observe the whole tree, which vetoes this candidate and every one after
// it. It carries reapDisabledPhrase on purpose: the operator condition is the
// same one the published CertConverterOrphanRemovalDisabled rule matches.
const flatRecheckIncompleteMsg = reapDisabledPhrase + ": /input could not be fully re-enumerated before deleting, " +
	"and an incompletely read input tree is not proof any artifact is orphaned"

// errRecheckIncomplete marks a confirming re-enumeration that saw less than the
// whole input tree: an unreadable path, a source path in an unusable shape, or
// the entry budget.
var errRecheckIncomplete = errors.New("confirming /input re-enumeration is incomplete")

// flatInventory is the flat layout's re-check evidence: one bounded enumeration
// of /input, taken immediately before a candidate's unlink so the fact deciding
// the removal is as fresh as the mirror layout's per-candidate stats. What
// remains is the same unavoidable POSIX gap sourceAllowsRemoval documents: no
// atomic multi-path conditional unlink exists, so a source restored between the
// verdict and the unlink can still lose its artifact.
type flatInventory struct {
	// expected is every artifact path the enabled formats derive from the
	// sources present at re-check time.
	expected map[string]struct{}
	// loneKeys is the flat output stem of every private key whose pair
	// certificate is gone: the half-deleted-pair veto, projected into the flat
	// namespace.
	loneKeys map[string]struct{}
}

// enumerateFlatInventory walks /input once and derives the re-check evidence.
// Any path it cannot observe makes the whole inventory unusable: deletions rest
// on proving absence, and a partially read tree proves nothing absent.
func (rp *reaper) enumerateFlatInventory(ctx context.Context) (*flatInventory, error) {
	walk := &flatRecheckWalk{
		files:   make(map[string]struct{}),
		budget:  scanbudget.NewCounter(rp.maxEntries),
		exclude: rp.exclude,
	}
	if err := atomicfile.WalkDirInRoot(ctx, rp.src.root, func(rel string, d fs.DirEntry, err error) error {
		return walk.visit(ctx, rel, d, err)
	}); err != nil {
		return nil, err
	}
	return deriveFlatInventory(walk.files, rp.formats), nil
}

// flatRecheckWalk carries the confirming re-enumeration's mutable accounting.
type flatRecheckWalk struct {
	// files is every relevant name the walk saw: sources, and keys for the
	// lone-key veto.
	files map[string]struct{}
	// exclude drops out-of-scope paths, so neither their artifacts nor their
	// keys are treated as evidence a candidate is still wanted.
	exclude layout.ExcludeSet
	budget  scanbudget.Counter
}

// visit is the re-enumeration's walk callback: collect relevant names, and
// refuse the whole inventory on anything the walk cannot observe.
func (w *flatRecheckWalk) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		if rel == "." {
			return err
		}
		return errRecheckIncomplete
	}
	if !w.budget.Charge() {
		return errRecheckIncomplete
	}
	if d.IsDir() {
		if layout.IsSource(rel) {
			// A directory occupying a source path is input this walk cannot
			// classify, exactly as the scan counts it unreadable.
			return errRecheckIncomplete
		}
		return nil
	}
	if layout.IsRelevant(rel) && (w.exclude.Empty() || !w.exclude.Excludes(rel)) {
		w.files[rel] = struct{}{}
	}
	return nil
}

// deriveFlatInventory turns one complete enumeration into the two re-check
// sets. Every present source claims its artifacts, decodable or not: presence
// is what the mirror layout's Lstat re-check reads too.
func deriveFlatInventory(files map[string]struct{}, formats outputpolicy.Formats) *flatInventory {
	inv := &flatInventory{expected: make(map[string]struct{}), loneKeys: make(map[string]struct{})}
	for rel := range files {
		if !layout.IsSource(rel) {
			continue
		}
		for _, artifact := range layout.ArtifactsFor(layout.FlatStem(layout.SourceStem(rel)), formats) {
			inv.expected[artifact] = struct{}{}
		}
	}
	for rel := range files {
		if !layout.IsKey(rel) {
			continue
		}
		stem := layout.KeyStem(rel)
		if _, paired := files[layout.CertFor(stem)]; paired {
			continue
		}
		inv.loneKeys[layout.FlatStem(stem)] = struct{}{}
	}
	return inv
}

// retainForLayout reports whether a candidate is kept because it is laid out
// for the OTHER layout and the operator never explicitly chose one: the unset
// default must not delete a tree a previous configuration wrote.
func (rp *reaper) retainForLayout(rel string) bool {
	return rp.layoutMode == outputpolicy.LayoutFlat && !rp.layoutExplicit && !layout.FlatProducible(rel)
}

// otherLayoutRetainedMsg is the once-per-scan record for candidates
// retainForLayout kept.
const otherLayoutRetainedMsg = "keeping output artifacts laid out for a different OUTPUT_LAYOUT"

// logOtherLayoutRetained emits that record, or nothing when nothing was kept
// for layout reasons.
func logOtherLayoutRetained(kept []string) {
	if len(kept) == 0 {
		return
	}
	slog.Warn(otherLayoutRetainedMsg,
		"count", len(kept), "paths", sampleOrphanPaths(kept),
		"remediation", "set OUTPUT_LAYOUT explicitly to have sync reconcile the previous layout's artifacts away, or remove them by hand")
}

// removeConfirmed is reapConfirmed's post-delay half: the interleaved re-check and
// unlink loop, split out to stay inside the package's complexity ceiling.
func (rp *reaper) removeConfirmed(ctx context.Context, candidates []string) (int, error) {
	var deleted int
	var removedPaths, refusedPaths, otherLayout []string
	// Deferred so all three records cover what happened on every exit from this
	// loop, including the shutdown return below.
	defer func() {
		logReapAudit(removedPaths)
		logReapRefusals(refusedPaths)
		logOtherLayoutRetained(otherLayout)
	}()
	// len(candidates)-deleted is the remaining-work count: `deleted` counts
	// unlinks, so this charges every legitimately-skipped candidate (certificate
	// came back, key still there, removeOrphan refused) to outstanding work too.
	for i, rel := range candidates {
		if rp.retainForLayout(rel) {
			otherLayout = append(otherLayout, rel)
			continue
		}
		// An artifact from a currently enabled format is orphaned only while all
		// of its possible sources remain absent. An artifact from an explicitly
		// disabled format needs no source check: the format choice itself made it
		// unwanted, and FormatsExplicit is what let it enter this candidate set.
		if layout.IsOutputShape(rel, rp.formats) {
			remove, err := rp.recheckAllowsRemoval(ctx, rel)
			switch {
			case errors.Is(err, errRecheckIncomplete):
				// One record covers this candidate and every one after it: the
				// same tree would answer every remaining candidate the same way,
				// so a per-candidate repeat would only multiply the WARN.
				slog.Warn(flatRecheckIncompleteMsg,
					"removed", deleted, "remaining", len(candidates)-i,
					"error", logtext.Path(err.Error()),
					"remediation", recheckUnreadableRemediation)
				return deleted, nil
			case err != nil:
				slog.Debug("orphan removal interrupted by shutdown during the confirming re-check",
					"removed", deleted, "remaining", len(candidates)-i, "error", logtext.Path(err.Error()))
				return deleted, err
			case !remove:
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			slog.Debug("orphan removal interrupted by shutdown",
				"removed", deleted, "remaining", len(candidates)-i, "error", logtext.Path(err.Error()))
			return deleted, err
		}
		switch rp.out.removeOrphan(rel) {
		case reapAttemptRemoved:
			removedPaths = append(removedPaths, rel)
			deleted++
		case reapAttemptRefused:
			refusedPaths = append(refusedPaths, rel)
		case reapAttemptVanished:
			// The producer race removeOrphan already logged at Debug.
		}
	}
	return deleted, nil
}

// recheckAllowsRemoval routes one candidate's pre-unlink source re-check to the
// layout's own evidence. A non-nil error is a shutdown or errRecheckIncomplete;
// both stop the loop, only the former propagates out of it.
func (rp *reaper) recheckAllowsRemoval(ctx context.Context, rel string) (bool, error) {
	if rp.layoutMode == outputpolicy.LayoutFlat {
		return rp.flatAllowsRemoval(ctx, rel)
	}
	return rp.sourceAllowsRemoval(ctx, rel)
}

// flatAllowsRemoval is the flat layout's per-candidate verdict: one fresh
// bounded /input enumeration immediately before the unlink, so a source
// restored at any point up to this check keeps its artifact. A source present
// now keeps every artifact it claims, and a lone private key whose flat stem
// matches keeps the candidate too. The candidate's stem is flat-projected
// first, so a mirror-laid leftover enjoys the same half-deleted-pair veto its
// flat sibling does.
func (rp *reaper) flatAllowsRemoval(ctx context.Context, rel string) (bool, error) {
	inv, err := rp.enumerateFlatInventory(ctx)
	switch {
	case err != nil && IsShutdown(err):
		return false, err
	case err != nil:
		return false, fmt.Errorf("%w: %w", errRecheckIncomplete, err)
	}
	if _, claimed := inv.expected[rel]; claimed {
		slog.Info("keeping an output artifact whose source came back during the confirmation delay",
			"path", logtext.Path(rel))
		return false, nil
	}
	if _, held := inv.loneKeys[layout.FlatStem(layout.OutputStem(rel))]; held {
		slog.Warn(loneKeyRetainedMsg,
			"path", logtext.Path(rel),
			"remediation", loneKeyRemediation(rp.mode))
		return false, nil
	}
	return true, nil
}

// sourceAllowsRemoval performs the post-delay source re-check for one artifact
// of a currently enabled format. The key is read first and the source set last,
// so the fact deciding removal is freshest when the unlink follows. POSIX has no
// atomic multi-path conditional unlink; a source restored after this check can
// still lose its artifact.
func (rp *reaper) sourceAllowsRemoval(ctx context.Context, rel string) (bool, error) {
	stem := layout.OutputStem(rel)
	cert := layout.CertFor(stem)
	keyVeto := rp.keyRetention(rel, cert)
	absent, absentErr := rp.sourcesAbsent(stem)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if absentErr != nil {
		slog.Warn(recheckUnreadableMsg,
			"path", logtext.Path(rel), "input", logtext.Path(cert),
			"error", logtext.Path(absentErr.Error()),
			"remediation", recheckUnreadableRemediation)
		return false, nil
	}
	if !absent {
		slog.Info("keeping an output artifact whose source came back during the confirmation delay",
			"path", logtext.Path(rel), "input", logtext.Path(cert))
		return false, nil
	}
	if keyVeto != nil {
		keyVeto()
		return false, nil
	}
	return true, nil
}

// keyStillPresent vetoes one confirmed candidate's deletion because the sibling PRIVATE
// KEY of its certificate is still under /input, and reports the retention.
func (rp *reaper) keyStillPresent(rel, cert string) bool {
	report := rp.keyRetention(rel, cert)
	if report == nil {
		return false
	}
	report()
	return true
}

// keyRetention reads the sibling PRIVATE KEY of cert and returns the record naming
// the retention it forces, or nil when the key is gone too. The record is returned
// rather than emitted so a caller that reads the key before re-checking the
// certificate still emits it behind that re-check: every record here asserts the
// certificate is gone, which only the certificate's own Lstat establishes.
func (rp *reaper) keyRetention(rel, cert string) func() {
	key := layout.KeyFor(cert)
	// An EXCLUDED pair is not a source, so a half-deleted-pair veto over it means
	// nothing: the operator declared the whole path out of scope, and the veto
	// exists to protect a pair mid-change, not one this app was told to ignore.
	if !rp.exclude.Empty() && (rp.exclude.Excludes(key) || rp.exclude.Excludes(cert)) {
		return nil
	}
	absent, err := rp.src.pathAbsent(key)
	switch {
	case err != nil:
		// Fail closed without claiming a key was observed.
		return func() {
			slog.Warn(recheckUnreadableMsg,
				"path", logtext.Path(rel), "input", logtext.Path(cert), "key", logtext.Path(key),
				"error", logtext.Path(err.Error()),
				"remediation", recheckUnreadableRemediation)
		}
	case absent:
		return nil
	default:
		return func() {
			slog.Warn(loneKeyRetainedMsg,
				"path", logtext.Path(rel), "input", logtext.Path(cert), "key", logtext.Path(key),
				"remediation", loneKeyRemediation(rp.mode))
		}
	}
}

// loneKeyRetainedMsg is the report for an artifact this app is keeping indefinitely
// because its certificate is gone while its private key is not.
const loneKeyRetainedMsg = "keeping an output artifact whose certificate is gone but whose private key is still in /input; a half-written or half-deleted pair is not proof the artifact is orphaned"

// loneKeyRemediationPrefix names both ways out: a pair mid-arrival (finish writing it)
// or one mid-removal (finish removing it) — this app cannot tell which.
const loneKeyRemediationPrefix = "finish the change under /input: add the matching <name>.crt, or remove the leftover <name>.key"

// loneKeyRemediation completes that sentence for the mode this scan is running in.
// Only sync ever deletes, so the other modes need their own tail naming that.
func loneKeyRemediation(mode outputpolicy.Lifecycle) string {
	if mode == outputpolicy.LifecycleSync {
		return loneKeyRemediationPrefix + " so the artifact can be reaped"
	}
	return loneKeyRemediationPrefix + "; OUTPUT_LIFECYCLE=" + string(mode) +
		" never removes an artifact, so this one is kept either way"
}

// recheckUnreadableMsg is the report for an /input presence check that could not be made
// at all: the path answered neither "here" nor ENOENT, which is what an unmounted,
// unreadable or newly permission-changed input tree looks like.
const recheckUnreadableMsg = "keeping an output artifact because its /input path could not be inspected; an unreadable input tree is not proof the artifact is orphaned"

// recheckUnreadableRemediation points at the mount rather than at the pair: nothing under
// /input needs fixing when the tree itself cannot be inspected.
const recheckUnreadableRemediation = "fix the /input mount named in the error (unmounted, permissions, or an unreadable parent), then re-check on the next scan"

// reapAuditMsg is the once-per-scan audit record for deletions this app actually made.
const reapAuditMsg = "removed output artifacts that are no longer requested"

// logReapAudit emits the deletion record, or nothing when nothing was deleted.
func logReapAudit(removed []string) {
	if len(removed) == 0 {
		return
	}
	slog.Warn(reapAuditMsg,
		"count", len(removed), "paths", sampleOrphanPaths(removed),
		"remediation", "expected under OUTPUT_LIFECYCLE=sync; set OUTPUT_LIFECYCLE=warn to have this app report orphans instead of deleting them")
}

// logReapRefusals emits the failure half of the deletion audit, and nothing when
// nothing was refused.
func logReapRefusals(refused []string) {
	if len(refused) == 0 {
		return
	}
	slog.Warn(removalRefusedMsg,
		"count", len(refused), "paths", sampleOrphanPaths(refused),
		"remediation", "review the per-path WARN records from this scan and repair the reported /output layout, non-regular occupant, or permissions")
}

// reapDeferral is how long reconcile waits, ONCE per scan, between identifying
// orphan candidates and deleting them.
const reapDeferral = 30 * time.Second

// waitBeforeReap is reapDeferral's wait, indirected through a package var for the
// same reason writeFileInRoot is: the behaviour cannot be produced in a test otherwise.
var waitBeforeReap = waitForReapDeferral

// waitForReapDeferral waits d, or returns early with the context's error when the
// process starts shutting down inside the window.
func waitForReapDeferral(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// reapRecheckMsg is the line that announces the deferral.
const reapRecheckMsg = "possible orphaned output artifacts; re-checking before deleting anything"

// maxLoggedOrphanBytes caps the rendered orphan sample by bytes: a root-relative path
// can itself be long, and a repeated WARN's worth of them can reach tens of kilobytes.
// The scale is not lost to the cut: every record carrying the sample also carries a
// `count` attribute holding the full total.
const maxLoggedOrphanBytes = 4096

// sampleOrphanPaths renders the orphan paths within maxLoggedOrphanBytes, marking a cut
// sample with logtext.Marker so the log line stays bounded.
func sampleOrphanPaths(paths []string) string {
	return logtext.CapJoin(paths, maxLoggedOrphanBytes)
}

// resolveReap reports whether one scan's lifecycle mode and vetoes let this app delete
// anything.
func resolveReap(mode outputpolicy.Lifecycle, result *ScanResult, walkSafe bool) bool {
	return mode == outputpolicy.LifecycleSync && walkSafe && result.conversionsClean()
}

// retentionProse is the operator wording for a scan that names orphans and deletes
// none of them.
func retentionProse(mode outputpolicy.Lifecycle, walkSafe bool) (inaction, remediation string) {
	if mode == outputpolicy.LifecycleSync || !walkSafe {
		return "kept: this scan could not prove every candidate is orphaned, so deleting could remove a live artifact",
			"do not remove anything from this list yet: fix the /output warnings above, then re-check it on a scan that reports no disabled orphan removal"
	}
	return "reported only (OUTPUT_LIFECYCLE=" + string(mode) + ")",
		"remove them from the output volume, or set OUTPUT_LIFECYCLE=sync to have this app do it"
}

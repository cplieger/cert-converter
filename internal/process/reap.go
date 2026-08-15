package process

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

// reaper reconciles output bundles with one scan's input enumeration.
type reaper struct {
	src *source
	out *store
	// observations is the Scanner's process-lifetime observation log, borrowed for the
	// one thing the reap needs from it: de-duplicating the lone-key retention report
	// per CHANGE rather than per scan (markLoneKey / clearLoneKey).
	observations *observationLog
	mode         outputpolicy.Lifecycle
}

// reapContext is everything the gate needs to decide whether `seen` can be
// trusted as a COMPLETE enumeration of the input tree.
type reapContext struct {
	// result is the scan's own outcome counts, carried whole rather than copied
	// field-by-field: several same-typed ints copied by hand is the transposition this
	// struct exists to prevent, and it is where a new coverage dimension would go
	// missing.
	result ScanResult
	// evidenceEvicted counts pairs whose "this pair was once read whole" evidence the
	// observation log's ceiling dropped during this scan (observationLog.reserveWhole).
	evidenceEvicted int
	walkCompleted   bool
	// shutdown is true when the walk ended because the process is stopping, which
	// is not an operator-actionable incomplete enumeration.
	shutdown bool
}

// evidenceComplete reports whether this scan still holds every piece of in-process
// evidence its own classifications depend on.
func (r *reapContext) evidenceComplete() bool {
	return r.evidenceEvicted == 0
}

// walkEnumerationComplete reports whether nothing PREVENTED the walk from observing
// every /input path: the walk ran to the end and no path was unreadable, unresolved
// or replaced under it.
func (r *reapContext) walkEnumerationComplete() bool {
	return r.walkCompleted && r.result.inputFullyEnumerated()
}

// enumerationClean reports whether nothing PREVENTED the walk from enumerating the
// whole input tree, and nothing spent the in-process evidence this scan's own
// classifications rest on.
func (r *reapContext) enumerationClean() bool {
	return r.walkEnumerationComplete() && r.evidenceComplete()
}

// vanishedOnly reports whether a mid-scan replacement is the ONLY thing that left the
// enumeration incomplete.
func (r *reapContext) vanishedOnly() bool {
	return r.walkCompleted && r.result.durablyEnumerated() && r.evidenceComplete() && r.result.Vanished > 0
}

// enumeratedInput reports whether `seen` can be trusted as a COMPLETE enumeration
// of the input tree.
func (r *reapContext) enumeratedInput() bool {
	return r.enumerationClean() && r.result.Total > 0
}

// reapDisabledPhrase is the substring the README's CertConverterOrphanRemovalDisabled Loki
// rule matches.
const reapDisabledPhrase = "orphan removal is disabled for this scan"

// evictedEvidenceMsg is the report for a scan that disabled orphan removal because the
// observation log's ceiling dropped the wholeness evidence noteMissingKey classifies a
// missing sibling key against.
const evictedEvidenceMsg = reapDisabledPhrase + ": the observation log dropped the evidence that separates a replaced private key from a missing one, so an orphan cannot be proven"

// evictedEvidenceRemediation is that WARN's operator action, and it deliberately does
// NOT lead with the pair count.
const evictedEvidenceRemediation = "clear whatever leaves scans incomplete first - the unreadable-path, " +
	"unresolved-symlink and entry-budget warnings above - because the observation log only " +
	"prunes paths that are gone on a scan that fully enumerates /input; if /input legitimately " +
	"churns certificate paths, raise MAX_SCAN_ENTRIES above the number of distinct paths it has " +
	"held since this container started, not the number it holds now"

// logIncompleteInputEnumeration reports why orphan reconciliation is skipped when
// the input enumeration is incomplete.
func logIncompleteInputEnumeration(rc *reapContext) {
	switch {
	case rc.shutdown:
		slog.Debug("skipping orphan reconciliation; scan cancelled during shutdown")
	case rc.vanishedOnly():
		// A renewal replaced a cert between readdir and the read.
		slog.Debug("skipping orphan reconciliation; input files were replaced during the scan",
			"vanished", rc.result.Vanished)
	case !rc.evidenceComplete():
		// The walk may have enumerated the tree perfectly; what this scan lost is the
		// in-process memory that separates a key being REPLACED right now from a key
		// that was never there.
		slog.Warn(evictedEvidenceMsg,
			"evidence_evicted", rc.evidenceEvicted,
			"remediation", evictedEvidenceRemediation)
	case rc.enumerationClean():
		// A complete walk that found no pair at all: the enumeration did not fail, there
		// is simply nothing to compare the output tree against.
		slog.Debug("skipping orphan reconciliation; the scan found no certificate pairs to compare the output tree against")
	default:
		slog.Warn(reapDisabledPhrase+": the scan did not fully enumerate the input tree, so no output can be proven orphaned",
			"walk_completed", rc.walkCompleted, "unreadable", rc.result.Unreadable,
			"unresolved", rc.result.Unresolved, "vanished", rc.result.Vanished,
			"total", rc.result.Total,
			// Names BOTH ways in, because this arm serves two conditions reapContext cannot
			// tell apart: a walk that could not read part of the tree (unreadable= is
			// non-zero and its own WARN is above), and a walk the entry budget stopped
			// (every count here is zero and the action is the budget, not the mount).
			"remediation", "check the /input mount and the unreadable-path warnings above; "+
				"if the scan stopped at the entry budget, raise MAX_SCAN_ENTRIES instead")
	}
}

// reconcile compares the output tree against the input enumeration and, in sync
// mode, deletes the bundles that no longer have an input.
func (rp *reaper) reconcile(ctx context.Context, seen map[string]struct{}, rc *reapContext) (int, error) {
	if rp.mode == outputpolicy.LifecycleKeep {
		// Keep neither deletes nor reports, so it returns before the output walk
		// rather than through resolveReap, which owns every other mode's decision.
		return 0, nil
	}
	if !rc.enumeratedInput() {
		logIncompleteInputEnumeration(rc)
		return 0, nil
	}
	outputs, walkSafe, err := rp.out.listOutputs(ctx)
	if err != nil {
		if IsShutdown(err) {
			// Shutdown, not a broken output tree.
			slog.Debug("orphan enumeration cancelled during shutdown", "error", err)
			return 0, err
		}
		if errors.Is(err, errOutputBudgetExceeded) {
			// Its own arm, and its own message, because this is a SIZE condition rather
			// than a permission one: the generic WARN below points an operator at /output
			// ownership, which is the wrong action and the wrong diagnosis for a tree that
			// is simply larger than one scan will enumerate.
			slog.Warn(outputBudgetMsg,
				"error", logtext.Path(err.Error()), "dir", logtext.Path(rp.out.root.Name()),
				"remediation", outputBudgetRemediation)
			return 0, nil
		}
		slog.Warn("could not enumerate output orphans; "+reapDisabledPhrase,
			"error", err, "dir", logtext.Path(rp.out.root.Name()),
			"remediation", outputPermRemediation)
		return 0, nil
	}
	orphaned := orphansOf(outputs, seen)
	if len(orphaned) == 0 {
		return 0, nil
	}

	// The enumeration half of the reap-safety question was already answered by the
	// !rc.enumeratedInput() return at the top of this function; what is left to ask
	// is whether this scan's own output work was clean, which resolveReap reads off
	// the result itself.
	d := resolveReap(rp.mode, &rc.result, walkSafe)
	if !d.reap {
		msg := "output bundles have no matching input"
		// In sync mode reaching this line means orphan removal is OFF for this scan,
		// which is the condition the README's CertConverterOrphanRemovalDisabled rule
		// matches, and the README's OUTPUT_LIFECYCLE row promises the phrase for every
		// failed proof term, the conversion-failure and refused-replacement vetoes
		// included.
		if rp.mode == outputpolicy.LifecycleSync {
			msg += "; " + reapDisabledPhrase
		}
		slog.Warn(msg,
			"count", len(orphaned), "paths", sampleOrphanPaths(orphaned),
			"action", d.inaction,
			"remediation", d.remediation)
		// The retention REPORTS are the whole point of this call, which is why it returns
		// no candidate list: OUTPUT_LIFECYCLE forbids a deletion in this arm.
		if walkSafe {
			rp.reportRetainedKeys(orphaned)
		}
		return 0, nil
	}

	return rp.reapConfirmed(ctx, orphaned)
}

// orphansOf selects, from the output tree's own enumeration, the bundles whose input
// certificate the scan did not see — in walk order.
func orphansOf(outputs []string, seen map[string]struct{}) []string {
	var orphaned []string
	for _, rel := range outputs {
		if _, ok := seen[layout.CertForOutput(rel)]; !ok {
			orphaned = append(orphaned, rel)
		}
	}
	return orphaned
}

// reapConfirmed is the deletion half of reconcile: wait reapDeferral ONCE for the whole
// batch, then, per candidate, re-check its INPUT path immediately before deleting that
// candidate's output.
func (rp *reaper) reapConfirmed(ctx context.Context, orphaned []string) (int, error) {
	// The key veto is asked BEFORE the window as well as inside it, and a batch it
	// empties is neither announced nor waited for.
	candidates, prefilterErr := rp.withoutConfirmedLoneKeys(ctx, orphaned)
	if prefilterErr != nil {
		// Shutdown inside the pre-pass, answered BEFORE the empty-batch return below: a
		// batch the pre-pass emptied while cancellation was already active is an
		// interrupted reap, and returning nil there would let the caller report the scan
		// as complete. Same Debug record and same reason as the wait path.
		slog.Debug("orphan removal abandoned during shutdown before the confirming re-check",
			"candidates", len(orphaned), "error", prefilterErr)
		return 0, prefilterErr
	}
	if len(candidates) == 0 {
		return 0, nil
	}
	slog.Info(reapRecheckMsg,
		"count", len(candidates), "recheck_in", reapDeferral.String())
	if err := waitBeforeReap(ctx, reapDeferral); err != nil {
		// Shutdown inside the window: delete nothing further.
		slog.Debug("orphan removal abandoned during shutdown before the confirming re-check",
			"candidates", len(candidates), "error", err)
		return 0, err
	}

	return rp.removeConfirmed(ctx, candidates)
}

// removeConfirmed is reapConfirmed's post-delay half: the interleaved re-check and unlink
// loop, split out only so each function stays inside the package's complexity ceiling.
func (rp *reaper) removeConfirmed(ctx context.Context, candidates []string) (int, error) {
	var deleted int
	var removedPaths, refusedPaths []string
	// Emitted from a defer so BOTH records cover what actually happened on every exit
	// from this loop, including the shutdown return below: a deletion that happened must
	// not go unrecorded because the process stopped afterwards, and neither must a refusal
	// that leaves /output unreconciled.
	defer func() {
		logReapAudit(removedPaths)
		logReapRefusals(refusedPaths)
	}()
	// The index is the remaining-work count's only accurate source: `deleted` counts
	// UNLINKS, so len(candidates)-deleted charges every candidate this loop already
	// examined and legitimately skipped (its certificate came back, its key is still
	// there, or removeOrphan refused) to the work still outstanding.
	for i, rel := range candidates {
		cert := layout.CertForOutput(rel)
		absent, absentErr := rp.src.pathAbsent(cert)
		if err := ctx.Err(); err != nil {
			slog.Debug("orphan removal interrupted by shutdown during the confirming re-check",
				"removed", deleted, "remaining", len(candidates)-i, "error", err)
			return deleted, err
		}
		if absentErr != nil {
			// The re-check could not be made, so this candidate is kept — and the
			// retention is named for what it is.
			slog.Warn(recheckUnreadableMsg,
				"path", logtext.Path(rel), "input", logtext.Path(cert),
				"error", logtext.Path(absentErr.Error()),
				"remediation", recheckUnreadableRemediation)
			continue
		}
		if !absent {
			// Named at the default level: this is the deletion this app decided NOT to
			// make, and it is the only trace that the delay did its job.
			slog.Info("keeping an output bundle whose certificate came back during the confirmation delay",
				"path", logtext.Path(rel), "input", logtext.Path(cert))
			continue
		}
		if rp.keyStillPresent(rel, cert) {
			continue
		}
		// A cancellation between candidates must delete no further key material and must
		// be reported, so the caller classifies the scan as a shutdown rather than a clean
		// reap.
		if err := ctx.Err(); err != nil {
			slog.Debug("orphan removal interrupted by shutdown",
				"removed", deleted, "remaining", len(candidates)-i, "error", err)
			return deleted, err
		}
		switch rp.out.removeOrphan(rel) {
		case reapAttemptRemoved:
			removedPaths = append(removedPaths, rel)
			deleted++
		case reapAttemptRefused:
			refusedPaths = append(refusedPaths, rel)
		case reapAttemptVanished:
			// The producer race removeOrphan already named at Debug.
		}
	}
	return deleted, nil
}

// withoutConfirmedLoneKeys is reapConfirmed's pre-pass: it drops from the batch every
// candidate whose certificate is confirmed absent RIGHT NOW and whose sibling private key
// is still under /input, and it returns cancellation as soon as shutdown arrives.
func (rp *reaper) withoutConfirmedLoneKeys(ctx context.Context, orphaned []string) ([]string, error) {
	var candidates []string
	for _, rel := range orphaned {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cert := layout.CertForOutput(rel)
		absent, absentErr := rp.src.pathAbsent(cert)
		if absentErr != nil || !absent {
			candidates = append(candidates, rel)
			continue
		}
		if rp.keyStillPresent(rel, cert) {
			continue
		}
		candidates = append(candidates, rel)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return candidates, nil
}

// reportRetainedKeys reports, for every bundle in a candidate list, the retention this
// app would refuse to delete because the certificate's sibling private key is still under
// /input (keyStillPresent owns the record).
func (rp *reaper) reportRetainedKeys(orphaned []string) {
	for _, rel := range orphaned {
		rp.keyStillPresent(rel, layout.CertForOutput(rel))
	}
}

// keyStillPresent vetoes one confirmed candidate's deletion because the sibling PRIVATE
// KEY of its certificate is still under /input, and reports the retention.
func (rp *reaper) keyStillPresent(rel, cert string) bool {
	key := layout.KeyFor(cert)
	absent, err := rp.src.pathAbsent(key)
	if err != nil {
		// Fail closed WITHOUT claiming a key was observed: the lone-key WARN below says
		// the private key is still in /input, which is a positive fact this Lstat did
		// not establish.
		if rp.observations.markLoneKey(key) {
			slog.Warn(recheckUnreadableMsg,
				"path", logtext.Path(rel), "input", logtext.Path(cert), "key", logtext.Path(key),
				"error", logtext.Path(err.Error()),
				"remediation", recheckUnreadableRemediation)
		}
		return true
	}
	// The path answered this time, so the uninspectable report is retired whichever way it
	// answered: a later failure at this name is a NEW condition to name.
	rp.observations.clearLoneKey(key)
	if absent {
		// The retention this report describes no longer holds, so retire it HERE: the
		// leftover key is gone, and a half-deleted pair at this name later is a NEW
		// condition to name.
		rp.observations.clearLoneKey(cert)
		return false
	}
	// De-duplicated per CHANGE, not per scan: the retention persists for as long as the
	// operator leaves the pair half-deleted, and this WARN would otherwise repeat on
	// every fsnotify event and every fallback tick.
	if rp.observations.markLoneKey(cert) {
		slog.Warn(loneKeyRetainedMsg,
			"path", logtext.Path(rel), "input", logtext.Path(cert), "key", logtext.Path(key),
			"remediation", loneKeyRemediation)
	}
	return true
}

// loneKeyRetainedMsg is the report for a bundle this app is keeping indefinitely
// because its certificate is gone while its private key is not.
const loneKeyRetainedMsg = "keeping an output bundle whose certificate is gone but whose private key is still in /input; a half-written or half-deleted pair is not proof the bundle is orphaned"

// loneKeyRemediation names both ways out, because this app cannot tell which case it is
// looking at: a pair mid-arrival (finish writing it) or one mid-removal (finish removing
// it).
const loneKeyRemediation = "finish the change under /input: add the matching <name>.crt, or remove the leftover <name>.key so the bundle can be reaped"

// recheckUnreadableMsg is the report for an /input presence check that could not be made
// at all: the path answered neither "here" nor ENOENT, which is what an unmounted,
// unreadable or newly permission-changed input tree looks like.
const recheckUnreadableMsg = "keeping an output bundle because its /input path could not be inspected; an unreadable input tree is not proof the bundle is orphaned"

// recheckUnreadableRemediation points at the mount rather than at the pair: nothing under
// /input needs fixing when the tree itself cannot be inspected.
const recheckUnreadableRemediation = "fix the /input mount named in the error (unmounted, permissions, or an unreadable parent), then re-check on the next scan"

// reapAuditMsg is the once-per-scan audit record for deletions this app actually made.
const reapAuditMsg = "removed output bundles whose input certificates are gone"

// logReapAudit emits that record for a scan that deleted something, and nothing at all
// for a scan that did not: the absence of the record is what "nothing was deleted"
// looks like, so a quiet log stays quiet.
func logReapAudit(removed []string) {
	if len(removed) == 0 {
		return
	}
	slog.Warn(reapAuditMsg,
		"count", len(removed), "paths", sampleOrphanPaths(removed),
		"remediation", "expected under OUTPUT_LIFECYCLE=sync; set OUTPUT_LIFECYCLE=warn to have this app report orphans instead of deleting them")
}

// logReapRefusals emits the failure half of the deletion audit, and nothing at all for a
// scan that was refused nothing, so sync mode reconciling normally stays quiet exactly as
// logReapAudit does for a scan that deleted nothing.
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
// same reason writeFileInRoot is: the behaviour that matters cannot be produced in a test
// otherwise.
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
const reapRecheckMsg = "possible orphaned output bundles; re-checking their certificates before deleting anything"

// maxLoggedOrphans caps how many orphan paths one report names.
const maxLoggedOrphans = 20

// maxLoggedOrphanBytes caps the rendered orphan sample by BYTES, which the item cap
// above does not do: a root-relative path is itself long enough (nested directories,
// long domain names) that maxLoggedOrphans of them can still be tens of kilobytes on
// a WARN that repeats for as long as the orphan exists.
const maxLoggedOrphanBytes = 4096

// sampleOrphanPaths renders at most maxLoggedOrphans paths within
// maxLoggedOrphanBytes, naming how many were elided so the log line stays bounded
// without hiding the scale.
func sampleOrphanPaths(paths []string) string {
	sample, elided := paths, ""
	if len(paths) > maxLoggedOrphans {
		sample = paths[:maxLoggedOrphans]
		elided = fmt.Sprintf(" (+%d more)", len(paths)-maxLoggedOrphans)
	}
	rendered := strings.Join(sample, ",")
	return logtext.Cap(logtext.Path(rendered), maxLoggedOrphanBytes) + elided
}

// reapDecision is the whole OUTPUT_LIFECYCLE decision for one scan: whether this
// app deletes anything, plus the operator wording that goes with not deleting.
type reapDecision struct {
	inaction    string
	remediation string
	reap        bool
}

// resolveReap maps one scan's lifecycle mode and vetoes onto that decision.
func resolveReap(mode outputpolicy.Lifecycle, result *ScanResult, walkSafe bool) reapDecision {
	if mode == outputpolicy.LifecycleSync && walkSafe && result.conversionsClean() {
		return reapDecision{reap: true}
	}
	switch {
	case !walkSafe:
		return reapDecision{
			inaction:    "kept: this scan could not prove every candidate is orphaned, so deleting could remove a live bundle",
			remediation: "do not remove anything from this list yet: fix the /output warnings above, then re-check it on a scan that reports no disabled orphan removal",
		}
	case mode == outputpolicy.LifecycleSync && result.unreplaceableOnly():
		return reapDecision{
			inaction:    "kept: the output volume refused to let this app replace a prior bundle on this scan, so nothing is removed until a scan with no refused replacement",
			remediation: "this app removes them itself on the next scan with no failed conversion and no refused replacement: fix the /output condition named in the warning above, or remove these from the output volume by hand",
		}
	case mode == outputpolicy.LifecycleSync:
		return reapDecision{
			inaction:    "kept: a conversion failed on this scan, so nothing is removed until a scan with no failures",
			remediation: "this app removes them itself on the next scan with no conversion failures: fix the conversion failure reported above, or remove them from the output volume by hand",
		}
	default:
		return reapDecision{
			inaction:    "reported only (OUTPUT_LIFECYCLE=" + string(mode) + ")",
			remediation: "remove them from the output volume, or set OUTPUT_LIFECYCLE=sync to have this app do it",
		}
	}
}

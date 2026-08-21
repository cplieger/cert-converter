package process

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

// reaper reconciles output bundles with one scan's input enumeration.
type reaper struct {
	src  *source
	out  *store
	mode outputpolicy.Lifecycle
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
	slog.Warn(reapDisabledPhrase+": this scan cannot prove any /output bundle is orphaned",
		"walk_completed", rc.walkCompleted, "unreadable", rc.result.Unreadable,
		"unresolved", rc.result.Unresolved, "vanished", rc.result.Vanished,
		"total", rc.result.Total,
		// Names both ways in, because this arm serves all four terms of enumeratedInput
		// and the attributes tell them apart: an incomplete walk (the entry budget, or an
		// abort), a path the walk could not read or resolve, an /input tree holding no
		// certificate pair (total=0, whose own WARN is above), and wholeness evidence the
		// observation log's ceiling evicted, whose action is also MAX_SCAN_ENTRIES.
		"remediation", "check the /input mount and the unreadable-path warnings above; "+
			"if the scan stopped at the entry budget, raise MAX_SCAN_ENTRIES and the container's "+
			"memory limit together, because one scan's memory grows with the total length of the "+
			"paths it enumerates")
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
			slog.Debug("orphan enumeration cancelled during shutdown", "error", logtext.Path(err.Error()))
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
			"error", logtext.Path(err.Error()), "dir", logtext.Path(rp.out.root.Name()),
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
	if !resolveReap(rp.mode, &rc.result, walkSafe) {
		rp.reportRetainedOrphans(orphaned, walkSafe)
		return 0, nil
	}

	return rp.reapConfirmed(ctx, orphaned)
}

// reportRetainedOrphans is reconcile's no-deletion arm: the orphans are named and
// kept, because OUTPUT_LIFECYCLE forbids a deletion for this scan. It deletes
// nothing, so it returns nothing to act on.
func (rp *reaper) reportRetainedOrphans(orphaned []string, walkSafe bool) {
	msg := "output bundles have no matching input"
	// In sync mode reaching this line means orphan removal is OFF for this scan,
	// which is the condition the README's CertConverterOrphanRemovalDisabled rule
	// matches, and the README's OUTPUT_LIFECYCLE row promises the phrase for every
	// failed proof term, the conversion-failure and refused-replacement vetoes
	// included.
	if rp.mode == outputpolicy.LifecycleSync {
		msg += "; " + reapDisabledPhrase
	}
	inaction, remediation := retentionProse(rp.mode, walkSafe)
	slog.Warn(msg,
		"count", len(orphaned), "paths", sampleOrphanPaths(orphaned),
		"action", inaction,
		"remediation", remediation)
	// keyStillPresent owns the half-deleted-pair record; with no deletion to gate,
	// its answer is the report itself. The CERTIFICATE is re-resolved before that record
	// fires, the property the deletion path also holds: `seen` was filled by the input walk
	// before the whole /output walk, so it cannot carry that record's central claim that the
	// certificate is gone by the time the record fires.
	if walkSafe {
		for _, rel := range orphaned {
			cert := layout.CertForOutput(rel)
			absent, err := rp.src.pathAbsent(cert)
			// Deliberately silent on the error: an /input path that cannot be inspected
			// proves neither half of the claim, and the aggregate WARN above has already
			// named this candidate with its count and sample.
			if err != nil || !absent {
				continue
			}
			rp.keyStillPresent(rel, cert)
		}
	}
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
	slog.Info(reapRecheckMsg,
		"count", len(orphaned), "recheck_in", reapDeferral.String())
	if err := waitBeforeReap(ctx, reapDeferral); err != nil {
		// Shutdown inside the window: delete nothing further.
		slog.Debug("orphan removal abandoned during shutdown before the confirming re-check",
			"candidates", len(orphaned), "error", logtext.Path(err.Error()))
		return 0, err
	}

	return rp.removeConfirmed(ctx, orphaned)
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
		// The sibling KEY is read first and the CERTIFICATE last, so the fact that decides
		// orphan-ness is this loop's freshest observation when it unlinks: nothing but a
		// context check stands between the certificate's re-check and the removal. The key
		// veto's record is held back to that same order, because the record asserts the
		// certificate is gone and only the re-check establishes it. The remaining window is
		// ACCEPTED, not closed: POSIX offers no atomic multi-path stat and no conditional
		// unlink, so a certificate restored after the final Lstat still loses its bundle.
		keyVeto := rp.keyRetention(rel, cert)
		absent, absentErr := rp.src.pathAbsent(cert)
		if err := ctx.Err(); err != nil {
			slog.Debug("orphan removal interrupted by shutdown during the confirming re-check",
				"removed", deleted, "remaining", len(candidates)-i, "error", logtext.Path(err.Error()))
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
		if keyVeto != nil {
			keyVeto()
			continue
		}
		// A cancellation between candidates must delete no further key material and must
		// be reported, so the caller classifies the scan as a shutdown rather than a clean
		// reap.
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
			// The producer race removeOrphan already named at Debug.
		}
	}
	return deleted, nil
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

// keyRetention reads the sibling PRIVATE KEY of cert and returns the record that names the
// retention it forces, or nil when the key is gone too and nothing vetoes the deletion.
// The record is returned rather than emitted so a caller that reads the key BEFORE
// re-checking the certificate still emits it behind that re-check: every record here
// asserts the certificate is gone, and only the certificate's own Lstat establishes that.
func (rp *reaper) keyRetention(rel, cert string) func() {
	key := layout.KeyFor(cert)
	absent, err := rp.src.pathAbsent(key)
	switch {
	case err != nil:
		// Fail closed WITHOUT claiming a key was observed: the lone-key WARN below says
		// the private key is still in /input, which is a positive fact this Lstat did
		// not establish.
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

// loneKeyRetainedMsg is the report for a bundle this app is keeping indefinitely
// because its certificate is gone while its private key is not.
const loneKeyRetainedMsg = "keeping an output bundle whose certificate is gone but whose private key is still in /input; a half-written or half-deleted pair is not proof the bundle is orphaned"

// loneKeyRemediationPrefix names both ways out, because this app cannot tell which case it
// is looking at: a pair mid-arrival (finish writing it) or one mid-removal (finish removing
// it). Every mode shares this sentence; only the tail below differs.
const loneKeyRemediationPrefix = "finish the change under /input: add the matching <name>.crt, or remove the leftover <name>.key"

// loneKeyRemediation completes that sentence for the mode this scan is running in. Only
// sync ever deletes, so promising a reap on a mode that never removes a bundle would have
// the operator finish a change for an outcome that cannot follow.
func loneKeyRemediation(mode outputpolicy.Lifecycle) string {
	if mode == outputpolicy.LifecycleSync {
		return loneKeyRemediationPrefix + " so the bundle can be reaped"
	}
	return loneKeyRemediationPrefix + "; OUTPUT_LIFECYCLE=" + string(mode) +
		" never removes a bundle, so this one is kept either way"
}

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

// maxLoggedOrphanBytes caps the rendered orphan sample by BYTES: a root-relative path
// is itself long enough (nested directories, long domain names) that a scan's worth of
// them can be tens of kilobytes on a WARN that repeats for as long as the orphan
// exists. The scale is not lost to the cut: every record carrying the sample carries a
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
// none of them: what this app did, and what the operator can do about it.
func retentionProse(mode outputpolicy.Lifecycle, walkSafe bool) (inaction, remediation string) {
	if mode == outputpolicy.LifecycleSync || !walkSafe {
		return "kept: this scan could not prove every candidate is orphaned, so deleting could remove a live bundle",
			"do not remove anything from this list yet: fix the /output warnings above, then re-check it on a scan that reports no disabled orphan removal"
	}
	return "reported only (OUTPUT_LIFECYCLE=" + string(mode) + ")",
		"remove them from the output volume, or set OUTPUT_LIFECYCLE=sync to have this app do it"
}

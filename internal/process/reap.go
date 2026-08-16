package process

import (
	"context"
	"errors"
	"log/slog"
	"strings"
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
	slog.Warn(reapDisabledPhrase+": the scan did not fully enumerate the input tree, so no output can be proven orphaned",
		"walk_completed", rc.walkCompleted, "unreadable", rc.result.Unreadable,
		"unresolved", rc.result.Unresolved, "vanished", rc.result.Vanished,
		"total", rc.result.Total,
		// Names BOTH ways in, because this arm serves every condition reapContext cannot
		// tell apart: a walk that could not read part of the tree (unreadable= is
		// non-zero and its own WARN is above), and a walk the entry budget stopped
		// (every count here is zero and the action is the budget, not the mount).
		"remediation", "check the /input mount and the unreadable-path warnings above; "+
			"if the scan stopped at the entry budget, raise MAX_SCAN_ENTRIES instead")
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
	if !resolveReap(rp.mode, &rc.result, walkSafe) {
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
		// The retention REPORTS are the whole point of this arm, which is why it deletes
		// nothing: OUTPUT_LIFECYCLE forbids a deletion here. keyStillPresent owns the
		// record; its answer has nothing left to gate.
		if walkSafe {
			for _, rel := range orphaned {
				rp.keyStillPresent(rel, layout.CertForOutput(rel))
			}
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
	slog.Info(reapRecheckMsg,
		"count", len(orphaned), "recheck_in", reapDeferral.String())
	if err := waitBeforeReap(ctx, reapDeferral); err != nil {
		// Shutdown inside the window: delete nothing further.
		slog.Debug("orphan removal abandoned during shutdown before the confirming re-check",
			"candidates", len(orphaned), "error", err)
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

// keyStillPresent vetoes one confirmed candidate's deletion because the sibling PRIVATE
// KEY of its certificate is still under /input, and reports the retention.
func (rp *reaper) keyStillPresent(rel, cert string) bool {
	key := layout.KeyFor(cert)
	absent, err := rp.src.pathAbsent(key)
	if err != nil {
		// Fail closed WITHOUT claiming a key was observed: the lone-key WARN below says
		// the private key is still in /input, which is a positive fact this Lstat did
		// not establish.
		slog.Warn(recheckUnreadableMsg,
			"path", logtext.Path(rel), "input", logtext.Path(cert), "key", logtext.Path(key),
			"error", logtext.Path(err.Error()),
			"remediation", recheckUnreadableRemediation)
		return true
	}
	if absent {
		return false
	}
	slog.Warn(loneKeyRetainedMsg,
		"path", logtext.Path(rel), "input", logtext.Path(cert), "key", logtext.Path(key),
		"remediation", loneKeyRemediation)
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

// maxLoggedOrphanBytes caps the rendered orphan sample by BYTES: a root-relative path
// is itself long enough (nested directories, long domain names) that a scan's worth of
// them can be tens of kilobytes on a WARN that repeats for as long as the orphan
// exists. The scale is not lost to the cut: every record carrying the sample carries a
// `count` attribute holding the full total.
const maxLoggedOrphanBytes = 4096

// sampleOrphanPaths renders the orphan paths within maxLoggedOrphanBytes, marking a cut
// sample with logtext.Marker so the log line stays bounded.
func sampleOrphanPaths(paths []string) string {
	return logtext.Cap(logtext.Path(strings.Join(paths, ",")), maxLoggedOrphanBytes)
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

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

// reaper reconciles output bundles with one scan's input enumeration. It borrows
// both confined roots for the scan and closes neither.
type reaper struct {
	src *source
	out *store
	// observations is the Scanner's process-lifetime observation log, borrowed for the
	// one thing the reap needs from it: de-duplicating the lone-key retention report
	// per CHANGE rather than per scan (markLoneKey / clearLoneKey). It is the same log
	// the walk writes, which is what makes "the pair read whole again" the report's
	// natural reset.
	observations *observationLog
	mode         outputpolicy.Lifecycle
}

// reapContext is everything the gate needs to decide whether `seen` can be
// trusted as a COMPLETE enumeration of the input tree. It is a struct rather than
// positional parameters because every field is a veto and a caller must not
// be able to transpose two of them silently.
type reapContext struct {
	// result is the scan's own outcome counts, carried whole rather than copied
	// field-by-field: several same-typed ints copied by hand is the transposition this
	// struct exists to prevent, and it is where a new coverage dimension would go
	// missing. The veto set itself is spelled once on ScanResult
	// (inputFullyEnumerated / durablyEnumerated), so the predicates below and
	// logInputCoverageWarnings cannot drift apart.
	result ScanResult
	// evidenceEvicted counts pairs whose "this pair was once read whole" evidence the
	// observation log's ceiling dropped during this scan (observationLog.reserveWhole). It
	// is a veto because that evidence is what noteMissingKey uses to classify a
	// missing sibling key: without it a key being replaced right now is recorded as an
	// ordinary orphan, which does NOT block reaping, so this scan would delete other
	// bundles on an enumeration reading it can no longer justify. Failing closed on
	// the loss is the only honest reading — the alternative is trusting evidence the
	// log has just admitted it no longer has.
	//
	// Ahead of the two bools for packing (govet fieldalignment), not by narrative order.
	evidenceEvicted int
	walkCompleted   bool
	// shutdown is true when the walk ended because the process is stopping, which
	// is not an operator-actionable incomplete enumeration.
	shutdown bool
}

// evidenceComplete reports whether this scan still holds every piece of in-process
// evidence its own classifications depend on. It is spelled separately from the
// walk-coverage vetoes because it is about MEMORY rather than about the tree: the walk
// can enumerate /input perfectly and still have lost the wholeness evidence that
// separates a replaced key from an absent one.
func (r *reapContext) evidenceComplete() bool {
	return r.evidenceEvicted == 0
}

// walkEnumerationComplete reports whether nothing PREVENTED the walk from observing
// every /input path: the walk ran to the end and no path was unreadable, unresolved
// or replaced under it. It is the ONE spelling of the walk-coverage veto, separate
// from evidenceComplete because the two are about different things — the TREE versus
// this process's MEMORY — and only the first says anything about whether `seen` is a
// complete enumeration.
func (r *reapContext) walkEnumerationComplete() bool {
	return r.walkCompleted && r.result.inputFullyEnumerated()
}

// enumerationClean reports whether nothing PREVENTED the walk from enumerating the
// whole input tree, and nothing spent the in-process evidence this scan's own
// classifications rest on. Both consumers are in this file: enumeratedInput adds
// result.Total > 0 (an empty tree is clean but gives the output nothing to be
// compared against), and logIncompleteInputEnumeration uses it to tell "nothing to
// compare" from a failed enumeration. Scanner.Run's observation-state prune
// deliberately does NOT compose it: the prune gates on walkEnumerationComplete
// alone, because an eviction does not make the enumeration partial, and gating the
// prune on evidence would let ceiling pressure disable the one mechanism that
// relieves it (the prune's own comment in process.go carries that rationale). Only
// the WALK half is a shared spelling: ScanResult.inputFullyEnumerated is the same
// question logInputCoverageWarnings asks, so a new walk-coverage dimension cannot be
// added to one asker and missed in the other. The evidence half is this file's own;
// logInputCoverageWarnings never sees it (it takes only the ScanResult and the walk
// error, and the evicted-evidence WARN is logIncompleteInputEnumeration's).
func (r *reapContext) enumerationClean() bool {
	return r.walkEnumerationComplete() && r.evidenceComplete()
}

// vanishedOnly reports whether a mid-scan replacement is the ONLY thing that left the
// enumeration incomplete. It exists to split the diagnostic, not the gate: reaping is
// blocked either way, but this shape is an ordinary renewal that the next scan
// resolves by itself, so it must not raise the WARN whose remediation tells the
// operator to check the /input mount. It differs from enumerationClean only in its
// Vanished term, and both compose ScanResult.durablyEnumerated so that shared half is
// spelled once. The evidence term is required here too: a scan that also lost wholeness
// evidence is not "only a renewal", and its operator action is a different one.
func (r *reapContext) vanishedOnly() bool {
	return r.walkCompleted && r.result.durablyEnumerated() && r.evidenceComplete() && r.result.Vanished > 0
}

// enumeratedInput reports whether `seen` can be trusted as a COMPLETE enumeration
// of the input tree. It is the precondition for calling an output an orphan AT ALL,
// not just for deleting one: without it every bundle whose cert the scan never
// reached reads as an orphan.
func (r *reapContext) enumeratedInput() bool {
	return r.enumerationClean() && r.result.Total > 0
}

// reapDisabledPhrase is the substring the README's CertConverterOrphanRemovalDisabled Loki
// rule matches.
// Every record that reports a scan declining to reap composes its message from it, so the
// alert cannot be dropped by rewording one site.
const reapDisabledPhrase = "orphan removal is disabled for this scan"

// evictedEvidenceMsg is the report for a scan that disabled orphan removal because the
// observation log's ceiling dropped the wholeness evidence noteMissingKey classifies a
// missing sibling key against. It is a const because it is the one line that explains an
// otherwise inexplicable steady state — sync mode enabled, orphans present, nothing
// removed — so the emit and the test that pins it cannot drift.
const evictedEvidenceMsg = reapDisabledPhrase + ": the observation log dropped the evidence that separates a replaced private key from a missing one, so an orphan cannot be proven"

// evictedEvidenceRemediation is that WARN's operator action, and it deliberately does
// NOT lead with the pair count. The log's ceiling is MAX_SCAN_ENTRIES and so is the walk
// budget (scanbudget.Effective serves both), while one scan charges at least two entries
// per pair (the .crt and its sibling .key), so a single scan can never fill the ceiling:
// reaching it means the log accumulated entries for paths that are GONE, which
// observationLog.forget prunes on any walk that proves the enumeration complete. The
// first action is therefore to clear whatever leaves scans incomplete; raising the
// ceiling only helps against genuine path churn, and against the count of paths this
// /input has HELD, not the count it holds now.
const evictedEvidenceRemediation = "clear whatever leaves scans incomplete first - the unreadable-path, " +
	"unresolved-symlink and entry-budget warnings above - because the observation log only " +
	"prunes paths that are gone on a scan that fully enumerates /input; if /input legitimately " +
	"churns certificate paths, raise MAX_SCAN_ENTRIES above the number of distinct paths it has " +
	"held since this container started, not the number it holds now"

// logIncompleteInputEnumeration reports why orphan reconciliation is skipped when
// the input enumeration is incomplete. Without a complete enumeration, "this output
// has no matching input" is not a claim the scan can make: a bundle whose cert the
// walk never reached is indistinguishable from one whose cert was deleted.
func logIncompleteInputEnumeration(rc *reapContext) {
	switch {
	case rc.shutdown:
		slog.Debug("skipping orphan reconciliation; scan cancelled during shutdown")
	case rc.vanishedOnly():
		// A renewal replaced a cert between readdir and the read. The enumeration is
		// incomplete, so nothing may be reaped, but the condition is transient and
		// needs no operator action: the WARN below points at the /input mount, which
		// would be the wrong diagnosis for the activity this daemon exists to process.
		slog.Debug("skipping orphan reconciliation; input files were replaced during the scan",
			"vanished", rc.result.Vanished)
	case !rc.evidenceComplete():
		// The walk may have enumerated the tree perfectly; what this scan lost is the
		// in-process memory that separates a key being REPLACED right now from a key
		// that was never there. Its own arm rather than a fold into the Debug arms,
		// because it is neither transient nor about the mount: it recurs on every scan
		// for as long as the tree holds more pairs than the log may remember, and the
		// operator action is the budget, not the /input layout.
		//
		// It is placed BELOW vanishedOnly and still wins over it, because vanishedOnly
		// composes evidenceComplete: a scan that saw a renewal AND lost evidence is not
		// "only a renewal", so it self-vetoes out of that arm and falls through here.
		// Dropping that term (or reordering these cases) would report this condition as
		// the transient Debug line and lose the only remediation an operator gets.
		slog.Warn(evictedEvidenceMsg,
			"evidence_evicted", rc.evidenceEvicted,
			"remediation", evictedEvidenceRemediation)
	case rc.enumerationClean():
		// A complete walk that found no pair at all: the enumeration did not fail, there
		// is simply nothing to compare the output tree against. logInputCoverageWarnings
		// already names this at WARN with the /input-mount remediation, and the operator
		// alert on "orphan removal is disabled for this scan" points at /output, so
		// repeating it here would fire that alert with the wrong diagnosis on every scan
		// of a deployment whose first certificate has not been issued yet.
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
// mode, deletes the bundles that no longer have an input. It returns how many were
// removed plus a cancellation error when the process is shutting down: the walk
// caller folds that error into the scan's outcome, so a scan interrupted after the
// input walk finished is not reported as a clean, complete scan.
//
// A deletion is never made on the strength of this scan's snapshot alone. Once the
// vetoes are passed, reapConfirmed defers the batch by reapDeferral and re-checks
// each candidate's certificate through rp.src, so an input observed mid-replacement
// keeps its bundle. rp.src is the input side of the same scan `seen` came from.
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
			// Shutdown, not a broken output tree. The input walk usually reports the
			// cancellation itself, but not when it finished cleanly before the signal
			// arrived, so the error is returned here too rather than only logged.
			slog.Debug("orphan enumeration cancelled during shutdown", "error", err)
			return 0, err
		}
		if errors.Is(err, errOutputBudgetExceeded) {
			// Its own arm, and its own message, because this is a SIZE condition rather
			// than a permission one: the generic WARN below points an operator at /output
			// ownership, which is the wrong action and the wrong diagnosis for a tree that
			// is simply larger than one scan will enumerate. Health-neutral like the /input
			// budget and for the same reason — no restart makes the tree smaller — and
			// carrying reapDisabledPhrase so the standing alert still fires: a budget that
			// bit silently would look exactly like an /output with nothing to reap.
			slog.Warn(outputBudgetMsg,
				"error", err, "dir", logtext.Path(rp.out.root.Name()),
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
	// is whether this scan's own output work was clean.
	reapable := rc.result.conversionsClean() && walkSafe
	d := resolveReap(rp.mode, reapable, walkSafe, rc.result.unreplaceableOnly())
	if !d.reap {
		msg := "output bundles have no matching input"
		// In sync mode reaching this line means orphan removal is OFF for this scan,
		// which is the condition the README's CertConverterOrphanRemovalDisabled rule
		// matches, and the README's OUTPUT_LIFECYCLE row promises the phrase for every
		// failed proof term, the conversion-failure and refused-replacement vetoes
		// included. The report-only modes reach this line as their normal feature, so
		// they must not compose it. On !walkSafe, logOrphanWalkOutcome has already
		// emitted a phrase-carrying WARN; a second occurrence in one scan is harmless
		// to a count_over_time rule.
		if rp.mode == outputpolicy.LifecycleSync {
			msg += "; " + reapDisabledPhrase
		}
		slog.Warn(msg,
			"count", len(orphaned), "paths", sampleOrphanPaths(orphaned),
			"action", d.inaction,
			"remediation", d.remediation)
		rp.reportRetainedLoneKeys(orphaned, walkSafe)
		return 0, nil
	}

	return rp.reapConfirmed(ctx, orphaned)
}

// orphansOf selects, from the output tree's own enumeration, the bundles whose input
// certificate the scan did not see — in walk order.
//
// It lives here rather than on the store because the claim it makes spans BOTH trees
// ("this /output bundle has no /input certificate"), which is the whole reason this
// type exists: the store enumerates the output tree, and every cross-tree admission
// decision is made in one place. seen is the set of input .crt paths a COMPLETE walk
// found; reconcile has already refused to get this far without one. layout owns both
// directions of the naming contract, so the reverse derivation cannot drift from the
// forward one used at write time.
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
// candidate's output. Split out so reconcile's gate reads as a sequence of refusals with
// one tail call, rather than carrying the delay's own three outcomes inline.
//
// One wait for the batch, not one per candidate: the window is about wall-clock time
// passing, not about the individual path, so waiting per orphan would make a tree with
// twenty of them cost two hundred seconds on the scan's only goroutine.
//
// The re-check is INTERLEAVED with the deletions rather than run as a batch pass ahead
// of them, and that ordering is the safety property: the absence observation that
// authorizes a destructive action must be immediately coupled to that action. A batch
// confirmation pass would let a later candidate's check widen the first candidate's
// stale-observation window, so a certificate restored after its own check but before the
// unlink would lose its live bundle.
//
// The re-check goes through the same confined input root the scan itself reads through,
// so a symlink planted under /input cannot make an unrelated path answer for a
// candidate. It asks TWO questions of each candidate, not one: is the certificate still
// absent, and is its sibling private key absent too (keyStillPresent). The certificate
// alone cannot tell a deleted pair from one being written key-first.
//
// A certificate that came back cancels that one deletion and nothing else: it is the
// ordinary producer transaction this delay exists for, not an error, so it does not fail
// the scan, does not affect health, and leaves every other candidate reapable. A
// cancellation during the wait, or between candidates, abandons the rest of the reap and
// is returned to the caller, which is what keeps an interrupted scan from being reported
// as complete.
func (rp *reaper) reapConfirmed(ctx context.Context, orphaned []string) (int, error) {
	slog.Info(reapRecheckMsg,
		"count", len(orphaned), "recheck_in", reapDeferral.String())
	if err := waitBeforeReap(ctx, reapDeferral); err != nil {
		// Shutdown inside the window: delete nothing further. Debug like the other
		// interrupted paths here, because the error itself is returned and the caller
		// reports the cancellation.
		slog.Debug("orphan removal abandoned during shutdown before the confirming re-check",
			"candidates", len(orphaned), "error", err)
		return 0, err
	}

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
	// UNLINKS, so len(orphaned)-deleted charges every candidate this loop already
	// examined and legitimately skipped (its certificate came back, its key is still
	// there, or removeOrphan refused) to the work still outstanding. Both shutdown
	// guards below abandon the loop BEFORE candidate i's unlink, so the candidates that
	// remain are i and everything after it.
	for i, rel := range orphaned {
		cert := layout.CertForOutput(rel)
		absent, absentErr := rp.src.pathAbsent(cert)
		if err := ctx.Err(); err != nil {
			slog.Debug("orphan removal interrupted by shutdown during the confirming re-check",
				"removed", deleted, "remaining", len(orphaned)-i, "error", err)
			return deleted, err
		}
		if absentErr != nil {
			// The re-check could not be made, so this candidate is kept — and the
			// retention is named for what it is. The INFO below must NOT be reached
			// here: reporting an uninspectable /input as "the certificate came back"
			// tells the operator the producer is working when the mount is not, and at
			// LOG_LEVEL=warn it reports nothing at all while the stale bundle stays.
			slog.Warn(recheckUnreadableMsg,
				"path", logtext.Path(rel), "input", logtext.Path(cert), "error", absentErr,
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
		// The shutdown guard the removal helper used to own, inlined at the only place
		// it ever ran: a cancellation between candidates must delete no further key
		// material and must be reported, so the caller classifies the scan as a
		// shutdown rather than a clean reap. It stays immediately before the unlink,
		// because cancellation can arrive during keyStillPresent. Same attributes and
		// same remaining-work arithmetic as its sibling guard above — two records for
		// one condition in one loop must not disagree about what they are counting.
		if err := ctx.Err(); err != nil {
			slog.Debug("orphan removal interrupted by shutdown",
				"removed", deleted, "remaining", len(orphaned)-i, "error", err)
			return deleted, err
		}
		switch rp.out.removeOrphan(rel) {
		case reapAttemptRemoved:
			removedPaths = append(removedPaths, rel)
			deleted++
		case reapAttemptRefused:
			refusedPaths = append(refusedPaths, rel)
		case reapAttemptVanished:
			// The producer race removeOrphan already named at Debug. Nothing to
			// aggregate: counting it would report a bundle that is gone as one this
			// app failed to remove.
		}
	}
	return deleted, nil
}

// reportRetainedLoneKeys names, on a scan that REPORTS orphans instead of deleting
// them, every candidate the sync path would refuse to delete because the certificate's
// sibling private key is still under /input.
//
// Without it this app's own promise — "a bundle whose <name>.key is still there is kept
// and reported by its own WARN" (README, OUTPUT_LIFECYCLE) — holds only under
// OUTPUT_LIFECYCLE=sync, so the DEFAULT warn mode reports the bundle as an ordinary
// orphan and its remediation offers sync, which would not delete it either. The report
// is de-duplicated per CHANGE by the same observation-log set the reap path uses, so it
// does not repeat on every fsnotify event and fallback tick.
//
// An OUTPUT walk that could not enumerate the tree is skipped for the same reason
// resolveReap withholds its delete advice on it: that candidate list can
// hold live bundles, so naming one of them as a half-deleted pair would be a wrong
// diagnosis. On a trustworthy list the input enumeration was proven complete, so every
// candidate's certificate really is gone and the only open question is the key.
func (rp *reaper) reportRetainedLoneKeys(orphaned []string, walkSafe bool) {
	if !walkSafe {
		return
	}
	for _, rel := range orphaned {
		_ = rp.keyStillPresent(rel, layout.CertForOutput(rel))
	}
}

// keyStillPresent vetoes one confirmed candidate's deletion because the sibling PRIVATE
// KEY of its certificate is still under /input, and reports the retention.
//
// The certificate check alone is not enough on the only path in this app that deletes
// private-key material. reapConfirmed waits reapDeferral and then asks whether the
// certificate came back; a producer that writes the pair in two steps MORE than 30
// seconds apart (a key written first, its certificate minutes later — an rsync of a
// large tree, a manual install, a slow network mount) presents exactly the same
// observation as a deleted certificate, and the live bundle was removed. The key is the
// second, independent piece of evidence: a pair whose key is still there is a pair
// somebody is still keeping, not one that was deleted.
//
// The 30-second confirmation is KEPT rather than widened to a one-scan grace, which was
// considered and rejected for two reasons worth recording here: a grace window would lag
// an INTENTIONAL deletion by up to FALLBACK_SCAN_HOURS, and while it stood an old PFX
// would coexist with a newly arrived certificate, so a consumer could read the stale
// bundle. Vetoing on the key costs nothing when the deletion is genuine (both halves are
// gone, so nothing vetoes) and refuses only the half-deleted pair.
//
// The key is asked for through the SAME confined input root and with the SAME ENOENT-only
// semantics as the certificate (source.pathAbsent, one primitive, so the two questions
// cannot drift): only an ENOENT counts as "no key". Any OTHER entry at the key path — a
// regular file, a directory, a FIFO, a symlink whose target does not resolve — counts as
// a key that is still there and vetoes the deletion, because the caller unlinks private
// key material on the other answer and an unreadable-or-odd occupant is not evidence
// that the operator removed the key. It never counts SILENTLY: the retention is reported
// below, which is what turns a stray directory at a key path from an invisible
// never-reaped bundle into a named condition.
//
// A key path the Lstat could not classify AT ALL — an unmounted or unreadable /input —
// vetoes the deletion on the same fail-closed reading, but is reported by its OWN record
// (recheckUnreadableMsg): the lone-key WARN below asserts the private key is still there,
// and that is a positive observation a failed Lstat did not make.
func (rp *reaper) keyStillPresent(rel, cert string) bool {
	key := layout.KeyFor(cert)
	absent, err := rp.src.pathAbsent(key)
	if err != nil {
		// Fail closed WITHOUT claiming a key was observed: the lone-key WARN below says
		// the private key is still in /input, which is a positive fact this Lstat did
		// not establish. Name the uninspectable path instead, and keep the bundle.
		//
		// De-duplicated per CHANGE like the lone-key WARN below, and for the same reason:
		// reportRetainedLoneKeys reaches this arm on every scan in the default warn mode,
		// so an unreadable /input sub-directory would otherwise re-report every candidate
		// under it on every fsnotify event and fallback tick. Keyed on the KEY path, which
		// no cert path can collide with, so the two reports retire independently.
		if rp.observations.markLoneKey(key) {
			slog.Warn(recheckUnreadableMsg,
				"path", logtext.Path(rel), "input", logtext.Path(cert), "key", logtext.Path(key), "error", err,
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
		// condition to name. Retiring it on the DELETION instead left it un-retired in
		// every mode that does not delete — warn is the default — so one report per
		// name lasted the process lifetime.
		rp.observations.clearLoneKey(cert)
		return false
	}
	// De-duplicated per CHANGE, not per scan: the retention persists for as long as the
	// operator leaves the pair half-deleted, and this WARN would otherwise repeat on
	// every fsnotify event and every fallback tick. It is retired by whichever change
	// ends the retention: observationLog.markWhole when the pair reads whole again, and
	// the absent-key arm above when the leftover key goes — whether or not this app is
	// the thing that then deletes the bundle.
	if rp.observations.markLoneKey(cert) {
		slog.Warn(loneKeyRetainedMsg,
			"path", logtext.Path(rel), "input", logtext.Path(cert), "key", logtext.Path(key),
			"remediation", loneKeyRemediation)
	}
	return true
}

// loneKeyRetainedMsg is the report for a bundle this app is keeping indefinitely
// because its certificate is gone while its private key is not. Nothing else in this
// app names a lone key at any level, so without this record the retention is invisible:
// the bundle is not converted (there is no certificate), not reaped (the key vetoes it),
// and counted in nothing.
const loneKeyRetainedMsg = "keeping an output bundle whose certificate is gone but whose private key is still in /input; a half-written or half-deleted pair is not proof the bundle is orphaned"

// loneKeyRemediation names both ways out, because this app cannot tell which case it is
// looking at: a pair mid-arrival (finish writing it) or one mid-removal (finish removing
// it).
const loneKeyRemediation = "finish the change under /input: add the matching <name>.crt, or remove the leftover <name>.key so the bundle can be reaped"

// recheckUnreadableMsg is the report for an /input presence check that could not be made
// at all: the path answered neither "here" nor ENOENT, which is what an unmounted,
// unreadable or newly permission-changed input tree looks like.
//
// It is its own record rather than a reuse of the two positive ones, because those state
// facts this failure did not establish — that the certificate came back, or that the
// private key is still there. The bundle is kept either way (an unanswerable question
// never authorizes deleting key material), so the only thing at stake is whether the
// operator can tell WHY, and the certificate arm previously said nothing at
// LOG_LEVEL=warn while the stale bundle stayed on disk.
//
// The wording names the RETENTION and not a pending removal, because both callers share
// it: sync's confirming re-check, where a deletion was indeed being considered, and
// reportRetainedLoneKeys in the report-only modes, where OUTPUT_LIFECYCLE forbids one. An
// operator diagnosing an unreadable input tree in warn or keep mode must not be told this
// app was preparing to delete key material.
const recheckUnreadableMsg = "keeping an output bundle because its /input path could not be inspected; an unreadable input tree is not proof the bundle is orphaned"

// recheckUnreadableRemediation points at the mount rather than at the pair: nothing under
// /input needs fixing when the tree itself cannot be inspected.
const recheckUnreadableRemediation = "fix the /input mount named in the error (unmounted, permissions, or an unreadable parent), then re-check on the next scan"

// reapAuditMsg is the once-per-scan audit record for deletions this app actually made.
//
// It is WARN rather than Info because of what it reports: every path in it held private
// key material that no longer exists. At LOG_LEVEL=warn the failures of orphan removal
// were loud while its successes were silent, which is the wrong way round for the one
// destructive action this app takes. One record per deletion-bearing scan rather than
// one per path keeps that visibility from becoming a log stream on a tree that lost many
// certificates at once, and it reuses the orphan report's own bounded sample
// (sampleOrphanPaths: at most maxLoggedOrphans paths within maxLoggedOrphanBytes) so the
// record cannot grow without limit.
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
//
// It exists because the per-candidate refusals removeOrphan logs carry no COUNT and no
// phrase any documented rule matches, while ScanResult.Removed reports 0 for a scan whose
// every unlink was refused — the same 0 a scan with nothing to reap reports. Without this
// record an /output subtree the UID cannot write stops reconciliation permanently, with
// health green and nothing countable to alert on.
//
// It reuses the orphan report's own bounded sample (sampleOrphanPaths: at most
// maxLoggedOrphans paths within maxLoggedOrphanBytes) so the record cannot grow without
// limit. Its remediation is deliberately cause-NEUTRAL: refusedPaths collects three
// unrelated shapes (a permission denial, an OpenParentInRoot layout refusal, and a
// non-regular occupant at an output name), each of which already logged its own
// cause-specific action per path, so naming any one of them here would send the operator
// after the wrong cause for the other two.
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
//
// It exists because none of the reap vetoes asks whether an input's absence is
// DURABLE, and the scan most likely to observe /input mid-transition is the one a
// deletion itself scheduled: internal/watch requests a rescan on any Remove and the
// debounce is 2s, so a producer that replaces a certificate by unlink-then-write (or
// an rsync --delete-before) can be observed between the two steps. The bundle would
// then be deleted and regenerated with fresh KDF salts and a fresh mtime, which is
// the downstream re-replication output-derived currency exists to prevent.
//
// The value balances two costs that are not symmetric. Waiting LONGER covers a slower
// producer transaction: a local unlink-then-write closes in milliseconds, but a
// network-mounted /input, an rsync that deletes before it transfers, or a `docker cp`
// of a whole tree can take seconds. Waiting longer costs only latency on work nobody
// is waiting for — the reap runs after this scan's conversions, so the delay defers
// deletions, plus at most one window of the NEXT scan on a daemon whose certificates
// renew every few weeks. Thirty seconds sits well past the realistic producer window
// and far below anything an operator would read as a stall: deliberately not minutes,
// because the wait blocks the scan's only goroutine, and deliberately not a couple of
// seconds, because that is the same order as the watcher's own 2s debounce and would
// cover little more than a local rewrite.
//
// Nothing here is a guarantee: a producer whose transaction outlasts the window is
// still observed mid-replacement. The window narrows the race; the vetoes above, the
// audit line on every deletion, and OUTPUT_LIFECYCLE=warn are what bound the
// consequence.
const reapDeferral = 30 * time.Second

// waitBeforeReap is reapDeferral's wait, indirected through a package var for the
// same reason writeFileInRoot is: the behaviour that matters cannot be produced in a test
// otherwise. Here it is the delay itself — a suite that really waited reapDeferral per
// case would cost minutes — plus the two edges the wait owns (a shutdown arriving
// inside the window, and the batch waiting once rather than once per orphan).
//
// It returns the context's error when cancellation wins, so the caller abandons the
// reap instead of running it to completion on the way out.
var waitBeforeReap = waitForReapDeferral

// waitForReapDeferral waits d, or returns early with the context's error when the
// process starts shutting down inside the window. It is a named function so the
// contract stays testable even where waitBeforeReap has been swapped.
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

// reapRecheckMsg is the line that announces the deferral. It is a const because it is
// the one message an operator correlates with a pause in the log and with every
// deletion that follows it, so the two call sites that matter — the emit and the test
// that pins the wording — cannot drift.
const reapRecheckMsg = "possible orphaned output bundles; re-checking their certificates before deleting anything"

// maxLoggedOrphans caps how many orphan paths one report names. The count is the
// actionable number; the paths are a sample, and an unbounded list on a per-scan
// WARN is a permanent multi-kilobyte log line.
const maxLoggedOrphans = 20

// maxLoggedOrphanBytes caps the rendered orphan sample by BYTES, which the item cap
// above does not do: a root-relative path is itself long enough (nested directories,
// long domain names) that maxLoggedOrphans of them can still be tens of kilobytes on
// a WARN that repeats for as long as the orphan exists. The budget is generous enough
// to name a realistic sample in full — 20 typical bundle paths are a few hundred bytes
// — so it only ever engages on the pathological tree.
const maxLoggedOrphanBytes = 4096

// sampleOrphanPaths renders at most maxLoggedOrphans paths within
// maxLoggedOrphanBytes, naming how many were elided so the log line stays bounded
// without hiding the scale.
//
// The two caps compose because they bound different things and neither implies the
// other: the ITEM cap keeps the sample readable, and the BYTE cap keeps the record
// small. An item cap alone is not a size bound, because one root-relative path is
// itself only bounded by the filesystem's own limits, so 20 deeply nested names can
// still be tens of kilobytes on a WARN that repeats every scan for as long as the
// orphan exists.
//
// The byte cut runs on the JOINED sample (that is what the budget is about) through
// logtext.Cap, which backs the cut off to a rune start so a multi-byte name is
// never cut into a partial rune. The sample is SANITIZED first and cut second
// (logtext.Path, then logtext.Cap), and that order is the whole reason the two steps
// are separate calls rather than one sanitize-and-cap primitive: /output is untrusted
// — this is a public image, so a co-writer on that mount chooses the names this walk
// enumerates, and a name holding CR/LF or a bidi control would forge or reorder a
// record here. Sanitizing is byte-identical for an ordinary bundle name, so the
// operator's query key for which bundles were reported is unchanged. A capped
// sanitizing primitive would charge its marker AGAINST the limit instead of appending
// it, and this function's own elision suffix below was budgeted against Cap's
// placement.
//
// Both suffixes are appended AFTER the cut, so a truncated sample exceeds the budget
// by their own length: the bound exists to stop a multi-kilobyte record, not to hit
// the budget exactly. The elision notice keeps its place at the very end, and the
// count of orphans is a separate attribute on the same record, so the scale survives
// either cut.
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
// app deletes anything, plus the operator wording that goes with not deleting. The
// two strings are resolved next to the deletion they explain, and next to each other,
// so the agreement between them is a property of one switch arm rather than something
// maintained by hand across two parallel mappings.
type reapDecision struct {
	inaction    string
	remediation string
	reap        bool
}

// resolveReap maps one scan's lifecycle mode and vetoes onto that decision. It is
// the single home for the mode -> action ranking: reconcile branches on the resolved
// decision rather than re-deriving the ranking beside its own report, so a fourth
// mode or a moved veto is one edit here instead of three that can disagree. The
// narration is only resolved when nothing is deleted; a reaping scan needs neither
// string.
//
// Four independent reasons can hold the reap back and the mode alone does not pick
// between them, so each gets one arm, strongest first, and each arm pairs the reason
// with the advice that clears it:
//
// An OUTPUT walk that could not enumerate the tree makes the LIST itself
// untrustworthy, so the advice withholds removal entirely: the candidate list then
// holds live bundles — a bundle written through a symlinked output directory is
// enumerated under its physical path, whose derived input name is absent from `seen`,
// so it reads as an orphan on the very scan that created it — and every entry in the
// list carries a private key.
//
// The refused REPLACEMENT (ScanResult.Unwritable, via conversionsClean) is a veto of
// its own and ranks ahead of the conversion-failure arm: it logs no conversion failure
// anywhere, so telling the operator one failed contradicts the same scan's failed=0
// summary, and it is cleared on the output volume — ownership, free space, a
// read-write remount, whichever the standing WARN named — rather than by fixing a
// conversion. That WARN is where the errno is known, so the advice sends the operator
// there instead of naming the condition a second time.
//
// Otherwise, in sync mode, the list is trustworthy — the input enumeration was
// complete, or reconcile would have returned earlier — and this app is only
// withholding its own deletion until a scan with no conversion failures.
//
// A non-sync mode is report-only and is the default arm, which is also why it must not
// outrank the two vetoes above: their wording promises removal on the next clean scan,
// which a mode that never removes anything cannot deliver, and the advice must not
// offer a setting that is already in effect.
//
// The sync arms need no separate reapable term: a sync scan that is reapable returns
// above, so every arm below is a scan that keeps its candidates.
func resolveReap(mode outputpolicy.Lifecycle, reapable, walkSafe, refusalOnly bool) reapDecision {
	// reapable already carries walkSafe: reconcile computes it as
	// `rc.result.conversionsClean() && walkSafe` at the single call site, so an untrustworthy output
	// walk has already forced it false. walkSafe stays a parameter because the narration
	// below distinguishes it from the other vetoes.
	if mode == outputpolicy.LifecycleSync && reapable {
		return reapDecision{reap: true}
	}
	switch {
	case !walkSafe:
		return reapDecision{
			inaction:    "kept: this scan could not prove every candidate is orphaned, so deleting could remove a live bundle",
			remediation: "do not remove anything from this list yet: fix the /output warnings above, then re-check it on a scan that reports no disabled orphan removal",
		}
	case mode == outputpolicy.LifecycleSync && refusalOnly:
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

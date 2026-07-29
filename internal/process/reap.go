package process

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

// reaper owns OUTPUT_LIFECYCLE reconciliation: deciding whether an output bundle
// whose input is gone may be deleted, and deleting it.
//
// It depends on BOTH boundary owners rather than living inside either, the way
// scanWalk already does. The claim behind every deletion spans the two trees ("this
// /output bundle has no /input certificate"), so it belongs to neither the input
// reader nor the output store: keeping it here leaves store owning exactly what it
// advertises — every touch of the output tree — while the /output primitives the reap
// needs (orphans, removeOrphans) stay on the store as the output-tree operations
// they are, called through rp.out.
//
// The OUTPUT_LIFECYCLE value domain itself (the Lifecycle type, its three modes and
// their parse) lives in internal/outputpolicy, which this package consumes: the
// operator's raw value is read and normalised by internal/config, and keeping the
// enum here put that configuration layer above the orchestrator. What follows is
// this package's own half — acting on an already-parsed mode across both trees.
//
// Scanner.Run constructs it, beside the scanWalk that already holds both roots and
// the injected Options. A reaper lasts one scan and closes neither root.
type reaper struct {
	src  *source
	out  *store
	mode outputpolicy.Lifecycle
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
	result        ScanResult
	walkCompleted bool
	// shutdown is true when the walk ended because the process is stopping, which
	// is not an operator-actionable incomplete enumeration.
	shutdown bool
}

// enumerationClean reports whether nothing PREVENTED the walk from enumerating the
// whole input tree. It is the shared half of two decisions that differ by one term:
// enumeratedInput adds result.Total > 0 (an empty tree is clean but gives the output
// nothing to be compared against), while Scanner.Run's observation-state prune does
// not. The veto set is ScanResult.inputFullyEnumerated, the same one
// logInputCoverageWarnings asks, so a new veto dimension cannot be added to one
// caller and missed in the other.
func (r *reapContext) enumerationClean() bool {
	return r.walkCompleted && r.result.inputFullyEnumerated()
}

// vanishedOnly reports whether a mid-scan replacement is the ONLY thing that left the
// enumeration incomplete. It exists to split the diagnostic, not the gate: reaping is
// blocked either way, but this shape is an ordinary renewal that the next scan
// resolves by itself, so it must not raise the WARN whose remediation tells the
// operator to check the /input mount. It differs from enumerationClean only in its
// Vanished term, and both compose ScanResult.durablyEnumerated so that shared half is
// spelled once.
func (r *reapContext) vanishedOnly() bool {
	return r.walkCompleted && r.result.durablyEnumerated() && r.result.Vanished > 0
}

// enumeratedInput reports whether `seen` can be trusted as a COMPLETE enumeration
// of the input tree. It is the precondition for calling an output an orphan AT ALL,
// not just for deleting one: without it every bundle whose cert the scan never
// reached reads as an orphan.
func (r *reapContext) enumeratedInput() bool {
	return r.enumerationClean() && r.result.Total > 0
}

// safeToReap reports whether the input enumeration is complete enough, and this
// scan's own output work clean enough, to justify deleting anything.
func (r *reapContext) safeToReap() bool {
	return r.enumeratedInput() && r.result.conversionsClean()
}

// permissionRefusalOnly reports whether the only thing this scan is still trying to
// repair on the output tree is a REFUSED PERMISSION REPAIR rather than a failed
// conversion. The two need different operator advice: a conversion failure is
// reported as one and can be fixed, while a refused repair is reported by
// unwritableBundleMsg and is cleared by chowning /output, not by fixing a conversion
// nothing logged.
func (r *reapContext) permissionRefusalOnly() bool {
	return r.result.Failed == 0 && r.result.Unwritable > 0
}

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
	case rc.enumerationClean():
		// A complete walk that found no pair at all: the enumeration did not fail, there
		// is simply nothing to compare the output tree against. logInputCoverageWarnings
		// already names this at WARN with the /input-mount remediation, and the operator
		// alert on "orphan removal is disabled for this scan" points at /output, so
		// repeating it here would fire that alert with the wrong diagnosis on every scan
		// of a deployment whose first certificate has not been issued yet.
		slog.Debug("skipping orphan reconciliation; the scan found no certificate pairs to compare the output tree against")
	default:
		slog.Warn("orphan removal is disabled for this scan: the scan did not fully enumerate the input tree, so no output can be proven orphaned",
			"walk_completed", rc.walkCompleted, "unreadable", rc.result.Unreadable,
			"unresolved", rc.result.Unresolved, "vanished", rc.result.Vanished,
			"total", rc.result.Total,
			"remediation", "check the /input mount and the unreadable-path warnings above")
	}
}

// reconcile compares the output tree against the input enumeration and, in sync
// mode, deletes the bundles that no longer have an input. It returns how many were
// removed plus a cancellation error when the process is shutting down: the walk
// caller folds that error into the scan's outcome, so a scan interrupted after the
// input walk finished is not reported as a clean, complete scan.
//
// A deletion is never made on the strength of this scan's snapshot alone. Once the
// vetoes are passed, confirmOrphans defers the batch by reapDeferral and re-checks
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
	orphaned, walkSafe, err := rp.out.orphans(ctx, seen)
	if err != nil {
		if IsShutdown(err) {
			// Shutdown, not a broken output tree. The input walk usually reports the
			// cancellation itself, but not when it finished cleanly before the signal
			// arrived, so the error is returned here too rather than only logged.
			slog.Debug("orphan enumeration cancelled during shutdown", "error", err)
			return 0, err
		}
		slog.Warn("could not enumerate output orphans; orphan removal is disabled for this scan",
			"error", err, "dir", rp.out.root.Name(),
			"remediation", outputPermRemediation)
		return 0, nil
	}
	if len(orphaned) == 0 {
		return 0, nil
	}

	reapable := rc.safeToReap() && walkSafe
	d := resolveReap(rp.mode, reapable, walkSafe, rc.permissionRefusalOnly())
	if !d.reap {
		slog.Warn("output bundles have no matching input",
			"count", len(orphaned), "paths", sampleOrphanPaths(orphaned),
			"action", d.inaction,
			"remediation", d.remediation)
		return 0, nil
	}

	return rp.reapConfirmed(ctx, orphaned)
}

// reapConfirmed is the deletion half of reconcile: confirm the batch after the
// deferral, then remove what is still orphaned. Split out so reconcile's gate reads
// as a sequence of refusals with one tail call, rather than carrying the delay's own
// three outcomes inline.
func (rp *reaper) reapConfirmed(ctx context.Context, orphaned []string) (int, error) {
	confirmed, err := rp.confirmOrphans(ctx, orphaned)
	if err != nil {
		return 0, err
	}
	if len(confirmed) == 0 {
		return 0, nil
	}
	return rp.out.removeOrphans(ctx, confirmed)
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
// same reason chmodInRoot is: the behaviour that matters cannot be produced in a test
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

// confirmOrphans waits reapDeferral once for the whole batch, then re-checks each
// candidate's INPUT path and returns only the candidates whose certificate is STILL
// absent.
//
// One wait for the batch, not one per candidate: the window is about wall-clock time
// passing, not about the individual path, so waiting per orphan would make a tree
// with twenty of them cost two hundred seconds on the scan's only goroutine.
//
// The re-check goes through the same confined input root the scan itself reads
// through, so a symlink planted under /input cannot make an unrelated path answer for
// a candidate.
//
// A certificate that came back cancels that one deletion and nothing else: it is the
// ordinary producer transaction this delay exists for, not an error, so it does not
// fail the scan, does not affect health, and leaves every other candidate reapable. A
// cancellation during the wait abandons the whole reap and is returned to the caller,
// which is what keeps an interrupted scan from being reported as complete.
func (rp *reaper) confirmOrphans(ctx context.Context, orphaned []string) ([]string, error) {
	slog.Info(reapRecheckMsg,
		"count", len(orphaned), "recheck_in", reapDeferral.String())
	if err := waitBeforeReap(ctx, reapDeferral); err != nil {
		// Shutdown inside the window: delete nothing further. Debug like the other
		// interrupted paths here, because the error itself is returned and the caller
		// reports the cancellation.
		slog.Debug("orphan removal abandoned during shutdown before the confirming re-check",
			"candidates", len(orphaned), "error", err)
		return nil, err
	}
	confirmed := make([]string, 0, len(orphaned))
	for _, rel := range orphaned {
		cert := layout.CertForOutput(rel)
		if !rp.src.pathAbsent(cert) {
			// Named at the default level: this is the deletion this app decided NOT to
			// make, and it is the only trace that the delay did its job.
			slog.Info("keeping an output bundle whose certificate came back during the confirmation delay",
				"path", rel, "input", cert)
			continue
		}
		confirmed = append(confirmed, rel)
	}
	return confirmed, nil
}

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

// truncationMarker names a sample maxLoggedOrphanBytes had to cut, so a reader can
// tell a path list that ends mid-name from one that genuinely ends there. The wording
// and the cap that appends it live in internal/logtext, which internal/convert shares,
// so the two cannot drift apart on it; this alias is what the package's own
// assertions read.
const truncationMarker = logtext.Marker

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
// never cut into a partial rune. Paths are NOT sanitized: /input is a read-only mount
// of the operator's own tree, and these attributes are the operator's query key for
// which bundles were reported (the settled path-attribute-runesafe-adoption
// decision).
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
	return logtext.Cap(rendered, maxLoggedOrphanBytes) + elided
}

// reapDecision is the whole OUTPUT_LIFECYCLE decision for one scan: whether this
// app deletes anything, plus the operator wording that goes with not deleting. The
// two strings are resolved next to the deletion they explain, so the agreement
// lifecycleInaction's doc requires between them is settled at one site instead of
// being maintained by hand across two functions.
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
func resolveReap(mode outputpolicy.Lifecycle, reapable, walkSafe, refusalOnly bool) reapDecision {
	if mode == outputpolicy.LifecycleSync && reapable && walkSafe {
		return reapDecision{reap: true}
	}
	return reapDecision{
		inaction:    lifecycleInaction(mode, reapable, walkSafe, refusalOnly),
		remediation: orphanReportRemediation(mode, walkSafe, refusalOnly),
	}
}

// lifecycleInaction explains why an orphan was reported rather than removed. Four
// independent reasons can apply and the mode alone does not pick between them, so
// each is named separately and the strongest wins, in this order:
//
// An OUTPUT walk that could not enumerate the tree makes the LIST itself
// untrustworthy (orphanReportRemediation withholds the delete advice for exactly
// this case, so the two attributes must agree on it).
//
// A non-sync mode is report-only, so it outranks the conversion-failure veto: the
// veto's wording promises removal on the next clean scan, which a mode that never
// removes anything cannot deliver — and the operator would wait for a recovery that
// cannot happen while a stale bundle stays served.
//
// The refused-permission repair (ScanResult.Unwritable, via conversionsClean) is a
// veto of its own and gets its own arm ahead of the conversion-failure one: it logs
// no conversion failure anywhere, so telling the operator one failed contradicts the
// same scan's failed=0 summary, and it is cleared by chowning /output rather than by
// fixing a conversion.
//
// Otherwise the list is trustworthy — the input enumeration was complete, or
// reconcile would have returned earlier — and sync mode is only withholding this
// app's own deletion until a scan with no conversion failures.
func lifecycleInaction(mode outputpolicy.Lifecycle, reapable, walkSafe, refusalOnly bool) string {
	switch {
	case !walkSafe:
		return "kept: this scan could not prove every candidate is orphaned, so deleting could remove a live bundle"
	case mode == outputpolicy.LifecycleSync && !reapable && refusalOnly:
		return "kept: a prior bundle's permission repair was refused on this scan, so nothing is removed until a scan with no refused repair"
	case mode == outputpolicy.LifecycleSync && !reapable:
		return "kept: a conversion failed on this scan, so nothing is removed until a scan with no failures"
	}
	return "reported only (OUTPUT_LIFECYCLE=" + string(mode) + ")"
}

// orphanReportRemediation is the orphan report's operator advice. It must not tell
// an operator to delete anything on a scan whose OUTPUT walk could not enumerate
// the tree: the candidate list then holds live bundles — a bundle written through a
// symlinked output directory is enumerated under its physical path, whose derived
// input name is absent from `seen`, so it reads as an orphan on the very scan that
// created it — and every entry in the list carries a private key.
func orphanReportRemediation(mode outputpolicy.Lifecycle, walkSafe, refusalOnly bool) string {
	if !walkSafe {
		return "do not remove anything from this list yet: fix the /output warnings above, then re-check it on a scan that reports no disabled orphan removal"
	}
	if mode == outputpolicy.LifecycleSync && refusalOnly {
		return "this app removes them itself on the next scan with no failed conversion and no refused permission repair: " + outputPermRemediation + ", or remove these from the output volume by hand"
	}
	if mode == outputpolicy.LifecycleSync {
		return "this app removes them itself on the next scan with no conversion failures: fix the conversion failure reported above, or remove them from the output volume by hand"
	}
	return "remove them from the output volume, or set OUTPUT_LIFECYCLE=sync to have this app do it"
}

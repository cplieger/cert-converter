package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"syscall"
	"time"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/scanbudget"
)

// Output file and directory modes. A PFX carries a private key, so it is
// owner-read/write only; its parent directory is owner-traversable plus group
// read, matching the documented deployment where a matching host UID owns the
// volume.
//
// pfxFileMode is both the mode this app INSTALLS on every bundle it writes and the
// policy a bundle already on disk is measured against. It is a CEILING for the second
// job, not an exact target: a mode the operator made STRICTER (0400) carries no bit
// beyond it and is left alone, which is what laxerThan tests.
//
// A prior bundle laxer than it is REPORTED (laxBundleMsg) and otherwise left exactly as
// found: no chmod, and no write either. The mode a bundle HAS never reaches the currency
// decision — currency is a question about content alone — so a bundle whose bytes are
// already right is skipped however lax its mode, and the mode is corrected only when the
// bundle is next written for its OWN reasons (a renewal, or content this app could not
// verify), where the atomic replacement lands a fresh inode at this mode for free
// (store.write's atomicfile.WithMode). A bundle whose certificate never renews therefore
// keeps the mode the operator left it with.
const (
	pfxFileMode = 0o600
	pfxDirMode  = 0o750
)

// outputPermRemediation is the shared remediation hint for /output permission and
// inspection WARNs. It is a single const rather than a literal per call site because
// every one of them names the SAME operator action, and an operator who sees two of
// them in one scan must not read two different pieces of advice for one cause.
const outputPermRemediation = "check /output ownership and permissions for the UID in user:"

// store owns every touch of the output tree.
//
// A store does not close its root; the Scanner that opened it does.
type store struct {
	root *os.Root
	// laxDirsReported dedupes the lax-output-directory WARN to once per directory
	// per scan. The check is asked per bundle (inspect runs for every .crt), but
	// the fact it reports is a property of the DIRECTORY, so a flat /output holding
	// twenty certificates must not emit twenty identical records every scan. The
	// store is constructed per Scanner.Run, so this lasts exactly one scan.
	laxDirsReported map[string]struct{}
	// maxEntries is this store's per-walk entry budget for the OUTPUT tree, injected
	// from Options.MaxScanEntries exactly as scanWalk's is for /input. Non-positive
	// means "use scanbudget.Default" (scanbudget.Effective), so a store assembled
	// without one — the package's own focused tests do this — is bounded rather than
	// unbounded. /output is a mounted tree this app does not own, so the reason for a
	// bound is the same on both sides: a writer with access to the volume chooses how
	// many entries one scan is asked to enumerate.
	maxEntries int
}

// laxDirMsg is the standing WARN for an /output directory more permissive than
// pfxDirMode: a group- or world-WRITABLE directory lets any other process on the
// shared mount unlink a bundle or replace it, and a world-TRAVERSABLE one exposes the
// bundle names. This app creates the directory at pfxDirMode (store.write's own
// root.MkdirAll, which is what atomicfile's WithMkdirMode did before the write's parent
// pin needed it to exist first) and never revisits it, so a directory an operator or an
// earlier deployment left lax is reported nowhere else — while the README's own setup
// step (`mkdir -p ... && chown ...`) produces 0755 under the default umask, and 0775
// under a umask of 0002.
const laxDirMsg = "the /output directory holding a pfx is more permissive than policy"

// reportLaxDir warns when rel's parent directory carries a permission bit pfxDirMode
// does not.
//
// REPORT-ONLY, and that is a decision rather than an omission. A directory this app
// can WRITE but cannot chmod is the operator's own choice: it gets one warning and
// nothing else — the mode on disk is left exactly as found, the bundle is still
// published, orphan reaping is not vetoed, and health is unaffected. Acting on the
// mode instead (chmod the ancestors, refuse to publish below a directory whose repair
// failed, count that refusal as a conversion failure) means publishing NOTHING and
// restart-looping forever on the mount types this app exists to serve: CIFS, NFS and
// vfat force directory modes, so the chmod can never succeed there.
//
// Naming it still costs the operator nothing and is the only signal that the
// confinement guarding a private-key bundle rests on a directory others can write.
func (s *store) reportLaxDir(rel string) {
	// Every ancestor up to the mount root, not just the immediate parent: the leaf
	// directory is app-created at pfxDirMode, so in the nested layout (the output
	// tree mirrors /input's sub-directories) the operator-created /output root --
	// the README's `mkdir -p` case this WARN exists for -- is reached only by
	// walking up. path.Dir converges to "." on a root-relative path, so the loop
	// always terminates.
	for dir := path.Dir(rel); ; dir = path.Dir(dir) {
		s.reportLaxDirAt(dir)
		if dir == "." {
			return
		}
	}
}

// reportLaxDirAt reports one output directory, once per directory per scan.
// Report-only: the mode on disk is left exactly as found, the bundle is still
// published, orphan reaping is not vetoed and health is unaffected (the 2026-07
// output-dir-write-bit-enforcement decision).
func (s *store) reportLaxDirAt(dir string) {
	if _, done := s.laxDirsReported[dir]; done {
		return
	}
	// Lstat, not Stat: a symlink at a directory name is classified as itself, never
	// by its target, so a linked directory is skipped rather than reported for a
	// mode this app did not observe on the real path.
	fi, err := s.root.Lstat(dir)
	if err != nil || !fi.IsDir() {
		// A directory that cannot be stat-ed or is not a directory is reported by the
		// write path itself; this check adds nothing there.
		return
	}
	if s.laxDirsReported == nil {
		s.laxDirsReported = make(map[string]struct{})
	}
	s.laxDirsReported[dir] = struct{}{}
	if perm := fi.Mode().Perm(); laxerThan(perm, pfxDirMode) {
		// dir is root-relative, so it is "." for the flat /output the README's own setup
		// step produces; the root is named alongside it, as logOrphanWalkOutcome does for
		// its own directory-level records.
		slog.Warn(laxDirMsg,
			"path", logtext.Path(dir), "dir", logtext.Path(s.root.Name()),
			"mode", perm.String(), "want", os.FileMode(pfxDirMode).String(),
			"remediation", outputPermRemediation)
	}
}

// writeFileInRoot is store.write's confined atomic write, indirected through a
// package var because the failure that decides a HEALTH outcome — an /output write the
// volume refuses for a reason no restart clears, while the bundle already there is one
// this app never proved wrong — cannot be staged in a temp directory. The suite owns
// everything it creates, and as root nothing refuses it at all, so without this seam the
// health-neutral arm in writeOutcome would go unpinned and a future simplification could
// fold it back into the ordinary conversion failure that restart-loops the container.
// Same seam shape internal/watch uses for fsnotify.NewWatcher and main for
// health.RunProbe.
//
// It is also now the ONLY way a mode reaches a bundle on disk: this write installs
// pfxFileMode on a fresh inode, which is what corrects a lax prior bundle.
var writeFileInRoot = atomicfile.WriteFileInRoot

// write puts pfx at rel inside the output tree, atomically, creating rel's parent
// directory if needed. Every touch goes through the confined root, so a symlink
// planted under the output directory cannot redirect the private-key-bearing PFX
// outside the mounted volume — and through a PINNED parent, so it cannot redirect it
// to another name INSIDE the volume either.
//
// Confinement alone is not enough for this write, which is the whole reason the
// parent is pinned first. An *os.Root confines a path but does not pin it: it
// deliberately FOLLOWS a symlink component that stays inside the root, and the
// confined write resolves rel again for each of its own steps (temp creation, the
// symlink check, cleanup, the rename). So a co-mounting writer that replaces an
// ANCESTOR directory of rel with a symlink to a sibling output directory makes those
// steps land on a different private-key bundle than the one this scan is publishing —
// inside /output, so confinement never notices. atomicfile.OpenParentInRoot closes
// that window the same way the orphan unlink already does (removeOrphan owns the full
// reasoning): it descends component by component, refuses a symlink, confirms each
// directory's identity, and returns a root pinned to the directory it inspected, so
// naming only the BASENAME through it removes every ancestor from the write's path.
//
// A pin this app cannot obtain FAILS the write, and the failure STATES its own
// classification (refusalOutputLayout) instead of leaving a consumer to infer one from
// the error value, so it is counted among the steady-state /output conditions no restart
// clears: for a bundle this app could not verify the entry is health-neutral (the
// existing file is left in place under the standing WARN), while a bundle it proved stale
// stays a loud conversion failure, which is the healthcheck contract's own scope. It is
// deliberately not the /output DIRECTORY-mode question, which stays report-only.
//
// The parent directory is created first and separately, because the pin needs a
// directory that already exists: WithMkdirMode would create it inside the write, which
// is the step the pin has to precede. MkdirAll runs through the same confined root at
// the same pfxDirMode the option used (that is literally what the option does), so
// mode and confinement still cannot drift. That mode is a REQUEST though, not a
// guarantee: an inheritable ACL can store something wider, so the created directory's
// real mode is OBSERVED right after the call (reportLaxDir) rather than assumed from
// the request — the one directory inspect's earlier scan could not have seen.
//
// Every failure return here is a writeRefusal, which cannot be constructed without its
// classification: this function's THREE refusal sites each say what they refused, and a
// fourth cannot compile without saying it too.
func (s *store) write(ctx context.Context, rel string, pfx []byte) writeRefusal {
	if dir := path.Dir(rel); dir != "." {
		if err := s.root.MkdirAll(dir, pfxDirMode); err != nil {
			// Named as part of the write, and carrying rel, because the step is invisible
			// to an operator otherwise: the failure the library used to report from inside
			// the write is now this call's, and the diagnosis has to keep naming the write
			// it belongs to and the path that could not be created.
			//
			// This site reads its own error to state its own verdict, which is the only
			// reading of an error the invariant allows: the party classifying is the party
			// that failed. The errno classes it shares with the write (ownership for
			// EACCES/EPERM, the volume for EROFS/ENOSPC/EDQUOT) come from
			// classifyWriteErrno; everything else it cannot attribute to one of those is
			// the SHAPE of the operator's output tree, so the residual here is
			// refusalOutputLayout rather than the write's refusalTransient.
			//
			// That residual is what makes the class right for the two failures no sentinel
			// can name. Root.MkdirAll reports EEXIST for a non-directory occupying the LAST
			// component of dir (mkdirat) and ENOTDIR for one occupying an earlier component
			// (openat) — both matchable, both layout. But an in-root symlink component whose
			// target LEAVES the root is refused by the confinement itself, and os.Root
			// reports that as "path escapes from parent", matching none of fs.ErrPermission,
			// fs.ErrNotExist, fs.ErrInvalid, syscall.ELOOP or the two errnos above — the same
			// unmatchable refusal noteUnreadableInput records on /input, and the same reason
			// it treats every non-ENOENT read failure alike. A symlink LOOP at an
			// intermediate component is ELOOP. Both are steady-state /output layouts no
			// restart re-reads differently, and both used to inherit the write's clearable
			// residual, which dropped the health marker and restart-looped the container over
			// a symlinked output tree — the mistake output-write-refusal-classification-home
			// exists to close, and the answer the pin one statement later already gives for
			// the same misconfiguration at depth 1.
			//
			// A genuinely transient EIO on the directory create is swept into the layout
			// class by this residual, which is the deliberate direction: no restart fixes it
			// either, the standing WARN still fires once per scan, orphan reaping is still
			// vetoed (conversionsClean), and the loud outcome is preserved exactly where it
			// matters — a bundle this app PROVED stale stays statusFailed whatever the cause,
			// because writeOutcome gates the health-neutral arm on bundleNotProvenWrong.
			cause := classifyWriteErrno(err)
			if cause == refusalTransient {
				cause = refusalOutputLayout
			}
			return refuseWrite(cause, "write pfx: create output directory for %q: %w", rel, err)
		}
		// MkdirAll's mode is a REQUEST, not the mode on disk: an inheritable ACL can
		// widen it (0770 on such a dataset), so the directory now holding a
		// private-key bundle is observed after creation rather than assumed. inspect
		// reported the ancestors it could stat, but this directory did not exist then,
		// so its pre-create Lstat failed and it was never inserted into the per-scan
		// map — this call is the only place the created mode is ever seen, and without
		// it a widened new directory goes undiagnosed until some later scan. Report-only
		// like every other laxDirMsg site: no chmod, no refusal, no health or reap
		// effect, and the per-scan map still suppresses the ancestors inspect covered.
		s.reportLaxDir(rel)
	}
	parent, base, err := atomicfile.OpenParentInRoot(s.root, rel)
	if err != nil {
		// Classified HERE, at the refusal, because only this site knows what it refused: a
		// symlinked output tree is an operator layout, and a component swapped mid-descent
		// is another writer on the volume. Neither is process state, so no restart clears
		// either. inspect has already classified the bundle it cannot pin as
		// contentUnverified, so writeOutcome's state gate keeps a genuinely absent bundle
		// (contentVerifiedStale) loud.
		return refuseWrite(refusalOutputLayout,
			"write pfx: pin output directory for %q: %w", rel, err)
	}
	defer func() { _ = parent.Close() }()
	if _, err := writeFileInRoot(ctx, parent, base, pfx,
		atomicfile.WithMode(pfxFileMode),
		// Mirror the read bound: inspect reads this same file back under
		// maxPFXSize, so a bundle this app writes above that cap is one its own
		// currency check would refuse, which is the permanent rewrite loop
		// maxPFXSize's comment exists to prevent. The cap is checked before the
		// temp is staged, so a violation leaves the previous bundle intact and
		// fails the entry loudly instead of churning it silently forever.
		atomicfile.WithMaxBytes(maxPFXSize),
	); err != nil {
		// The bounded atomic write is where the errno classes live, so this site reads its
		// OWN error to state its own verdict.
		return refuseWrite(classifyWriteErrno(err), "write pfx: %w", err)
	}
	return nil
}

// --- Stale-temp sweep (store-owned) ---
//
// The sweep belongs to the store because it is output-tree maintenance: it walks
// the same confined root the writes go through, and it exists only because those
// writes are atomic temp+rename.

// staleTempAge is the age past which an atomicfile temp is considered orphaned by
// an interrupted write rather than staged by one still in flight.
const staleTempAge = time.Hour

// sweepStaleTemps removes PFX temp files orphaned by an interrupted atomic write
// (a crash between temp-write and rename), then narrates the outcome.
//
// atomicfile owns the mechanics — the confined walk (recursive via WithRecursive), the temp-name match,
// the re-stat before each unlink, and the cancellation. All three properties this
// sweep needs are the library's guarantees rather than this app's code: the walk is
// root-relative so a co-mounting writer that swaps an output subdirectory for a
// symlink mid-sweep cannot redirect a deletion outside the mounted volume; it
// recurses because atomicfile stages its temp in the TARGET
// directory, so a nested cert (input/example.com/cert.crt) leaves its orphan in the
// matching nested output directory; and it stops between entries on cancellation,
// because this runs before the input walk and must not traverse a large tree while
// SIGTERM handling waits.
//
// What stays here is the operator-facing half: which counts are actionable for THIS
// app, and the /output ownership hint that goes with them.
func (s *store) sweepStaleTemps(ctx context.Context) {
	res, walkErr := atomicfile.CleanupStaleTempsInRoot(ctx, s.root, staleTempAge, atomicfile.WithRecursive())
	s.logSweepOutcome(res, walkErr)
}

// logSweepOutcome emits the end-of-sweep logs: the walk error (Debug for a shutdown
// cancellation, Warn otherwise), the reclaimed-orphan count, the count of temps
// that could not be inspected or removed, and the count of output sub-paths the
// sweep could not enter. The last two are steady-state permissions/UID
// misconfigurations that let stale atomic-write artifacts accumulate unnoticed,
// so they carry a remediation hint at the default log level.
func (s *store) logSweepOutcome(res atomicfile.SweepResult, walkErr error) {
	// One sanitized rendering of the output root's name for every record below
	// (logtext.Path); the handle itself is unaffected.
	logDir := logtext.Path(s.root.Name())
	if walkErr != nil {
		if IsShutdown(walkErr) {
			// Shutdown, not an operator-actionable cleanup failure; the input
			// walk's own context check reports the cancellation to the caller.
			slog.Debug("stale temp cleanup cancelled during shutdown", "dir", logDir, "error", logtext.Path(walkErr.Error()))
		} else {
			slog.Warn("stale temp cleanup failed", "dir", logDir, "error", logtext.Path(walkErr.Error()),
				"remediation", outputPermRemediation)
		}
	}
	if res.Removed > 0 {
		// A reclaimed orphan is evidence of an earlier interrupted write (a
		// crash or a kill between temp-write and rename), so it belongs in the
		// default-level log rather than only under LOG_LEVEL=debug.
		slog.Info("reaped stale temp files", "dir", logDir, "count", res.Removed)
	}
	if res.Failed > 0 {
		slog.Warn("some stale output temps could not be inspected or removed", "dir", logDir,
			"count", res.Failed, "remediation", outputPermRemediation)
	}
	if res.Unreadable > 0 {
		slog.Warn("some output paths could not be inspected during stale temp cleanup",
			"dir", logDir, "count", res.Unreadable, "remediation", outputPermRemediation)
	}
}

// --- Output-derived currency ---

// maxPFXSize bounds a prior output the store reads back before decoding it.
//
// It MUST exceed the largest bundle this app can itself produce. A cap tuned to a
// typical PFX (single-digit kilobytes) looks reasonable and is a trap: an input
// pair near the read limit encodes to a bundle over the cap, so the store declares
// its OWN output unreadable, reports it stale, rewrites it, and does that again on
// every scan forever — a permanent write loop with a fresh mtime each time, which
// in the documented deployment re-replicates the file downstream. The bound is
// therefore derived from the input limit rather than from what a normal bundle
// looks like: two inputs plus PKCS#12 framing, with headroom.
//
// It still bounds a hostile file, which is its other purpose: decoding feeds the
// FILE'S OWN key-derivation iteration counts into PBKDF2, so an unbounded read
// would let one crafted file spend arbitrary CPU on the scan's only goroutine.
//
// The value is convert.MaxBundleBytes, the size the codec's own allocation bounds are
// sized against: the party whose parser allocations scale with the input states the
// limit, so the read cap here and the preflight's own bounds cannot drift apart. The
// codec no longer re-checks it — this cap and the lstat check below are the only
// whole-bundle controls — so neither may be removed as redundant.
const maxPFXSize = convert.MaxBundleBytes

// contentState is what one prior-bundle inspection resolves:
// what this app KNOWS about the bytes already at the output path. It answers only that
// question — never "should a write happen", never "is this a failure" — so the facts
// that used to be smuggled through a single currency verdict each have a home of their
// own instead.
//
// Three outcomes rather than two, and that is the point. "Could not verify" is a
// first-class value and NOT a synonym for stale: a bundle this app could not read is one
// it cannot compare, which is a different fact from one it compared and found out of
// date, and only the second is evidence that the operator is being served the wrong
// bundle. Collapsing the two is what let a permission-refused rewrite of an unverifiable
// bundle count as a conversion failure and pin the container unhealthy on every scan,
// unclearable by a restart.
type contentState int

const (
	// contentUnresolved is the zero value and is deliberately NOT an outcome: inspect
	// returns it only alongside an error (a shutdown), where the caller returns before any
	// outcome is derived. Like statusUnset it exists so a value propagated by mistake
	// cannot read as one of the two facts that grant health-neutrality.
	contentUnresolved contentState = iota
	// contentVerifiedCurrent: the bytes on disk were read, decoded and compared, and they
	// ARE the bundle these inputs produce. The strongest fact here, and the only one that
	// lets a scan skip the write entirely.
	contentVerifiedCurrent
	// contentVerifiedStale: this app established that the output path does not hold a
	// usable copy of the bundle these inputs produce — it holds nothing at all, holds
	// something that is not a regular file, holds a bundle whose encoder profile or
	// content differs, or holds one that will not decode with the configured password.
	// The operator is being served the wrong bundle, or none, so the rewrite is the WHOLE
	// remedy and a rewrite that fails is a conversion failure whatever the errno.
	contentVerifiedStale
	// contentUnverified: nobody compared the bytes. The stat failed, the file is above
	// maxPFXSize, the read failed for a reason that does not itself settle what is on
	// disk, or the codec's preflight refused to look at it. A
	// rewrite is still the right move — this app can answer "I cannot tell" by writing
	// what it knows — but the fact carries NO claim that the bundle on disk is wrong, so
	// on its own it never affects health.
	contentUnverified
)

// upToDate reports whether the output path needs no write at all: the bytes on disk are
// already the bundle these inputs produce. Currency is a question about CONTENT and
// nothing else — a lax mode is reported and left alone, because this app never writes a
// bundle in order to change its permissions (see reportLaxBundle).
//
// The mode on disk is deliberately NOT one of these facts. A bundle laxer than
// pfxFileMode is REPORTED where it is observed (reportLaxBundle's WARN) and acts on
// nothing: it does not make the bundle out of date, it schedules no write, and it never
// reaches health (output-dir-write-bit-enforcement, extended to files). Carrying the
// fact past its own WARN would hand every future reader of writeOutcome a routing input
// that routes nothing.
func (c contentState) upToDate() bool {
	return c == contentVerifiedCurrent
}

// bundleNotProvenWrong reports whether a failed rewrite leaves the operator with a
// bundle this app has no evidence against: one it could not read at all. Spelled as an
// ALLOWLIST of exactly that one fact, so the zero value and any fact added later take the
// loud direction — a conversion failure — by construction rather than by omission.
//
// contentVerifiedCurrent is deliberately absent, and could not be honoured if it were
// present: currency is decided on content alone, so convertEntry returns at its
// `if state.upToDate()` gate before reaching its sole call to writeOutcome (no line
// numbers: both statements moved 17 lines in the cycle that wrote this sentence).
// A future write reason that does NOT pass through that content gate
// would arrive here as a fact this list does not name and would be counted a conversion
// failure — the loud direction, which is the point of the shape.
func (c contentState) bundleNotProvenWrong() bool {
	return c == contentUnverified
}

// inspect resolves what this app knows about the output at rel, by READING it rather
// than by remembering what was written: the state of its content. A mode laxer than
// policy is WARNED about where it is observed, here, and carried no further. It decides
// nothing else — not whether to write, not whether a failure is a failure. Those are
// derived once, after the write, in writeOutcome.
//
// Reading the output keeps currency stable across process restarts and detects
// out-of-band replacement, password rotation, and encoder-profile changes without
// persisted state.
//
// Every "I cannot tell what is on disk" outcome resolves to contentUnverified: a decode
// failure is the exception, because the codec DID look and the bundle will not open with
// the configured password, which proves it is not the one these inputs produce
// (contentVerifiedStale). The unverified arms are the stat failure, the file above
// maxPFXSize, a read failure that does not itself prove the path holds no usable bundle
// (an ENOENT or a non-regular occupant seen by the read is verified-stale, like the lstat
// arms that see the same two facts) and the codec's preflight refusing to look. All of them
// still lead to a rewrite — the app can answer "I cannot tell" by writing what it knows —
// but none of them claims the bundle on disk is wrong, and that distinction is exactly
// what health has to respect. The stat and read arms carry the /output ownership hint,
// because that is what they mean; the oversized arm deliberately carries none, because
// store.write refuses to emit a bundle above maxPFXSize, so a file over the bound was
// written by something else and the rewrite itself is the whole remedy. Only shutdown is
// a hard error: it is neither current nor stale, and treating it as stale would rewrite
// every in-flight pair on the way out.
//
// Permission bits never reach the content fact, and are never acted on at all. A bundle
// laxer than pfxFileMode is REPORTED (laxBundleMsg) where it is observed and carried no
// further; its content is compared as usual, and the mode changes nothing about what
// happens next. No chmod is attempted and no write is scheduled, which is the settled
// shape for both halves of /output — the app warns about a mode it would not have chosen
// and changes nothing about what is already there (output-dir-write-bit-enforcement,
// extended to files). When the bundle is next written for a CONTENT reason, that write's
// fresh inode carries pfxFileMode.
//
// want is a convert.Analysis value, not a pointer: the codec's producer returns a
// value, so there is no nil analysis to pass on or to check for at this layer
// either.
//
//nolint:gocritic // hugeParam: convert.Analysis is ~96 bytes and passed by value on purpose; a pointer here would reopen the nil case the codec's value shape closes, to save a copy that is noise beside a PKCS#12 decode.
func (s *store) inspect(ctx context.Context, rel string, want convert.Analysis,
	wantEncoder convert.EncoderType, password string,
) (contentState, error) {
	// Asked before the bundle's own lstat so it covers the absent-bundle arm too: the
	// directory is lax whether or not a prior bundle sits in it. Report-only, so it
	// never changes the currency answer, the write, the reap or health — see
	// reportLaxDir.
	s.reportLaxDir(rel)
	// Pin rel's parent ONCE and address the bundle by basename through that pin for
	// both syscalls below. An *os.Root confines a path but does not pin it: it
	// deliberately follows an in-root symlink component and re-resolves the whole name
	// on every call, so classifying rel with one resolution and reading it back with
	// another lets a co-mounting writer swap an ANCESTOR between the two and have the
	// read address a different physical bundle than the one whose shape, mode and size
	// were just classified — inside /output, so confinement never notices, and the
	// currency gate can then be satisfied by a sibling bundle while the stale one stays
	// served. store.write and removeOrphan close the same window the same way
	// (atomicfile.OpenParentInRoot descends component by component, refuses a symlink
	// and confirms each directory's identity); the inspection path has to close it too,
	// because it is what decides whether a write happens at all.
	parent, base, err := atomicfile.OpenParentInRoot(s.root, rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// An ancestor of the output name does not exist, so neither does the bundle.
		// Nothing on disk is the strongest form of "not the bundle these inputs produce":
		// there is no copy for a consumer to read, so a rewrite that fails here is a
		// conversion failure whatever refused it.
		return contentVerifiedStale, nil
	case err != nil:
		// A pin this app cannot obtain — a symlinked output tree, a component it may not
		// traverse, a directory replaced mid-descent — is "I cannot tell what is on disk",
		// the same fact as a stat failure, and it degrades the same way rather than
		// failing the pair. The remediation names the pin's own two causes.
		slog.Warn("cannot stat prior pfx; regenerating",
			"path", logtext.Path(rel), "error", logtext.Path(err.Error()),
			"remediation", outputPinRemediation)
		return contentUnverified, nil
	}
	defer func() { _ = parent.Close() }()

	fi, err := parent.Lstat(base)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Nothing on disk is the strongest form of "not the bundle these inputs produce":
		// there is no copy for a consumer to read, so a rewrite that fails here is a
		// conversion failure whatever refused it.
		return contentVerifiedStale, nil
	case err != nil:
		// Degrade rather than fail the pair. This question is only "is the file on disk
		// already the bundle these inputs produce?", and "I cannot tell" answers it: treat
		// it as unverified and rewrite. Failing here instead flipped the pair to
		// statusFailed and pinned the container unhealthy over something the app can fix
		// ITSELF — the realistic cause is a root-owned .pfx left behind by an earlier
		// deployment before the user: mapping changed. If the rewrite genuinely cannot
		// happen and a restart could clear the reason, THAT failure flips health, which is
		// the honest signal. Consistent with the oversized case below, which already
		// regenerates.
		slog.Warn("cannot stat prior pfx; regenerating",
			"path", logtext.Path(rel), "error", logtext.Path(err.Error()),
			"remediation", outputPermRemediation)
		return contentUnverified, nil
	case !fi.Mode().IsRegular():
		// A directory, symlink or device node at the output name is not a usable
		// prior bundle, and a symlink must never be followed here or unrelated
		// content could satisfy the check. It is a VERIFIED absence of a usable bundle
		// rather than an unverified one: the shape alone settles it, no read required.
		//
		// Named at WARN like the other "cannot tell what is on disk" arms, because
		// nothing else records the SHAPE. What happens next depends on the occupant:
		// atomicfile refuses a symlink target outright ("atomicfile: target is a
		// symlink") and a directory cannot be renamed over, so those fail the pair and
		// flip health — where the operator would otherwise get a bare "conversion
		// failed", this line names the occupied output path and its mode before that
		// error arrives. Any other non-regular occupant (a device node, FIFO or socket)
		// IS replaced by the rename, and then this line is the only trace that anything
		// unusual was there at all. It also records the attempt itself, which matters
		// when the occupant is a symlink pointing out of the mounted volume: that is a
		// redirection attempt on a private-key-bearing file, and the confined root
		// refusing it should not be the only trace.
		slog.Warn("prior output path is not a regular file; regenerating",
			"path", logtext.Path(rel), "mode", fi.Mode().String(),
			"remediation", "remove whatever occupies the output path; this app writes only regular files there")
		return contentVerifiedStale, nil
	}

	// The mode report. It runs before every return below so a bundle this app keeps and
	// one it is about to replace are treated alike, and so a rewrite that then fails does
	// not leave a private key readable by the world with nothing logged. The three arms
	// above return before it because there is no mode on disk worth reporting there —
	// nothing is present, or what is present is not a bundle at all.
	s.reportLaxBundle(rel, fi.Mode().Perm())

	if fi.Size() > maxPFXSize {
		slog.Warn("prior pfx exceeds the readable bound; regenerating",
			"path", logtext.Path(rel), "size", fi.Size(), "limit", maxPFXSize)
		return contentUnverified, nil
	}

	prior, err := readBoundedInRoot(ctx, parent, base, maxPFXSize)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Shutdown, not an unreadable output: propagate so the scan reports the
			// cancellation rather than rewriting on the way out. Join ctx.Err() with
			// the read error: atomicfile checks the context only on ENTRY, so a read
			// that raced the cancellation returns a plain ENOENT/ErrNotRegular here,
			// and wrapping that alone made IsShutdown false and logged a routine
			// shutdown at ERROR. The decode-failure gate below already wraps ctx.Err()
			// for the same reason; joining keeps the read error for diagnosis.
			return contentUnresolved, fmt.Errorf("read prior pfx: %w", errors.Join(ctxErr, err))
		}
		// An ENOENT or a non-regular occupant here is not "cannot tell": the read looked
		// and VERIFIED the path holds no usable prior bundle, the same two facts the lstat
		// arms above classify as contentVerifiedStale, and the shape types.go promises
		// stays a conversion failure when the rewrite is then refused ("an absent or
		// non-regular output path... stays statusFailed and still flips health however the
		// write failed"). Routing them to contentUnverified made the same absent path
		// health-neutral or health-flipping depending on which syscall observed it first,
		// and let unreplaceableBundleMsg promise "leaving the existing bundle in place"
		// over a path that holds nothing. Every OTHER read failure stays the stat arm's
		// "cannot tell". The WARN is unchanged: it is the pinned record of the race.
		content := contentUnverified
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, atomicfile.ErrNotRegular) {
			content = contentVerifiedStale
		}
		slog.Warn("cannot read prior pfx; regenerating",
			"path", logtext.Path(rel), "error", logtext.Path(err.Error()),
			"remediation", outputPermRemediation)
		return content, nil
	}

	// CheckCurrency owns the mandatory preflight -> profile -> decode -> content
	// order; this layer only maps its typed outcome to output-tree policy.
	//
	// The decode is synchronous: the preflight bounded every derivation count it
	// can read, which covers every bundle this app wrote and any bundle whose
	// counts are visible, so for those there is nothing to time out and no
	// goroutine to abandon. One shape escapes it, a shrouded key bag nested inside
	// an encryptedData safe, and a deadline is not the answer there either: it
	// would bound how long this caller waits, not the work done. See
	// internal/convert profile.go maxKDFIterations.
	res := want.CheckCurrency(prior, password, wantEncoder)
	content, err := contentFromCurrency(ctx, rel, res, wantEncoder)
	return content, err
}

// contentFromCurrency turns a convert.Currency outcome into a content fact: what each
// outcome MEANS about the bytes on disk, with its own diagnostic. Only shutdown is a hard
// error; every other outcome resolves to a fact, and every fact but contentVerifiedCurrent
// leads to a rewrite.
func contentFromCurrency(ctx context.Context, rel string, res convert.Currency,
	wantEncoder convert.EncoderType,
) (contentState, error) {
	// Shutdown is a third category, neither current nor stale, and it is
	// state-independent: it wins before every verdict arm below. Checked here rather
	// than inside one arm, because a stale verdict returned from any other arm makes
	// convertEntry start a full PKCS#12 encode after cancellation was already
	// requested. Treating it as stale would make every in-flight pair rewrite on the
	// way out.
	if err := ctx.Err(); err != nil {
		return contentUnresolved, fmt.Errorf("inspect prior pfx: %w", err)
	}
	switch res.Reason {
	case convert.CurrencyPreflightFailed:
		// The preflight REFUSED TO LOOK — a bundle whose declared key-derivation counts
		// are outside what this app will spend CPU on, or one whose structure it will not
		// parse. Nothing about the bytes was compared, so this is the unverified fact and
		// not a claim that the operator's bundle is wrong.
		slog.Debug("prior pfx failed preflight; regenerating", "path", logtext.Path(rel), "error", res.Err)
		return contentUnverified, nil
	case convert.CurrencyProfileMismatch:
		// A deliberate PFX_ENCODER change. Without this the switch would rewrite
		// nothing: the leaf, key and chain all still match, so the bundle would keep
		// its old algorithms indefinitely while the startup log announced the new
		// profile.
		slog.Info("prior pfx uses a different encoder profile; regenerating",
			"path", logtext.Path(rel), "found", string(res.Profile), "configured", string(wantEncoder))
		return contentVerifiedStale, nil
	case convert.CurrencyDecodeFailed:
		// Expected and non-fatal: a rotated password, a truncated file, a foreign file at
		// that path. Verified STALE rather than unverified, because the codec did look and
		// the bundle will not open with the configured password — which is the password
		// every consumer of this output uses, so what is on disk is not a usable copy of
		// the bundle these inputs produce.
		slog.Debug("prior pfx did not decode; regenerating", "path", logtext.Path(rel), "error", res.Err)
		return contentVerifiedStale, nil
	default:
		// A match, or a plain content mismatch: the ordinary renewed-certificate
		// outcome, which needs no diagnostic of its own.
		if res.Current() {
			return contentVerifiedCurrent, nil
		}
		return contentVerifiedStale, nil
	}
}

// laxBundleMsg is the standing WARN for a prior bundle carrying a permission bit
// pfxFileMode does not. It names the mode found and the mode this app installs on a
// bundle it writes, and it promises nothing else: the mode on disk is left exactly as
// found. Nothing is chmodded and no write is triggered, so the condition persists — and
// the WARN recurs once per scan — until either the operator tightens the mode or the
// bundle is next written for a CONTENT reason, whose fresh inode carries pfxFileMode.
//
// The report-only tone is laxDirMsg's, and deliberately: one principle covers both halves
// of /output — the app warns about a mode it would not have chosen and changes nothing
// about what is already there. That is also the ecosystem consensus. OpenSSH refuses an
// over-permissive private key and never chmods it; certbot warns about an over-permissive
// credentials file and makes the operator act; certbot's own key RENEWAL applies its
// restrictive mode to the NEW file it was writing anyway, and never rewrites an unchanged
// certificate to correct a mode; lego sets no modes at all. Rewriting a bundle in order to
// correct its mode is what none of them do, and it cannot converge on a mount that forces
// or ignores permission bits (CIFS/SMB forced mode, NFS squash, vfat fmask): the
// replacement lands with the same lax mode, so every scan would re-detect the bundle the
// previous scan wrote, with fresh KDF salts and a fresh mtime re-triggering downstream
// replication every cycle.
//
// Carries no remediation attribute: the mode found and the mode wanted are the whole of
// the operator's decision, and this app has no action of its own to report or request.
const laxBundleMsg = "prior pfx is more permissive than policy; leaving its mode as found"

// outputPinRemediation is the operator action behind every /output LAYOUT refusal
// (refusalOutputLayout). It names all THREE causes those refusals cannot tell apart, in
// the order an operator can check them: a non-directory occupant of a mirrored output
// directory path, a symlinked output tree (both standing misconfigurations), and a path
// replaced while the scan was running (a co-mounting writer).
//
// The occupant is named FIRST because it is the one cause nothing else in the record
// hints at. On that route there is no prior bundle at the output path at all — a regular
// file at /output/<dir> makes /output/<dir>/<name>.pfx unreachable — so
// unreplaceableBundleMsg's "leaving the existing bundle in place" describes a file that is
// not there, and an operator reading only the remediation is sent after a symlink and a
// mid-scan replacement that are both absent. Health is green on that route by design (the
// settled output-write-refusal-classification-home decision), which makes this WARN the
// only signal that the certificate is producing no PFX at all.
const outputPinRemediation = "remove whatever occupies the /output directory path named in the error (this app publishes only through real directories), mount the real output directory instead of linking to it, and check /output for paths replaced while the scan was running"

// outputVolumeRemediation is the remediation for a write the VOLUME refused rather than
// ownership: this app may write /output, but the filesystem will not take the bytes.
// Deliberately not outputPermRemediation — chowning /output frees no space and does not
// remount it read-write, and an operator sent after the wrong cause reads the WARN as
// noise.
const outputVolumeRemediation = "check /output for free space, a quota and a read-only mount"

// outputTransientRemediation is the operator action behind a refusal whose own site could
// not attribute it to ownership, to the output tree's layout or to the volume
// (refusalTransient): a raw filesystem I/O error, a symlink planted at the output name, or
// a bundle the write cap refused. It is the advice the loud conversion-failure record
// carried as a literal before every register asked the cause, composed from
// outputPermRemediation so the two cannot drift.
const outputTransientRemediation = outputPermRemediation +
	", and that no symlink is planted at the output path"

// laxerThan reports whether perm carries a permission bit policy does not. It is the
// WHOLE of the mode question for BOTH halves of /output — a bundle measured against
// pfxFileMode and its ancestor directories against pfxDirMode: set means the mode is
// REPORTED, and nothing else follows from it.
//
// A bitmask test rather than an inequality, because a mode can differ from policy by
// being STRICTER: against pfxFileMode, 0400 and 0600 carry no extra bit and are left
// exactly as found, while 0640, 0644 and 0700 each do.
func laxerThan(perm, policy os.FileMode) bool {
	return perm&^policy != 0
}

// reportLaxBundle warns when a prior bundle's mode is laxer than pfxFileMode. It is
// detection and narration only — it opens nothing, pins nothing, mutates nothing and
// tells no caller, so the mode on disk is left exactly as found and nothing downstream
// can act on the fact. The WARN is the whole of what a lax mode does.
//
// One WARN per lax bundle per scan, and it recurs on every scan for as long as the mode
// does: this app changes nothing about the file, so the condition it reports is not one
// its own scan can clear. That repetition is the intended shape rather than an
// unconverged loop — the alternative, rewriting the bundle to install pfxFileMode, churns
// a fresh inode, fresh KDF salts and a fresh mtime on every scan of a mount that forces
// or ignores permission bits, and re-triggers downstream replication with it. A bundle
// written for a CONTENT reason lands at pfxFileMode by construction, which is the only
// way this app ever corrects a mode, so on a mode-storing filesystem the next renewal
// ends the WARN by itself.
func (s *store) reportLaxBundle(rel string, perm os.FileMode) {
	if !laxerThan(perm, pfxFileMode) {
		return
	}
	slog.Warn(laxBundleMsg,
		"path", logtext.Path(rel), "mode", perm.String(), "want", os.FileMode(pfxFileMode).String())
}

// writeRefusalCause names WHAT refused an /output write, as the site that refused it
// diagnosed it. It is the classification a writeRefusal CARRIES, and it is the whole of
// what a consumer is allowed to know: writeOutcome asks restartCanClear, reportWriteFailure
// asks remediation, and neither one re-examines the error value.
//
// It replaced restartCanClearWrite, a predicate over the error value whose
// `default: return true` failed OPEN in the harmful direction. A producer nobody had
// registered there was silently called clearable, so writeOutcome granted statusFailed,
// healthyAfterScan dropped the health marker, and an orchestrator restart-looped the
// container over an /output layout no restart changes — the same mistake statusUnreadable
// exists to prevent on the /input side. Registering one such producer correctly needed
// four coordinated edits and got one. Stating the class at the point of refusal removes
// the coordination entirely: there is nothing for a new refusal site to forget to
// register, because refuseWrite will not mint a refusal without a cause.
//
// This mirrors what the /input side already does. noteUnreadableInput returns the
// conversionStatus it diagnosed so that "the classification and its diagnostic cannot
// drift apart"; a refusal here carries its cause for the same reason, on the other mount.
type writeRefusalCause int

const (
	// refusalUnclassified is the zero value and is deliberately NOT a cause, like
	// statusUnset and contentUnresolved. Nothing produces it — refuseWrite takes the cause
	// as its first parameter — so it exists only so that a value arriving by mistake takes
	// the same direction as a cause nobody characterised: see restartCanClear.
	refusalUnclassified writeRefusalCause = iota
	// refusalOwnership: the filesystem refused the operation for a permission reason
	// (EACCES / EPERM). A UID does not gain a permission by restarting; only a chown or a
	// chmod on /output clears it.
	refusalOwnership
	// refusalOutputLayout: the SHAPE of the operator's output tree will not take this
	// bundle at this path — a symlinked output tree, a component that is not a directory,
	// a non-directory occupant of a mirrored output directory, or a component another
	// writer replaced mid-descent. A restart re-reads the same layout.
	refusalOutputLayout
	// refusalVolume: the volume will not take the bytes (EROFS / ENOSPC / EDQUOT). A
	// read-only mount is a mount option rather than process state, and a restarted
	// container writes the same bytes into the same full volume or against the same
	// exhausted quota.
	refusalVolume
	// refusalTransient: the write failed for something that is NOT a steady-state
	// condition of the operator's volume — a genuinely transient I/O error, a bundle above
	// maxPFXSize, a symlink at the output name. It is the one cause a restart can
	// plausibly clear, so it is the one cause that keeps the loud conversion-failure
	// outcome, and it is only ever stated by a site reading its own error.
	refusalTransient

	// refusalCauseCount is the enum's LENGTH, not a cause. It is last so that a cause
	// added above it is covered by construction: the policy test walks [0, refusalCauseCount)
	// and fails on a member whose two facts nobody stated, which is the enum-side half of
	// the same guarantee refuseWrite's required parameter gives the refusal sites.
	refusalCauseCount
)

// restartCanClear reports whether a container restart could plausibly clear this refusal.
// That is the only question health has to answer — health means "should an orchestrator
// restart this container?" — so it is the second fact writeOutcome derives an entry's
// status from.
//
// Spelled as an ALLOWLIST of the single cause a restart CAN clear, so a cause added later
// takes the unclearable direction by construction rather than by omission. That is the
// exact inverse of the enumeration-with-a-clearable-default this replaced, and
// deliberately so: the direction that used to be free is the one that restart-loops a
// container over a state no restart changes.
//
// It says nothing about whether the write SHOULD have succeeded. writeOutcome asks this
// only after establishing that the bundle already on disk is not one this app proved
// wrong, so a renewal this app could not publish stays loud whatever refused it.
func (c writeRefusalCause) restartCanClear() bool {
	return c == refusalTransient
}

// remediation names the operator action that clears this refusal. It is the SECOND
// consumer of the carried classification, and the reason the cause is an enum rather than
// a bare clearable bool: what refused decides both facts, so one refusal cannot carry a
// health verdict and a remediation that disagree, and neither is re-matched against the
// error a third time.
//
// The four axes are ownership, the output tree's own layout, the volume, and a refusal its
// own site could not attribute to any of those; an operator sent after the wrong cause
// reads the WARN as noise. A layout refusal in particular is not a volume condition, so it
// gets outputPinRemediation exactly as inspect's own per-scan WARN for the same condition
// already advises.
//
// refusalTransient has its own answer rather than falling through, because BOTH registers
// ask this: the health-neutral WARN never sees a clearable cause, but the loud
// conversion-failure record does — that is the only cause it can carry alongside the three
// unclearable ones — and its members (an I/O error, a symlink at the output name, a bundle
// over the write cap) are not an ownership problem.
func (c writeRefusalCause) remediation() string {
	switch c {
	case refusalOutputLayout:
		return outputPinRemediation
	case refusalVolume:
		return outputVolumeRemediation
	case refusalTransient:
		return outputTransientRemediation
	default:
		// refusalOwnership, plus refusalUnclassified, which nothing produces — and any
		// cause added later. /output ownership and permissions is the broadest of the four
		// actions and the only one worth naming for a condition nobody has characterised
		// yet.
		return outputPermRemediation
	}
}

// writeRefusal is the error store.write returns when it refuses to publish a bundle: the
// diagnosis and its classification, minted together at the point of refusal so the two
// cannot drift apart.
//
// It is an INTERFACE with an unexported method, and that is the ENFORCEMENT rather than a
// convention. A refusal site cannot `return fmt.Errorf(...)` here, because a plain error
// does not implement cause(); the only value that does is minted by refuseWrite, whose
// FIRST parameter is the classification. So a fourth refusal site states what it refused
// or it does not compile, which is the one hard requirement of this shape: adding a site
// must not be able to silently inherit "clearable".
//
// Nothing downstream may infer the class from the error value, and there is no fallback
// that hands an uncharacterised refusal the clearable verdict (restartCanClear is an
// allowlist).
type writeRefusal interface {
	error
	// cause is what refused, as the refusing site diagnosed it.
	cause() writeRefusalCause
}

// classifiedWriteError is the only implementation of writeRefusal. Unexported with
// unexported fields, and never built by a composite literal outside refuseWrite, so a
// refusal that exists at all has a cause somebody stated.
type classifiedWriteError struct {
	err          error
	refusalCause writeRefusalCause
}

func (r classifiedWriteError) Error() string { return r.err.Error() }

// Unwrap keeps errors.Is/As working THROUGH the refusal, so the wrapped diagnosis an
// operator reads and the errno a test seam injects both stay reachable. What is no longer
// reachable is a consumer deriving the health verdict from them.
//
// It is load-bearing rather than decorative: reportWriteFailure hands the refusal to
// failEntry, whose IsShutdown check is errors.Is(err, context.Canceled), so without this
// method a write cancelled by SIGTERM would log a routine shutdown at ERROR and raise the
// documented CertConverterConversionFailed alert. That is a bug this repo has already
// shipped once, from a wrapper missing exactly this method.
func (r classifiedWriteError) Unwrap() error { return r.err }

func (r classifiedWriteError) cause() writeRefusalCause { return r.refusalCause }

// refuseWrite mints store.write's refusal. The cause is the first parameter and there is
// no form without it: that is the whole of the guarantee.
func refuseWrite(cause writeRefusalCause, format string, args ...any) writeRefusal {
	return classifiedWriteError{err: fmt.Errorf(format, args...), refusalCause: cause}
}

// classifyWriteErrno is how a refusal site that hands back a RAW filesystem error states
// its own verdict: the errno classes of the bounded atomic write, plus the residual
// errnos of the directory creation that are not the layout state that site names itself.
//
// Reading an error to classify it is legitimate HERE and nowhere downstream, because the
// party doing the reading is the party that failed. Its residual arm is refusalTransient,
// which is the one class a restart can clear — deliberate and scoped to a raw errno from
// a filesystem syscall, where "not one of the steady-state volume conditions" genuinely
// does mean "worth another attempt". No LAYOUT condition ever reaches it: those sites
// state refusalOutputLayout directly, which is what the sentinel-plus-enumeration shape
// could not guarantee.
func classifyWriteErrno(err error) writeRefusalCause {
	switch {
	// fs.ErrPermission is the whole test rather than two errors.Is calls against
	// syscall.EPERM and syscall.EACCES: atomicfile's confined write returns an
	// *fs.PathError wrapping a syscall.Errno, and Errno.Is maps BOTH of those errnos
	// (and only those, of the ones reachable here — the EROFS, ENOSPC and EDQUOT below
	// do not match) onto fs.ErrPermission. The portable sentinel therefore covers both
	// refusals with one test, and matches an fs.ErrPermission a test seam injects.
	case errors.Is(err, fs.ErrPermission):
		return refusalOwnership
	case errors.Is(err, syscall.EROFS), errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return refusalVolume
	default:
		return refusalTransient
	}
}

// readBoundedInRoot reads a bundle from inside the output tree under maxPFXSize.
//
// atomicfile owns the confined read: it opens through the root non-blocking (so a
// FIFO or device node planted at an output name is rejected rather than wedging
// the scan's only goroutine in open(2) forever), requires a regular file, and
// stats the OPEN HANDLE rather than the path — closing the window between
// inspect's lstat and this open on a volume other containers write to. Those
// are the same three guarantees the input side already delegates in
// source.readBounded. inspect passes it the parent root it pinned plus the
// BASENAME, so no ancestor component takes part in this resolution either.
//
// It is indirected through a package var for the same reason writeFileInRoot is: the
// failure that decides a HEALTH outcome here — a prior bundle
// that is unlinked, or stops being a regular file, between inspect's classifying lstat
// and this read, which inspect classifies as contentVerifiedStale so a refused rewrite
// stays a conversion failure — cannot be staged in a temp directory the suite owns.
// Without the seam that arm is unreachable from a test, and a future simplification
// could fold it back into the health-neutral "cannot tell" case with the whole suite
// green.
var readBoundedInRoot = atomicfile.ReadBoundedInRoot

// --- Output lifecycle: the /output half ---
//
// The reap POLICY — the vetoes, the confirmation delay, the mode ranking, which
// enumerated output counts as an orphan, and the operator narration — lives in reap.go
// on *reaper, which depends on this store and on the input source because the claim
// behind a deletion spans both trees. What stays here is what that policy asks OF the
// output tree: enumerating the bundles this app owns, and removing a confirmed one.

// listOutputs lists every path under the store matching the app's OWN output shape, as
// root-relative paths in walk order, plus whether this walk saw the tree completely
// enough for a deletion decision to rest on it.
//
// Restricting the list to layout.IsOutput paths is the output-tree half of the
// deletion rule and belongs here: a file this app would never have written is never a
// candidate. WHICH of these outputs has no input is not this function's call — that
// comparison spans both trees, so it stays with the rest of the deletion-admission
// rule in reap.go.
//
// The enumeration itself is atomicfile's (WalkDirInRoot), the same walk the /input scan
// and the library's own stale-temp sweep use: confined descent, streaming ReadDir
// batches, one directory handle at a time, and no descent into a symlinked directory. It
// is a single decision for both mounts on purpose — this is the path that DELETES
// private-key material, and it had already drifted once when each mount enumerated
// itself.
func (s *store) listOutputs(ctx context.Context) (found []string, safe bool, err error) {
	walk := outputWalk{budget: scanbudget.NewCounter(s.maxEntries)}
	if err := atomicfile.WalkDirInRoot(ctx, s.root, func(rel string, d fs.DirEntry, err error) error {
		return walk.visit(ctx, rel, d, err)
	}); err != nil {
		// The ENTRY-BUDGET stop is the one abort whose per-path counts are OBSERVATIONS
		// rather than casualties of the stop: every path this walk was handed, it
		// classified normally, and the stop reason is typed (errOutputBudgetExceeded)
		// rather than inferred. So both aggregates still hold, and they are the two an
		// operator most needs - they name the conditions that will keep reaping off after
		// MAX_SCAN_ENTRIES is raised, and their per-path lines are Debug-only. This is
		// logInputCoverageWarnings' errScanBudgetExceeded exception applied to the other
		// tree. No partial-coverage attribute is needed here, unlike the /input side: both
		// messages say "some output paths", which reads honestly as a floor, where
		// /input's arms make whole-tree claims ("no certificate pairs found") that a
		// truncated scan cannot make. Every OTHER abort - an unreadable /output root, a
		// cancellation - stopped for a reason unrelated to the tree's contents, so its
		// partial counts claim nothing and stay silent.
		if errors.Is(err, errOutputBudgetExceeded) {
			s.logOrphanWalkOutcome(walk.unreadable, walk.symlinked)
		}
		return nil, false, fmt.Errorf("walk output tree: %w", err)
	}
	s.logOrphanWalkOutcome(walk.unreadable, walk.symlinked)
	return walk.found, walk.unreadable == 0 && walk.symlinked == 0, nil
}

// errOutputBudgetExceeded marks an output walk the entry budget stopped. It is its own
// sentinel, separate from errScanBudgetExceeded, because the two name different trees
// and therefore different operator actions, and because reconcile has to tell this
// condition apart from an /output the walk could not read: both disable orphan
// reconciliation, only this one is about SIZE.
//
// Reaching it discards the partial candidate list (listOutputs returns safe=false and
// no paths), which is what keeps a truncated enumeration from being read as a complete
// one — the whole premise of a deletion.
var errOutputBudgetExceeded = errors.New("output tree exceeds the per-scan entry budget")

// outputBudgetMsg is the operator-facing half of that abort. It carries
// reapDisabledPhrase so the documented CertConverterOrphanRemovalDisabled alert fires
// on it like every other reason reaping stops — a budget that bites silently is a
// bundle set that stops being reconciled with nothing to show why — and it names the
// health outcome, because a too-large /output is not clearable by a restart.
//
// Its wording must NOT contain "holds more entries than one scan will enumerate": the
// README publishes that phrase as CertConverterInputTreeTooLarge's whole matcher, whose
// remediation sends the operator to the /input mount. Two documented conditions with
// different remediations cannot share a matcher, so this message says "bundles" and
// "output walk" where scanBudgetMsg says "entries" and "scan". The exclusion is pinned
// in alert_contract_test.go.
const outputBudgetMsg = reapDisabledPhrase + ": the /output tree holds more bundles than one output walk will enumerate, so no output can be proven orphaned; health is unaffected"

// outputBudgetRemediation is that WARN's operator action, naming both ways out exactly
// as scanbudget.InputRemediation does for /input.
const outputBudgetRemediation = "check that /output is mounted at the bundle directory and holds nothing else, or raise MAX_SCAN_ENTRIES if the tree is legitimately this large"

// outputWalk is listOutputs' visitor state: the candidate list plus the two
// deletion-safety counters that derive the verdict. It exists so the walk body is a
// named method with explicit state rather than a closure mutating five captured
// variables — the traversal control, the safety accounting, the diagnostics and the
// candidate collection are the same branches either way, but the state a deletion
// decision rests on is now spelled out as fields.
//
// The safety verdict is DERIVED from unreadable and symlinked rather than mirrored in
// a field of its own: nothing can restore it once either counter moves, so a stored
// boolean would be a second representation of one invariant that both veto arms would
// have to keep in step.
type outputWalk struct {
	found      []string
	unreadable int
	symlinked  int
	// budget is this walk's entry ceiling and its charge counter, on the same
	// scanbudget.Counter every walk in this app uses. Counting only layout.IsOutput names
	// would let a flat set of ignored names walk past the bound for free, so the counter
	// is charged for every enumerated path.
	budget scanbudget.Counter
}

// visit is listOutputs' walk callback: one entry, one verdict. The context arrives as a
// parameter, exactly as scanWalk.visit's does — one ctx-threading shape for both tree
// walks.
func (w *outputWalk) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	// Same per-entry cancellation contract the input walk and the stale-temp
	// sweep already honour: this walk runs on the shutdown path, because the
	// scan is driven synchronously from the watcher's onChange callback.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		if rel == "." {
			return err
		}
		// An ENOENT below the root is the /output half of the producer race the input
		// walk already carves out (scanWalk.visit's fs.ErrNotExist arm). Only real
		// directories are ever ReadDir-ed, so the only way a path this walk just
		// enumerated answers ENOENT is that it was removed under the walk — an
		// operator following this app's own "remove them from the output volume by
		// hand" advice, or any other writer on a mount this app does not own. It is
		// not a path this scan could not READ, so it must not raise the aggregate
		// whose remediation sends the operator after /output ownership, and must not
		// carry reapDisabledPhrase into the documented alert for an ordinary removal.
		//
		// Unlike the /input side it also does not veto the reap, and the asymmetry is
		// the point: a missing /input path leaves a hole in `seen`, which can make a
		// live bundle read as an orphan, while a missing /output path is simply absent
		// from w.found — and a candidate that was never enumerated is never reaped, so
		// the omission can only ever reap LESS.
		if errors.Is(err, fs.ErrNotExist) {
			slog.Debug("skipping output path that vanished during the orphan walk",
				"path", logtext.Path(rel), "error", logtext.Path(err.Error()))
			return nil
		}
		// Debug per path, one aggregate Warn from logOrphanWalkOutcome: the same
		// two-level contract the input walk and the stale-temp sweep use. This recurs
		// on every scan for a persistent misconfiguration, so naming each path at the
		// default level is a permanent log stream for a condition already reported.
		slog.Debug("skipping unreadable output path while looking for orphans", "path", logtext.Path(rel), "error", logtext.Path(err.Error()))
		w.unreadable++
		return nil
	}
	// Charged once per ENUMERATED path and before any classification, so the budget
	// bounds this walk's own retained state rather than trailing it: w.found holds one
	// string per candidate until the walk completes, and /output is a mounted tree a
	// co-mounting writer can fill with cheap zero-length .pfx names. Below the error arm
	// for the reason scanWalk.visit states in full — a directory the walk could not
	// finish reading is reported through visit for its OWN path, which its parent
	// already charged, so charging there would enforce the operator's budget below its
	// configured value.
	//
	// Returning an error aborts the walk, and listOutputs then discards every candidate
	// it had collected: a partial enumeration cannot prove anything orphaned, and the
	// alternative — reaping on a prefix of the tree — deletes live bundles.
	if !w.budget.Charge() {
		// The stopping path reaches the reap's `error` attribute through this wrap, so it
		// goes through the same log-boundary gate the attributes do.
		return fmt.Errorf("%w: stopped at %d entries (%s)", errOutputBudgetExceeded, w.budget.Count(), logtext.Path(rel))
	}
	// A symlink anywhere in the output tree makes this walk and the WRITE path
	// disagree about where a bundle lives: writes resolve through *os.Root,
	// which follows a symlink that stays inside the root, while the walk does
	// not follow symlinks at all (its entries come from ReadDir, so a symlink
	// reports fs.ModeSymlink and is never descended into). So a bundle written
	// through a symlinked
	// directory is enumerated here under its PHYSICAL path, whose derived input
	// name is not in the scan's enumeration, and it reads as an orphan the same
	// scan that created it. Refuse to reap rather than try to reconcile two
	// namespaces.
	if d.Type()&fs.ModeSymlink != 0 {
		slog.Debug("output tree contains a symlink; "+reapDisabledPhrase, "path", logtext.Path(rel))
		w.symlinked++
		return nil
	}
	if d.IsDir() {
		// The directory's own mode is not this walk's business: it is reported once per
		// scan by reportLaxDir on the write side and acts on nothing (a directory this
		// app can write but not chmod is the operator's choice), so it can neither veto
		// a deletion nor be repaired from here.
		return nil
	}
	if !layout.IsOutput(rel) {
		return nil
	}
	w.found = append(w.found, rel)
	return nil
}

// logOrphanWalkOutcome emits the orphan walk's single aggregate Warn.
//
// Both counts disable orphan removal for the scan, which is a decision the operator
// has to be able to see at the default log level — without it, `OUTPUT_LIFECYCLE=sync`
// would silently stop reaping and look identical to a tree with nothing to reap. The
// individual paths stay at Debug.
func (s *store) logOrphanWalkOutcome(unreadable, symlinked int) {
	logDir := logtext.Path(s.root.Name())
	if unreadable > 0 {
		slog.Warn("some output paths could not be read while looking for orphans; "+reapDisabledPhrase,
			"dir", logDir, "count", unreadable,
			"remediation", outputPermRemediation)
	}
	if symlinked > 0 {
		slog.Warn("output tree contains symlinks; "+reapDisabledPhrase+" because writes and the orphan walk resolve paths differently",
			"dir", logDir, "count", symlinked,
			"remediation", "mount the real output directory instead of linking to it")
	}
}

// pinRedirectedMsg is the WARN for a candidate whose own output directory could not be
// pinned to the physical directory the orphan walk classified: a component that is a
// symlink or not a directory at all, or one that changed identity while it was being
// opened. The walk already vetoes reaping on any symlink it SEES, but that snapshot is
// taken before the confirmation delay, so this is the same rule applied at unlink time.
const pinRedirectedMsg = "could not pin the output directory of an orphaned bundle; leaving it in place"

// reapAttempt is what one confirmed candidate's removal resolved. Three values rather than
// a bool because the two non-deletions need different reporting: a bundle that vanished
// under the deferral is the ordinary producer race (Debug, nothing to aggregate), while a
// refusal is an /output condition the operator has to act on and the only one that must
// reach a per-scan record.
//
// reapAttemptRefused is the ZERO value on purpose, like statusUnset, contentUnresolved and
// refusalUnclassified: a value arriving by mistake reports a spurious refusal, never a
// bundle still on disk audited as deleted.
type reapAttempt int

const (
	reapAttemptRefused reapAttempt = iota
	reapAttemptVanished
	reapAttemptRemoved
)

// removalRefusedMsg is the once-per-scan record for confirmed orphans this app was refused
// permission to unlink. A const for the reason reapAuditMsg is one: it is the line an
// operator correlates with a sync deployment that has stopped reconciling, and the only
// default-level signal for that state that carries a COUNT.
const removalRefusedMsg = "some orphaned output bundles could not be removed; /output is not reconciling with /input"

// removeOrphan re-checks one confirmed orphan and unlinks it through a PINNED parent
// root, reporting how the attempt resolved (see reapAttempt).
//
// The parent root is what makes the unlink safe, and it is atomicfile's descent
// (OpenParentInRoot) because the hazard is a property of *os.Root rather than of this
// app: a root deliberately follows a symlink component that stays inside it, so a path
// string re-checked with Lstat and then removed with Remove can address two different
// files if an ANCESTOR is swapped in between — and reapDeferral leaves a 30-second window
// for exactly that: replacing an approved candidate's parent directory with a symlink to
// a live directory would make this code stat and unlink a live bundle while the input
// confirmation was asked about the approved path. The library descends component by
// component, refusing a symlink and confirming each directory's identity, so naming only
// the BASENAME removes every ancestor from the remove path, and the open root keeps the
// directory pinned even if it is renamed afterwards.
//
// What stays here is this app's policy: which failures are transient races and which are
// operator-actionable, and what an operator is told about each.
func (s *store) removeOrphan(rel string) reapAttempt {
	// One sanitized rendering for every record this attempt can emit (logtext.Path);
	// `rel` itself stays raw for the pin and the unlink below.
	logRel := logtext.Path(rel)
	parent, base, err := atomicfile.OpenParentInRoot(s.root, rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// An ancestor vanished with its bundle during the deferral: the same
			// transient race as the basename arm below, not a redirection. The pin
			// wraps its Lstat error, so this is the nested layout's spelling of the
			// disappearance the flat layout reports from Lstat directly — and the
			// symlink remediation on the WARN below would send an operator looking for
			// a misconfiguration that is not there.
			slog.Debug("orphaned output vanished before removal", "path", logRel)
			return reapAttemptVanished
		}
		slog.Warn(pinRedirectedMsg, "path", logRel, "error", logtext.Path(err.Error()),
			"remediation", outputPinRemediation)
		return reapAttemptRefused
	}
	defer func() { _ = parent.Close() }()
	// The walk classified this entry up to reapDeferral ago, and only a REGULAR
	// file is a bundle this app wrote. Re-check through the pinned parent right
	// before the unlink: it is the same durability question reapConfirmed asks of
	// the input side, and it is what makes the README's promise ("sync only ever
	// removes files matching this app's own output shape") true of a non-regular
	// occupant and of one swapped in after the walk.
	//
	// Spelled out here rather than delegated to atomicfile.RemoveFileInRoot, which
	// performs the same three steps: this app has to tell a vanished candidate from an
	// uninspectable one from a non-regular occupant, name the mode it found, and attach a
	// different remediation to each. A single error return cannot carry that.
	fi, statErr := parent.Lstat(base)
	switch {
	case errors.Is(statErr, fs.ErrNotExist):
		slog.Debug("orphaned output vanished before removal", "path", logRel)
		return reapAttemptVanished
	case statErr != nil:
		slog.Warn("could not re-check an orphaned output before removing it; leaving it in place",
			"path", logRel, "error", logtext.Path(statErr.Error()), "remediation", outputPermRemediation)
		return reapAttemptRefused
	case !fi.Mode().IsRegular():
		slog.Warn("orphaned output path is not a regular file; leaving it in place",
			"path", logRel, "mode", fi.Mode().String(),
			"remediation", "remove whatever occupies the output path by hand; this app deletes only the regular files it writes")
		return reapAttemptRefused
	}
	if err := parent.Remove(base); err != nil {
		slog.Warn("could not remove orphaned output", "path", logRel, "error", logtext.Path(err.Error()),
			"remediation", outputPermRemediation)
		return reapAttemptRefused
	}
	// Every deletion is named. The once-per-scan audit record (reapAuditMsg) is the
	// warn-visible contract for that; this per-path line is the complete, unbounded
	// list for a reader who asked for detail, so it sits at Debug rather than repeating
	// the audit at the default level once per path.
	slog.Debug("removed orphaned output whose input is gone", "path", logRel)
	return reapAttemptRemoved
}

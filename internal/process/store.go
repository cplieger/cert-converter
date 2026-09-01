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

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/scanbudget"
)

// Output file and directory modes.
const (
	pfxFileMode = 0o600
	pfxDirMode  = 0o750
)

// outputPermRemediation is the shared remediation hint for /output permission and
// inspection WARNs.
const outputPermRemediation = "check /output ownership and permissions for the UID in user:"

// store owns every touch of the output tree.
type store struct {
	root *os.Root
	// laxDirsReported dedupes the lax-output-directory WARN to once per directory
	// per scan.
	laxDirsReported map[string]struct{}
	// maxEntries is this store's per-walk entry budget for the OUTPUT tree, injected
	// from Options.MaxScanEntries exactly as scanWalk's is for /input.
	maxEntries int
}

// laxDirMsg is the standing WARN for an /output directory more permissive than
// pfxDirMode: a group- or world-WRITABLE directory lets any other process on the
// shared mount unlink a bundle or replace it, and a world-TRAVERSABLE one exposes the
// bundle names.
const laxDirMsg = "the /output directory holding a pfx is more permissive than policy"

// reportLaxDir warns when rel's parent directory carries a permission bit pfxDirMode
// does not.
func (s *store) reportLaxDir(rel string) {
	// Walk every ancestor up to the mount root, not just the immediate parent:
	// the leaf directory is app-created at pfxDirMode, so an operator-created
	// /output root is reached only by walking up.
	for dir := path.Dir(rel); ; dir = path.Dir(dir) {
		s.reportLaxDirAt(dir)
		if dir == "." {
			return
		}
	}
}

// reportLaxDirAt reports one output directory, once per directory per scan.
func (s *store) reportLaxDirAt(dir string) {
	if _, done := s.laxDirsReported[dir]; done {
		return
	}
	// Lstat, not Stat: a symlink at a directory name is classified as itself,
	// never by its target, so a linked directory is skipped rather than reported
	// for a mode this app did not observe on the real path.
	fi, err := s.root.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return
	}
	if s.laxDirsReported == nil {
		s.laxDirsReported = make(map[string]struct{})
	}
	s.laxDirsReported[dir] = struct{}{}
	if perm := fi.Mode().Perm(); laxerThan(perm, pfxDirMode) {
		// dir is root-relative, so "." for a flat /output; the root is named
		// alongside it, matching logOrphanWalkOutcome's own directory-level records.
		slog.Warn(laxDirMsg,
			"path", logtext.Path(dir), "dir", logtext.Path(s.root.Name()),
			"mode", perm.String(), "want", os.FileMode(pfxDirMode).String(),
			"remediation", outputPermRemediation)
	}
}

// writeFileInRoot is store.write's confined atomic write, indirected through a
// package var: the failure that decides a HEALTH outcome cannot be staged in a temp
// directory.
var writeFileInRoot = atomicfile.WriteFileInRoot

// write puts pfx at rel inside the output tree, atomically, creating rel's parent
// directory if needed. Every touch goes through the confined root, and through a
// PINNED parent, so a symlink planted under /output cannot redirect the write
// outside the mounted volume or to another name inside it.
func (s *store) write(ctx context.Context, rel string, pfx []byte) writeRefusal {
	if dir := path.Dir(rel); dir != "." {
		if err := s.root.MkdirAll(dir, pfxDirMode); err != nil {
			cause := classifyWriteErrno(err)
			if cause == refusalTransient {
				cause = refusalOutputLayout
			}
			return refuseWrite(cause, "write pfx: create output directory for %q: %w", rel, err)
		}
		// MkdirAll's mode is a REQUEST, not the mode on disk: an inheritable ACL
		// can widen it, so the directory is observed after creation rather than assumed.
		s.reportLaxDir(rel)
	}
	parent, base, err := atomicfile.OpenParentInRoot(s.root, rel)
	if err != nil {
		return refuseWrite(classifyPinRefusal(err),
			"write pfx: pin output directory for %q: %w", rel, err)
	}
	defer func() { _ = parent.Close() }()
	if _, err := writeFileInRoot(ctx, parent, base, pfx,
		atomicfile.WithMode(pfxFileMode),
		// Mirrors the read bound: inspect reads this file back under
		// maxPFXSize, which is the permanent rewrite loop this bound prevents.
		atomicfile.WithMaxBytes(maxPFXSize),
	); err != nil {
		return refuseWrite(classifyWriteErrno(err), "write pfx: %w", err)
	}
	return nil
}

// --- Stale-temp sweep (store-owned) ---

// staleTempAge is the age past which an atomicfile temp is considered orphaned by
// an interrupted write rather than staged by one still in flight.
const staleTempAge = time.Hour

// sweepStaleTemps removes PFX temp files orphaned by an interrupted atomic write
// (a crash between temp-write and rename), then narrates the outcome.
func (s *store) sweepStaleTemps(ctx context.Context) {
	res, walkErr := atomicfile.CleanupStaleTempsInRoot(ctx, s.root, staleTempAge, atomicfile.WithRecursive(true))
	s.logSweepOutcome(res, walkErr)
}

// logSweepOutcome emits the end-of-sweep logs: the walk error, the reclaimed-orphan
// count, temps that could not be inspected or removed, and output sub-paths the
// sweep could not enter.
func (s *store) logSweepOutcome(res atomicfile.SweepResult, walkErr error) {
	logDir := logtext.Path(s.root.Name())
	if walkErr != nil {
		if IsShutdown(walkErr) {
			slog.Debug("stale temp cleanup cancelled during shutdown", "dir", logDir, "error", logtext.Path(walkErr.Error()))
		} else {
			slog.Warn("stale temp cleanup failed", "dir", logDir, "error", logtext.Path(walkErr.Error()),
				"remediation", outputPermRemediation)
		}
	}
	if res.Removed > 0 {
		// A reclaimed orphan is evidence of an earlier interrupted write, so it
		// belongs at the default level rather than only under LOG_LEVEL=debug.
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
// It MUST exceed the largest bundle this app can itself produce.
const maxPFXSize = convert.MaxBundleBytes

// contentState is what one prior-bundle inspection resolves:
// what this app KNOWS about the bytes already at the output path.
type contentState int

const (
	// contentUnresolved is the zero value and is deliberately NOT an outcome: inspect
	// returns it only alongside an error (a shutdown), where the caller returns before any
	// outcome is derived.
	contentUnresolved contentState = iota
	// contentVerifiedCurrent: the bytes on disk were read, decoded and compared, and they
	// ARE the bundle these inputs produce.
	contentVerifiedCurrent
	// contentVerifiedStale: this app established that the output path does not hold a
	// usable copy of the bundle these inputs produce — it holds nothing at all, holds
	// something that is not a regular file, holds a bundle whose encoder profile or
	// content differs, or holds one that will not decode with the configured password.
	contentVerifiedStale
	// contentUnverified: nobody compared the bytes.
	contentUnverified
)

// upToDate reports whether the output path needs no write at all: the bytes on disk are
// already the bundle these inputs produce.
func (c contentState) upToDate() bool {
	return c == contentVerifiedCurrent
}

// bundleNotProvenWrong reports whether a failed rewrite leaves the operator with a
// bundle this app has no evidence against: one it could not read at all.
func (c contentState) bundleNotProvenWrong() bool {
	return c == contentUnverified
}

// inspect resolves what this app knows about the output at rel, by READING it rather
// than by remembering what was written: the state of its content.
//
//nolint:gocritic // hugeParam: convert.Analysis is ~96 bytes and passed by value on purpose; a pointer here would reopen the nil case the codec's value shape closes, to save a copy that is noise beside a PKCS#12 decode.
func (s *store) inspect(ctx context.Context, rel string, want convert.Analysis,
	wantEncoder convert.EncoderType, password string,
) (contentState, error) {
	// Asked before the bundle's own lstat too: the directory is lax whether or
	// not a prior bundle sits in it.
	s.reportLaxDir(rel)
	// Pin rel's parent ONCE and address the bundle by basename through that pin
	// for both syscalls below.
	parent, base, err := atomicfile.OpenParentInRoot(s.root, rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return contentVerifiedStale, nil
	case err != nil:
		// A pin this app cannot obtain degrades the same way a stat failure
		// does, rather than failing the pair; the remediation is the pin
		// cause's own.
		slog.Warn(priorPinRefusedMsg,
			"path", logtext.Path(rel), "error", logtext.Path(err.Error()),
			"remediation", classifyPinRefusal(err).remediation())
		return contentUnverified, nil
	}
	defer func() { _ = parent.Close() }()

	fi, err := parent.Lstat(base)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return contentVerifiedStale, nil
	case err != nil:
		slog.Warn("cannot stat prior pfx; regenerating",
			"path", logtext.Path(rel), "error", logtext.Path(err.Error()),
			"remediation", outputPermRemediation)
		return contentUnverified, nil
	case !fi.Mode().IsRegular():
		// A symlink must never be followed here, or unrelated content could
		// satisfy the check.
		slog.Warn("prior output path is not a regular file; regenerating",
			"path", logtext.Path(rel), "mode", fi.Mode().String(),
			"remediation", "remove whatever occupies the output path; this app writes only regular files there")
		return contentVerifiedStale, nil
	}

	s.reportLaxBundle(rel, fi.Mode().Perm())

	if fi.Size() > maxPFXSize {
		slog.Warn("prior pfx exceeds the readable bound; regenerating",
			"path", logtext.Path(rel), "size", fi.Size(), "limit", maxPFXSize)
		return contentUnverified, nil
	}

	prior, err := readBoundedInRoot(ctx, parent, base, maxPFXSize)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return contentUnresolved, fmt.Errorf("read prior pfx: %w", errors.Join(ctxErr, err))
		}
		// An ENOENT or non-regular occupant here VERIFIED the path holds no
		// usable prior bundle, the same facts the lstat arms above classify as
		// contentVerifiedStale, so a rewrite this app is then refused stays a
		// conversion failure rather than a health-neutral one.
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
	res := want.CheckCurrency(prior, password, wantEncoder)
	content, err := contentFromCurrency(ctx, rel, res, wantEncoder)
	return content, err
}

// contentFromCurrency turns a convert.Currency outcome into a content fact: what each
// outcome means about the bytes on disk, with its own diagnostic.
func contentFromCurrency(ctx context.Context, rel string, res convert.Currency,
	wantEncoder convert.EncoderType,
) (contentState, error) {
	// Shutdown wins before every verdict arm below: it is state-independent.
	if err := ctx.Err(); err != nil {
		return contentUnresolved, fmt.Errorf("inspect prior pfx: %w", err)
	}
	switch res.Reason {
	case convert.CurrencyPreflightFailed:
		// The preflight refused to look: key-derivation counts outside the
		// spendable-CPU bound mean nothing about these bytes was compared.
		slog.Debug("prior pfx failed preflight; regenerating", "path", logtext.Path(rel), "error", res.Err)
		return contentUnverified, nil
	case convert.CurrencyForeign:
		slog.Debug("prior pfx was not written by this app; regenerating", "path", logtext.Path(rel), "error", res.Err)
		return contentVerifiedStale, nil
	case convert.CurrencyProfileMismatch:
		// A deliberate PFX_ENCODER change.
		slog.Info("prior pfx uses a different encoder profile; regenerating",
			"path", logtext.Path(rel), "found", string(res.Profile), "configured", string(wantEncoder))
		return contentVerifiedStale, nil
	case convert.CurrencyDecodeFailed:
		slog.Debug("prior pfx did not decode; regenerating", "path", logtext.Path(rel), "error", res.Err)
		return contentVerifiedStale, nil
	case convert.CurrencyMatch:
		return contentVerifiedCurrent, nil
	case convert.CurrencyContentMismatch:
		return contentVerifiedStale, nil
	default:
		slog.Warn("prior pfx currency verdict is not one this app maps; regenerating",
			"path", logtext.Path(rel), "reason", string(res.Reason))
		return contentUnverified, nil
	}
}

// laxBundleMsg is the standing WARN for a prior bundle carrying a permission bit
// pfxFileMode does not.
const laxBundleMsg = "prior pfx is more permissive than policy; leaving its mode as found"

// outputPinRemediation is the operator action behind every /output LAYOUT refusal
// (refusalOutputLayout).
const outputPinRemediation = "remove whatever occupies the /output directory path named in the error (this app publishes only through real directories), mount the real output directory instead of linking to it, and check /output for paths replaced while the scan was running"

// priorPinRefusedMsg is the WARN for a prior bundle whose own output directory could not
// be pinned, as distinct from one that could not be stat-ed through the pin: the two
// /output conditions carry different repairs, so they are different records.
const priorPinRefusedMsg = "cannot pin the output directory of a prior pfx; regenerating"

// outputVolumeRemediation is the remediation for a write the VOLUME refused rather than
// ownership: this app may write /output, but the filesystem will not take the bytes.
const outputVolumeRemediation = "check /output for free space, a quota and a read-only mount"

// outputTransientRemediation is the operator action behind a refusal whose own site could
// not attribute it to ownership, to the output tree's layout or to the volume
// (refusalTransient): a raw filesystem I/O error, a symlink planted at the output name, or
// a bundle the write cap refused.
const outputTransientRemediation = outputPermRemediation +
	", and that no symlink is planted at the output path"

// laxerThan reports whether perm carries a permission bit policy does not.
func laxerThan(perm, policy os.FileMode) bool {
	return perm&^policy != 0
}

// reportLaxBundle warns when a prior bundle's mode is laxer than pfxFileMode.
func (s *store) reportLaxBundle(rel string, perm os.FileMode) {
	if !laxerThan(perm, pfxFileMode) {
		return
	}
	slog.Warn(laxBundleMsg,
		"path", logtext.Path(rel), "mode", perm.String(), "want", os.FileMode(pfxFileMode).String())
}

// writeRefusalCause names WHAT refused an /output write, as the site that refused it
// diagnosed it.
type writeRefusalCause int

const (
	// refusalUnclassified is the zero value and is deliberately NOT a cause, like
	// statusUnset and contentUnresolved.
	refusalUnclassified writeRefusalCause = iota
	// refusalOwnership: the filesystem refused the operation for a permission reason
	// (EACCES / EPERM).
	refusalOwnership
	// refusalOutputLayout: the SHAPE of the operator's output tree will not take this
	// bundle at this path — a symlinked output tree, a component that is not a directory,
	// a non-directory occupant of a mirrored output directory, or a component another
	// writer replaced mid-descent. A restart re-reads the same layout.
	refusalOutputLayout
	// refusalVolume: the volume will not take the bytes (EROFS / ENOSPC / EDQUOT).
	refusalVolume
	// refusalTransient: the write failed for something that is NOT a steady-state
	// condition of the operator's volume — a genuinely transient I/O error, a bundle above
	// maxPFXSize, a symlink at the output name.
	refusalTransient

	// refusalCauseCount is the enum's LENGTH, not a cause.
	refusalCauseCount
)

// restartCanClear reports whether a container restart could plausibly clear this refusal.
func (c writeRefusalCause) restartCanClear() bool {
	return c == refusalTransient
}

// remediation names the operator action that clears this refusal.
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
		// cause added later.
		return outputPermRemediation
	}
}

// writeRefusal is the error store.write returns when it refuses to publish a bundle: the
// diagnosis and its classification, minted together at the point of refusal so the two
// cannot drift apart.
type writeRefusal interface {
	error
	// cause is what refused, as the refusing site diagnosed it.
	cause() writeRefusalCause
}

// classifiedWriteError is the only implementation of writeRefusal.
type classifiedWriteError struct {
	err          error
	refusalCause writeRefusalCause
}

func (r classifiedWriteError) Error() string { return r.err.Error() }

// Unwrap keeps errors.Is/As working THROUGH the refusal, so the wrapped diagnosis an
// operator reads and the errno a test seam injects both stay reachable.
func (r classifiedWriteError) Unwrap() error { return r.err }

func (r classifiedWriteError) cause() writeRefusalCause { return r.refusalCause }

// refuseWrite mints store.write's refusal.
func refuseWrite(cause writeRefusalCause, format string, args ...any) writeRefusal {
	return classifiedWriteError{err: fmt.Errorf(format, args...), refusalCause: cause}
}

// classifyWriteErrno is how a refusal site that hands back a RAW filesystem error states
// its own verdict: the errno classes of the bounded atomic write, plus the residual
// errnos of the directory creation.
func classifyWriteErrno(err error) writeRefusalCause {
	switch {
	// fs.ErrPermission covers both EPERM and EACCES: atomicfile's confined write
	// returns an *fs.PathError wrapping a syscall.Errno, and Errno.Is maps both
	// onto fs.ErrPermission (and only those, of the ones reachable here).
	case errors.Is(err, fs.ErrPermission):
		return refusalOwnership
	case errors.Is(err, syscall.EROFS), errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return refusalVolume
	default:
		return refusalTransient
	}
}

// classifyPinRefusal is how the two sites that pin an /output parent state their own
// verdict: a component the process may not traverse is the operator's ownership to
// fix, while everything else the pinned descent refuses is the output tree's shape.
func classifyPinRefusal(err error) writeRefusalCause {
	if errors.Is(err, fs.ErrPermission) {
		return refusalOwnership
	}
	return refusalOutputLayout
}

// readBoundedInRoot reads a bundle from inside the output tree under maxPFXSize.
var readBoundedInRoot = atomicfile.ReadBoundedInRoot

// --- Output lifecycle: the /output half ---

// listOutputs lists every path under the store matching the app's OWN output shape, as
// root-relative paths in walk order, plus whether this walk saw the tree completely
// enough for a deletion decision to rest on it.
func (s *store) listOutputs(ctx context.Context) (found []string, safe bool, err error) {
	walk := outputWalk{budget: scanbudget.NewCounter(s.maxEntries)}
	if err := atomicfile.WalkDirInRoot(ctx, s.root, func(rel string, d fs.DirEntry, err error) error {
		return walk.visit(ctx, rel, d, err)
	}); err != nil {
		// The entry-budget stop's per-path counts are observations rather than
		// casualties: every path this walk was handed, it classified normally.
		if errors.Is(err, errOutputBudgetExceeded) {
			s.logOrphanWalkOutcome(walk.unreadable, walk.symlinked)
		}
		return nil, false, fmt.Errorf("walk output tree: %w", err)
	}
	s.logOrphanWalkOutcome(walk.unreadable, walk.symlinked)
	return walk.found, walk.unreadable == 0 && walk.symlinked == 0, nil
}

// errOutputBudgetExceeded marks an output walk the entry budget stopped.
var errOutputBudgetExceeded = errors.New("output tree exceeds the per-scan entry budget")

// outputBudgetMsg is the operator-facing half of that abort.
const outputBudgetMsg = reapDisabledPhrase + ": the /output tree holds more entries than one output walk will enumerate, so no output can be proven orphaned; health is unaffected"

// outputBudgetRemediation is that WARN's operator action, naming both ways out and the cost
// of the second exactly as scanbudget.InputRemediation does for /input.
const outputBudgetRemediation = "check that /output is mounted at the bundle directory and holds nothing else; if the tree is legitimately this large, raise MAX_SCAN_ENTRIES and the container's memory limit together, because one walk's memory grows with the total length of the paths it enumerates and not only with their number"

// outputWalk is listOutputs' visitor state: the candidate list plus the two
// deletion-safety counters that derive the verdict.
type outputWalk struct {
	found      []string
	unreadable int
	symlinked  int
	// budget is this walk's entry ceiling and its charge counter, on the same
	// scanbudget.Counter every walk in this app uses.
	budget scanbudget.Counter
}

// visit is listOutputs' walk callback: one entry, one verdict.
func (w *outputWalk) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	// Same per-entry cancellation contract the input walk and the stale-temp
	// sweep use: this walk runs on the shutdown path, driven synchronously from
	// the watcher's onChange callback.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		if rel == "." {
			return err
		}
		if errors.Is(err, fs.ErrNotExist) {
			slog.Debug("skipping output path that vanished during the orphan walk",
				"path", logtext.Path(rel), "error", logtext.Path(err.Error()))
			return nil
		}
		slog.Debug("skipping unreadable output path while looking for orphans", "path", logtext.Path(rel), "error", logtext.Path(err.Error()))
		w.unreadable++
		return nil
	}
	// Charged once per enumerated path, before any classification, so the budget
	// bounds this walk's own retained state: /output is a mounted tree a
	// co-mounting writer can fill with cheap zero-length .pfx names.
	if !w.budget.Charge() {
		return fmt.Errorf("%w: stopped at %d entries (%s)", errOutputBudgetExceeded, w.budget.Count(), rel)
	}
	if d.Type()&fs.ModeSymlink != 0 {
		slog.Debug("output tree contains a symlink; "+reapDisabledPhrase, "path", logtext.Path(rel))
		w.symlinked++
		return nil
	}
	if d.IsDir() {
		// The directory's own mode is not this walk's business: reportLaxDir
		// reports it once per scan on the write side, and this walk can neither
		// veto a deletion nor repair it.
		return nil
	}
	if !layout.IsOutput(rel) {
		return nil
	}
	w.found = append(w.found, rel)
	return nil
}

// logOrphanWalkOutcome emits the orphan walk's single aggregate Warn.
func (s *store) logOrphanWalkOutcome(unreadable, symlinked int) {
	logDir := logtext.Path(s.root.Name())
	if unreadable > 0 {
		slog.Warn("some output paths could not be read while looking for orphans; "+reapDisabledPhrase,
			"dir", logDir, "count", unreadable,
			"remediation", outputPermRemediation)
	}
	if symlinked > 0 {
		slog.Warn("output tree contains symlinks; "+reapDisabledPhrase,
			"dir", logDir, "count", symlinked,
			"remediation", "remove symlinks from /output, or mount the real output directory instead of linking to it")
	}
}

// pinRedirectedMsg is the WARN for a candidate whose own output directory could not be
// pinned to the physical directory the orphan walk classified: a component that is a
// symlink or not a directory at all, or one that changed identity while it was being
// opened.
const pinRedirectedMsg = "could not pin the output directory of an orphaned bundle; leaving it in place"

// reapAttempt is what one confirmed candidate's removal resolved.
type reapAttempt int

const (
	reapAttemptRefused reapAttempt = iota
	reapAttemptVanished
	reapAttemptRemoved
)

// removalRefusedMsg is the once-per-scan record for confirmed orphans this app was refused
// permission to unlink.
const removalRefusedMsg = "some orphaned output bundles could not be removed; /output is not reconciling with /input"

// removeOrphan re-checks one confirmed orphan and unlinks it through a PINNED parent
// root, reporting how the attempt resolved (see reapAttempt).
func (s *store) removeOrphan(rel string) reapAttempt {
	// One sanitized rendering for every record this attempt can emit; `rel`
	// itself stays raw for the pin and the unlink below.
	logRel := logtext.Path(rel)
	parent, base, err := atomicfile.OpenParentInRoot(s.root, rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			slog.Debug("orphaned output vanished before removal", "path", logRel)
			return reapAttemptVanished
		}
		slog.Warn(pinRedirectedMsg, "path", logRel, "error", logtext.Path(err.Error()),
			"remediation", outputPinRemediation)
		return reapAttemptRefused
	}
	defer func() { _ = parent.Close() }()
	// The walk classified this entry up to reapDeferral ago; only a REGULAR
	// file is a bundle this app wrote.
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
		if errors.Is(err, fs.ErrNotExist) {
			slog.Debug("orphaned output vanished before removal", "path", logRel)
			return reapAttemptVanished
		}
		slog.Warn("could not remove orphaned output", "path", logRel, "error", logtext.Path(err.Error()),
			"remediation", outputPermRemediation)
		return reapAttemptRefused
	}
	slog.Debug("removed orphaned output whose input is gone", "path", logRel)
	return reapAttemptRemoved
}

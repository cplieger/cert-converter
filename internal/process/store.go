package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/runesafe"
)

// Output file and directory modes. A PFX carries a private key, so it is
// owner-read/write only; its parent directory is owner-traversable plus group
// read, matching the documented deployment where a matching host UID owns the
// volume.
//
// pfxFileMode is a CEILING on a bundle already on disk, not an exact target:
// tightenMode chmods away any bit beyond it and leaves a mode the operator made
// stricter alone. The mode a bundle HAS is never part of the currency decision;
// only a mode repair the filesystem REFUSED is (see tightenMode's tightenRefused).
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
}

// writeFileInRoot is store.write's confined atomic write, indirected through a
// package var for the same reason chmodInRoot is: the failure that now decides a
// HEALTH outcome — an /output directory whose write is refused for a permission
// reason, while the bundle already there holds the right bytes — cannot be staged in
// a temp directory. The suite owns everything it creates, and as root nothing refuses
// it at all, so without this seam the health-neutral arm in
// scanWalk.noteWriteFailure would go unpinned and a future simplification could fold
// it back into the ordinary conversion failure that restart-loops the container.
var writeFileInRoot = atomicfile.WriteFileInRoot

// write puts pfx at rel inside the output tree, atomically, creating rel's parent
// directory if needed. Every touch goes through the confined root, so a symlink
// planted under the output directory cannot redirect the private-key-bearing PFX
// outside the mounted volume.
// The parent directory is created by atomicfile's own WithMkdirMode rather than
// by a hand-rolled MkdirAll here. WithMkdirMode creates the parent inside the
// same confined root as the write, so mode and confinement cannot drift.
func (s *store) write(ctx context.Context, rel string, pfx []byte) error {
	if _, err := writeFileInRoot(ctx, s.root, rel, pfx,
		atomicfile.WithMode(pfxFileMode),
		atomicfile.WithMkdirMode(pfxDirMode),
		// Mirror the read bound: isCurrent reads this same file back under
		// maxPFXSize, so a bundle this app writes above that cap is one its own
		// currency check would refuse, which is the permanent rewrite loop
		// maxPFXSize's comment exists to prevent. The cap is checked before the
		// temp is staged, so a violation leaves the previous bundle intact and
		// fails the entry loudly instead of churning it silently forever.
		atomicfile.WithMaxBytes(maxPFXSize),
	); err != nil {
		return fmt.Errorf("write pfx: %w", err)
	}
	return nil
}

// lstat reports on rel inside the output tree WITHOUT following a symlink.
//
// Lstat rather than Stat is deliberate: a symlink planted under an output name
// must not be accepted as a prior PFX, or unrelated content could satisfy the
// coherence gate. The caller owns what each outcome means, so the raw result is
// returned rather than a boolean.
func (s *store) lstat(rel string) (os.FileInfo, error) {
	return s.root.Lstat(rel)
}

// --- Stale-temp sweep (store-owned) ---
//
// The sweep belongs to the store because it is output-tree maintenance: it walks
// the same confined root the writes go through, and it exists only because those
// writes are atomic temp+rename.

// staleTempAge is the age past which an atomicfile temp is considered orphaned by
// an interrupted write rather than staged by one still in flight.
const staleTempAge = time.Hour

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

// truncationMarker is appended to a sample maxLoggedOrphanBytes had to cut, so a
// reader can tell a path list that ends mid-name from one that genuinely ends there.
// Same wording as internal/convert's marker, deliberately louder than runesafe's own
// "...", which is why the cap composes runesafe.CapBytes instead of taking a preset.
const truncationMarker = "...(truncated)"

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
	if walkErr != nil {
		if IsShutdown(walkErr) {
			// Shutdown, not an operator-actionable cleanup failure; the input
			// walk's own context check reports the cancellation to the caller.
			slog.Debug("stale temp cleanup cancelled during shutdown", "dir", s.root.Name(), "error", walkErr)
		} else {
			slog.Warn("stale temp cleanup failed", "dir", s.root.Name(), "error", walkErr,
				"remediation", outputPermRemediation)
		}
	}
	if res.Removed > 0 {
		// A reclaimed orphan is evidence of an earlier interrupted write (a
		// crash or a kill between temp-write and rename), so it belongs in the
		// default-level log rather than only under LOG_LEVEL=debug.
		slog.Info("reaped stale temp files", "dir", s.root.Name(), "count", res.Removed)
	}
	if res.Failed > 0 {
		slog.Warn("some stale output temps could not be inspected or removed", "dir", s.root.Name(),
			"count", res.Failed, "remediation", outputPermRemediation)
	}
	if res.Unreadable > 0 {
		slog.Warn("some output paths could not be inspected during stale temp cleanup",
			"dir", s.root.Name(), "count", res.Unreadable, "remediation", outputPermRemediation)
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
const maxPFXSize = 2*maxFileSize + 64<<10

// staleCause names WHY a bundle was reported stale, for the ONE consumer that has to
// tell the difference: convertEntry, which must know whether an /output write the
// filesystem refuses is a conversion failure or the health-neutral ownership condition
// the mode repair has already reported. It is meaningful only alongside a stale
// verdict; a current bundle carries staleOrdinary and nothing reads it.
type staleCause int

const (
	// staleOrdinary covers every reason a rewrite is the WHOLE remedy: absent, renewed,
	// unreadable, oversized, a changed encoder profile or password, a non-regular
	// occupant. A write that fails here means the bundle those inputs produce is not on
	// disk, so it is a conversion failure whatever the errno.
	staleOrdinary staleCause = iota
	// staleModeRepairRefused means the bundle's CONTENT was never in question: it is
	// stale only because its mode is laxer than policy and the chmod was refused, so the
	// rewrite is a permission repair rather than a conversion. When that rewrite is
	// ALSO refused for a permission reason, nothing about the operator's PFX is missing
	// or out of date and no restart can change the outcome, which is what makes that one
	// case health-neutral (see scanWalk.noteWriteFailure).
	staleModeRepairRefused
)

// isCurrent reports whether the output at rel is already the bundle want would
// produce, by READING it rather than by remembering what was written.
//
// This replaces the in-memory fingerprint cache. The cache answered a narrower
// question — "have these input bytes been converted during this process's
// lifetime?" — which produced three defects at once: every restart reconverted
// the whole tree with fresh KDF salts (churning mtimes and re-replicating every
// bundle downstream), a PFX replaced or truncated out of band was never noticed,
// and rotating PFX_PASSWORD changed nothing because the inputs had not changed.
// Deriving currency from the output answers all three, and needs no persistent
// state to survive a restart.
//
// Every "I cannot tell what is on disk" outcome resolves to stale: rewrite. That
// covers a decode failure (Debug: a rotated password, a truncated or foreign file)
// and, at WARN, a stat failure, an unreadable file, or an oversized file — the app
// can fix all of those itself by rewriting, and if the rewrite genuinely cannot
// happen THAT failure flips health, which is the honest signal. The first two carry
// the /output ownership hint, because that is what they mean; the oversized arm
// deliberately carries none, because store.write refuses to emit a bundle above
// maxPFXSize, so a file over the bound was written by something else and the rewrite
// itself is the whole remedy. Only shutdown is a hard error: it is neither current
// nor stale, and treating it as stale would rewrite every in-flight pair on the way
// out.
//
// Permission bits reach the verdict in ONE case only: a mode repair the filesystem
// REFUSED. A bundle laxer than pfxFileMode is normally tightened in place with a
// chmod (tightenMode, which owns the reasoning) and stays current, so no mode a chmod
// can fix ever triggers a rewrite. When the chmod is refused outright (EPERM/EACCES,
// i.e. the bundle belongs to another UID), the chmod cannot converge but a rewrite
// can — the temp+rename needs write permission on the output DIRECTORY, not on the
// file it replaces — so that case resolves to stale like every other "this app can
// fix it itself" outcome. It is reported as staleModeRepairRefused rather than as a
// plain stale verdict, because it is the one stale reason whose FAILED rewrite is not
// a conversion failure.
func (s *store) isCurrent(ctx context.Context, rel string, want *convert.Analysis,
	wantEncoder convert.EncoderType, password string,
) (bool, staleCause, error) {
	fi, err := s.lstat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, staleOrdinary, nil
	case err != nil:
		// Degrade rather than fail the pair. This question is only "is the file on disk
		// already the bundle these inputs produce?", and "I cannot tell" answers it: treat
		// it as stale and rewrite. Failing here instead flipped the pair to statusFailed
		// and pinned the container unhealthy over something the app can fix ITSELF — the
		// realistic cause is a root-owned .pfx left behind by an earlier deployment before
		// the user: mapping changed. If the rewrite genuinely cannot happen, THAT failure
		// flips health, which is the honest signal. Consistent with the oversized case
		// below, which already regenerates.
		slog.Warn("cannot stat prior pfx; regenerating",
			"path", rel, "error", err,
			"remediation", outputPermRemediation)
		return false, staleOrdinary, nil
	case !fi.Mode().IsRegular():
		// A directory, symlink or device node at the output name is not a usable
		// prior bundle, and a symlink must never be followed here or unrelated
		// content could satisfy the check.
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
			"path", rel, "mode", fi.Mode().String(),
			"remediation", "remove whatever occupies the output path; this app writes only regular files there")
		return false, staleOrdinary, nil
	}

	// Permission repair, not a verdict — with one exception. It runs before every
	// return below so a bundle this app keeps and one it is about to replace are
	// treated alike, and so a rewrite that then fails does not leave a private key
	// readable by the world with nothing logged.
	if s.tightenMode(rel, fi.Mode().Perm()) == tightenRefused {
		// The one mode outcome that IS a verdict. A refused chmod means this process
		// does not own the bundle (the documented case: a root-owned .pfx left behind
		// by an earlier deployment before the user: mapping changed), so no number of
		// scans will ever tighten it — while the bundle holds a private key at, say,
		// 0644 on a volume the documented downstream rsync replicates onward. A rewrite
		// DOES converge here, because atomicfile's temp+rename needs write permission
		// on the output directory rather than on the foreign-owned file, and the
		// replacement is written WithMode(pfxFileMode). Returning stale hands that to
		// the ordinary currency path instead of adding a second write path.
		//
		// Deliberately narrower than "any chmod error": a chmod the filesystem accepts
		// without storing (mount-forced modes) or one that fails for any other reason
		// (EROFS, EINVAL) is NOT evidence that a rewrite would land, and rewriting
		// there would replace one WARN per scan with a failed encode+write per scan
		// forever. Those stay tightenIneffective — warned, still current.
		//
		// The verdict is tagged staleModeRepairRefused because the rewrite it schedules
		// can itself be refused — the same UID that does not own the bundle plausibly
		// does not own the DIRECTORY either, which is the "operator changed PUID and
		// left root-owned output behind" shape this arm exists for. That outcome is
		// NOT a conversion failure: the bundle on disk still holds the right bytes, and
		// no restart can grant a permission the UID does not have, so counting it in
		// ScanResult.Failed would restart-loop the container over a condition it cannot
		// clear — the mistake ScanResult.Unreadable already exists to avoid on the
		// /input side. scanWalk.noteWriteFailure owns that split: a permission refusal
		// on THIS cause is the health-neutral ScanResult.Unwritable plus a standing
		// WARN, while any other write failure stays a conversion failure and flips
		// health exactly as before.
		return false, staleModeRepairRefused, nil
	}

	if fi.Size() > maxPFXSize {
		slog.Warn("prior pfx exceeds the readable bound; regenerating",
			"path", rel, "size", fi.Size(), "limit", maxPFXSize)
		return false, staleOrdinary, nil
	}

	prior, err := s.readBoundedPFX(ctx, rel)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Shutdown, not an unreadable output: propagate so the scan reports the
			// cancellation rather than rewriting on the way out. Join ctx.Err() with
			// the read error: atomicfile checks the context only on ENTRY, so a read
			// that raced the cancellation returns a plain ENOENT/ErrNotRegular here,
			// and wrapping that alone made IsShutdown false and logged a routine
			// shutdown at ERROR. The decode-failure gate below already wraps ctx.Err()
			// for the same reason; joining keeps the read error for diagnosis.
			return false, staleOrdinary, fmt.Errorf("read prior pfx: %w", errors.Join(ctxErr, err))
		}
		// Same reasoning as the stat failure above: unreadable means "cannot tell",
		// which resolves to stale.
		slog.Warn("cannot read prior pfx; regenerating",
			"path", rel, "error", err,
			"remediation", outputPermRemediation)
		return false, staleOrdinary, nil
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
	res := convert.CheckCurrency(prior, password, want, wantEncoder)
	current, err := currentFromCurrency(ctx, rel, res, wantEncoder)
	return current, staleOrdinary, err
}

// currentFromCurrency turns a convert.Currency outcome into isCurrent's verdict:
// what each outcome MEANS for the output tree, with its own diagnostic. Only
// shutdown is a hard error; every other non-match resolves to "rewrite it".
func currentFromCurrency(ctx context.Context, rel string, res convert.Currency,
	wantEncoder convert.EncoderType,
) (bool, error) {
	// Shutdown is a third category, neither current nor stale, and it is
	// state-independent: it wins before every verdict arm below. Checked here rather
	// than inside one arm, because a stale verdict returned from any other arm makes
	// convertEntry start a full PKCS#12 encode after cancellation was already
	// requested. Treating it as stale would make every in-flight pair rewrite on the
	// way out.
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("inspect prior pfx: %w", err)
	}
	switch res.Reason {
	case convert.CurrencyPreflightFailed:
		slog.Debug("prior pfx failed preflight; regenerating", "path", rel, "error", res.Err)
		return false, nil
	case convert.CurrencyProfileMismatch:
		// A deliberate PFX_ENCODER change. Without this the switch would rewrite
		// nothing: the leaf, key and chain all still match, so the bundle would keep
		// its old algorithms indefinitely while the startup log announced the new
		// profile.
		slog.Info("prior pfx uses a different encoder profile; regenerating",
			"path", rel, "found", string(res.Profile), "configured", string(wantEncoder))
		return false, nil
	case convert.CurrencyDecodeFailed:
		// Expected and non-fatal: a rotated password, a truncated file, a foreign
		// file at that path. All mean the same thing — rewrite it.
		slog.Debug("prior pfx did not decode; regenerating", "path", rel, "error", res.Err)
		return false, nil
	default:
		// A match, or a plain content mismatch: the ordinary renewed-certificate
		// outcome, which needs no diagnostic of its own.
		return res.Current(), nil
	}
}

// modeNotTightenedMsg is the message for a tightening that did not take effect and
// that a rewrite cannot fix either: a chmod the filesystem accepted without storing,
// or a chmod that failed for a reason other than a refusal. The fact the operator has
// to act on is that a bundle under /output is more permissive than this app's policy
// and this app could not fix it, and will not keep trying to.
const modeNotTightenedMsg = "prior pfx is more permissive than policy and could not be tightened"

// modeRepairRefusedMsg is the message for the OTHER half: the chmod was refused
// outright, so this app does not own the bundle. Separate from modeNotTightenedMsg
// because the two now differ in what happens next — this one is followed by a
// regeneration, which converges wherever the output DIRECTORY is writable — and an
// operator must not read one message for two causes with two outcomes. When the
// directory refuses the write too, this line is followed by unwritableBundleMsg, which
// names the standing condition; this one only ever announces the attempt.
const modeRepairRefusedMsg = "prior pfx is more permissive than policy and the mode repair was refused; regenerating"

// outputModeRemediation is modeNotTightenedMsg's hint. Deliberately NOT
// outputPermRemediation: there the app cannot read or write /output and ownership is
// the fix, while here it can already do both and the permission bit itself is the
// problem — which an ownership change alone need not fix, because a filesystem with
// mount-forced modes stores no bit at all. modeRepairRefusedMsg is the opposite case
// and does carry outputPermRemediation, because a refusal IS an ownership problem.
const outputModeRemediation = "chmod the bundle to the wanted mode, and check that /output's filesystem honours permission bits"

// chmodInRoot is tightenMode's confined chmod, indirected through a package var for
// one reason: the filesystem this design exists to survive — one that ACCEPTS a
// chmod and stores nothing (CIFS/vfat with mount-forced modes, some NFS squash
// configs) — cannot be staged in a temp directory, so the property that matters
// there (the bundle stays current, so nothing rewrites it in a loop) would otherwise
// go unpinned. Same seam shape internal/watch uses for fsnotify.NewWatcher and main
// for health.RunProbe.
var chmodInRoot = (*os.Root).Chmod

// laxerThanPolicy reports whether perm carries a permission bit pfxFileMode does
// not.
//
// A bitmask test rather than an inequality, because a mode can differ from policy by
// being STRICTER: 0400 and 0600 have nothing to tighten, while 0640, 0644 and 0700
// each do.
func laxerThanPolicy(perm os.FileMode) bool {
	return perm&^pfxFileMode != 0
}

// tightenResult is the outcome of one mode-repair attempt, as isCurrent needs to see
// it: whether the extra permission bits are gone, and when they are not, whether a
// rewrite could still remove them. The distinction is the whole point of the type —
// exactly one failure shape (a refusal) is convergeable by rewriting, so collapsing
// them into a bare error or a bool would either leave a world-readable private key in
// place forever or churn a bundle a rewrite cannot fix.
type tightenResult int

const (
	// tightenNotNeeded: the mode is already at or stricter than policy, so nothing was
	// attempted.
	tightenNotNeeded tightenResult = iota
	// tightenApplied: the chmod took and the mode the filesystem stored is within policy.
	tightenApplied
	// tightenRefused: the kernel refused the chmod outright (EPERM/EACCES). In the
	// documented deployment that means the bundle belongs to another UID, which a
	// temp+rename rewrite replaces even though a chmod cannot touch it.
	tightenRefused
	// tightenIneffective: the repair did not take effect for a reason a rewrite need
	// not fix — a filesystem that accepts a chmod and stores nothing (mount-forced
	// modes), or any other chmod/re-stat failure (EROFS, EINVAL, a bundle that vanished
	// mid-inspection).
	tightenIneffective
)

// isPermissionRefusal reports whether err is the filesystem REFUSING an operation for
// a permission reason, as opposed to failing it for any other reason. Both /output
// touches whose outcome turns on that distinction ask it: tightenMode's chmod, and the
// rewrite that a refused chmod schedules (scanWalk.noteWriteFailure).
//
// fs.ErrPermission is the whole test rather than two errors.Is calls against
// syscall.EPERM and syscall.EACCES: os.Root.Chmod and atomicfile's confined write both
// return an *fs.PathError wrapping a syscall.Errno, and Errno.Is maps BOTH of those
// errnos (and only those, of the ones reachable here — EROFS, EINVAL and ENOSPC do not
// match) onto fs.ErrPermission. Checking the portable sentinel therefore covers both
// refusals, keeps this file free of a syscall import, and matches an fs.ErrPermission a
// test seam injects directly.
func isPermissionRefusal(err error) bool {
	return errors.Is(err, fs.ErrPermission)
}

// tightenMode chmods a prior bundle whose mode is laxer than pfxFileMode back to
// policy and reports, as a tightenResult, whether the tightening took effect — and
// when it did not, whether a rewrite could still converge it. It moves permission
// bits only: the bundle's bytes and its mtime are never touched.
//
// Tighten with chmod rather than rewriting: rewriting would loosen an operator's
// deliberate 0400 mode and would churn the bundle forever on filesystems that
// accept chmod without storing permission bits.
//
// The ONE exception is a REFUSED chmod (tightenRefused), which the caller turns into
// a stale verdict: there the chmod can never converge — this process does not own the
// file — while a temp+rename rewrite can, because it needs permission on the output
// directory rather than on the file. Without that arm a private-key-bearing bundle
// left world-readable by another UID keeps its mode for the life of the deployment
// and is re-warned once per scan. Every other failure stays WARN-only
// (tightenIneffective): a chmod error is not evidence that a rewrite would land, and
// on a mode-forcing or read-only mount rewriting would turn one WARN per scan into a
// failed encode+write per scan.
//
// Only the EXTRA bits are cleared, so a deliberately stricter mode survives
// untouched (laxerThanPolicy is what protects it) and the tightening adds no bit the
// file did not already carry — with one exception: a lax mode with no owner READ or
// WRITE bit masks to 0000, a mode this app could not read its own bundle back
// through, so that case targets pfxFileMode instead. See the inline comment.
//
// The chmod goes through the store's confined root like every other output touch, so
// a symlink planted under the output tree cannot redirect it outside the mounted
// volume. os.Root.Chmod does follow a symlink, and isCurrent's lstat cannot rule out
// a swap in the window before this call, but the reach of that race is one permission
// bit: it never touches content, and anyone able to stage the swap on a co-mounted
// /output can already replace the bundle itself.
func (s *store) tightenMode(rel string, perm os.FileMode) tightenResult {
	if !laxerThanPolicy(perm) {
		return tightenNotNeeded
	}
	want := perm & pfxFileMode
	// A lax mode carrying no owner READ or WRITE bit (0044, 0060, 0004, and the
	// execute-only 0100 family) masks to 0000, which is not a tightening: it leaves
	// this app unable to read the bundle. It is also the one arm here that adds owner
	// bits the file did not carry, which is why it is spelled out. Output-derived
	// currency then fails on the very next read — "cannot read prior pfx; regenerating"
	// plus a rewrite with fresh KDF salts and a fresh mtime, the downstream
	// re-replication maxPFXSize's comment exists to prevent — or, where the process can
	// still read it (running as root), the private-key bundle sits at 0000 for the life
	// of the deployment, unreadable to the documented downstream replicator, while this
	// function logs a successful tighten at INFO. pfxFileMode is the right target there:
	// it is the mode a rewrite would install anyway, it still removes every group/other
	// bit, and the deliberately-stricter case is protected by laxerThanPolicy above, not
	// by this mask.
	if want == 0 {
		want = pfxFileMode
	}
	got, err := s.chmodAndObserve(rel, want)
	switch {
	case err != nil && isPermissionRefusal(err):
		// Not ours to chmod, but ours to replace: the caller reads this outcome as
		// stale, and the ordinary write path converges it. Named with the ownership
		// remediation rather than the filesystem one, because that is what a refusal
		// means.
		slog.Warn(modeRepairRefusedMsg,
			"path", rel, "mode", perm.String(), "want", want.String(),
			"error", err, "remediation", outputPermRemediation)
		return tightenRefused
	case err != nil:
		slog.Warn(modeNotTightenedMsg,
			"path", rel, "mode", perm.String(), "want", want.String(),
			"error", err, "remediation", outputModeRemediation)
		return tightenIneffective
	case laxerThanPolicy(got):
		// The filesystem took the chmod and kept nothing. Saying so is all this can
		// do, and all it SHOULD do: the bytes are still the right bytes, so the bundle
		// stays current and the WARN no longer drags a rewrite behind it.
		slog.Warn(modeNotTightenedMsg,
			"path", rel, "mode", got.String(), "want", want.String(),
			"remediation", outputModeRemediation)
		return tightenIneffective
	default:
		// Named at the default level because this app just changed the permissions of
		// a file on the operator's volume, as every other output-tree mutation is
		// named (a write, a reaped temp, a removed orphan).
		slog.Info("tightened the file mode of a prior pfx",
			"path", rel, "from", perm.String(), "to", got.String())
		return tightenApplied
	}
}

// chmodAndObserve tightens rel to want inside the output tree and reports the mode
// the filesystem actually stored.
//
// The re-stat is the point: a chmod's return value says the request was accepted,
// not that the bits were kept, and the filesystems this app has to survive differ
// exactly there — mount-forced modes store nothing, an inherited ACL can widen what
// it is given.
func (s *store) chmodAndObserve(rel string, want os.FileMode) (os.FileMode, error) {
	if err := chmodInRoot(s.root, rel, want); err != nil {
		return 0, fmt.Errorf("chmod: %w", err)
	}
	fi, err := s.lstat(rel)
	if err != nil {
		return 0, fmt.Errorf("re-stat after chmod: %w", err)
	}
	return fi.Mode().Perm(), nil
}

// readBoundedPFX reads rel from inside the output tree under maxPFXSize.
//
// atomicfile owns the confined read: it opens through the root non-blocking (so a
// FIFO or device node planted at an output name is rejected rather than wedging
// the scan's only goroutine in open(2) forever), requires a regular file, and
// stats the OPEN HANDLE rather than the path — closing the window between
// isCurrent's lstat and this open on a volume other containers write to. Those
// are the same three guarantees the input side already delegates in
// source.readBoundedLimit.
func (s *store) readBoundedPFX(ctx context.Context, rel string) ([]byte, error) {
	return atomicfile.ReadBoundedInRoot(ctx, s.root, rel, maxPFXSize)
}

// --- Output lifecycle ---
//
// The OUTPUT_LIFECYCLE value domain itself (the Lifecycle type, its three modes
// and their parse) lives in internal/outputpolicy, which this package consumes:
// the operator's raw value is read and normalised by internal/config, and keeping
// the enum here put that configuration layer above the orchestrator. What follows
// is this package's own half — acting on an already-parsed mode over the output
// tree.

// orphans lists outputs under the store whose input pair is absent, as
// root-relative paths in walk order.
//
// seen is the set of input .crt paths a COMPLETE walk found. Only paths matching
// the app's own output shape are considered, so a file the app would never have
// written is never a deletion candidate.
func (s *store) orphans(ctx context.Context, seen map[string]struct{}) (found []string, safe bool, err error) {
	safe = true
	var unreadable, symlinked int
	walkErr := fs.WalkDir(s.root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
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
			// Debug per path, one aggregate Warn below: the same two-level contract
			// the input walk and the stale-temp sweep use. This recurs on every scan
			// for a persistent misconfiguration, so naming each path at the default
			// level is a permanent log stream for a condition already reported.
			slog.Debug("skipping unreadable output path while looking for orphans", "path", rel, "error", err)
			unreadable++
			safe = false
			return nil
		}
		// A symlink anywhere in the output tree makes this walk and the WRITE path
		// disagree about where a bundle lives: writes resolve through *os.Root,
		// which follows a symlink that stays inside the root, while fs.WalkDir does
		// not follow symlinks at all. So a bundle written through a symlinked
		// directory is enumerated here under its PHYSICAL path, whose derived input
		// name is not in `seen`, and it reads as an orphan the same scan that
		// created it. Refuse to reap rather than try to reconcile two namespaces.
		if d.Type()&fs.ModeSymlink != 0 {
			slog.Debug("output tree contains a symlink; orphan removal is disabled for this scan", "path", rel)
			symlinked++
			safe = false
			return nil
		}
		if d.IsDir() || !layout.IsOutput(rel) {
			return nil
		}
		// layout owns both directions of the naming contract, so the reverse
		// derivation cannot drift from the forward one used at write time.
		if _, ok := seen[layout.CertForOutput(rel)]; !ok {
			found = append(found, rel)
		}
		return nil
	})
	if walkErr != nil {
		return nil, false, fmt.Errorf("walk output tree: %w", walkErr)
	}
	s.logOrphanWalkOutcome(unreadable, symlinked)
	return found, safe, nil
}

// logOrphanWalkOutcome emits the orphan walk's single aggregate Warn.
//
// Both counts disable orphan removal for the scan, which is a decision the operator
// has to be able to see at the default log level — without it, `OUTPUT_LIFECYCLE=sync`
// would silently stop reaping and look identical to a tree with nothing to reap. The
// individual paths stay at Debug.
func (s *store) logOrphanWalkOutcome(unreadable, symlinked int) {
	if unreadable > 0 {
		slog.Warn("some output paths could not be read while looking for orphans; orphan removal is disabled for this scan",
			"dir", s.root.Name(), "count", unreadable,
			"remediation", outputPermRemediation)
	}
	if symlinked > 0 {
		slog.Warn("output tree contains symlinks; orphan removal is disabled for this scan because writes and the orphan walk resolve paths differently",
			"dir", s.root.Name(), "count", symlinked,
			"remediation", "mount the real output directory instead of linking to it")
	}
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
// each candidate's certificate through src, so an input observed mid-replacement
// keeps its bundle. src is the input side of the same scan `seen` came from.
func (s *store) reconcile(ctx context.Context, mode outputpolicy.Lifecycle, src *source,
	seen map[string]struct{}, rc *reapContext,
) (int, error) {
	if mode == outputpolicy.LifecycleKeep {
		return 0, nil
	}
	if !rc.enumeratedInput() {
		logIncompleteInputEnumeration(rc)
		return 0, nil
	}
	orphaned, walkSafe, err := s.orphans(ctx, seen)
	if err != nil {
		if IsShutdown(err) {
			// Shutdown, not a broken output tree. The input walk usually reports the
			// cancellation itself, but not when it finished cleanly before the signal
			// arrived, so the error is returned here too rather than only logged.
			slog.Debug("orphan enumeration cancelled during shutdown", "error", err)
			return 0, err
		}
		slog.Warn("could not enumerate output orphans; orphan removal is disabled for this scan",
			"error", err, "dir", s.root.Name(),
			"remediation", outputPermRemediation)
		return 0, nil
	}
	if len(orphaned) == 0 {
		return 0, nil
	}

	reapable := rc.safeToReap() && walkSafe
	if mode != outputpolicy.LifecycleSync || !reapable {
		slog.Warn("output bundles have no matching input",
			"count", len(orphaned), "paths", sampleOrphanPaths(orphaned),
			"action", lifecycleInaction(mode, reapable, walkSafe),
			"remediation", orphanReportRemediation(mode, walkSafe))
		return 0, nil
	}

	return s.reapConfirmed(ctx, src, orphaned)
}

// reapConfirmed is the deletion half of reconcile: confirm the batch after the
// deferral, then remove what is still orphaned. Split out so reconcile's gate reads
// as a sequence of refusals with one tail call, rather than carrying the delay's own
// three outcomes inline.
func (s *store) reapConfirmed(ctx context.Context, src *source, orphaned []string) (int, error) {
	confirmed, err := s.confirmOrphans(ctx, src, orphaned)
	if err != nil {
		return 0, err
	}
	if len(confirmed) == 0 {
		return 0, nil
	}
	return s.removeOrphans(ctx, confirmed)
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
func (s *store) confirmOrphans(ctx context.Context, src *source, orphaned []string) ([]string, error) {
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
		if !src.pathAbsent(cert) {
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

// removeOrphans deletes each named output bundle, stopping early on shutdown and
// skipping (never aborting on) an individual removal failure. Returns how many
// were actually deleted, plus the context's cancellation error when shutdown cut
// the loop short so the caller does not report the scan as complete.
func (s *store) removeOrphans(ctx context.Context, orphaned []string) (int, error) {
	var deleted int
	for _, rel := range orphaned {
		if err := ctx.Err(); err != nil {
			slog.Debug("orphan removal interrupted by shutdown",
				"removed", deleted, "remaining", len(orphaned)-deleted)
			return deleted, err
		}
		if err := s.root.Remove(rel); err != nil {
			slog.Warn("could not remove orphaned output", "path", rel, "error", err,
				"remediation", outputPermRemediation)
			continue
		}
		// Every deletion is named. Removing key material without an audit line is
		// not acceptable even when it is correct.
		slog.Info("removed orphaned output whose input is gone", "path", rel)
		deleted++
	}
	return deleted, nil
}

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
// runesafe.CapBytes, which backs the cut off to a rune start so a multi-byte name is
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
	if len(rendered) > maxLoggedOrphanBytes {
		rendered = runesafe.CapBytes(rendered, maxLoggedOrphanBytes) + truncationMarker
	}
	return rendered + elided
}

// lifecycleInaction explains why an orphan was reported rather than removed. Three
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
// The conversion-failure arm also covers the health-neutral refused-permission repair
// (ScanResult.Unwritable, via conversionsClean): its wording holds for that shape too —
// nothing is removed until a scan with no failures — and the standing WARN that names
// the ownership problem is emitted per bundle, so this attribute does not need to
// re-diagnose it.
//
// Otherwise the list is trustworthy — the input enumeration was complete, or
// reconcile would have returned earlier — and sync mode is only withholding this
// app's own deletion until a scan with no conversion failures.
func lifecycleInaction(mode outputpolicy.Lifecycle, reapable, walkSafe bool) string {
	switch {
	case !walkSafe:
		return "kept: this scan could not prove every candidate is orphaned, so deleting could remove a live bundle"
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
func orphanReportRemediation(mode outputpolicy.Lifecycle, walkSafe bool) string {
	if !walkSafe {
		return "do not remove anything from this list yet: fix the /output warnings above, then re-check it on a scan that reports no disabled orphan removal"
	}
	if mode == outputpolicy.LifecycleSync {
		return "this app removes them itself on the next scan with no conversion failures: fix the conversion failure reported above, or remove them from the output volume by hand"
	}
	return "remove them from the output volume, or set OUTPUT_LIFECYCLE=sync to have this app do it"
}

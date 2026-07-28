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
)

// Output file and directory modes. A PFX carries a private key, so it is
// owner-read/write only; its parent directory is owner-traversable plus group
// read, matching the documented deployment where a matching host UID owns the
// volume.
//
// pfxFileMode is a CEILING on a bundle already on disk, not an exact target:
// tightenMode chmods away any bit beyond it and leaves a mode the operator made
// stricter alone. It is never part of the currency decision.
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

// write puts pfx at rel inside the output tree, atomically, creating rel's parent
// directory if needed. Every touch goes through the confined root, so a symlink
// planted under the output directory cannot redirect the private-key-bearing PFX
// outside the mounted volume.
// The parent directory is created by atomicfile's own WithMkdirMode rather than
// by a hand-rolled MkdirAll here. WithMkdirMode creates the parent inside the
// same confined root as the write, so mode and confinement cannot drift.
func (s *store) write(ctx context.Context, rel string, pfx []byte) error {
	if _, err := atomicfile.WriteFileInRoot(ctx, s.root, rel, pfx,
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
// and, at WARN with a remediation hint, a stat failure, an oversized file, or an
// unreadable file — the app can fix all of those itself by rewriting, and if the
// rewrite genuinely cannot happen THAT failure flips health, which is the honest
// signal. Only shutdown is a hard error: it is neither current nor stale, and
// treating it as stale would rewrite every in-flight pair on the way out.
//
// Permission bits are NOT one of those outcomes and never reach the verdict: a
// bundle laxer than pfxFileMode is tightened in place with a chmod (tightenMode,
// which owns the reasoning) and stays current, so no mode can ever trigger a
// rewrite.
func (s *store) isCurrent(ctx context.Context, rel string, want *convert.Analysis,
	wantEncoder convert.EncoderType, password string,
) (bool, error) {
	fi, err := s.lstat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
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
		return false, nil
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
		return false, nil
	}

	// Permission repair, not a verdict: it runs before every return below so a
	// bundle this app keeps and one it is about to replace are treated alike, and
	// so a rewrite that then fails does not leave a private key readable by the
	// world with nothing logged.
	s.tightenMode(rel, fi.Mode().Perm())

	if fi.Size() > maxPFXSize {
		slog.Warn("prior pfx exceeds the readable bound; regenerating",
			"path", rel, "size", fi.Size(), "limit", maxPFXSize)
		return false, nil
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
			return false, fmt.Errorf("read prior pfx: %w", errors.Join(ctxErr, err))
		}
		// Same reasoning as the stat failure above: unreadable means "cannot tell",
		// which resolves to stale.
		slog.Warn("cannot read prior pfx; regenerating",
			"path", rel, "error", err,
			"remediation", outputPermRemediation)
		return false, nil
	}

	// One call, because the codec owns the ORDER: the preflight runs before any
	// derivation (it bounds every iteration count the file exposes without
	// decrypting a safe), the profile comparison runs before the decode, and the
	// content comparison runs last. That sequence used to live here, which meant
	// the codec published three steps any caller could take out of order; it is
	// now unbypassable inside convert.CheckCurrency. What stays here is what it
	// always was: deciding what each outcome MEANS for the output tree.
	//
	// The decode is synchronous: the preflight bounded every derivation count it
	// can read, which covers every bundle this app wrote and any bundle whose
	// counts are visible, so for those there is nothing to time out and no
	// goroutine to abandon. One shape escapes it, a shrouded key bag nested inside
	// an encryptedData safe, and a deadline is not the answer there either: it
	// would bound how long this caller waits, not the work done. See
	// internal/convert profile.go maxKDFIterations.
	res := convert.CheckCurrency(prior, password, want, wantEncoder)
	return currentFromCurrency(ctx, rel, res, wantEncoder)
}

// currentFromCurrency turns a convert.Currency outcome into isCurrent's verdict:
// what each outcome MEANS for the output tree, with its own diagnostic. Only
// shutdown is a hard error; every other non-match resolves to "rewrite it".
func currentFromCurrency(ctx context.Context, rel string, res convert.Currency,
	wantEncoder convert.EncoderType,
) (bool, error) {
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
		if ctx.Err() != nil {
			// Shutdown is a third category, neither current nor stale. Treating it as
			// stale would make every in-flight pair rewrite on the way out.
			return false, fmt.Errorf("inspect prior pfx: %w", ctx.Err())
		}
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

// modeNotTightenedMsg is the one message both tightening failures share — a refused
// chmod and a chmod the filesystem accepted without storing — because the fact the
// operator has to act on is identical: a bundle under /output is more permissive
// than this app's policy and this app could not fix it.
const modeNotTightenedMsg = "prior pfx is more permissive than policy and could not be tightened"

// outputModeRemediation is that WARN's hint. Deliberately NOT outputPermRemediation:
// there the app cannot read or write /output and ownership is the fix, while here it
// can already do both and the permission bit itself is the problem — which an
// ownership change alone need not fix, because a filesystem with mount-forced modes
// stores no bit at all.
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

// tightenMode chmods a prior bundle whose mode is laxer than pfxFileMode back to
// policy and reports when the tightening did not take effect. It moves permission
// bits only: the bundle's bytes and its mtime are never touched, and its currency is
// decided without reference to its mode.
//
// This replaces an earlier design that reported a mode mismatch as STALE so the
// rewrite would converge the mode, which was wrong twice over. It replaced a
// STRICTER bundle too — a deliberate 0400 was already perfectly usable, since the
// atomic temp+rename never needs the old file to be owner-writable — handing back a
// laxer 0600, discarding the protection the operator chose and moving the mtime for
// no benefit. And on a filesystem that does not honour permission bits it could never
// converge: the mode never sticks, so EVERY bundle failed the check on EVERY scan — a
// permanent rewrite loop with fresh KDF salts and fresh mtimes, which the documented
// downstream rsync replication then copies every cycle. That is the same trap
// maxPFXSize's comment exists to avoid. chmod is the right tool for a permission
// bit; rewriting the bundle is not, and a rewrite driven by a bit the filesystem
// will not store cannot converge.
//
// Only the EXTRA bits are cleared, so the tightening can never add a bit the file
// did not already carry and a deliberately stricter mode survives untouched.
//
// The chmod goes through the store's confined root like every other output touch, so
// a symlink planted under the output tree cannot redirect it outside the mounted
// volume. os.Root.Chmod does follow a symlink, and isCurrent's lstat cannot rule out
// a swap in the window before this call, but the reach of that race is one permission
// bit: it never touches content, and anyone able to stage the swap on a co-mounted
// /output can already replace the bundle itself.
func (s *store) tightenMode(rel string, perm os.FileMode) {
	if !laxerThanPolicy(perm) {
		return
	}
	want := perm & pfxFileMode
	got, err := s.chmodAndObserve(rel, want)
	switch {
	case err != nil:
		slog.Warn(modeNotTightenedMsg,
			"path", rel, "mode", perm.String(), "want", want.String(),
			"error", err, "remediation", outputModeRemediation)
	case laxerThanPolicy(got):
		// The filesystem took the chmod and kept nothing. Saying so is all this can
		// do, and all it SHOULD do: the bytes are still the right bytes, so the bundle
		// stays current and the WARN no longer drags a rewrite behind it.
		slog.Warn(modeNotTightenedMsg,
			"path", rel, "mode", got.String(), "want", want.String(),
			"remediation", outputModeRemediation)
	default:
		// Named at the default level because this app just changed the permissions of
		// a file on the operator's volume, as every other output-tree mutation is
		// named (a write, a reaped temp, a removed orphan).
		slog.Info("tightened the file mode of a prior pfx",
			"path", rel, "from", perm.String(), "to", got.String())
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
// five positional parameters because every field is a veto and a caller must not
// be able to transpose two of them silently.
type reapContext struct {
	scanTotal     int
	failed        int
	unreadable    int
	unresolved    int
	walkCompleted bool
	// shutdown is true when the walk ended because the process is stopping, which
	// is not an operator-actionable incomplete enumeration.
	shutdown bool
}

// enumerationClean reports whether nothing PREVENTED the walk from enumerating the
// whole input tree. It is the shared half of two decisions that differ by one term:
// enumeratedInput adds scanTotal > 0 (an empty tree is clean but gives the output
// nothing to be compared against), while Scanner.Run's observation-state prune does
// not. Spelling the veto set once means a new veto field cannot be added to one
// caller and missed in the other.
func (r reapContext) enumerationClean() bool {
	return r.walkCompleted && r.unreadable == 0 && r.unresolved == 0
}

// enumeratedInput reports whether `seen` can be trusted as a COMPLETE enumeration
// of the input tree. It is the precondition for calling an output an orphan AT ALL,
// not just for deleting one: without it every bundle whose cert the scan never
// reached reads as an orphan.
func (r reapContext) enumeratedInput() bool {
	return r.enumerationClean() && r.scanTotal > 0
}

// safeToReap reports whether the input enumeration is complete enough to justify
// deleting anything.
func (r reapContext) safeToReap() bool {
	return r.enumeratedInput() && r.failed == 0
}

// logIncompleteInputEnumeration reports why orphan reconciliation is skipped when
// the input enumeration is incomplete. Without a complete enumeration, "this output
// has no matching input" is not a claim the scan can make: a bundle whose cert the
// walk never reached is indistinguishable from one whose cert was deleted.
func logIncompleteInputEnumeration(rc reapContext) {
	switch {
	case rc.shutdown:
		slog.Debug("skipping orphan reconciliation; scan cancelled during shutdown")
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
			"walk_completed", rc.walkCompleted, "unreadable", rc.unreadable,
			"unresolved", rc.unresolved, "total", rc.scanTotal,
			"remediation", "check the /input mount and the unreadable-path warnings above")
	}
}

// reconcile compares the output tree against the input enumeration and, in sync
// mode, deletes the bundles that no longer have an input. It returns how many were
// removed plus a cancellation error when the process is shutting down: the walk
// caller folds that error into the scan's outcome, so a scan interrupted after the
// input walk finished is not reported as a clean, complete scan.
func (s *store) reconcile(ctx context.Context, mode outputpolicy.Lifecycle, seen map[string]struct{}, rc reapContext) (int, error) {
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
			"action", lifecycleInaction(mode, reapable),
			"remediation", orphanReportRemediation(walkSafe))
		return 0, nil
	}

	return s.removeOrphans(ctx, orphaned)
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

// sampleOrphanPaths renders at most maxLoggedOrphans paths, naming how many were
// elided so the log line stays bounded without hiding the scale.
func sampleOrphanPaths(paths []string) string {
	if len(paths) <= maxLoggedOrphans {
		return strings.Join(paths, ",")
	}
	return strings.Join(paths[:maxLoggedOrphans], ",") +
		fmt.Sprintf(" (+%d more)", len(paths)-maxLoggedOrphans)
}

// lifecycleInaction explains why an orphan was reported rather than removed. Two
// independent reasons can apply and the mode alone does not pick between them: a
// non-sync mode reports by configuration, AND any mode reaches this point when the
// scan could not prove every candidate is genuinely orphaned (a failed conversion
// or an unsafe OUTPUT walk; reconcile returns before this point when the INPUT
// enumeration is incomplete). The unproven reason wins, because it is the one that
// changes what the operator may safely do with the list.
func lifecycleInaction(mode outputpolicy.Lifecycle, reapable bool) string {
	if !reapable {
		return "kept: this scan could not prove every candidate is orphaned, so deleting could remove a live bundle"
	}
	return "reported only (OUTPUT_LIFECYCLE=" + string(mode) + ")"
}

// orphanReportRemediation is the orphan report's operator advice. It must not tell
// an operator to delete anything on a scan whose OUTPUT walk could not enumerate
// the tree: the candidate list then holds live bundles — a bundle written through a
// symlinked output directory is enumerated under its physical path, whose derived
// input name is absent from `seen`, so it reads as an orphan on the very scan that
// created it — and every entry in the list carries a private key.
func orphanReportRemediation(walkSafe bool) string {
	if !walkSafe {
		return "do not remove anything from this list yet: fix the /output warnings above, then re-check it on a scan that reports no disabled orphan removal"
	}
	return "remove them from the output volume, or set OUTPUT_LIFECYCLE=sync to have this app do it"
}

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
	// laxDirsReported dedupes the lax-output-directory WARN to once per directory
	// per scan. The check is asked per bundle (inspect runs for every .crt), but
	// the fact it reports is a property of the DIRECTORY, so a flat /output holding
	// twenty certificates must not emit twenty identical records every scan. The
	// store is constructed per Scanner.Run, so this lasts exactly one scan.
	laxDirsReported map[string]struct{}
}

// laxDirMsg is the standing WARN for an /output directory more permissive than
// pfxDirMode: a group- or world-WRITABLE directory lets any other process on the
// shared mount unlink a bundle or replace it, and a world-TRAVERSABLE one exposes the
// bundle names. This app creates the directory at pfxDirMode
// (atomicfile.WithMkdirMode) and never revisits it, so a directory an operator or an
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
	fi, err := s.lstat(dir)
	if err != nil || !fi.IsDir() {
		// A directory that cannot be stat-ed or is not a directory is reported by the
		// write path itself; this check adds nothing there.
		return
	}
	if s.laxDirsReported == nil {
		s.laxDirsReported = make(map[string]struct{})
	}
	s.laxDirsReported[dir] = struct{}{}
	if perm := fi.Mode().Perm(); perm&^pfxDirMode != 0 {
		// dir is root-relative, so it is "." for the flat /output the README's own setup
		// step produces; the root is named alongside it, as logOrphanWalkOutcome does for
		// its own directory-level records.
		slog.Warn(laxDirMsg,
			"path", dir, "dir", s.root.Name(),
			"mode", perm.String(), "want", os.FileMode(pfxDirMode).String(),
			"remediation", outputPermRemediation)
	}
}

// writeFileInRoot is store.write's confined atomic write, indirected through a
// package var for the same reason chmodInRoot is: the failure that now decides a
// HEALTH outcome — an /output write the volume refuses for a reason no restart clears,
// while the bundle already there is one this app never proved wrong — cannot be staged in
// a temp directory. The suite owns everything it creates, and as root nothing refuses
// it at all, so without this seam the health-neutral arm in
// writeOutcome would go unpinned and a future simplification could fold
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
		// Mirror the read bound: inspect reads this same file back under
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
//
// The value is convert.MaxBundleBytes, the largest bundle the codec will inspect:
// the party whose parser allocations scale with the input states the limit, so the
// read cap here and the preflight's own bounds cannot drift apart.
const maxPFXSize = convert.MaxBundleBytes

// contentState is the first of the two facts one prior-bundle inspection resolves:
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
	// maxPFXSize, the read failed, or the codec's preflight refused to look at it. A
	// rewrite is still the right move — this app can answer "I cannot tell" by writing
	// what it knows — but the fact carries NO claim that the bundle on disk is wrong, so
	// on its own it never affects health.
	contentUnverified
)

// String names the fact for an operator. The standing WARN for a health-neutral write
// refusal carries it, because "which of these three did the app actually know?" is the
// first thing an operator has to establish about a bundle left in place, and one message
// text cannot carry all three.
func (c contentState) String() string {
	switch c {
	case contentVerifiedCurrent:
		return "verified-current"
	case contentVerifiedStale:
		return "verified-stale"
	case contentUnverified:
		return "unverified"
	default:
		return "unresolved"
	}
}

// bundleState is what one inspection of the output path resolved, as two INDEPENDENT
// facts rather than one verdict: what this app knows about the bytes on disk
// (contentState) and whether the mode repair converged (tightenResult). Neither says
// what should happen next — convertEntry derives that once, after the write, from these
// two facts plus the write's own outcome (writeOutcome).
//
// Two ints: cheap to pass by value, and nothing here is mutated after inspect returns.
type bundleState struct {
	content contentState
	repair  tightenResult
}

// upToDate reports whether the output path needs no write at all: the bytes on disk are
// already the bundle these inputs produce AND the mode repair converged. A REFUSED mode
// repair is the one non-content reason to rewrite — a chmod this process may not perform
// on a file it does not own, which a temp+rename replacement can still converge because
// it needs permission on the output DIRECTORY rather than on the file (tightenMode owns
// that reasoning).
func (st bundleState) upToDate() bool {
	return st.content == contentVerifiedCurrent && st.repair != tightenRefused
}

// modeRepairOnly reports the one shape whose rewrite carries no new bytes: the content
// was compared and matched, the mode is laxer than policy, and the chmod was refused.
// It is DERIVED from the two facts here rather than remembered by whoever noticed the
// refusal first, which is the whole reason they are separate — the previous shape had to
// tag its currency verdict to keep this promise, and the arms that could not read the
// bundle overwrote the tag.
func (st bundleState) modeRepairOnly() bool {
	return st.content == contentVerifiedCurrent && st.repair == tightenRefused
}

// bundleNotProvenWrong reports whether a failed rewrite leaves the operator with a
// bundle this app has no evidence against: one it compared and matched, or one it could
// not read at all. Spelled as an ALLOWLIST of exactly those two facts, so the zero value
// and any fact added later take the loud direction — a conversion failure — by
// construction rather than by omission.
func (st bundleState) bundleNotProvenWrong() bool {
	return st.content == contentVerifiedCurrent || st.content == contentUnverified
}

// inspect resolves what this app knows about the output at rel, by READING it rather
// than by remembering what was written: the state of its content, and the outcome of the
// mode repair. It decides nothing else — not whether to write, not whether a failure is
// a failure. Those are derived once, after the write, in writeOutcome.
//
// Reading the output keeps currency stable across process restarts and detects
// out-of-band replacement, password rotation, and encoder-profile changes without
// persisted state.
//
// Every "I cannot tell what is on disk" outcome resolves to contentUnverified: a decode
// failure is the exception, because the codec DID look and the bundle will not open with
// the configured password, which proves it is not the one these inputs produce
// (contentVerifiedStale). The unverified arms are the stat failure, the file above
// maxPFXSize, the read failure and the codec's preflight refusing to look. All of them
// still lead to a rewrite — the app can answer "I cannot tell" by writing what it knows —
// but none of them claims the bundle on disk is wrong, and that distinction is exactly
// what health has to respect. The stat and read arms carry the /output ownership hint,
// because that is what they mean; the oversized arm deliberately carries none, because
// store.write refuses to emit a bundle above maxPFXSize, so a file over the bound was
// written by something else and the rewrite itself is the whole remedy. Only shutdown is
// a hard error: it is neither current nor stale, and treating it as stale would rewrite
// every in-flight pair on the way out.
//
// Permission bits never reach the content fact. A bundle laxer than pfxFileMode is
// normally tightened in place with a chmod (tightenMode, which owns the reasoning) and
// its content is compared as usual; when that chmod is REFUSED outright (EPERM/EACCES,
// i.e. the bundle belongs to another UID) the chmod can never converge but a rewrite can,
// because the temp+rename needs write permission on the output DIRECTORY rather than on
// the file it replaces. That refusal is REPORTED as the repair fact and nothing else:
// bundleState.upToDate is what turns it into a rewrite, and bundleState.modeRepairOnly is
// what lets the caller say afterwards that this rewrite carried no new bytes. Returning
// it folded into the currency verdict is what previously made those two facts one value.
func (s *store) inspect(ctx context.Context, rel string, want *convert.Analysis,
	wantEncoder convert.EncoderType, password string,
) (bundleState, error) {
	// Asked before the bundle's own lstat so it covers the absent-bundle arm too: the
	// directory is lax whether or not a prior bundle sits in it. Report-only, so it
	// never changes the currency answer, the write, the reap or health — see
	// reportLaxDir.
	s.reportLaxDir(rel)
	fi, err := s.lstat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Nothing on disk is the strongest form of "not the bundle these inputs produce":
		// there is no copy for a consumer to read, so a rewrite that fails here is a
		// conversion failure whatever refused it.
		return bundleState{content: contentVerifiedStale}, nil
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
			"path", rel, "error", err,
			"remediation", outputPermRemediation)
		return bundleState{content: contentUnverified}, nil
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
			"path", rel, "mode", fi.Mode().String(),
			"remediation", "remove whatever occupies the output path; this app writes only regular files there")
		return bundleState{content: contentVerifiedStale}, nil
	}

	// Fact two, resolved in full rather than reduced to a boolean. It runs before every
	// return below so a bundle this app keeps and one it is about to replace are treated
	// alike, and so a rewrite that then fails does not leave a private key readable by the
	// world with nothing logged. The three arms above return before it because no repair
	// was attempted there, which is exactly what tightenNotNeeded (the zero value) says.
	repair := s.tightenMode(rel, fi)

	if fi.Size() > maxPFXSize {
		slog.Warn("prior pfx exceeds the readable bound; regenerating",
			"path", rel, "size", fi.Size(), "limit", maxPFXSize)
		return bundleState{content: contentUnverified, repair: repair}, nil
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
			return bundleState{repair: repair}, fmt.Errorf("read prior pfx: %w", errors.Join(ctxErr, err))
		}
		// Same reasoning as the stat failure above: unreadable means "cannot tell".
		slog.Warn("cannot read prior pfx; regenerating",
			"path", rel, "error", err,
			"remediation", outputPermRemediation)
		return bundleState{content: contentUnverified, repair: repair}, nil
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
	content, err := contentFromCurrency(ctx, rel, res, wantEncoder)
	return bundleState{content: content, repair: repair}, err
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
		slog.Debug("prior pfx failed preflight; regenerating", "path", rel, "error", res.Err)
		return contentUnverified, nil
	case convert.CurrencyProfileMismatch:
		// A deliberate PFX_ENCODER change. Without this the switch would rewrite
		// nothing: the leaf, key and chain all still match, so the bundle would keep
		// its old algorithms indefinitely while the startup log announced the new
		// profile.
		slog.Info("prior pfx uses a different encoder profile; regenerating",
			"path", rel, "found", string(res.Profile), "configured", string(wantEncoder))
		return contentVerifiedStale, nil
	case convert.CurrencyDecodeFailed:
		// Expected and non-fatal: a rotated password, a truncated file, a foreign file at
		// that path. Verified STALE rather than unverified, because the codec did look and
		// the bundle will not open with the configured password — which is the password
		// every consumer of this output uses, so what is on disk is not a usable copy of
		// the bundle these inputs produce.
		slog.Debug("prior pfx did not decode; regenerating", "path", rel, "error", res.Err)
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
// directory refuses the write too, this line is followed by unwritableBundleMsg (or, for
// a refusal that is not a permission denial, unreplaceableBundleMsg), which names the
// standing condition; this one only ever announces the attempt.
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

// tightenResult is the outcome of one mode-repair attempt, as its caller needs to see
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
// a permission reason, as opposed to failing it for any other reason. Two /output
// questions turn on that distinction and both ask it here: tightenMode's chmod, where a
// refusal is the evidence that another UID owns the bundle, and restartCanClearWrite,
// where it is the first of the classes no restart clears.
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

// restartCanClearWrite reports whether a FAILED /output write is one a container restart
// could plausibly clear. That is the only question health has to answer — health means
// "should an orchestrator restart this container?" — so it is the third fact writeOutcome
// derives an entry's status from.
//
// It is a property of the ERROR and of nothing else. The previous shape asked the
// STALENESS CAUSE instead, which is why a rewrite refused for permissions was counted as
// a conversion failure whenever the bundle happened to be one this app could not read:
// why the app decided to rewrite says nothing about whether restarting changes the
// outcome.
//
// The unclearable classes are enumerated, and everything else is clearable — the safe
// direction, because an error this app cannot attribute to a steady-state condition of
// the operator's volume might genuinely be gone on the next attempt, and a conversion
// failure is the loud outcome:
//
//   - EACCES / EPERM (isPermissionRefusal): a UID does not gain a permission by
//     restarting. Only a chown or a chmod on /output clears it.
//   - EROFS: a read-only mount is a mount option, not process state.
//   - ENOSPC / EDQUOT: a full volume or an exhausted quota. A restarted container writes
//     the same bytes into the same full volume.
//
// It says nothing about whether the write SHOULD have succeeded: writeOutcome asks this
// only after establishing that the bundle already on disk is not one this app proved
// wrong.
func restartCanClearWrite(err error) bool {
	switch {
	case isPermissionRefusal(err):
		return false
	case errors.Is(err, syscall.EROFS), errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return false
	default:
		return true
	}
}

// fileOwnedByProcess is tightenMode's ownership question, indirected through a
// package var for the same reason chmodInRoot is: a suite cannot stage a
// foreign-owned bundle in a directory it created itself, and a chmod refusal
// injected through chmodInRoot means "another UID owns this" only if the ownership
// read agrees.
var fileOwnedByProcess = ownedByThisProcess

// ownedByThisProcess reports whether fi is owned by the UID this process runs as.
// It is the discriminator the refused-chmod arm's premise rests on: only a bundle
// this process does NOT own is one a temp+rename rewrite can converge.
//
// Geteuid, not Getuid: the kernel checks a chmod against the EFFECTIVE (fs) uid
// (inode_owner_or_capable -> current_fsuid), which is the authorization this
// discriminator models. Where the two differ, the real uid would answer "owned" for a
// bundle this process may not chmod (routing a genuinely unconvergeable refusal onto
// the WARN-only arm) or the reverse.
//
// A missing *syscall.Stat_t answers false, which keeps the documented deployment
// shape (a root-owned bundle left behind by an earlier PUID mapping) on the arm
// that repairs it.
func ownedByThisProcess(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Geteuid()
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
// The ONE exception is a REFUSED chmod (tightenRefused), which is the one repair
// outcome bundleState.upToDate turns into a rewrite even over content that matched:
// there the chmod can never converge — this process does not own the file — while a
// temp+rename rewrite can, because it needs permission on the output directory rather
// than on the file. Without that arm a private-key-bearing bundle
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
// volume. os.Root.Chmod does follow a symlink, and inspect's lstat cannot rule out
// a swap in the window before this call, but the reach of that race is one permission
// bit: it never touches content, and anyone able to stage the swap on a co-mounted
// /output can already replace the bundle itself.
func (s *store) tightenMode(rel string, fi os.FileInfo) tightenResult {
	perm := fi.Mode().Perm()
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
	case errors.Is(err, errModeUnobserved):
		// The chmod was accepted; only the confirming re-stat failed. That says nothing
		// about ownership, so it must not schedule the rewrite tightenRefused asks for —
		// the bits may well be correct now, and rewriting would churn the bundle with
		// fresh KDF salts and a fresh mtime for nothing.
		slog.Warn(modeNotTightenedMsg,
			"path", rel, "mode", perm.String(), "want", want.String(),
			"error", err, "remediation", outputModeRemediation)
		return tightenIneffective
	case err != nil && isPermissionRefusal(err) && !fileOwnedByProcess(fi):
		// Not ours to chmod, but ours to replace: bundleState.upToDate reads this outcome
		// as a reason to rewrite, and the ordinary write path converges it. Named with the ownership
		// remediation rather than the filesystem one, because that is what a refusal
		// means.
		//
		// The ownership term is what keeps this arm honest. A refusal on a bundle this
		// process OWNS is not evidence about ownership — a UID that owns a file may always
		// chmod it, so what was refused is the requested BITS, not our right to set them:
		// a filesystem which forces modes and reports the refusal instead of swallowing it
		// (fat_setattr returns EPERM for any mode outside the mount's fmask). A rewrite
		// cannot converge that either — the replacement lands with the same forced mode —
		// so it must NOT schedule one, and it falls through to the generic error arm below,
		// which reports it exactly as a chmod the filesystem accepts and stores nothing is
		// reported (tightenIneffective, modeNotTightenedMsg, outputModeRemediation).
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

// errModeUnobserved marks a repair whose CHMOD was ACCEPTED and whose confirming
// re-stat then failed. It exists so tightenMode cannot read a refused re-stat as a
// refused chmod: only the chmod being refused is evidence this process does not own
// the bundle, and only that justifies the rewrite tightenRefused schedules.
var errModeUnobserved = errors.New("mode not observed after chmod")

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
		return 0, fmt.Errorf("re-stat after chmod: %w", errors.Join(errModeUnobserved, err))
	}
	return fi.Mode().Perm(), nil
}

// readBoundedPFX reads rel from inside the output tree under maxPFXSize.
//
// atomicfile owns the confined read: it opens through the root non-blocking (so a
// FIFO or device node planted at an output name is rejected rather than wedging
// the scan's only goroutine in open(2) forever), requires a regular file, and
// stats the OPEN HANDLE rather than the path — closing the window between
// inspect's lstat and this open on a volume other containers write to. Those
// are the same three guarantees the input side already delegates in
// source.readBoundedLimit.
func (s *store) readBoundedPFX(ctx context.Context, rel string) ([]byte, error) {
	return atomicfile.ReadBoundedInRoot(ctx, s.root, rel, maxPFXSize)
}

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
	walk := outputWalk{ctx: ctx, safe: true}
	if err := atomicfile.WalkDirInRoot(ctx, s.root, walk.visit); err != nil {
		return nil, false, fmt.Errorf("walk output tree: %w", err)
	}
	s.logOrphanWalkOutcome(walk.unreadable, walk.symlinked)
	return walk.found, walk.safe, nil
}

// outputWalk is listOutputs' visitor state: the candidate list plus the two
// deletion-safety counters and the verdict they feed. It exists so the walk body is a
// named method with explicit state rather than a closure mutating five captured
// variables — the traversal control, the safety accounting, the diagnostics and the
// candidate collection are the same branches either way, but the state a deletion
// decision rests on is now spelled out as fields.
type outputWalk struct {
	ctx        context.Context
	found      []string
	unreadable int
	symlinked  int
	safe       bool
}

// visit is listOutputs' walk callback: one entry, one verdict.
func (w *outputWalk) visit(rel string, d fs.DirEntry, err error) error {
	// Same per-entry cancellation contract the input walk and the stale-temp
	// sweep already honour: this walk runs on the shutdown path, because the
	// scan is driven synchronously from the watcher's onChange callback.
	if ctxErr := w.ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		if rel == "." {
			return err
		}
		// Debug per path, one aggregate Warn from logOrphanWalkOutcome: the same
		// two-level contract the input walk and the stale-temp sweep use. This recurs
		// on every scan for a persistent misconfiguration, so naming each path at the
		// default level is a permanent log stream for a condition already reported.
		slog.Debug("skipping unreadable output path while looking for orphans", "path", rel, "error", err)
		w.unreadable++
		w.safe = false
		return nil
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
		slog.Debug("output tree contains a symlink; "+reapDisabledPhrase, "path", rel)
		w.symlinked++
		w.safe = false
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
	if unreadable > 0 {
		slog.Warn("some output paths could not be read while looking for orphans; "+reapDisabledPhrase,
			"dir", s.root.Name(), "count", unreadable,
			"remediation", outputPermRemediation)
	}
	if symlinked > 0 {
		slog.Warn("output tree contains symlinks; "+reapDisabledPhrase+" because writes and the orphan walk resolve paths differently",
			"dir", s.root.Name(), "count", symlinked,
			"remediation", "mount the real output directory instead of linking to it")
	}
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
		if s.removeOrphan(rel) {
			deleted++
		}
	}
	return deleted, nil
}

// pinRedirectedMsg is the WARN for a candidate whose own output directory could not be
// pinned to the physical directory the orphan walk classified: a component that is a
// symlink or not a directory at all, or one that changed identity while it was being
// opened. The walk already vetoes reaping on any symlink it SEES, but that snapshot is
// taken before the confirmation delay, so this is the same rule applied at unlink time.
const pinRedirectedMsg = "could not pin the output directory of an orphaned bundle; leaving it in place"

// removeOrphan re-checks one confirmed orphan and unlinks it through a PINNED parent
// root, reporting whether it was deleted.
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
func (s *store) removeOrphan(rel string) bool {
	parent, base, err := atomicfile.OpenParentInRoot(s.root, rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// An ancestor vanished with its bundle during the deferral: the same
			// transient race as the basename arm below, not a redirection. The pin
			// wraps its Lstat error, so this is the nested layout's spelling of the
			// disappearance the flat layout reports from Lstat directly — and the
			// symlink remediation on the WARN below would send an operator looking for
			// a misconfiguration that is not there.
			slog.Debug("orphaned output vanished before removal", "path", rel)
			return false
		}
		slog.Warn(pinRedirectedMsg, "path", rel, "error", err,
			"remediation", "mount the real output directory instead of linking to it, and check /output for paths replaced while the scan was running")
		return false
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
		slog.Debug("orphaned output vanished before removal", "path", rel)
		return false
	case statErr != nil:
		slog.Warn("could not re-check an orphaned output before removing it; leaving it in place",
			"path", rel, "error", statErr, "remediation", outputPermRemediation)
		return false
	case !fi.Mode().IsRegular():
		slog.Warn("orphaned output path is not a regular file; leaving it in place",
			"path", rel, "mode", fi.Mode().String(),
			"remediation", "remove whatever occupies the output path by hand; this app deletes only the regular files it writes")
		return false
	}
	if err := parent.Remove(base); err != nil {
		slog.Warn("could not remove orphaned output", "path", rel, "error", err,
			"remediation", outputPermRemediation)
		return false
	}
	// Every deletion is named. The once-per-scan audit record (reapAuditMsg) is the
	// warn-visible contract for that; this per-path line is the complete, unbounded
	// list for a reader who asked for detail, so it sits at Debug rather than repeating
	// the audit at the default level once per path.
	slog.Debug("removed orphaned output whose input is gone", "path", rel)
	return true
}

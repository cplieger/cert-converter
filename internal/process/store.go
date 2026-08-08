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
// pfxFileMode is both the mode this app INSTALLS on every bundle it writes and the
// policy a bundle already on disk is measured against. It is a CEILING for the second
// job, not an exact target: a mode the operator made STRICTER (0400) carries no bit
// beyond it and is left alone, which is what laxerThanPolicy tests.
//
// A prior bundle laxer than it is never chmodded in place. It is reported
// (laxBundleMsg) and then corrected as a side effect of the ordinary atomic rewrite
// this app already performs, which installs a fresh inode at this mode by construction
// (store.write's atomicfile.WithMode). So the mode a bundle HAS does reach the currency
// decision — bundleState.modeLax routes it to that rewrite — but nothing here ever
// mutates a mode on the operator's volume.
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
	// means "use fallbackScanEntries" (outputWalk.entryBudget), so a store assembled
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
// A pin this app cannot obtain FAILS the write, which is a conversion failure and
// flips health, exactly as the leaf-symlink refusal atomicfile already returns does.
// That is the healthcheck contract's own scope — failing to write a renewed bundle is
// a real conversion failure — and it is deliberately not the /output DIRECTORY-mode
// question, which stays report-only.
//
// The parent directory is created first and separately, because the pin needs a
// directory that already exists: WithMkdirMode would create it inside the write, which
// is the step the pin has to precede. MkdirAll runs through the same confined root at
// the same pfxDirMode the option used (that is literally what the option does), so
// mode and confinement still cannot drift.
func (s *store) write(ctx context.Context, rel string, pfx []byte) error {
	if dir := path.Dir(rel); dir != "." {
		if err := s.root.MkdirAll(dir, pfxDirMode); err != nil {
			// Named as part of the write, and carrying rel, because the step is invisible
			// to an operator otherwise: the failure the library used to report from inside
			// the write is now this call's, and the diagnosis has to keep naming the write
			// it belongs to and the path that could not be created.
			return fmt.Errorf("write pfx: create output directory for %q: %w", rel, err)
		}
	}
	parent, base, err := atomicfile.OpenParentInRoot(s.root, rel)
	if err != nil {
		return fmt.Errorf("write pfx: pin output directory for %q: %w", rel, err)
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
	// maxPFXSize, the read failed for a reason that does not itself settle what is on
	// disk, or the codec's preflight refused to look at it. A
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
// (contentState) and whether the mode on disk is laxer than policy (modeLax). Neither
// says what should happen next — convertEntry derives that once, after the write, from
// these two facts plus the write's own outcome (writeOutcome).
//
// Cheap to pass by value, and nothing here is mutated after inspect returns.
type bundleState struct {
	content contentState
	// modeLax is the whole of what a permission bit contributes to the decision: the
	// bundle on disk carries a bit pfxFileMode does not. It replaced a four-valued
	// mode-repair outcome, because with no chmod there is no repair to have converged,
	// failed, or been refused — only a mode that needs rewriting or does not.
	modeLax bool
}

// upToDate reports whether the output path needs no write at all: the bytes on disk are
// already the bundle these inputs produce AND its mode is not laxer than policy. A lax
// mode is the one non-content reason to rewrite, because the rewrite is the ONLY way
// this app corrects a mode: store.write installs pfxFileMode on a fresh inode, so
// routing a lax bundle through the ordinary write path is what fixes it. Skipping the
// write on content alone would leave a private-key bundle permanently over-permissive.
func (st bundleState) upToDate() bool {
	return st.content == contentVerifiedCurrent && !st.modeLax
}

// modeRepairOnly reports the one shape whose rewrite carries no new bytes: the content
// was compared and matched, and only the mode is laxer than policy. It survives the
// removal of the chmod mechanism because it still names the distinction health turns on
// — a rewrite that carries no new bytes and fails leaves the operator exactly the bundle
// they already had, so it must not flip health, while a failed write of a RENEWED bundle
// must. It is DERIVED from the two facts rather than remembered by whoever noticed the
// lax mode first, which is the whole reason they are separate.
func (st bundleState) modeRepairOnly() bool {
	return st.content == contentVerifiedCurrent && st.modeLax
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
// than by remembering what was written: the state of its content, and whether its mode is
// laxer than policy. It decides nothing else — not whether to write, not whether a
// failure is a failure. Those are derived once, after the write, in writeOutcome.
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
// Permission bits never reach the content fact, and are never acted on in place. A
// bundle laxer than pfxFileMode is REPORTED (laxBundleMsg) and recorded as the second
// fact; its content is compared as usual. Correcting it is the ordinary write path's job
// and nothing else's: bundleState.upToDate turns the lax mode into a rewrite, store.write
// installs pfxFileMode on the fresh inode, and bundleState.modeRepairOnly is what lets
// the caller say afterwards that this rewrite carried no new bytes. No chmod is
// attempted, which is the settled shape for both halves of /output — the app warns about
// a mode it would not have chosen and changes nothing about what is already there
// (output-dir-write-bit-enforcement, extended to files).
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

	// Fact two. It runs before every return below so a bundle this app keeps and one it
	// is about to replace are treated alike, and so a rewrite that then fails does not
	// leave a private key readable by the world with nothing logged. The three arms above
	// return before it because there is no mode on disk worth reporting there — nothing
	// is present, or what is present is not a bundle at all — which is exactly what the
	// zero value says.
	modeLax := s.reportLaxBundle(rel, fi.Mode().Perm())

	if fi.Size() > maxPFXSize {
		slog.Warn("prior pfx exceeds the readable bound; regenerating",
			"path", rel, "size", fi.Size(), "limit", maxPFXSize)
		return bundleState{content: contentUnverified, modeLax: modeLax}, nil
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
			return bundleState{modeLax: modeLax}, fmt.Errorf("read prior pfx: %w", errors.Join(ctxErr, err))
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
			"path", rel, "error", err,
			"remediation", outputPermRemediation)
		return bundleState{content: content, modeLax: modeLax}, nil
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
	return bundleState{content: content, modeLax: modeLax}, err
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

// laxBundleMsg is the standing WARN for a prior bundle carrying a permission bit
// pfxFileMode does not. It names the mode found and the mode this app will install, and
// it promises nothing else: no chmod is attempted, so there is no repair outcome to
// report and no operator action to request. The lax mode is corrected as a side effect
// of the ordinary atomic rewrite the app already performs on this bundle
// (bundleState.upToDate routes it there), which installs a fresh inode at pfxFileMode
// by construction — so this fires once and never again, and the operator is told what
// happened rather than asked to do it.
//
// The report-only tone is laxDirMsg's, and deliberately: one principle now covers both
// halves of /output. For a DIRECTORY the app warns and does nothing
// (output-dir-write-bit-enforcement); for a FILE it warns and lets its own write path
// install the mode it wants. Neither half mutates a mode in place, which is the
// ecosystem consensus — OpenSSH refuses an over-permissive key without chmodding it,
// certbot warns and requires the operator to act, and certbot's own renewal applies its
// restrictive mode to the NEW file it writes rather than to the old one.
//
// Carries no remediation: unlike every other /output WARN, nothing is being asked of the
// operator. If the correcting rewrite is then REFUSED, that standing condition gets its
// own WARN with the right remediation (unwritableBundleMsg via unwritableReport).
const laxBundleMsg = "prior pfx is more permissive than policy; rewriting it at the wanted mode"

// outputPinRemediation is the operator action behind every /output pin refusal. It
// names both causes the pin cannot tell apart: a symlinked output tree (a standing
// misconfiguration) and a path replaced while the scan was running (a co-mounting
// writer).
const outputPinRemediation = "mount the real output directory instead of linking to it, and check /output for paths replaced while the scan was running"

// laxerThanPolicy reports whether perm carries a permission bit pfxFileMode does
// not. It is the WHOLE of the mode decision now: set means the bundle needs rewriting,
// nothing more.
//
// A bitmask test rather than an inequality, because a mode can differ from policy by
// being STRICTER: 0400 and 0600 carry no extra bit and are left exactly as found, while
// 0640, 0644 and 0700 each do.
func laxerThanPolicy(perm os.FileMode) bool {
	return perm&^pfxFileMode != 0
}

// reportLaxBundle warns when a prior bundle's mode is laxer than pfxFileMode, and
// reports that fact to the caller. It is detection and narration only — it opens
// nothing, pins nothing and mutates nothing, so the mode on disk is left exactly as
// found and the correction happens in store.write like any other rewrite.
//
// One WARN per lax bundle per scan, and in practice once ever: the fact it reports makes
// bundleState.upToDate false, so the same scan rewrites the bundle at pfxFileMode and
// the condition cannot re-trigger. It repeats per scan only while the correcting write
// is itself refused, which is the standing condition an operator does need told about
// every scan (unwritableReport emits the message that names it).
func (s *store) reportLaxBundle(rel string, perm os.FileMode) bool {
	if !laxerThanPolicy(perm) {
		return false
	}
	slog.Warn(laxBundleMsg,
		"path", rel, "mode", perm.String(), "want", os.FileMode(pfxFileMode).String())
	return true
}

// isPermissionRefusal reports whether err is the filesystem REFUSING an operation for
// a permission reason, as opposed to failing it for any other reason. Its consumer is
// restartCanClearWrite, where a refusal is the first of the classes no restart clears,
// and unwritableReport, which turns the same distinction into the operator remediation
// (ownership versus volume).
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
	walk := outputWalk{ctx: ctx, safe: true, maxEntries: s.maxEntries}
	if err := atomicfile.WalkDirInRoot(ctx, s.root, walk.visit); err != nil {
		return nil, false, fmt.Errorf("walk output tree: %w", err)
	}
	s.logOrphanWalkOutcome(walk.unreadable, walk.symlinked)
	return walk.found, walk.safe, nil
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
// as scanBudgetRemediation does for /input.
const outputBudgetRemediation = "check that /output is mounted at the bundle directory and holds nothing else, or raise MAX_SCAN_ENTRIES if the tree is legitimately this large"

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
	// entries counts every path this walk has been handed, including directories and
	// entries it could not read, for the same reason scanWalk.entries does: the cap is
	// about how much of an untrusted tree one scan takes on, so it counts what the walk
	// TOUCHED rather than what it kept as a candidate. Counting only layout.IsOutput
	// names would let a flat set of ignored names walk past the bound for free.
	entries int
	// maxEntries is this walk's injected budget; non-positive means fallbackScanEntries
	// (entryBudget), so a walk assembled without one is still bounded.
	maxEntries int
	safe       bool
}

// entryBudget is the effective ceiling for this walk: the injected budget, or
// fallbackScanEntries when nothing was injected. Resolved HERE rather than at
// construction for the reason scanWalk.entryBudget states — every assembler of one gets
// a bound, including the tests that build one field by field.
func (w *outputWalk) entryBudget() int {
	return effectiveEntryBudget(w.maxEntries)
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
	w.entries++
	if budget := w.entryBudget(); w.entries > budget {
		return fmt.Errorf("%w: stopped at %d entries (%s)", errOutputBudgetExceeded, w.entries, rel)
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
			"remediation", outputPinRemediation)
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

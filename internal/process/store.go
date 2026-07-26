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
)

// Output file and directory modes. A PFX carries a private key, so it is
// owner-read/write only; its parent directory is owner-traversable plus group
// read, matching the documented deployment where a matching host UID owns the
// volume.
const (
	pfxFileMode = 0o600
	pfxDirMode  = 0o750
)

// store owns every touch of the output tree.
//
// Before this type, output responsibility was spread across three places: the
// atomic write lived in internal/convert (on a root that package did not own),
// while the root itself, the path derivation, the directory mode, the prior-output
// check and the stale-temp sweep lived in the scan. Deferred finding l-f27 named
// the missing owner directly.
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
// by a hand-rolled MkdirAll here. That is the library's job — it creates the
// directory inside the same confined root, before staging the temp file — and
// duplicating it locally is what deferred findings l-f41 and l-f18 flagged: the
// write went through the library while the directory step did not, so the two
// halves of one operation could drift in mode or in confinement behaviour.
func (s *store) write(ctx context.Context, rel string, pfx []byte) error {
	if _, err := atomicfile.WriteFileInRoot(ctx, s.root, rel, pfx,
		atomicfile.WithMode(pfxFileMode),
		atomicfile.WithMkdirMode(pfxDirMode),
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
// writes are atomic temp+rename. It used to sit beside the scan as free functions
// over a raw *os.Root, which is what left the output tree with no single owner
// (deferred finding l-f27).

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
// sweep needs are the library's guarantees rather than this app's code (deferred
// finding l-f16): the walk is root-relative so a co-mounting writer that swaps an
// output subdirectory for a symlink mid-sweep cannot redirect a deletion outside the
// mounted volume; it recurses because atomicfile stages its temp in the TARGET
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
	const remediation = "check /output ownership and permissions for the UID in user:"
	if walkErr != nil {
		if IsShutdown(walkErr) {
			// Shutdown, not an operator-actionable cleanup failure; the input
			// walk's own context check reports the cancellation to the caller.
			slog.Debug("stale temp cleanup cancelled during shutdown", "dir", s.root.Name(), "error", walkErr)
		} else {
			slog.Warn("stale temp cleanup failed", "dir", s.root.Name(), "error", walkErr)
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
			"count", res.Failed, "remediation", remediation)
	}
	if res.Unreadable > 0 {
		slog.Warn("some output paths could not be inspected during stale temp cleanup",
			"dir", s.root.Name(), "count", res.Unreadable, "remediation", remediation)
	}
}

// --- Input walk ---

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
			"remediation", "check /output ownership and permissions for the UID in user:")
		return false, nil
	case !fi.Mode().IsRegular():
		// A directory, symlink or device node at the output name is not a usable
		// prior bundle, and a symlink must never be followed here or unrelated
		// content could satisfy the check.
		return false, nil
	case fi.Mode().Perm() != pfxFileMode:
		// The bundle carries a private key, so pfxFileMode is this app's policy for
		// it, not just the mode of a fresh write. A file whose contents already match
		// would otherwise keep a laxer mode forever, because currency is decided on
		// content alone. Rewriting converges it: atomicfile chmods to the exact mode.
		slog.Warn("prior pfx has an unexpected file mode; regenerating",
			"path", rel, "mode", fi.Mode().Perm().String(), "want", os.FileMode(pfxFileMode).String())
		return false, nil
	case fi.Size() > maxPFXSize:
		slog.Warn("prior pfx exceeds the readable bound; regenerating",
			"path", rel, "size", fi.Size(), "limit", maxPFXSize)
		return false, nil
	}

	prior, err := s.readBoundedPFX(ctx, rel)
	if err != nil {
		if ctx.Err() != nil {
			// Shutdown, not an unreadable output: propagate so the scan reports the
			// cancellation rather than rewriting on the way out.
			return false, fmt.Errorf("read prior pfx: %w", err)
		}
		// Same reasoning as the stat failure above: unreadable means "cannot tell",
		// which resolves to stale.
		slog.Warn("cannot read prior pfx; regenerating",
			"path", rel, "error", err,
			"remediation", "check /output ownership and permissions for the UID in user:")
		return false, nil
	}

	// Preflight BEFORE any derivation: it bounds the iteration counts the file
	// itself dictates, and it names the encoder profile the file was written with,
	// which decoding cannot reveal.
	insp, err := convert.Inspect(prior)
	if err != nil {
		slog.Debug("prior pfx failed preflight; regenerating", "path", rel, "error", err)
		return false, nil
	}
	if insp.Profile != wantEncoder {
		// A deliberate PFX_ENCODER change. Without this the switch would rewrite
		// nothing: the leaf, key and chain all still match, so the bundle would keep
		// its old algorithms indefinitely while the startup log announced the new
		// profile.
		slog.Info("prior pfx uses a different encoder profile; regenerating",
			"path", rel, "found", string(insp.Profile), "configured", string(wantEncoder))
		return false, nil
	}

	// Synchronous: the preflight has already bounded the work, so there is nothing
	// to time out and no goroutine to abandon.
	decoded, err := convert.Decode(prior, password)
	if err != nil {
		if ctx.Err() != nil {
			// Shutdown is a third category, neither current nor stale. Treating it as
			// stale would make every in-flight pair rewrite on the way out.
			return false, fmt.Errorf("inspect prior pfx: %w", ctx.Err())
		}
		// Expected and non-fatal: a rotated password, a truncated file, a foreign
		// file at that path. All mean the same thing — rewrite it.
		slog.Debug("prior pfx did not decode; regenerating", "path", rel, "error", err)
		return false, nil
	}
	return decoded.MatchesAnalysis(want), nil
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

// Lifecycle decides what happens to an output whose input pair has disappeared.
type Lifecycle string

// The three lifecycle modes.
const (
	// LifecycleWarn reports orphaned outputs and deletes nothing. The DEFAULT:
	// deletion is opt-in, so an upgrade cannot remove files on its own.
	LifecycleWarn Lifecycle = "warn"
	// LifecycleSync makes the output tree mirror the input tree, deleting a bundle
	// whose source is gone. The homelab deployment opts into this explicitly.
	LifecycleSync Lifecycle = "sync"
	// LifecycleKeep leaves orphans in place silently.
	LifecycleKeep Lifecycle = "keep"
)

// ParseLifecycle normalises a raw OUTPUT_LIFECYCLE value. An unrecognised value
// falls back to the default with known false, so the caller that read the
// environment is the one that names it in a warning.
func ParseLifecycle(raw string) (mode Lifecycle, known bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(LifecycleSync):
		return LifecycleSync, true
	case string(LifecycleKeep):
		return LifecycleKeep, true
	case "", string(LifecycleWarn):
		return LifecycleWarn, true
	default:
		return LifecycleWarn, false
	}
}

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
			"remediation", "check /output ownership and permissions for the UID in user:")
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

// enumeratedInput reports whether `seen` can be trusted as a COMPLETE enumeration
// of the input tree. It is the precondition for calling an output an orphan AT ALL,
// not just for deleting one: without it every bundle whose cert the scan never
// reached reads as an orphan.
func (r reapContext) enumeratedInput() bool {
	return r.walkCompleted && r.unreadable == 0 && r.unresolved == 0 && r.scanTotal > 0
}

// safeToReap reports whether the input enumeration is complete enough to justify
// deleting anything.
func (r reapContext) safeToReap() bool {
	return r.enumeratedInput() && r.failed == 0
}

func (s *store) reconcile(ctx context.Context, mode Lifecycle, seen map[string]struct{}, rc reapContext) int {
	if mode == LifecycleKeep {
		return 0
	}
	if !rc.enumeratedInput() {
		// Without a complete input enumeration, "this output has no matching input"
		// is not a claim the scan can make: a bundle whose cert the walk never
		// reached is indistinguishable from one whose cert was deleted.
		if rc.shutdown {
			slog.Debug("skipping orphan reconciliation; scan cancelled during shutdown")
			return 0
		}
		slog.Warn("orphan removal is disabled for this scan: the scan did not fully enumerate the input tree, so no output can be proven orphaned",
			"walk_completed", rc.walkCompleted, "unreadable", rc.unreadable,
			"unresolved", rc.unresolved, "total", rc.scanTotal,
			"remediation", "check the /input mount and the unreadable-path warnings above")
		return 0
	}
	orphaned, walkSafe, err := s.orphans(ctx, seen)
	if err != nil {
		if IsShutdown(err) {
			// Shutdown, not a broken output tree; the input walk already reports the
			// cancellation to the caller.
			slog.Debug("orphan enumeration cancelled during shutdown", "error", err)
			return 0
		}
		slog.Warn("could not enumerate output orphans; orphan removal is disabled for this scan",
			"error", err, "dir", s.root.Name(),
			"remediation", "check /output ownership and permissions for the UID in user:")
		return 0
	}
	if len(orphaned) == 0 {
		return 0
	}

	reapable := rc.safeToReap() && walkSafe
	if mode != LifecycleSync || !reapable {
		slog.Warn("output bundles have no matching input",
			"count", len(orphaned), "paths", sampleOrphanPaths(orphaned),
			"action", lifecycleInaction(mode),
			"remediation", "remove them from the output volume, or set OUTPUT_LIFECYCLE=sync to have this app do it")
		return 0
	}

	return s.removeOrphans(ctx, orphaned)
}

// removeOrphans deletes each named output bundle, stopping early on shutdown and
// skipping (never aborting on) an individual removal failure. Returns how many
// were actually deleted.
func (s *store) removeOrphans(ctx context.Context, orphaned []string) int {
	var deleted int
	for _, rel := range orphaned {
		if ctx.Err() != nil {
			slog.Debug("orphan removal interrupted by shutdown",
				"removed", deleted, "remaining", len(orphaned)-deleted)
			break
		}
		if err := s.root.Remove(rel); err != nil {
			slog.Warn("could not remove orphaned output", "path", rel, "error", err)
			continue
		}
		// Every deletion is named. Removing key material without an audit line is
		// not acceptable even when it is correct.
		slog.Info("removed orphaned output whose input is gone", "path", rel)
		deleted++
	}
	return deleted
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

// lifecycleInaction explains why an orphan was reported rather than removed. It
// is only called when no deletion happened, so the mode alone determines which of
// the two reasons applies: any mode other than sync reports by configuration, and
// sync reports only when the scan could not prove every candidate is genuinely
// orphaned — reconcile now returns before this point when the INPUT enumeration is
// incomplete, so the sync arm is reached via a failed conversion or an unsafe
// OUTPUT walk.
func lifecycleInaction(mode Lifecycle) string {
	if mode != LifecycleSync {
		return "reported only (OUTPUT_LIFECYCLE=" + string(mode) + ")"
	}
	return "kept: this scan could not prove every candidate is orphaned, so deleting could remove a live bundle"
}

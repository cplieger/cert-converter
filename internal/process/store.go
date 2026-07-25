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

// tempNamePrefix, tempNameSuffix and staleTempAge mirror atomicfile's temp
// naming (".atomicfile-<digits>.tmp") and the reap cutoff, so the sweep stays
// matched to the writes and can never delete a caller-owned file.
const (
	tempNamePrefix = ".atomicfile-"
	tempNameSuffix = ".tmp"
	staleTempAge   = time.Hour
)

// isStaleTempName reports whether name has exactly atomicfile's temp shape:
// ".atomicfile-" followed by one or more decimal digits and ".tmp".
func isStaleTempName(name string) bool {
	digits, ok := strings.CutPrefix(name, tempNamePrefix)
	if !ok {
		return false
	}
	digits, ok = strings.CutSuffix(digits, tempNameSuffix)
	if !ok || digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// reapStaleTemp handles one candidate entry of the sweepStaleTemps walk: it
// filters non-candidates, re-checks the entry through the root before unlinking
// (only a regular file older than cutoff is a reclaimable orphan, and Lstat
// never follows a symlink planted under the temp's name) and removes it. Every
// operation stays root-relative through the store's root, so the confinement invariant
// is identical to doing the work inline in the callback. It reports whether a
// file was reaped and whether a non-benign failure occurred — a candidate that
// could not be inspected counts too, matching atomicfile.CleanupStaleTemps,
// whose equivalent stat failure also feeds its aggregate warning (the caller
// aggregates both).
func (s *store) reapStaleTemp(rel string, d fs.DirEntry, cutoff time.Time) (didRemove, didFail bool) {
	if d.IsDir() || !isStaleTempName(d.Name()) {
		return false, false
	}
	fi, err := s.root.Lstat(rel)
	if err != nil {
		// One per-entry detail stays at Debug; the aggregate Warn in
		// sweepStaleTemps carries the operator signal.
		slog.Debug("skipping unstattable temp during cleanup", "path", rel, "error", err)
		if errors.Is(err, fs.ErrNotExist) {
			// The candidate vanished between the readdir and the Lstat (a
			// co-mounting reaper, or the write it belonged to finishing its
			// rename). Benign, exactly as the unlink race below.
			return false, false
		}
		// A permission or IO error means a stale temp may be accumulating
		// unnoticed, so it must reach the aggregate Warn rather than being
		// visible only under LOG_LEVEL=debug.
		return false, true
	}
	if !fi.Mode().IsRegular() || fi.ModTime().After(cutoff) {
		return false, false
	}
	if err := s.root.Remove(rel); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The temp vanished between the Lstat and the unlink (a co-mounting
			// reaper, or the write it belonged to finishing its rename). Benign,
			// exactly as atomicfile's own CleanupStaleTemps treats it.
			return false, false
		}
		// One unlink failure is not actionable on its own; the aggregate Warn
		// in sweepStaleTemps carries the operator signal, matching
		// atomicfile.CleanupStaleTemps' per-entry Debug policy.
		slog.Debug("stale temp remove failed", "path", rel, "error", err)
		return false, true
	}
	return true, false
}

// sweepStaleTemps removes PFX temp files orphaned by an interrupted atomic write
// (a crash between temp-write and rename). It matches exactly the
// ".atomicfile-<digits>.tmp" shape atomicfile stages, so a caller-owned file in
// /output is never touched. The sweep covers the whole output tree, not just its
// top level: atomicfile stages its temp in the TARGET directory, so a nested
// cert (input/example.com/cert.crt) leaves its orphaned temp in the matching
// nested output directory.
//
// Every step — the walk, the stat and the unlink — is root-relative through
// the store's root, so a co-mounting writer that swaps an output subdirectory for a
// symlink mid-sweep cannot redirect the deletion outside the mounted volume.
// Reconstructed ambient paths are deliberately never handed to
// atomicfile.CleanupStaleTemps: that helper reopens the directory outside the
// root, which would reintroduce exactly that TOCTOU window.
//
// The sweep is cancellable: it walks the whole output tree before the input
// walk starts, so an already-cancelled or mid-shutdown scan must stop between
// entries instead of traversing (and unlinking across) a large tree while
// SIGTERM handling waits.
func (s *store) sweepStaleTemps(ctx context.Context) {
	tr := &tempReap{store: s, cutoff: time.Now().Add(-staleTempAge)}
	walkErr := fs.WalkDir(s.root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		return tr.visit(ctx, rel, d, err)
	})
	tr.logOutcome(walkErr)
}

// tempReap carries the confined output root, the staleness cutoff and the
// mutable accounting for one sweepStaleTemps walk (files reaped, candidates that
// could not be inspected or unlinked, unreadable output sub-paths). Hoisting the
// WalkDir callback onto this struct keeps sweepStaleTemps flat, mirroring
// scanWalk's role for the input walk.
type tempReap struct {
	store      *store
	cutoff     time.Time
	reaped     int
	failed     int
	unreadable int
}

// visit is the sweepStaleTemps WalkDir callback. A cancelled context aborts the
// sweep between entries; a walk error at the root (".") aborts it too, while an
// error below the root is counted as an unreadable sub-path, logged and skipped
// (a sub-path the sweep cannot enter may be hiding orphaned temps, so it feeds
// the aggregate Warn rather than being visible only at Debug). Every surviving
// entry goes to reapStaleTemp, whose two outcomes are aggregated here.
func (tr *tempReap) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if rel == "." {
			return err
		}
		slog.Debug("skipping unreadable output path during temp cleanup", "path", rel, "error", err)
		tr.unreadable++
		return nil
	}
	removed, didFail := tr.store.reapStaleTemp(rel, d, tr.cutoff)
	if removed {
		tr.reaped++
	}
	if didFail {
		tr.failed++
	}
	return nil
}

// logOutcome emits the end-of-sweep logs: the walk error (Debug for a shutdown
// cancellation, Warn otherwise), the reclaimed-orphan count, the count of temps
// that could not be inspected or removed, and the count of output sub-paths the
// sweep could not enter. The last two are steady-state permissions/UID
// misconfigurations that let stale atomic-write artifacts accumulate unnoticed,
// so they carry a remediation hint at the default log level.
func (tr *tempReap) logOutcome(walkErr error) {
	const remediation = "check /output ownership and permissions for the UID in user:"
	if walkErr != nil {
		if isShutdown(walkErr) {
			// Shutdown, not an operator-actionable cleanup failure; the input
			// walk's own context check reports the cancellation to the caller.
			slog.Debug("stale temp cleanup cancelled during shutdown", "dir", tr.store.root.Name(), "error", walkErr)
		} else {
			slog.Warn("stale temp cleanup failed", "dir", tr.store.root.Name(), "error", walkErr)
		}
	}
	if tr.reaped > 0 {
		// A reclaimed orphan is evidence of an earlier interrupted write (a
		// crash or a kill between temp-write and rename), so it belongs in the
		// default-level log rather than only under LOG_LEVEL=debug.
		slog.Info("reaped stale temp files", "dir", tr.store.root.Name(), "count", tr.reaped)
	}
	if tr.failed > 0 {
		slog.Warn("some stale output temps could not be inspected or removed", "dir", tr.store.root.Name(),
			"count", tr.failed, "remediation", remediation)
	}
	if tr.unreadable > 0 {
		slog.Warn("some output paths could not be inspected during stale temp cleanup",
			"dir", tr.store.root.Name(), "count", tr.unreadable, "remediation", remediation)
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
// Any decode failure means stale: rewrite. A read or confinement failure is a
// hard error and is never silently treated as stale, because that would hide a
// broken output mount behind a stream of rewrites.
func (s *store) isCurrent(ctx context.Context, rel string, want *convert.Analysis,
	wantEncoder convert.EncoderType, password string,
) (bool, error) {
	fi, err := s.lstat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("stat prior pfx: %w", err)
	case !fi.Mode().IsRegular():
		// A directory, symlink or device node at the output name is not a usable
		// prior bundle, and a symlink must never be followed here or unrelated
		// content could satisfy the check.
		return false, nil
	case fi.Size() > maxPFXSize:
		slog.Warn("prior pfx exceeds the readable bound; regenerating",
			"path", rel, "size", fi.Size(), "limit", maxPFXSize)
		return false, nil
	}

	prior, err := s.readBoundedPFX(ctx, rel)
	if err != nil {
		return false, fmt.Errorf("read prior pfx: %w", err)
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
func (s *store) readBoundedPFX(ctx context.Context, rel string) ([]byte, error) {
	f, err := s.root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return atomicfile.ReadBoundedFile(ctx, f, maxPFXSize)
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
func (s *store) orphans(seen map[string]struct{}) (found []string, safe bool, err error) {
	safe = true
	walkErr := fs.WalkDir(s.root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			if rel == "." {
				return err
			}
			slog.Warn("skipping unreadable output path while looking for orphans", "path", rel, "error", err)
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
			slog.Warn("output tree contains a symlink; orphan removal is disabled for this scan because writes and this walk resolve paths differently",
				"path", rel)
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
	return found, safe, nil
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
}

// safeToReap reports whether the input enumeration is complete enough to justify
// deleting anything.
func (r reapContext) safeToReap() bool {
	return r.walkCompleted && r.unreadable == 0 && r.unresolved == 0 &&
		r.failed == 0 && r.scanTotal > 0
}

func (s *store) reconcile(mode Lifecycle, seen map[string]struct{}, rc reapContext) int {
	if mode == LifecycleKeep {
		return 0
	}

	orphaned, walkSafe, err := s.orphans(seen)
	if err != nil {
		slog.Warn("could not enumerate output orphans", "error", err)
		return 0
	}
	if len(orphaned) == 0 {
		return 0
	}

	reapable := rc.safeToReap() && walkSafe
	if mode != LifecycleSync || !reapable {
		slog.Warn("output bundles have no matching input",
			"count", len(orphaned), "paths", strings.Join(orphaned, ","),
			"action", lifecycleInaction(mode),
			"remediation", "remove them from the output volume, or set OUTPUT_LIFECYCLE=sync to have this app do it")
		return 0
	}

	var deleted int
	for _, rel := range orphaned {
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

// lifecycleInaction explains why an orphan was reported rather than removed. It
// is only called when no deletion happened, so the mode alone determines which of
// the two reasons applies: any mode other than sync reports by configuration, and
// sync reports only when the scan could not prove the input tree was fully
// enumerated.
func lifecycleInaction(mode Lifecycle) string {
	if mode != LifecycleSync {
		return "reported only (OUTPUT_LIFECYCLE=" + string(mode) + ")"
	}
	return "kept: this scan did not fully enumerate the input tree, so deleting could remove a live bundle"
}

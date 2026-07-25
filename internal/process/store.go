package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
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
func (s *store) write(ctx context.Context, rel string, pfx []byte) error {
	if destDir := filepath.Dir(rel); destDir != "." {
		if err := s.root.MkdirAll(destDir, pfxDirMode); err != nil {
			// destDir is filepath.Dir(rel), and the *os.Root error names the
			// failing component, so the caller's path carries the directory too.
			return fmt.Errorf("create output directory: %w", err)
		}
	}
	if _, err := atomicfile.WriteFileInRoot(ctx, s.root, rel, pfx,
		atomicfile.WithMode(pfxFileMode),
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
// A legitimate PFX for a certificate chain is single-digit kilobytes, so 1 MiB is
// already generous; the 10 MiB input cap would be far too loose here. The bound
// matters because decoding feeds the FILE'S OWN key-derivation iteration counts
// into PBKDF2, so an oversized or crafted file could otherwise spend arbitrary
// CPU on the scan's only goroutine. Anything over the cap is treated as stale and
// rewritten, which self-heals.
const maxPFXSize = 1 << 20

// decodeTimeout bounds one prior-output decode.
//
// go-pkcs12's Decode is not context-aware and honours the file's own iteration
// counts, so a hostile file cannot be interrupted from the inside. Running it
// under a deadline means one pathological file costs one timeout rather than
// wedging every future scan. Defence in depth: the output tree is this app's own
// volume and it is the only intended writer.
const decodeTimeout = 5 * time.Second

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
func (s *store) isCurrent(ctx context.Context, rel string, want *convert.Analysis, password string) (bool, error) {
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

	decoded, err := decodeWithin(ctx, prior, password)
	if err != nil {
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

// decodeWithin runs a PKCS#12 decode under a deadline.
//
// The decode happens on its own goroutine because go-pkcs12 cannot be cancelled
// mid-derivation. On timeout the caller moves on and the goroutine is left to
// finish and exit on its own; it holds only the bytes it was given, and the
// buffered channel means it never blocks on a receiver that has gone away.
func decodeWithin(ctx context.Context, pfx []byte, password string) (convert.Decoded, error) {
	type result struct {
		err     error
		decoded convert.Decoded
	}
	done := make(chan result, 1)
	go func() {
		decoded, err := convert.Decode(pfx, password)
		done <- result{decoded: decoded, err: err}
	}()

	timer := time.NewTimer(decodeTimeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.decoded, r.err
	case <-timer.C:
		return convert.Decoded{}, fmt.Errorf("decode exceeded %s", decodeTimeout)
	case <-ctx.Done():
		return convert.Decoded{}, ctx.Err()
	}
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
func (s *store) orphans(seen map[string]struct{}) ([]string, error) {
	var found []string
	err := fs.WalkDir(s.root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			if rel == "." {
				return err
			}
			slog.Warn("skipping unreadable output path while looking for orphans", "path", rel, "error", err)
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(rel, layout.PFXExt) {
			return nil
		}
		// Map the output back to the input that would have produced it. layout owns
		// both directions of the naming contract, so this cannot drift from the
		// forward derivation used at write time.
		certRel := strings.TrimSuffix(rel, layout.PFXExt) + layout.CertExt
		if _, ok := seen[certRel]; !ok {
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk output tree: %w", err)
	}
	return found, nil
}

// reconcile applies the lifecycle mode to the outputs whose inputs are gone, and
// returns how many were deleted.
//
// The gate is strict and every condition is load-bearing:
//
//   - scanTotal == 0 blocks reaping outright. An /input that is mounted empty but
//     readable produces a clean, complete walk, so without this the first scan
//     after a slow or wrong mount would delete every bundle. Known residual: a
//     wrong but POPULATED mount passes this, which is why deletion is opt-in.
//   - walkComplete and unreadable == 0 mean the seen set is a full enumeration.
//     Pruning against a partial set would delete live bundles.
//   - failed == 0 keeps a scan that is already in trouble from also deleting.
//
// This is deliberately stricter than anything the (now removed) fingerprint cache
// needed: getting a prune wrong cost one spurious reconversion, whereas getting a
// deletion wrong destroys private key material — and in the documented deployment
// the output tree is replicated onward, so a mistake propagates to a second host.
func (s *store) reconcile(mode Lifecycle, seen map[string]struct{}, scanTotal, unreadable int, walkComplete bool) int {
	if mode == LifecycleKeep {
		return 0
	}

	orphaned, err := s.orphans(seen)
	if err != nil {
		slog.Warn("could not enumerate output orphans", "error", err)
		return 0
	}
	if len(orphaned) == 0 {
		return 0
	}

	reapable := walkComplete && unreadable == 0 && scanTotal > 0
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

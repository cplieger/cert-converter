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

// Package process provides the certificate scanning and conversion orchestration.
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

	"github.com/cplieger/cert-converter/internal/convert"
)

// ScanResult carries per-pair outcome summary counts from a scan run.
type ScanResult struct {
	Total      int
	Converted  int
	Unchanged  int
	Orphan     int
	Failed     int
	Unreadable int
}

// Options carries the process-lifetime scan configuration the composition root
// chooses once at startup: the confined input and output roots, the password
// embedded in generated PFX files, and the PKCS#12 encoder profile. The encoder
// is carried as the app-owned convert.EncoderType name, not as a go-pkcs12
// value, so the vendor type stays confined to internal/convert. These values
// never vary between Run calls, so they are injected at construction rather
// than re-supplied per scan.
type Options struct {
	Encoder   convert.EncoderType
	CertsRoot string
	OutRoot   string
	Password  string
}

// Scanner walks a certificate directory, checks for changes via a hash cache,
// and dispatches conversion of cert/key pairs to PFX format.
//
// A Scanner is NOT safe for concurrent Run calls sharing a cache. Each cache
// method is individually atomic, but the per-entry Changed -> convert -> Invalidate
// sequence is not: overlapping scans could let one skip a pair as unchanged on the
// strength of a fingerprint the other recorded for a conversion still in flight (or
// already failed), and one scan's Prune can drop the other's live fingerprints. Run
// every scan from a single goroutine, as main.go does (initial scan, then the
// watcher's synchronous onChange callback).
type Scanner struct {
	cache *convert.HashCache
	opts  Options
}

// New constructs a Scanner with the given hash cache and process-lifetime scan
// configuration.
func New(cache *convert.HashCache, opts Options) *Scanner {
	return &Scanner{cache: cache, opts: opts}
}

// Run walks the configured certs root, converts changed .crt/.key pairs to PFX
// in the configured output root, and returns a ScanResult with outcome counts
// plus any walk-level error. Every
// /input read is confined to certsRoot through an *os.Root, so a symlink in the
// watched tree cannot redirect a read outside it, and every /output stat,
// directory creation and PFX write is confined to outRoot the same way, so a
// symlink planted there cannot redirect the private-key-bearing PFX outside the
// mounted volume. A certsRoot or outRoot that cannot be opened as a root is a
// hard error (the caller marks the container unhealthy).
func (s *Scanner) Run(ctx context.Context) (ScanResult, error) {
	certsRoot, outRoot := s.opts.CertsRoot, s.opts.OutRoot
	root, err := os.OpenRoot(certsRoot)
	if err != nil {
		return ScanResult{}, fmt.Errorf("open input root %q: %w", certsRoot, err)
	}
	defer func() { _ = root.Close() }()

	outHandle, err := os.OpenRoot(outRoot)
	if err != nil {
		return ScanResult{}, fmt.Errorf("open output root %q: %w", outRoot, err)
	}
	defer func() { _ = outHandle.Close() }()

	reapStaleTemps(ctx, outHandle)

	sw := &scanWalk{
		scanner:   s,
		root:      root,
		outHandle: outHandle,
		certsRoot: certsRoot,
		password:  s.opts.Password,
		enc:       s.opts.Encoder,
		seen:      make(map[string]struct{}),
	}
	walkErr := filepath.WalkDir(certsRoot, func(path string, d fs.DirEntry, err error) error {
		return sw.visit(ctx, path, d, err)
	})

	// A non-nil walkErr means WalkDir aborted before visiting every entry
	// (e.g. the /input root briefly became unreadable on a network mount),
	// so `seen` is incomplete; pruning against a partial set drops live
	// fingerprints and forces a full, timestamp-churning reconversion on the
	// next clean cycle. Prune only after a complete walk -- a genuinely
	// removed pair is reaped on the next successful scan.
	// An unreadable sub-path leaves `seen` incomplete for the certs beneath
	// it in exactly the same way, so it gets the same treatment.
	if walkErr == nil && sw.unreadable == 0 {
		s.cache.Prune(sw.seen)
	}

	result := countResults(sw.results, sw.unreadable)
	logScanOutcome(ctx, result, walkErr)
	return result, walkErr
}

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

// reapStaleTemp handles one candidate entry of the reapStaleTemps walk: it
// filters non-candidates, re-checks the entry through the root before unlinking
// (only a regular file older than cutoff is a reclaimable orphan, and Lstat
// never follows a symlink planted under the temp's name) and removes it,
// reporting whether a file was reaped. Every operation stays root-relative
// through outHandle, so the confinement invariant is identical to doing the work
// inline in the callback.
func reapStaleTemp(outHandle *os.Root, rel string, d fs.DirEntry, cutoff time.Time) bool {
	if d.IsDir() || !isStaleTempName(d.Name()) {
		return false
	}
	fi, err := outHandle.Lstat(rel)
	if err != nil {
		slog.Debug("skipping unstattable temp during cleanup", "path", rel, "error", err)
		return false
	}
	if !fi.Mode().IsRegular() || fi.ModTime().After(cutoff) {
		return false
	}
	if err := outHandle.Remove(rel); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The temp vanished between the Lstat and the unlink (a co-mounting
			// reaper, or the write it belonged to finishing its rename). Benign,
			// exactly as atomicfile's own CleanupStaleTemps treats it.
			return false
		}
		slog.Warn("stale temp cleanup failed", "path", rel, "error", err)
		return false
	}
	return true
}

// reapStaleTemps removes PFX temp files orphaned by an interrupted atomic write
// (a crash between temp-write and rename). It matches exactly the
// ".atomicfile-<digits>.tmp" shape atomicfile stages, so a caller-owned file in
// /output is never touched. The sweep covers the whole output tree, not just its
// top level: atomicfile stages its temp in the TARGET directory, so a nested
// cert (input/example.com/cert.crt) leaves its orphaned temp in the matching
// nested output directory.
//
// Every step — the walk, the stat and the unlink — is root-relative through
// outHandle, so a co-mounting writer that swaps an output subdirectory for a
// symlink mid-sweep cannot redirect the deletion outside the mounted volume.
// Reconstructed ambient paths are deliberately never handed to
// atomicfile.CleanupStaleTemps: that helper reopens the directory outside the
// root, which would reintroduce exactly that TOCTOU window.
//
// The sweep is cancellable: it walks the whole output tree before the input
// walk starts, so an already-cancelled or mid-shutdown scan must stop between
// entries instead of traversing (and unlinking across) a large tree while
// SIGTERM handling waits.
func reapStaleTemps(ctx context.Context, outHandle *os.Root) {
	total := 0
	cutoff := time.Now().Add(-staleTempAge)
	walkErr := fs.WalkDir(outHandle.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if rel == "." {
				return err
			}
			slog.Debug("skipping unreadable output path during temp cleanup", "path", rel, "error", err)
			return nil
		}
		if reapStaleTemp(outHandle, rel, d, cutoff) {
			total++
		}
		return nil
	})
	if walkErr != nil {
		if errors.Is(walkErr, context.Canceled) || errors.Is(walkErr, context.DeadlineExceeded) {
			// Shutdown, not an operator-actionable cleanup failure; the input
			// walk's own context check reports the cancellation to the caller.
			slog.Debug("stale temp cleanup cancelled during shutdown", "dir", outHandle.Name(), "error", walkErr)
		} else {
			slog.Warn("stale temp cleanup failed", "dir", outHandle.Name(), "error", walkErr)
		}
	}
	if total > 0 {
		slog.Debug("reaped stale temp files", "dir", outHandle.Name(), "count", total)
	}
}

// scanWalk carries the read-only conversion parameters and the mutable
// accounting for one Scanner.Run tree walk: the per-pair results, the count of
// unreadable sub-paths, and the set of cert paths seen (for cache pruning).
// Hoisting the WalkDir callback onto this struct keeps Scanner.Run flat.
type scanWalk struct {
	scanner    *Scanner
	root       *os.Root
	outHandle  *os.Root
	seen       map[string]struct{}
	enc        convert.EncoderType
	certsRoot  string
	password   string
	results    []conversionStatus
	unreadable int
}

// visit is the WalkDir callback. The context is checked before and after each
// entry: a walk error at the root, or a cancelled context, aborts the walk; an
// error below the root marks one unreadable sub-path and continues. Directories
// and non-.crt files are ignored; every .crt entry is recorded as seen and
// dispatched to convertEntry.
func (sw *scanWalk) visit(ctx context.Context, path string, d fs.DirEntry, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if path == sw.certsRoot {
			return err
		}
		slog.Warn("skipping unreadable path", "path", path, "error", err)
		sw.unreadable++
		return nil
	}
	if d.IsDir() || !strings.HasSuffix(path, ".crt") {
		return nil
	}
	sw.seen[path] = struct{}{}
	sw.results = append(sw.results, sw.convertEntry(ctx, path))
	// A cancellation that landed *during* the conversion above already turned
	// that entry into statusFailed (the bounded read and the atomic write both
	// return ctx.Err()). Re-check here so the walk aborts and Run reports the
	// cancellation, instead of returning a "completed" scan whose failed count
	// is really a shutdown artifact.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// logScanOutcome emits the end-of-scan summary. A completed walk logs at Info;
// a walk aborted by shutdown (context cancellation or deadline) logs at Debug;
// any other abort logs at Warn so an operator sees the partial scan and its
// error. The count attributes are identical in all three cases (the README's Loki
// alert matches on them), so they are built once.
func logScanOutcome(ctx context.Context, result ScanResult, walkErr error) {
	level, msg := slog.LevelInfo, "scan complete"
	if walkErr != nil {
		level, msg = slog.LevelWarn, "scan aborted before completion"
		if errors.Is(walkErr, context.Canceled) || errors.Is(walkErr, context.DeadlineExceeded) {
			level, msg = slog.LevelDebug, "scan cancelled during shutdown"
		}
	}
	attrs := make([]any, 0, 14)
	if walkErr != nil {
		attrs = append(attrs, "error", walkErr)
	}
	attrs = append(attrs,
		"total", result.Total,
		"converted", result.Converted,
		"unchanged", result.Unchanged,
		"orphan", result.Orphan,
		"unreadable", result.Unreadable,
		"failed", result.Failed)
	slog.Log(ctx, level, msg, attrs...)
}

// logEntryFailure logs a per-entry failure. A failure caused by shutdown
// (context cancellation or deadline) logs at Debug -- it is not an operator
// actionable conversion error -- while every real failure logs at Error, the
// same split logScanOutcome applies to the walk-level error.
func logEntryFailure(msg, logPath string, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		slog.Debug(msg+" (shutdown)", "path", logPath, "error", err)
		return
	}
	slog.Error(msg, "path", logPath, "error", err)
}

// convertEntry resolves the outcome for one .crt entry under certsRoot. It
// reads the cert and its sibling .key exactly once through root, fingerprints
// them, and either skips (input unchanged and the prior PFX still present),
// regenerates (input unchanged but the output went missing), or converts
// (input changed). Every output touch — the stat, the directory creation and
// the atomic write — is confined to outHandle, so a symlink planted under the
// output tree cannot redirect the private-key-bearing PFX outside it. It
// invalidates the cache on every failure path so the next scan retries. All
// per-cert logs use the certsRoot-relative path for a stable, non-leaky
// identifier (the absolute path appears only when the relative path cannot be
// derived).
func (sw *scanWalk) convertEntry(ctx context.Context, path string) conversionStatus {
	rel, relErr := filepath.Rel(sw.certsRoot, path)
	if relErr != nil {
		// Without a root-relative key the file cannot be read through root;
		// fail the entry. rel is unavailable, so this one log uses the
		// absolute path.
		slog.Error("failed to compute relative path", "path", path, "error", relErr)
		sw.scanner.cache.Invalidate(path)
		return statusFailed
	}
	logPath := rel
	keyRel := strings.TrimSuffix(rel, ".crt") + ".key"

	if _, statErr := sw.root.Stat(keyRel); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			slog.Debug("skipping cert without matching key", "path", logPath)
		} else {
			// A non-ENOENT stat failure (a sibling key that is a symlink the
			// *os.Root refuses because it escapes /input, or a permission/IO
			// error) is not a genuine "no key" orphan: surface it so the
			// misconfiguration is diagnosable instead of silently skipped at
			// debug. Still health-neutral (statusOrphan) and non-invalidating.
			slog.Warn("skipping cert: cannot stat sibling key", "path", logPath, "error", statErr)
		}
		return statusOrphan
	}

	certPEM, err := convert.ReadBoundedFromRoot(ctx, sw.root, rel, convert.MaxFileSize)
	if err != nil {
		logEntryFailure("failed to read certificate", logPath, err)
		sw.scanner.cache.Invalidate(path)
		return statusFailed
	}
	keyPEM, err := convert.ReadBoundedFromRoot(ctx, sw.root, keyRel, convert.MaxFileSize)
	if err != nil {
		logEntryFailure("failed to read private key", logPath, err)
		sw.scanner.cache.Invalidate(path)
		return statusFailed
	}

	pfxRel := strings.TrimSuffix(rel, ".crt") + ".pfx"

	if sw.outputIsCurrent(path, pfxRel, logPath, certPEM, keyPEM) {
		return statusUnchanged
	}

	if destDir := filepath.Dir(pfxRel); destDir != "." {
		if err := sw.outHandle.MkdirAll(destDir, 0o750); err != nil {
			slog.Error("failed to create output directory", "path", destDir, "error", err)
			sw.scanner.cache.Invalidate(path)
			return statusFailed
		}
	}

	slog.Debug("converting cert pair", "path", logPath)
	if err := convert.PairInRoot(ctx, certPEM, keyPEM, sw.outHandle, pfxRel, sw.password, sw.enc); err != nil {
		logEntryFailure("conversion failed", logPath, err)
		sw.scanner.cache.Invalidate(path)
		return statusFailed
	}

	slog.Info("wrote pfx", "path", pfxRel)
	return statusConverted
}

// outputIsCurrent reports whether the entry can be skipped as already
// converted: the cert+key fingerprint is unchanged AND the prior PFX is still
// present under outHandle as a regular file. The cache fingerprints inputs
// only, so a PFX deleted out of band would otherwise never be regenerated while
// the input stays unchanged (until a renewal or process restart), and a
// skip-only scan still counts as a healthy cycle, masking the missing file from
// monitoring; hence the output stat, which forces a reconvert when the prior
// output is gone or is no longer a usable PFX file.
func (sw *scanWalk) outputIsCurrent(path, pfxRel, logPath string, certPEM, keyPEM []byte) bool {
	if sw.scanner.cache.Changed(path, convert.Fingerprint(certPEM, keyPEM)) {
		return false
	}
	// Lstat, not Stat: a symlink planted under the output name must not be
	// accepted as the prior PFX (it would let unrelated content satisfy the
	// cache-coherence gate), and only a regular file is a usable PFX. Anything
	// else -- a directory, a symlink, a device node -- means the output
	// contract is broken, so force a reconvert whose confined atomic write
	// either restores a regular PFX or fails the entry and reports unhealthy.
	fi, statErr := sw.outHandle.Lstat(pfxRel)
	if statErr == nil && fi.Mode().IsRegular() {
		slog.Debug("skipping unchanged cert pair", "path", logPath)
		return true
	}
	switch {
	case statErr == nil:
		slog.Warn("unchanged input but output PFX is not a regular file; regenerating",
			"path", logPath, "type", fi.Mode().Type().String())
	case errors.Is(statErr, fs.ErrNotExist):
		slog.Warn("unchanged input but output PFX missing; regenerating", "path", logPath)
	default:
		slog.Warn("unchanged input but output PFX stat failed; regenerating", "path", logPath, "error", statErr)
	}
	return false
}

// countResults derives summary counts from typed results.
func countResults(results []conversionStatus, unreadable int) ScanResult {
	var converted, unchanged, orphan, failed int
	for _, r := range results {
		switch r {
		case statusConverted:
			converted++
		case statusUnchanged:
			unchanged++
		case statusOrphan:
			orphan++
		case statusFailed:
			failed++
		}
	}
	return ScanResult{
		Total:      len(results),
		Converted:  converted,
		Unchanged:  unchanged,
		Orphan:     orphan,
		Failed:     failed,
		Unreadable: unreadable,
	}
}

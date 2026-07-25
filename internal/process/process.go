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

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
	"software.sslmate.com/src/go-pkcs12"
)

// CacheChecker abstracts the fingerprint-cache operations Scanner requires. It
// is keyed by an opaque string (the scanner uses the absolute cert path) and a
// content fingerprint derived from the already-read cert+key bytes; it performs
// no file I/O of its own.
type CacheChecker interface {
	Changed(key, fingerprint string) bool
	Invalidate(key string)
	Prune(seen map[string]struct{})
}

// Compile-time assertion: *convert.HashCache, the production implementation, satisfies
// CacheChecker.
var _ CacheChecker = (*convert.HashCache)(nil)

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
// embedded in generated PFX files, and the PKCS#12 encoder profile. These
// values never vary between Run calls, so they are injected at construction
// rather than re-supplied per scan. Field order is pointer-first to satisfy
// govet's fieldalignment.
type Options struct {
	Encoder   *pkcs12.Encoder
	CertsRoot string
	OutRoot   string
	Password  string
}

// Scanner walks a certificate directory, checks for changes via a hash cache,
// and dispatches conversion of cert/key pairs to PFX format.
//
// A Scanner is NOT safe for concurrent Run calls sharing a cache. Each CacheChecker
// method is individually atomic, but the per-entry Changed -> convert -> Invalidate
// sequence is not: overlapping scans could let one skip a pair as unchanged on the
// strength of a fingerprint the other recorded for a conversion still in flight (or
// already failed), and one scan's Prune can drop the other's live fingerprints. Run
// every scan from a single goroutine, as main.go does (initial scan, then the
// watcher's synchronous onChange callback).
type Scanner struct {
	cache CacheChecker
	opts  Options
}

// New constructs a Scanner with the given hash cache and process-lifetime scan
// configuration.
func New(cache CacheChecker, opts Options) *Scanner {
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

	reapStaleTemps(outRoot)

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

// reapStaleTemps removes PFX temp files orphaned by an interrupted atomic write
// (a crash between temp-write and rename). WriteFile names temps
// ".atomicfile-<digits>.tmp" and the default CleanupStaleTemps recognizes
// exactly that shape, so the sweep stays matched to the writes. The sweep
// covers the whole output tree, not just its top level: CleanupStaleTemps does
// not recurse and atomicfile stages its temp in the TARGET directory, so a
// nested cert (input/example.com/cert.crt) leaves its orphaned temp in the
// matching nested output directory.
func reapStaleTemps(outRoot string) {
	total := 0
	walkErr := filepath.WalkDir(outRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == outRoot {
				return err
			}
			slog.Debug("skipping unreadable output path during temp cleanup", "path", path, "error", err)
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		removed, cleanErr := atomicfile.CleanupStaleTemps(path, time.Hour)
		if cleanErr != nil {
			slog.Warn("stale temp cleanup failed", "dir", path, "error", cleanErr)
			return nil
		}
		total += removed
		return nil
	})
	if walkErr != nil {
		slog.Warn("stale temp cleanup failed", "dir", outRoot, "error", walkErr)
	}
	if total > 0 {
		slog.Debug("reaped stale temp files", "dir", outRoot, "count", total)
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
	enc        *pkcs12.Encoder
	seen       map[string]struct{}
	certsRoot  string
	password   string
	results    []ConversionStatus
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
	// that entry into StatusFailed (the bounded read and the atomic write both
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
func (sw *scanWalk) convertEntry(ctx context.Context, path string) ConversionStatus {
	rel, relErr := filepath.Rel(sw.certsRoot, path)
	if relErr != nil {
		// Without a root-relative key the file cannot be read through root;
		// fail the entry. rel is unavailable, so this one log uses the
		// absolute path.
		slog.Error("failed to compute relative path", "path", path, "error", relErr)
		sw.scanner.cache.Invalidate(path)
		return StatusFailed
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
			// debug. Still health-neutral (StatusOrphan) and non-invalidating.
			slog.Warn("skipping cert: cannot stat sibling key", "path", logPath, "error", statErr)
		}
		return StatusOrphan
	}

	certPEM, err := convert.ReadBoundedFromRoot(ctx, sw.root, rel, convert.MaxFileSize)
	if err != nil {
		logEntryFailure("failed to read certificate", logPath, err)
		sw.scanner.cache.Invalidate(path)
		return StatusFailed
	}
	keyPEM, err := convert.ReadBoundedFromRoot(ctx, sw.root, keyRel, convert.MaxFileSize)
	if err != nil {
		logEntryFailure("failed to read private key", logPath, err)
		sw.scanner.cache.Invalidate(path)
		return StatusFailed
	}

	pfxRel := strings.TrimSuffix(rel, ".crt") + ".pfx"

	if sw.outputIsCurrent(path, pfxRel, logPath, certPEM, keyPEM) {
		return StatusUnchanged
	}

	if destDir := filepath.Dir(pfxRel); destDir != "." {
		if err := sw.outHandle.MkdirAll(destDir, 0o750); err != nil {
			slog.Error("failed to create output directory", "path", destDir, "error", err)
			sw.scanner.cache.Invalidate(path)
			return StatusFailed
		}
	}

	slog.Debug("converting cert pair", "path", logPath)
	if err := convert.PairInRoot(ctx, certPEM, keyPEM, sw.outHandle, pfxRel, sw.password, sw.enc); err != nil {
		logEntryFailure("conversion failed", logPath, err)
		sw.scanner.cache.Invalidate(path)
		return StatusFailed
	}

	slog.Info("wrote pfx", "path", pfxRel)
	return StatusConverted
}

// outputIsCurrent reports whether the entry can be skipped as already
// converted: the cert+key fingerprint is unchanged AND the prior PFX is still
// present under outHandle. The cache fingerprints inputs only, so a PFX deleted
// out of band would otherwise never be regenerated while the input stays
// unchanged (until a renewal or process restart), and a skip-only scan still
// counts as a healthy cycle, masking the missing file from monitoring; hence the
// output stat, which forces a reconvert when the prior output is gone.
func (sw *scanWalk) outputIsCurrent(path, pfxRel, logPath string, certPEM, keyPEM []byte) bool {
	if sw.scanner.cache.Changed(path, convert.Fingerprint(certPEM, keyPEM)) {
		return false
	}
	_, statErr := sw.outHandle.Stat(pfxRel)
	if statErr == nil {
		slog.Debug("skipping unchanged cert pair", "path", logPath)
		return true
	}
	if errors.Is(statErr, fs.ErrNotExist) {
		slog.Warn("unchanged input but output PFX missing; regenerating", "path", logPath)
	} else {
		slog.Warn("unchanged input but output PFX stat failed; regenerating", "path", logPath, "error", statErr)
	}
	return false
}

// countResults derives summary counts from typed results.
func countResults(results []ConversionStatus, unreadable int) ScanResult {
	var converted, unchanged, orphan, failed int
	for _, r := range results {
		switch r {
		case StatusConverted:
			converted++
		case StatusUnchanged:
			unchanged++
		case StatusOrphan:
			orphan++
		case StatusFailed:
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

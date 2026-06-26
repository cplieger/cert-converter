// Package process provides the certificate scanning and conversion orchestration.
package process

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-watcher/internal/convert"
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

// ScanResult carries per-pair outcome summary counts from a scan run.
type ScanResult struct {
	Total      int
	Converted  int
	Unchanged  int
	Orphan     int
	Failed     int
	Unreadable int
}

// Scanner walks a certificate directory, checks for changes via a hash cache,
// and dispatches conversion of cert/key pairs to PFX format.
type Scanner struct {
	cache CacheChecker
}

// New constructs a Scanner with the given hash cache.
func New(cache CacheChecker) *Scanner {
	return &Scanner{cache: cache}
}

// Run walks certsRoot, converts changed .crt/.key pairs to PFX in outRoot, and
// returns a ScanResult with outcome counts plus any walk-level error. Every
// /input read is confined to certsRoot through an *os.Root, so a symlink in the
// watched tree cannot redirect a read outside it. A certsRoot that cannot be
// opened as a root is a hard error (the caller marks the container unhealthy).
func (s *Scanner) Run(ctx context.Context, certsRoot, outRoot, password string, enc *pkcs12.Encoder) (ScanResult, error) {
	root, err := os.OpenRoot(certsRoot)
	if err != nil {
		return ScanResult{}, fmt.Errorf("open input root %q: %w", certsRoot, err)
	}
	defer func() { _ = root.Close() }()

	reapStaleTemps(outRoot)

	sw := &scanWalk{
		scanner:   s,
		root:      root,
		certsRoot: certsRoot,
		outRoot:   outRoot,
		password:  password,
		enc:       enc,
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
	if walkErr == nil {
		s.cache.Prune(sw.seen)
	}

	result := countResults(sw.results, sw.unreadable)
	logScanOutcome(result, walkErr)
	return result, walkErr
}

// reapStaleTemps removes PFX temp files orphaned by an interrupted atomic write
// (a crash between temp-write and rename). WriteFile names temps
// ".atomicfile-<digits>.tmp" and the default CleanupStaleTemps recognizes
// exactly that shape, so the sweep stays matched to the writes.
func reapStaleTemps(outRoot string) {
	if removed, err := atomicfile.CleanupStaleTemps(outRoot, time.Hour); err != nil {
		slog.Warn("stale temp cleanup failed", "dir", outRoot, "error", err)
	} else if removed > 0 {
		slog.Debug("reaped stale temp files", "dir", outRoot, "count", removed)
	}
}

// scanWalk carries the read-only conversion parameters and the mutable
// accounting for one Scanner.Run tree walk: the per-pair results, the count of
// unreadable sub-paths, and the set of cert paths seen (for cache pruning).
// Hoisting the WalkDir callback onto this struct keeps Scanner.Run flat.
type scanWalk struct {
	scanner    *Scanner
	root       *os.Root
	enc        *pkcs12.Encoder
	seen       map[string]struct{}
	certsRoot  string
	outRoot    string
	password   string
	results    []convert.ConversionResult
	unreadable int
}

// visit is the WalkDir callback. A walk error at the root, or a cancelled
// context, aborts the walk; an error below the root marks one unreadable
// sub-path and continues. Directories and non-.crt files are ignored; every
// .crt entry is recorded as seen and dispatched to convertEntry.
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
	sw.results = append(sw.results,
		sw.scanner.convertEntry(ctx, sw.root, path, sw.certsRoot, sw.outRoot, sw.password, sw.enc))
	return nil
}

// logScanOutcome emits the end-of-scan summary. A completed walk logs at Info;
// a walk aborted by shutdown (context cancellation or deadline) logs at Debug;
// any other abort logs at Warn so an operator sees the partial scan and its
// error.
func logScanOutcome(result ScanResult, walkErr error) {
	if walkErr == nil {
		slog.Info("scan complete",
			"total", result.Total,
			"converted", result.Converted,
			"unchanged", result.Unchanged,
			"orphan", result.Orphan,
			"unreadable", result.Unreadable,
			"failed", result.Failed)
		return
	}
	if errors.Is(walkErr, context.Canceled) || errors.Is(walkErr, context.DeadlineExceeded) {
		slog.Debug("scan cancelled during shutdown",
			"error", walkErr,
			"total", result.Total,
			"converted", result.Converted,
			"unchanged", result.Unchanged,
			"orphan", result.Orphan,
			"unreadable", result.Unreadable,
			"failed", result.Failed)
		return
	}
	slog.Warn("scan aborted before completion",
		"error", walkErr,
		"total", result.Total,
		"converted", result.Converted,
		"unchanged", result.Unchanged,
		"orphan", result.Orphan,
		"unreadable", result.Unreadable,
		"failed", result.Failed)
}

// convertEntry resolves the outcome for one .crt entry under certsRoot. It
// reads the cert and its sibling .key exactly once through root, fingerprints
// them, and either skips (input unchanged and the prior PFX still present),
// regenerates (input unchanged but the output went missing), or converts
// (input changed). It invalidates the cache on every failure path so the next
// scan retries. All per-cert logs use the certsRoot-relative path for a stable,
// non-leaky identifier (the absolute path appears only when the relative path
// cannot be derived).
func (s *Scanner) convertEntry(ctx context.Context, root *os.Root, path, certsRoot, outRoot, password string, enc *pkcs12.Encoder) convert.ConversionResult {
	rel, relErr := filepath.Rel(certsRoot, path)
	if relErr != nil {
		// Without a root-relative key the file cannot be read through root;
		// fail the entry. rel is unavailable, so this one log uses the
		// absolute path.
		slog.Error("failed to compute relative path", "path", path, "error", relErr)
		s.cache.Invalidate(path)
		return convert.ConversionResult{Status: convert.StatusFailed}
	}
	logPath := rel
	keyRel := strings.TrimSuffix(rel, ".crt") + ".key"

	if _, statErr := root.Stat(keyRel); statErr != nil {
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
		return convert.ConversionResult{Status: convert.StatusOrphan}
	}

	certPEM, err := convert.ReadBoundedFromRoot(ctx, root, rel, convert.MaxFileSize)
	if err != nil {
		slog.Error("failed to read certificate", "path", logPath, "error", err)
		s.cache.Invalidate(path)
		return convert.ConversionResult{Status: convert.StatusFailed}
	}
	keyPEM, err := convert.ReadBoundedFromRoot(ctx, root, keyRel, convert.MaxFileSize)
	if err != nil {
		slog.Error("failed to read private key", "path", logPath, "error", err)
		s.cache.Invalidate(path)
		return convert.ConversionResult{Status: convert.StatusFailed}
	}

	pfxRel := strings.TrimSuffix(rel, ".crt") + ".pfx"
	destPath := filepath.Join(outRoot, pfxRel)

	if !s.cache.Changed(path, convert.Fingerprint(certPEM, keyPEM)) {
		// The cache fingerprints inputs only, so a PFX deleted out of band is
		// never regenerated while the input stays unchanged (until a renewal or
		// process restart), and a skip-only scan still counts as a healthy
		// cycle, masking the missing file from monitoring. Reconvert when the
		// prior output is gone.
		_, statErr := os.Stat(destPath)
		if statErr == nil {
			slog.Debug("skipping unchanged cert pair", "path", logPath)
			return convert.ConversionResult{Status: convert.StatusUnchanged}
		}
		if errors.Is(statErr, fs.ErrNotExist) {
			slog.Warn("unchanged input but output PFX missing; regenerating", "path", logPath)
		} else {
			slog.Warn("unchanged input but output PFX stat failed; regenerating", "path", logPath, "error", statErr)
		}
	}

	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		slog.Error("failed to create output directory", "path", destDir, "error", err)
		s.cache.Invalidate(path)
		return convert.ConversionResult{Status: convert.StatusFailed}
	}

	slog.Debug("converting cert pair", "path", logPath)
	if err := ConvertPair(ctx, certPEM, keyPEM, destPath, password, enc); err != nil {
		slog.Error("conversion failed", "path", logPath, "error", err)
		s.cache.Invalidate(path)
		return convert.ConversionResult{Status: convert.StatusFailed}
	}

	slog.Info("wrote pfx", "path", pfxRel)
	return convert.ConversionResult{Status: convert.StatusConverted}
}

// countResults derives summary counts from typed results.
func countResults(results []convert.ConversionResult, unreadable int) ScanResult {
	var converted, unchanged, orphan, failed int
	for _, r := range results {
		switch r.Status {
		case convert.StatusConverted:
			converted++
		case convert.StatusUnchanged:
			unchanged++
		case convert.StatusOrphan:
			orphan++
		case convert.StatusFailed:
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

// ConvertPair parses an already-read cert chain and private key, verifies the
// leaf certificate and key correspond, and writes the PFX to destPath. The
// caller reads the PEM bytes once (see Scanner.convertEntry, which reads them
// through the confined *os.Root); ConvertPair performs no file reads.
func ConvertPair(ctx context.Context, certPEM, keyPEM []byte, destPath, password string, enc *pkcs12.Encoder) error {
	chain, err := convert.ParseCertChain(certPEM)
	if err != nil {
		return fmt.Errorf("parse cert chain: %w", err)
	}
	leaf := chain[0]
	var caCerts []*x509.Certificate
	if len(chain) > 1 {
		caCerts = chain[1:]
	}
	privKey, err := convert.ParsePrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key type %T does not implement crypto.Signer", privKey)
	}
	matcher, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("leaf certificate public key type %T cannot be verified against the private key", leaf.PublicKey)
	}
	if !matcher.Equal(signer.Public()) {
		return errors.New("leaf certificate public key does not match the private key")
	}
	return convert.ToPFX(ctx, privKey, leaf, caCerts, destPath, password, enc)
}

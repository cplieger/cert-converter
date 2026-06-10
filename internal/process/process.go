// Package process provides the certificate scanning and conversion orchestration.
package process

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cplieger/atomicfile"
	"github.com/cplieger/cert-watcher/internal/convert"
	"software.sslmate.com/src/go-pkcs12"
)

// CacheChecker abstracts the hash-cache operations Scanner requires.
type CacheChecker interface {
	Changed(crtPath, keyPath string) bool
	Invalidate(crtPath string)
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

// Run walks certsRoot, converts changed .crt/.key pairs to PFX in outRoot,
// and returns a ScanResult with outcome counts plus any walk-level error.
func (s *Scanner) Run(ctx context.Context, certsRoot, outRoot, password string, enc *pkcs12.Encoder) (ScanResult, error) {
	var results []convert.ConversionResult
	var unreadable int
	seen := make(map[string]struct{})

	// Reap temps orphaned by an interrupted PFX write (crash between temp-write
	// and rename). The custom-pattern sweep is effective only once a
	// WithTempPattern-aware CleanupStaleTemps is published in atomicfile and
	// pinned here; on the currently pinned version it is a no-op for the custom
	// pattern (normal writes stay fully atomic regardless). The shared const
	// keeps the write and the sweep in lockstep for when that lands.
	atomicfile.CleanupStaleTemps(outRoot, time.Hour, atomicfile.WithTempPattern(convert.TempPattern))

	walkErr := filepath.WalkDir(certsRoot, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if path == certsRoot {
				return err
			}
			slog.Warn("skipping unreadable path", "path", path, "error", err)
			unreadable++
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(path, ".crt") {
			return nil
		}

		keyPath := strings.TrimSuffix(path, ".crt") + ".key"
		rel, relErr := filepath.Rel(certsRoot, path)
		if relErr != nil {
			rel = path
		}
		pair := convert.CertPair{CertPath: path, KeyPath: keyPath, RelPath: rel}
		seen[path] = struct{}{}

		if _, statErr := os.Stat(keyPath); statErr != nil {
			slog.Debug("skipping cert without matching key", "path", path)
			results = append(results, convert.ConversionResult{Pair: pair, Status: convert.StatusOrphan})
			return nil
		}

		if !s.cache.Changed(path, keyPath) {
			slog.Debug("skipping unchanged cert pair", "path", path)
			results = append(results, convert.ConversionResult{Pair: pair, Status: convert.StatusUnchanged})
			return nil
		}

		if relErr != nil {
			slog.Error("failed to compute relative path", "path", path, "error", relErr)
			results = append(results, convert.ConversionResult{Pair: pair, Status: convert.StatusFailed, Err: relErr})
			return nil
		}
		pfxRel := strings.TrimSuffix(rel, ".crt") + ".pfx"
		destPath := filepath.Join(outRoot, pfxRel)
		destDir := filepath.Dir(destPath)
		if err := os.MkdirAll(destDir, 0o750); err != nil {
			slog.Error("failed to create output directory", "path", destDir, "error", err)
			s.cache.Invalidate(path)
			results = append(results, convert.ConversionResult{Pair: pair, Status: convert.StatusFailed, Err: err})
			return nil
		}

		slog.Debug("converting cert pair", "path", rel)
		if err := ConvertPair(ctx, pair, destPath, password, enc); err != nil {
			slog.Error("conversion failed", "path", rel, "error", err)
			s.cache.Invalidate(path)
			results = append(results, convert.ConversionResult{Pair: pair, Status: convert.StatusFailed, Err: err})
			return nil
		}

		slog.Info("wrote pfx", "path", pfxRel)
		results = append(results, convert.ConversionResult{Pair: pair, Status: convert.StatusConverted, PFXPath: destPath})
		return nil
	})

	s.cache.Prune(seen)

	result := countResults(results, unreadable)
	slog.Info("scan complete",
		"total", result.Total,
		"converted", result.Converted,
		"unchanged", result.Unchanged,
		"orphan", result.Orphan,
		"unreadable", result.Unreadable,
		"failed", result.Failed)
	return result, walkErr
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

// ConvertPair reads a cert/key pair, parses them, and writes a PFX file.
func ConvertPair(ctx context.Context, pair convert.CertPair, destPath, password string, enc *pkcs12.Encoder) error {
	certPEM, err := convert.ReadFileWithLimit(ctx, pair.CertPath, convert.MaxFileSize)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := convert.ReadFileWithLimit(ctx, pair.KeyPath, convert.MaxFileSize)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
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
	return convert.ToPFX(ctx, privKey, leaf, caCerts, destPath, password, enc)
}

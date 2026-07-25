package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/health"
	"software.sslmate.com/src/go-pkcs12"
)

// --- Test helpers ---

// newTestScanner creates a fresh cache and a scanner over the given roots for
// test isolation. The scan configuration is process-lifetime, so it is injected
// at construction.
func newTestScanner(certsRoot, outRoot, password string, enc *pkcs12.Encoder) (*process.Scanner, *convert.HashCache) {
	c := convert.NewHashCache()
	return process.New(c, process.Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  password,
		Encoder:   enc,
	}), c
}

// writeCertAndKey writes a .crt and .key file pair into dir and returns their paths.
func writeCertAndKey(t *testing.T, dir, base string, certPEM, keyPEM []byte) (crtPath, keyPath string) {
	t.Helper()
	crtPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return crtPath, keyPath
}

// decodePFX reads and decodes a PFX file, returning the private key, leaf cert, and CA certs.
func decodePFX(t *testing.T, path, password string) (key any, leaf *x509.Certificate, ca []*x509.Certificate) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}
	privKey, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		t.Fatalf("decode pfx: %v", err)
	}
	return privKey, cert, caCerts
}

func TestConvertToPFX(t *testing.T) {
	t.Parallel()

	t.Run("ECDSA round trip", func(t *testing.T) {
		t.Parallel()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "ecdsa-test", "ecdsa")
		pfxPath := filepath.Join(t.TempDir(), "test.pfx")

		if err := convert.Pair(t.Context(), certPEM, keyPEM, pfxPath, "pass", pkcs12.Modern2023); err != nil {
			t.Fatalf("convert.Pair: %v", err)
		}

		privKey, cert, caCerts := decodePFX(t, pfxPath, "pass")
		if cert.Subject.CommonName != "ecdsa-test" {
			t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "ecdsa-test")
		}
		if _, ok := privKey.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", privKey)
		}
		if len(caCerts) != 0 {
			t.Errorf("expected 0 CA certs, got %d", len(caCerts))
		}
		// PFX contains private keys — must be 0o600 (owner-only).
		fi, err := os.Stat(pfxPath)
		if err != nil {
			t.Fatalf("stat pfx: %v", err)
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("PFX mode = %o, want 0o600 (private key file must be owner-only readable)", mode)
		}
	})

	t.Run("RSA round trip", func(t *testing.T) {
		t.Parallel()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "rsa-test", "rsa")
		pfxPath := filepath.Join(t.TempDir(), "test.pfx")

		if err := convert.Pair(t.Context(), certPEM, keyPEM, pfxPath, "", pkcs12.Modern2023); err != nil {
			t.Fatalf("convert.Pair: %v", err)
		}

		privKey, cert, _ := decodePFX(t, pfxPath, "")
		if cert.Subject.CommonName != "rsa-test" {
			t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "rsa-test")
		}
		if _, ok := privKey.(*rsa.PrivateKey); !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", privKey)
		}
	})

	t.Run("chain with CA cert", func(t *testing.T) {
		t.Parallel()
		_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
		pfxPath := filepath.Join(t.TempDir(), "chain.pfx")

		if err := convert.Pair(t.Context(), chainPEM, keyPEM, pfxPath, "chainpass", pkcs12.Modern2023); err != nil {
			t.Fatalf("convert.Pair: %v", err)
		}

		privKey, cert, caCerts := decodePFX(t, pfxPath, "chainpass")
		if cert.Subject.CommonName != "leaf.example.com" {
			t.Errorf("leaf CN = %q, want %q", cert.Subject.CommonName, "leaf.example.com")
		}
		if _, ok := privKey.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", privKey)
		}
		if len(caCerts) != 1 {
			t.Fatalf("expected 1 CA cert, got %d", len(caCerts))
		}
		if caCerts[0].Subject.CommonName != "Test CA" {
			t.Errorf("CA CN = %q, want %q", caCerts[0].Subject.CommonName, "Test CA")
		}
	})

	t.Run("atomic overwrite", func(t *testing.T) {
		t.Parallel()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "atomic", "ecdsa")
		pfxPath := filepath.Join(t.TempDir(), "atomic.pfx")

		// Pre-existing file should be replaced.
		if err := os.WriteFile(pfxPath, []byte("old data"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := convert.Pair(t.Context(), certPEM, keyPEM, pfxPath, "", pkcs12.Modern2023); err != nil {
			t.Fatalf("convert.Pair: %v", err)
		}

		decodePFX(t, pfxPath, "") // panics if still "old data"
	})
}

// --- Tests: scan pipeline (process.Scanner.Run) ---

func TestProcessAll(t *testing.T) {
	t.Parallel()

	enc := pkcs12.Modern2023

	t.Run("reconverts on change", func(t *testing.T) {
		t.Parallel()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		scanner, _ := newTestScanner(tmpDir, outDir, "", enc)
		writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

		if _, err := scanner.Run(context.Background()); err != nil {
			t.Fatalf("first scanner.Run: %v", err)
		}

		// Replace with new cert.
		certPEM2, keyPEM2 := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		writeCertAndKey(t, tmpDir, "test", certPEM2, keyPEM2)

		if _, err := scanner.Run(context.Background()); err != nil {
			t.Fatalf("second scanner.Run: %v", err)
		}

		decodePFX(t, filepath.Join(outDir, "test.pfx"), "")
	})

	t.Run("preserves nested directory structure", func(t *testing.T) {
		t.Parallel()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		scanner, _ := newTestScanner(tmpDir, outDir, "", enc)

		nestedDir := filepath.Join(tmpDir, "sub", "dir")
		if err := os.MkdirAll(nestedDir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeCertAndKey(t, nestedDir, "nested", certPEM, keyPEM)

		if _, err := scanner.Run(context.Background()); err != nil {
			t.Fatalf("scanner.Run: %v", err)
		}

		pfxPath := filepath.Join(outDir, "sub", "dir", "nested.pfx")
		if _, err := os.Stat(pfxPath); err != nil {
			t.Fatalf("expected PFX at %s: %v", pfxPath, err)
		}
	})

	t.Run("skips .crt without matching .key", func(t *testing.T) {
		t.Parallel()
		certPEM, _ := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		scanner, _ := newTestScanner(tmpDir, outDir, "", enc)

		if err := os.WriteFile(filepath.Join(tmpDir, "orphan.crt"), certPEM, 0o644); err != nil {
			t.Fatal(err)
		}

		if _, err := scanner.Run(context.Background()); err != nil {
			t.Fatalf("scanner.Run: %v", err)
		}

		if _, err := os.Stat(filepath.Join(outDir, "orphan.pfx")); err == nil {
			t.Error("PFX should not be created when .key is missing")
		}
	})

	t.Run("retries after conversion failure", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		scanner, _ := newTestScanner(tmpDir, outDir, "", enc)

		// Write a valid cert but an invalid key to trigger conversion failure.
		certPEM, _ := testcerts.GenerateSelfSignedCert(t, "retry", "ecdsa")
		crtPath := filepath.Join(tmpDir, "retry.crt")
		keyPath := filepath.Join(tmpDir, "retry.key")
		if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
			t.Fatal(err)
		}

		// First scan: conversion fails (bad key), but should not cache the hash.
		if _, err := scanner.Run(context.Background()); err != nil {
			t.Fatalf("first scanner.Run: %v", err)
		}
		if _, err := os.Stat(filepath.Join(outDir, "retry.pfx")); err == nil {
			t.Fatal("PFX should not exist after failed conversion")
		}

		// Fix the key file — generate a new matching cert+key pair.
		certPEM2, keyPEM2 := testcerts.GenerateSelfSignedCert(t, "retry", "ecdsa")
		if err := os.WriteFile(crtPath, certPEM2, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM2, 0o600); err != nil {
			t.Fatal(err)
		}

		// Second scan: should retry because hash was invalidated on failure.
		if _, err := scanner.Run(context.Background()); err != nil {
			t.Fatalf("second scanner.Run: %v", err)
		}
		if _, err := os.Stat(filepath.Join(outDir, "retry.pfx")); err != nil {
			t.Fatalf("PFX should exist after retry with valid key: %v", err)
		}
	})
}

// --- Tests: Pair error paths ---

// Pair operates on already-read bytes, so the former "nonexistent
// cert/key file" cases moved to the read seam (convert.ReadBoundedFromRoot, see
// internal/convert) and the scanner's orphan/unreadable handling. What remains
// here are the parse and write failures Pair itself owns.

func TestConvertToPFX_invalid_cert_PEM(t *testing.T) {
	t.Parallel()

	_, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	err := convert.Pair(t.Context(), []byte("not a cert"), keyPEM, filepath.Join(t.TempDir(), "out.pfx"), "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("convert.Pair should fail for invalid cert PEM")
	}
}

func TestConvertToPFX_invalid_key_PEM(t *testing.T) {
	t.Parallel()

	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	err := convert.Pair(t.Context(), certPEM, []byte("not a key"), filepath.Join(t.TempDir(), "out.pfx"), "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("convert.Pair should fail for invalid key PEM")
	}
}

func TestConvertToPFX_unwritable_dest(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	err := convert.Pair(t.Context(), certPEM, keyPEM, "/nonexistent/dir/out.pfx", "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("convert.Pair should fail for unwritable destination")
	}
}

// --- Tests: runAndSetHealth ---

// newTestMarker constructs a marker rooted in a fresh TempDir so tests
// don't race on /tmp/.healthy.
func newTestMarker(t *testing.T) (*health.Marker, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".healthy")
	return health.NewMarker(path), path
}

func TestScanAndSetHealth_sets_marker_after_failure_free_scan(t *testing.T) {
	t.Parallel()

	marker, markerPath := newTestMarker(t)

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "health-test", "ecdsa")
	inDir := t.TempDir()
	outDir := t.TempDir()
	scanner, _ := newTestScanner(inDir, outDir, "", pkcs12.Modern2023)
	writeCertAndKey(t, inDir, "test", certPEM, keyPEM)

	scanAndSetHealth(t.Context(), scanner, marker)

	if _, err := os.Stat(markerPath); err != nil {
		t.Errorf("health marker should exist after a failure-free scan: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "test.pfx")); err != nil {
		t.Errorf("PFX should be created: %v", err)
	}
}

func TestScanAndSetHealth_clears_marker_when_scan_errors(t *testing.T) {
	t.Parallel()

	marker, markerPath := newTestMarker(t)

	// Start healthy so the assertion proves the scan error cleared it.
	marker.Set(true)
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	scanner, _ := newTestScanner(missing, t.TempDir(), "", pkcs12.Modern2023)

	scanAndSetHealth(t.Context(), scanner, marker)

	if _, err := os.Stat(markerPath); err == nil {
		t.Error("health marker should be cleared when the input root cannot be scanned")
	}
}

func TestScanAndSetHealth_unreadable_subdir_stays_healthy(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("chmod 0 does not block root / differs on Windows")
	}
	marker, markerPath := newTestMarker(t)
	marker.Set(false) // start unhealthy; a failure-free scan must restore health
	inDir, outDir := t.TempDir(), t.TempDir()
	scanner, _ := newTestScanner(inDir, outDir, "", pkcs12.Modern2023)
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "good", "ecdsa")
	writeCertAndKey(t, inDir, "good", certPEM, keyPEM)
	bad := filepath.Join(inDir, "blocked")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o755) })
	// Establish the precondition (the blocked subdir really is unreadable) with a
	// throwaway scanner, then drive the production wiring itself so the WARN branch
	// and the marker decision in scanAndSetHealth are the code under test.
	precheck, _ := newTestScanner(inDir, outDir, "", pkcs12.Modern2023)
	result, err := precheck.Run(context.Background())
	if err != nil {
		t.Fatalf("scan should not error on an unreadable subdir: %v", err)
	}
	if result.Unreadable == 0 {
		t.Fatal("expected Unreadable > 0 from the blocked subdir (test precondition)")
	}
	// The remediation hint is the only observable effect of the Unreadable
	// branch, so capture the default logger to pin it. slog.Default is
	// process-global; this test is deliberately serial (no t.Parallel).
	var logs bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prevLogger) })

	scanAndSetHealth(t.Context(), scanner, marker)

	if !strings.Contains(logs.String(), "unreadable") {
		t.Errorf("scanAndSetHealth should WARN about unreadable /input paths; got logs %q", logs.String())
	}
	if _, statErr := os.Stat(markerPath); statErr != nil {
		t.Fatalf("marker must stay healthy when only Unreadable>0 and no conversion failed: %v", statErr)
	}
}

// TestScanAndSetHealth_cancelled_context_leaves_marker_untouched pins the
// shutdown contract: a cancelled scan is not a conversion failure, so the
// marker keeps whatever value the last completed scan gave it.
func TestScanAndSetHealth_cancelled_context_leaves_marker_untouched(t *testing.T) {
	t.Parallel()

	marker, markerPath := newTestMarker(t)
	marker.Set(true) // start healthy; a cancellation must not clear it

	inDir, outDir := t.TempDir(), t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "cancelled", "ecdsa")
	writeCertAndKey(t, inDir, "cancelled", certPEM, keyPEM)
	scanner, _ := newTestScanner(inDir, outDir, "", pkcs12.Modern2023)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanAndSetHealth(ctx, scanner, marker)

	if _, err := os.Stat(markerPath); err != nil {
		t.Errorf("marker must be left untouched when the scan is cancelled by shutdown: %v", err)
	}
}

func TestConvertToPFX_round_trip_all_encoders(t *testing.T) {
	t.Parallel()

	encoders := []struct {
		enc  *pkcs12.Encoder
		name string
	}{
		{enc: pkcs12.Modern2023, name: "modern2023"},
		{enc: pkcs12.Modern2026, name: "modern2026"},
		{enc: pkcs12.LegacyDES, name: "legacyDES"},
		{enc: pkcs12.LegacyRC2, name: "legacyRC2"},
	}

	for _, tc := range encoders {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "encoder-"+tc.name, "ecdsa")
			pfxPath := filepath.Join(t.TempDir(), "test.pfx")

			if err := convert.Pair(t.Context(), certPEM, keyPEM, pfxPath, "testpass", tc.enc); err != nil {
				t.Fatalf("convert.Pair(%s): %v", tc.name, err)
			}

			_, cert, _ := decodePFX(t, pfxPath, "testpass")
			if cert.Subject.CommonName != "encoder-"+tc.name {
				t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "encoder-"+tc.name)
			}
		})
	}
}

func TestProcessAll_empty_directory(t *testing.T) {
	t.Parallel()

	inDir := t.TempDir()
	outDir := t.TempDir()
	scanner, _ := newTestScanner(inDir, outDir, "", pkcs12.Modern2023)

	if _, err := scanner.Run(context.Background()); err != nil {
		t.Fatalf("scanner.Run(empty dir) = %v, want nil", err)
	}

	// Output dir should remain empty.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("scanner.Run(empty dir) created %d files, want 0", len(entries))
	}
}

func TestProcessAll_ignores_non_crt_files(t *testing.T) {
	t.Parallel()

	inDir := t.TempDir()
	outDir := t.TempDir()
	scanner, _ := newTestScanner(inDir, outDir, "", pkcs12.Modern2023)

	// Write files that aren't .crt — should be ignored.
	for _, name := range []string{"readme.txt", "config.json", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(inDir, name), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := scanner.Run(context.Background()); err != nil {
		t.Fatalf("scanner.Run = %v, want nil", err)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("scanner.Run created %d files for non-.crt input, want 0", len(entries))
	}
}

func TestProcessAll_prunes_hashes_for_deleted_certs(t *testing.T) {
	t.Parallel()

	inDir := t.TempDir()
	outDir := t.TempDir()
	scanner, _ := newTestScanner(inDir, outDir, "", pkcs12.Modern2023)

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "prune", "ecdsa")
	crtPath, keyPath := writeCertAndKey(t, inDir, "prune", certPEM, keyPEM)

	if _, err := scanner.Run(context.Background()); err != nil {
		t.Fatalf("first scanner.Run: %v", err)
	}

	// Delete the cert and key files.
	if err := os.Remove(crtPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}

	// Second scan should prune the stale hash entry.
	if _, err := scanner.Run(context.Background()); err != nil {
		t.Fatalf("second scanner.Run: %v", err)
	}

	// After pruning, re-creating the same file should be re-converted
	// because the hash was pruned (not skipped as "unchanged").
	certPEM2, keyPEM2 := testcerts.GenerateSelfSignedCert(t, "prune-v2", "ecdsa")
	writeCertAndKey(t, inDir, "prune", certPEM2, keyPEM2)

	if _, err := scanner.Run(context.Background()); err != nil {
		t.Fatalf("third scanner.Run: %v", err)
	}

	pfxPath := filepath.Join(outDir, "prune.pfx")
	_, cert, _ := decodePFX(t, pfxPath, "")
	if cert.Subject.CommonName != "prune-v2" {
		t.Errorf("PFX CN = %q, want %q after re-creation", cert.Subject.CommonName, "prune-v2")
	}
}

func TestConvertToPFX_with_password_containing_special_chars(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "special-pass", "ecdsa")
	pfxPath := filepath.Join(t.TempDir(), "test.pfx")

	password := "p@$$w0rd!#%&*(){}[]|\\:\";<>?,./~`"
	if err := convert.Pair(t.Context(), certPEM, keyPEM, pfxPath, password, pkcs12.Modern2023); err != nil {
		t.Fatalf("convert.Pair(special password): %v", err)
	}

	_, cert, _ := decodePFX(t, pfxPath, password)
	if cert.Subject.CommonName != "special-pass" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "special-pass")
	}
}

func TestProcessAll_multiple_cert_pairs(t *testing.T) {
	t.Parallel()

	inDir := t.TempDir()
	outDir := t.TempDir()
	scanner, _ := newTestScanner(inDir, outDir, "pass", pkcs12.Modern2023)

	// Create 3 cert/key pairs.
	for _, name := range []string{"alpha", "beta", "gamma"} {
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, name, "ecdsa")
		writeCertAndKey(t, inDir, name, certPEM, keyPEM)
	}

	if _, err := scanner.Run(context.Background()); err != nil {
		t.Fatalf("scanner.Run = %v", err)
	}

	for _, name := range []string{"alpha", "beta", "gamma"} {
		pfxPath := filepath.Join(outDir, name+".pfx")
		_, cert, _ := decodePFX(t, pfxPath, "pass")
		if cert.Subject.CommonName != name {
			t.Errorf("PFX %s: CN = %q, want %q", name, cert.Subject.CommonName, name)
		}
	}
}

func TestConvertToPFX_single_cert_has_no_CA_certs(t *testing.T) {
	t.Parallel()

	// Verify that a single-cert PFX has zero CA certs (not the leaf duplicated as CA).
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "single", "ecdsa")
	pfxPath := filepath.Join(t.TempDir(), "test.pfx")

	if err := convert.Pair(t.Context(), certPEM, keyPEM, pfxPath, "pass", pkcs12.Modern2023); err != nil {
		t.Fatalf("convert.Pair: %v", err)
	}

	_, _, caCerts := decodePFX(t, pfxPath, "pass")
	if len(caCerts) != 0 {
		t.Errorf("single-cert PFX has %d CA certs, want 0", len(caCerts))
	}
}

// --- Tests: scan pipeline error branches ---

func TestProcessAll_returns_error_when_root_missing(t *testing.T) {
	t.Parallel()

	outDir := t.TempDir()
	scanner, _ := newTestScanner("/nonexistent/input/dir", outDir, "", pkcs12.Modern2023)
	_, err := scanner.Run(context.Background())
	if err == nil {
		t.Fatal("scanner.Run should return error for nonexistent root dir")
	}
}

func TestProcessAll_skips_unreadable_subdirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: chmod semantics differ")
	}
	if os.Geteuid() == 0 {
		t.Skip("skipping as root: chmod 0 does not block root")
	}
	inDir := t.TempDir()
	outDir := t.TempDir()
	scanner, _ := newTestScanner(inDir, outDir, "", pkcs12.Modern2023)

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "good", "ecdsa")
	writeCertAndKey(t, inDir, "good", certPEM, keyPEM)

	badDir := filepath.Join(inDir, "blocked")
	if err := os.MkdirAll(badDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(badDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(badDir, 0o755) })

	_, err := scanner.Run(context.Background())
	if err != nil {
		t.Errorf("scanner.Run should skip unreadable subdir, got error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "good.pfx")); err != nil {
		t.Errorf("good.pfx should have been produced despite blocked sibling: %v", err)
	}
}

func TestProcessAll_invalidates_hash_when_mkdir_fails(t *testing.T) {
	t.Parallel()

	inDir := t.TempDir()
	outDir := t.TempDir()
	scanner, _ := newTestScanner(inDir, outDir, "", pkcs12.Modern2023)

	nested := filepath.Join(inDir, "conflict")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "conflict", "ecdsa")
	writeCertAndKey(t, nested, "cert", certPEM, keyPEM)

	// Plant a regular file at the output path where MkdirAll would
	// need to create the "conflict" directory. MkdirAll fails with
	// "not a directory".
	blockingFile := filepath.Join(outDir, "conflict")
	if err := os.WriteFile(blockingFile, []byte("blocker"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := scanner.Run(context.Background()); err != nil {
		t.Fatalf("scanner.Run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "conflict", "cert.pfx")); err == nil {
		t.Fatal("pfx should not exist after MkdirAll failure")
	}

	// Remove the blocker, retry: hash was invalidated so re-conversion must occur.
	if err := os.Remove(blockingFile); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Run(context.Background()); err != nil {
		t.Fatalf("scanner.Run (second run): %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "conflict", "cert.pfx")); err != nil {
		t.Errorf("pfx should have been produced on retry after blocker removal: %v", err)
	}
}

// --- Tests: convertPair rename failure ---

func TestConvertToPFX_cleans_up_tmp_on_rename_failure(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: rename-over-directory semantics differ")
	}
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "rename-fail", "ecdsa")
	tmpDir := t.TempDir()

	// Create a DIRECTORY at destPath. os.Rename(tmp, destDir) fails.
	destPath := filepath.Join(tmpDir, "out.pfx")
	if err := os.MkdirAll(destPath, 0o755); err != nil {
		t.Fatal(err)
	}

	err := convert.Pair(t.Context(), certPEM, keyPEM, destPath, "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("convert.Pair should fail when destPath is a directory")
	}

	// Verify no leaked tmp files (atomicfile names temps ".atomicfile-<digits>.tmp").
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".atomicfile-") {
			t.Errorf("leaked temp file after rename failure: %s", e.Name())
		}
	}
}

func TestHealthyAfterScan(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   process.ScanResult
		want bool
	}{
		{"clean scan is healthy", process.ScanResult{Total: 3, Converted: 3}, true},
		{"conversion failure clears health", process.ScanResult{Total: 2, Converted: 1, Failed: 1}, false},
		{"unreadable path alone stays healthy", process.ScanResult{Total: 1, Converted: 1, Unreadable: 1}, true},
		{"failure stays unhealthy even with unreadable", process.ScanResult{Failed: 2, Unreadable: 3}, false},
		{"orphan-only scan stays healthy", process.ScanResult{Total: 1, Orphan: 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := healthyAfterScan(tc.in); got != tc.want {
				t.Errorf("healthyAfterScan(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cert-watcher/internal/convert"
	"cert-watcher/internal/health"
	"cert-watcher/internal/process"
	"cert-watcher/internal/testcerts"

	"software.sslmate.com/src/go-pkcs12"
)

// --- Test helpers ---

// newTestScanner creates a fresh cache and scanner for test isolation.
func newTestScanner() (*process.Scanner, *convert.HashCache) {
	c := convert.NewHashCache()
	return process.New(c), c
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
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "test.pfx")

		if err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, pfxPath, "pass", pkcs12.Modern2023); err != nil {
			t.Fatalf("process.ConvertPair: %v", err)
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
	})

	t.Run("RSA round trip", func(t *testing.T) {
		t.Parallel()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "rsa-test", "rsa")
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "test.pfx")

		if err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, pfxPath, "", pkcs12.Modern2023); err != nil {
			t.Fatalf("process.ConvertPair: %v", err)
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
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "chain", chainPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "chain.pfx")

		if err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, pfxPath, "chainpass", pkcs12.Modern2023); err != nil {
			t.Fatalf("process.ConvertPair: %v", err)
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
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "atomic", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "atomic.pfx")

		// Pre-existing file should be replaced.
		if err := os.WriteFile(pfxPath, []byte("old data"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, pfxPath, "", pkcs12.Modern2023); err != nil {
			t.Fatalf("process.ConvertPair: %v", err)
		}

		decodePFX(t, pfxPath, "") // panics if still "old data"
	})
}

// --- Tests: processAll ---

func TestProcessAll(t *testing.T) {
	t.Parallel()

	enc := pkcs12.Modern2023

	t.Run("skips unchanged files", func(t *testing.T) {
		t.Parallel()
		scanner, _ := newTestScanner()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

		if _, err := scanner.Run(context.Background(), tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("first scanner.Run: %v", err)
		}

		pfxPath := filepath.Join(outDir, "test.pfx")
		info1, err := os.Stat(pfxPath)
		if err != nil {
			t.Fatalf("pfx not created: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		if _, err := scanner.Run(context.Background(), tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("second scanner.Run: %v", err)
		}

		info2, err := os.Stat(pfxPath)
		if err != nil {
			t.Fatalf("pfx disappeared: %v", err)
		}
		if info2.ModTime() != info1.ModTime() {
			t.Error("pfx was rewritten despite unchanged input")
		}
	})

	t.Run("reconverts on change", func(t *testing.T) {
		t.Parallel()
		scanner, _ := newTestScanner()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

		if _, err := scanner.Run(context.Background(), tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("first scanner.Run: %v", err)
		}

		// Replace with new cert.
		certPEM2, keyPEM2 := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		writeCertAndKey(t, tmpDir, "test", certPEM2, keyPEM2)

		if _, err := scanner.Run(context.Background(), tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("second scanner.Run: %v", err)
		}

		decodePFX(t, filepath.Join(outDir, "test.pfx"), "")
	})

	t.Run("preserves nested directory structure", func(t *testing.T) {
		t.Parallel()
		scanner, _ := newTestScanner()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()

		nestedDir := filepath.Join(tmpDir, "sub", "dir")
		if err := os.MkdirAll(nestedDir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeCertAndKey(t, nestedDir, "nested", certPEM, keyPEM)

		if _, err := scanner.Run(context.Background(), tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("scanner.Run: %v", err)
		}

		pfxPath := filepath.Join(outDir, "sub", "dir", "nested.pfx")
		if _, err := os.Stat(pfxPath); err != nil {
			t.Fatalf("expected PFX at %s: %v", pfxPath, err)
		}
	})

	t.Run("skips .crt without matching .key", func(t *testing.T) {
		t.Parallel()
		scanner, _ := newTestScanner()
		certPEM, _ := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()

		if err := os.WriteFile(filepath.Join(tmpDir, "orphan.crt"), certPEM, 0o644); err != nil {
			t.Fatal(err)
		}

		if _, err := scanner.Run(context.Background(), tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("scanner.Run: %v", err)
		}

		if _, err := os.Stat(filepath.Join(outDir, "orphan.pfx")); err == nil {
			t.Error("PFX should not be created when .key is missing")
		}
	})

	t.Run("retries after conversion failure", func(t *testing.T) {
		t.Parallel()
		scanner, _ := newTestScanner()
		tmpDir := t.TempDir()
		outDir := t.TempDir()

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
		if _, err := scanner.Run(context.Background(), tmpDir, outDir, "", enc); err != nil {
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
		if _, err := scanner.Run(context.Background(), tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("second scanner.Run: %v", err)
		}
		if _, err := os.Stat(filepath.Join(outDir, "retry.pfx")); err != nil {
			t.Fatalf("PFX should exist after retry with valid key: %v", err)
		}
	})
}

// --- Tests: convertPair error paths ---

func TestConvertToPFX_nonexistent_cert(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	_, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	keyPath := filepath.Join(tmpDir, "test.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	err := process.ConvertPair(convert.CertPair{CertPath: filepath.Join(tmpDir, "missing.crt"), KeyPath: keyPath}, filepath.Join(tmpDir, "out.pfx"), "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("process.ConvertPair should fail for nonexistent cert file")
	}
	if !strings.Contains(err.Error(), "read cert") {
		t.Errorf("process.ConvertPair error = %q, want it to contain %q", err.Error(), "read cert")
	}
}

func TestConvertToPFX_nonexistent_key(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	crtPath := filepath.Join(tmpDir, "test.crt")
	if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: filepath.Join(tmpDir, "missing.key")}, filepath.Join(tmpDir, "out.pfx"), "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("process.ConvertPair should fail for nonexistent key file")
	}
	if !strings.Contains(err.Error(), "read key") {
		t.Errorf("process.ConvertPair error = %q, want it to contain %q", err.Error(), "read key")
	}
}

func TestConvertToPFX_invalid_cert_PEM(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	_, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "bad", []byte("not a cert"), keyPEM)

	err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, filepath.Join(tmpDir, "out.pfx"), "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("process.ConvertPair should fail for invalid cert PEM")
	}
}

func TestConvertToPFX_invalid_key_PEM(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "bad", certPEM, []byte("not a key"))

	err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, filepath.Join(tmpDir, "out.pfx"), "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("process.ConvertPair should fail for invalid key PEM")
	}
}

func TestConvertToPFX_unwritable_dest(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

	err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, "/nonexistent/dir/out.pfx", "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("process.ConvertPair should fail for unwritable destination")
	}
}

// --- Tests: processAndSetHealth ---

// newTestMarker constructs a marker rooted in a fresh TempDir so tests
// don't race on /tmp/.healthy.
func newTestMarker(t *testing.T) (*health.Marker, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".healthy")
	return health.NewMarker(path), path
}

func TestProcessAndSetHealth(t *testing.T) {
	t.Parallel()

	scanner, _ := newTestScanner()
	marker, markerPath := newTestMarker(t)

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "health-test", "ecdsa")
	inDir := t.TempDir()
	outDir := t.TempDir()
	writeCertAndKey(t, inDir, "test", certPEM, keyPEM)

	result, err := scanner.Run(context.Background(), inDir, outDir, "", pkcs12.Modern2023)
	if err != nil {
		marker.Set(false)
	} else {
		marker.Set(result.Failed == 0)
	}

	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("health marker should exist after successful processAndSetHealth: %v", err)
	}

	pfxPath := filepath.Join(outDir, "test.pfx")
	if _, err := os.Stat(pfxPath); err != nil {
		t.Fatalf("PFX should be created: %v", err)
	}
}

func TestProcessAndSetHealth_failure(t *testing.T) {
	t.Parallel()

	scanner, _ := newTestScanner()
	marker, markerPath := newTestMarker(t)

	// Set healthy first, then trigger a failure to verify it gets cleared.
	marker.Set(true)

	result, err := scanner.Run(context.Background(), "/nonexistent/input", "/nonexistent/output", "", pkcs12.Modern2023)
	if err != nil {
		marker.Set(false)
	} else {
		marker.Set(result.Failed == 0)
	}

	if _, err := os.Stat(markerPath); err == nil {
		t.Fatal("health marker should not exist after failed processAndSetHealth")
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
			tmpDir := t.TempDir()
			crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
			pfxPath := filepath.Join(tmpDir, "test.pfx")

			if err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, pfxPath, "testpass", tc.enc); err != nil {
				t.Fatalf("process.ConvertPair(%s): %v", tc.name, err)
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

	scanner, _ := newTestScanner()
	inDir := t.TempDir()
	outDir := t.TempDir()

	if _, err := scanner.Run(context.Background(), inDir, outDir, "", pkcs12.Modern2023); err != nil {
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

	scanner, _ := newTestScanner()
	inDir := t.TempDir()
	outDir := t.TempDir()

	// Write files that aren't .crt — should be ignored.
	for _, name := range []string{"readme.txt", "config.json", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(inDir, name), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := scanner.Run(context.Background(), inDir, outDir, "", pkcs12.Modern2023); err != nil {
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

	scanner, cache := newTestScanner()
	inDir := t.TempDir()
	outDir := t.TempDir()

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "prune", "ecdsa")
	crtPath, keyPath := writeCertAndKey(t, inDir, "prune", certPEM, keyPEM)

	if _, err := scanner.Run(context.Background(), inDir, outDir, "", pkcs12.Modern2023); err != nil {
		t.Fatalf("first scanner.Run: %v", err)
	}

	// Verify hash is cached (Changed returns false for unchanged file).
	if cache.Changed(crtPath, keyPath) {
		t.Fatal("hash should be cached after first scanner.Run (Changed should return false)")
	}

	// Delete the cert and key files.
	if err := os.Remove(crtPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}

	// Second scan should prune the stale hash entry.
	if _, err := scanner.Run(context.Background(), inDir, outDir, "", pkcs12.Modern2023); err != nil {
		t.Fatalf("second scanner.Run: %v", err)
	}

	// After pruning, re-creating the same file should be re-converted
	// because the hash was pruned (not skipped as "unchanged").
	certPEM2, keyPEM2 := testcerts.GenerateSelfSignedCert(t, "prune-v2", "ecdsa")
	writeCertAndKey(t, inDir, "prune", certPEM2, keyPEM2)

	if _, err := scanner.Run(context.Background(), inDir, outDir, "", pkcs12.Modern2023); err != nil {
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
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
	pfxPath := filepath.Join(tmpDir, "test.pfx")

	password := "p@$$w0rd!#%&*(){}[]|\\:\";<>?,./~`"
	if err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, pfxPath, password, pkcs12.Modern2023); err != nil {
		t.Fatalf("process.ConvertPair(special password): %v", err)
	}

	_, cert, _ := decodePFX(t, pfxPath, password)
	if cert.Subject.CommonName != "special-pass" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "special-pass")
	}
}

func TestProcessAll_multiple_cert_pairs(t *testing.T) {
	t.Parallel()

	scanner, _ := newTestScanner()
	inDir := t.TempDir()
	outDir := t.TempDir()

	// Create 3 cert/key pairs.
	for _, name := range []string{"alpha", "beta", "gamma"} {
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, name, "ecdsa")
		writeCertAndKey(t, inDir, name, certPEM, keyPEM)
	}

	if _, err := scanner.Run(context.Background(), inDir, outDir, "pass", pkcs12.Modern2023); err != nil {
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

func TestHashFile_exactly_at_max_size(t *testing.T) {
	t.Parallel()

	// Boundary test: file exactly at convert.MaxFileSize should succeed.
	_, cache := newTestScanner()
	path := filepath.Join(t.TempDir(), "exact-max.bin")
	data := make([]byte, convert.MaxFileSize)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	h, err := cache.HashFile(path)
	if err != nil {
		t.Fatalf("cache.HashFile(exactly convert.MaxFileSize) = error %v, want success", err)
	}
	if len(h) != 64 {
		t.Errorf("cache.HashFile returned hash of length %d, want 64", len(h))
	}
}

func TestConvertToPFX_single_cert_has_no_CA_certs(t *testing.T) {
	t.Parallel()

	// Verify that a single-cert PFX has zero CA certs (not the leaf duplicated as CA).
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "single", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
	pfxPath := filepath.Join(tmpDir, "test.pfx")

	if err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, pfxPath, "pass", pkcs12.Modern2023); err != nil {
		t.Fatalf("process.ConvertPair: %v", err)
	}

	_, _, caCerts := decodePFX(t, pfxPath, "pass")
	if len(caCerts) != 0 {
		t.Errorf("single-cert PFX has %d CA certs, want 0", len(caCerts))
	}
}

// --- Tests: processAll error branches ---

func TestProcessAll_returns_error_when_root_missing(t *testing.T) {
	t.Parallel()

	scanner, _ := newTestScanner()
	outDir := t.TempDir()
	_, err := scanner.Run(context.Background(), "/nonexistent/input/dir", outDir, "", pkcs12.Modern2023)
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
	scanner, _ := newTestScanner()
	inDir := t.TempDir()
	outDir := t.TempDir()

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

	_, err := scanner.Run(context.Background(), inDir, outDir, "", pkcs12.Modern2023)
	if err != nil {
		t.Errorf("scanner.Run should skip unreadable subdir, got error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "good.pfx")); err != nil {
		t.Errorf("good.pfx should have been produced despite blocked sibling: %v", err)
	}
}

func TestProcessAll_invalidates_hash_when_mkdir_fails(t *testing.T) {
	t.Parallel()

	scanner, cache := newTestScanner()
	inDir := t.TempDir()
	outDir := t.TempDir()

	nested := filepath.Join(inDir, "conflict")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "conflict", "ecdsa")
	crtPath, keyPath := writeCertAndKey(t, nested, "cert", certPEM, keyPEM)

	// Plant a regular file at the output path where MkdirAll would
	// need to create the "conflict" directory. MkdirAll fails with
	// "not a directory".
	blockingFile := filepath.Join(outDir, "conflict")
	if err := os.WriteFile(blockingFile, []byte("blocker"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := scanner.Run(context.Background(), inDir, outDir, "", pkcs12.Modern2023); err != nil {
		t.Fatalf("scanner.Run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "conflict", "cert.pfx")); err == nil {
		t.Fatal("pfx should not exist after MkdirAll failure")
	}

	// Remove the blocker, retry: hash was invalidated so re-conversion must occur.
	if err := os.Remove(blockingFile); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Run(context.Background(), inDir, outDir, "", pkcs12.Modern2023); err != nil {
		t.Fatalf("scanner.Run (second run): %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "conflict", "cert.pfx")); err != nil {
		t.Errorf("pfx should have been produced on retry after blocker removal: %v", err)
	}

	// Verify hash is cached after successful retry (Changed returns false).
	if cache.Changed(crtPath, keyPath) {
		t.Error("hash entry missing after successful retry (Changed should return false)")
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
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "rename-fail", certPEM, keyPEM)

	// Create a DIRECTORY at destPath. os.Rename(tmp, destDir) fails.
	destPath := filepath.Join(tmpDir, "out.pfx")
	if err := os.MkdirAll(destPath, 0o755); err != nil {
		t.Fatal(err)
	}

	err := process.ConvertPair(convert.CertPair{CertPath: crtPath, KeyPath: keyPath}, destPath, "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("process.ConvertPair should fail when destPath is a directory")
	}

	// Verify no leaked tmp files.
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".cert-convert-") {
			t.Errorf("leaked temp file after rename failure: %s", e.Name())
		}
	}
}

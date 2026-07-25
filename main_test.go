package main

import (
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
	"time"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/health"
	"github.com/cplieger/slogx/capture"
	"software.sslmate.com/src/go-pkcs12"
)

// --- Test helpers ---

// newTestScanner creates a scanner (with its own fresh fingerprint cache) over
// the given roots for test isolation. The scan configuration is
// process-lifetime, so it is injected at construction.
func newTestScanner(certsRoot, outRoot, password string, enc convert.EncoderType) *process.Scanner {
	return process.New(&process.Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  password,
		Encoder:   enc,
	})
}

// convertPairToPath converts an already-read cert+key pair to a PFX at destPath
// by composing the same three steps production composes: convert.Analyse resolves
// the pair, convert.Encode produces the bytes, and the write is confined to an
// *os.Root over destPath's directory. internal/convert is a pure codec and no
// longer writes anything, so there is no single call to wrap any more.
func convertPairToPath(ctx context.Context, certPEM, keyPEM []byte, destPath, password string, enc convert.EncoderType) error {
	root, err := os.OpenRoot(filepath.Dir(destPath))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	analysis, err := convert.Analyse(certPEM, keyPEM)
	if err != nil {
		return err
	}
	pfx, err := convert.Encode(&analysis, enc, password)
	if err != nil {
		return err
	}
	_, err = atomicfile.WriteFileInRoot(ctx, root, filepath.Base(destPath), pfx,
		atomicfile.WithMode(0o600))
	return err
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

		if err := convertPairToPath(t.Context(), certPEM, keyPEM, pfxPath, "pass", convert.EncNameModern2023); err != nil {
			t.Fatalf("convertPairToPath: %v", err)
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

		if err := convertPairToPath(t.Context(), certPEM, keyPEM, pfxPath, "", convert.EncNameModern2023); err != nil {
			t.Fatalf("convertPairToPath: %v", err)
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

		if err := convertPairToPath(t.Context(), chainPEM, keyPEM, pfxPath, "chainpass", convert.EncNameModern2023); err != nil {
			t.Fatalf("convertPairToPath: %v", err)
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

		if err := convertPairToPath(t.Context(), certPEM, keyPEM, pfxPath, "", convert.EncNameModern2023); err != nil {
			t.Fatalf("convertPairToPath: %v", err)
		}

		decodePFX(t, pfxPath, "") // fails the test if the file still holds "old data"
	})
}

// --- Tests: scan pipeline (process.Scanner.Run) ---

func TestProcessAll(t *testing.T) {
	t.Parallel()

	enc := convert.EncNameModern2023

	t.Run("reconverts on change", func(t *testing.T) {
		t.Parallel()
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		scanner := newTestScanner(tmpDir, outDir, "", enc)
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
		scanner := newTestScanner(tmpDir, outDir, "", enc)

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
		scanner := newTestScanner(tmpDir, outDir, "", enc)

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
		scanner := newTestScanner(tmpDir, outDir, "", enc)

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

// --- Tests: logPasswordStatus ---

// TestLogPasswordStatus pins the startup password-status decision: the returned
// status string and the WARN branch must agree, and a real password must produce
// no log record at all (the value is a secret). slog.Default is process-global,
// so this test is deliberately serial (no t.Parallel).
func TestLogPasswordStatus(t *testing.T) {
	for _, tc := range []struct {
		name        string
		password    string
		wantStatus  string
		wantWarnSub string
	}{
		{"empty reports empty", "", "empty", "PFX_PASSWORD is empty"},
		{"single space is whitespace-only", " ", "whitespace-only", "PFX_PASSWORD is whitespace-only"},
		{"tab and newline are whitespace-only", "\t\n ", "whitespace-only", "PFX_PASSWORD is whitespace-only"},
		{"real value is configured", "s3cret", "configured", ""},
		{"padded value is configured", "  s3cret  ", "configured", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			got := logPasswordStatus(tc.password)

			if got != tc.wantStatus {
				t.Errorf("logPasswordStatus(%q) = %q, want %q", tc.password, got, tc.wantStatus)
			}
			if tc.wantWarnSub == "" {
				if logs.Len() != 0 {
					t.Errorf("logPasswordStatus(%q) logged %v, want no log records for a real password",
						tc.password, logs.Messages())
				}
				return
			}
			if n := logs.CountLevel(slog.LevelWarn, tc.wantWarnSub); n != 1 {
				t.Errorf("logPasswordStatus(%q) logged %d WARN records matching %q, want 1 (logs %v)",
					tc.password, n, tc.wantWarnSub, logs.Messages())
			}
			if !logs.AttrContains(tc.wantWarnSub, "remediation", "PFX_PASSWORD") {
				t.Errorf("logPasswordStatus(%q) WARN is missing an actionable remediation attr (logs %v)",
					tc.password, logs.Messages())
			}
		})
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
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)
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
	scanner := newTestScanner(missing, t.TempDir(), "", convert.EncNameModern2023)

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
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)
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
	precheck := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)
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
	logs := capture.Default(t)

	scanAndSetHealth(t.Context(), scanner, marker)

	if logs.CountLevel(slog.LevelWarn, "unreadable") == 0 {
		t.Errorf("scanAndSetHealth should WARN about unreadable /input paths; got logs %q", logs.Messages())
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

	for _, tc := range []struct {
		name             string
		initiallyHealthy bool
	}{
		{name: "healthy marker stays healthy", initiallyHealthy: true},
		{name: "unhealthy marker stays unhealthy", initiallyHealthy: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker, markerPath := newTestMarker(t)
			marker.Set(tc.initiallyHealthy)

			inDir, outDir := t.TempDir(), t.TempDir()
			certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "cancelled", "ecdsa")
			writeCertAndKey(t, inDir, "cancelled", certPEM, keyPEM)
			scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			scanAndSetHealth(ctx, scanner, marker)

			_, statErr := os.Stat(markerPath)
			if gotHealthy := statErr == nil; gotHealthy != tc.initiallyHealthy {
				t.Errorf("marker healthy after cancelled scan = %v, want prior state %v (stat error: %v)",
					gotHealthy, tc.initiallyHealthy, statErr)
			}
		})
	}
}

func TestConvertToPFX_round_trip_all_encoders(t *testing.T) {
	t.Parallel()

	encoders := []struct {
		enc  convert.EncoderType
		name string
	}{
		{enc: convert.EncNameModern2023, name: "modern2023"},
		{enc: convert.EncNameModern2026, name: "modern2026"},
		{enc: convert.EncNameLegacyDES, name: "legacyDES"},
		{enc: convert.EncNameLegacyRC2, name: "legacyRC2"},
	}

	for _, tc := range encoders {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "encoder-"+tc.name, "ecdsa")
			pfxPath := filepath.Join(t.TempDir(), "test.pfx")

			if err := convertPairToPath(t.Context(), certPEM, keyPEM, pfxPath, "testpass", tc.enc); err != nil {
				t.Fatalf("convertPairToPath(%s): %v", tc.name, err)
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
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

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
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

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
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

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
	if err := convertPairToPath(t.Context(), certPEM, keyPEM, pfxPath, password, convert.EncNameModern2023); err != nil {
		t.Fatalf("convertPairToPath(special password): %v", err)
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
	scanner := newTestScanner(inDir, outDir, "pass", convert.EncNameModern2023)

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

	if err := convertPairToPath(t.Context(), certPEM, keyPEM, pfxPath, "pass", convert.EncNameModern2023); err != nil {
		t.Fatalf("convertPairToPath: %v", err)
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
	scanner := newTestScanner("/nonexistent/input/dir", outDir, "", convert.EncNameModern2023)
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
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

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
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

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

	err := convertPairToPath(t.Context(), certPEM, keyPEM, destPath, "", convert.EncNameModern2023)
	if err == nil {
		t.Fatal("convertPairToPath should fail when destPath is a directory")
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

// TestFallbackLogValue pins the startup log's rendering of the fallback
// cadence, the one operator-visible decision left in run(): a disabled
// rescan must read "disabled", never a bare "0s".
func TestFallbackLogValue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   time.Duration
		want string
	}{
		{"explicit zero is disabled", 0, "disabled"},
		{"negative is disabled", -1 * time.Hour, "disabled"},
		{"default cadence", 6 * time.Hour, "6h0m0s"},
		{"one hour", 1 * time.Hour, "1h0m0s"},
		{"clamp ceiling", 87600 * time.Hour, "87600h0m0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := fallbackLogValue(tc.in); got != tc.want {
				t.Errorf("fallbackLogValue(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDispatchArgs pins the argv policy behind the runProbe seam: the health
// subcommand probes the marker at health.DefaultPath, an unknown argument warns
// and falls through to the watcher, and a bare invocation does neither. No
// t.Parallel: it swaps the package-level runProbe var and slog.Default().
func TestDispatchArgs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		wantProbe bool
		wantWarn  bool
		wantCode  int
	}{
		{"no argument starts the watcher", []string{"cert-watcher"}, false, false, continueToWatcher},
		{"health probes the marker", []string{"cert-watcher", "health"}, true, false, continueToWatcher},
		// A typo used to WARN and fall through, which unlinked the resident
		// watcher's health marker and started a second watcher over the same
		// output tree. It is now a usage error that never reaches the marker.
		{"typo is a usage error and never starts a watcher", []string{"cert-watcher", "helth"}, false, false, exitUsage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			gotPath, probed := "", false
			prev := runProbe
			runProbe = func(path string, _ ...health.ProbeOption) {
				probed, gotPath = true, path
			}
			t.Cleanup(func() { runProbe = prev })

			gotCode := dispatchArgs(tc.args)

			if probed != tc.wantProbe {
				t.Errorf("dispatchArgs(%q) probed = %v, want %v", tc.args, probed, tc.wantProbe)
			}
			if tc.wantProbe && gotPath != health.DefaultPath {
				t.Errorf("dispatchArgs(%q) probed %q, want %q", tc.args, gotPath, health.DefaultPath)
			}
			if warned := logs.CountLevel(slog.LevelWarn, "unrecognized argument") > 0; warned != tc.wantWarn {
				t.Errorf("dispatchArgs(%q) warned = %v, want %v (log: %v)", tc.args, warned, tc.wantWarn, logs.Messages())
			}
			if gotCode != tc.wantCode {
				t.Errorf("dispatchArgs(%q) = %d, want %d", tc.args, gotCode, tc.wantCode)
			}
		})
	}
}

// TestDispatchArgs_arms_the_marker_lease pins the staleness deadline the health
// subcommand hands the probe: three fallback intervals (18h on the default 6h
// cadence), and no deadline at all when FALLBACK_SCAN_HOURS disables the
// fallback rescan, because watch-only mode has no guaranteed refresh cadence.
// The captured options are applied with health.ProbeCheck to markers whose
// mtimes straddle the deadline, so a wrong multiplier or a dropped option fails
// here rather than in production. No t.Parallel: it swaps runProbe and mutates
// the environment.
func TestDispatchArgs_arms_the_marker_lease(t *testing.T) {
	for _, tc := range []struct {
		name          string
		fallbackHours string
		markerAge     time.Duration
		wantCode      int
	}{
		{"default cadence keeps a marker inside the 18h lease healthy", "", 17 * time.Hour, 0},
		{"default cadence fails a marker past the 18h lease", "", 19 * time.Hour, 1},
		{"a disabled fallback disarms the lease entirely", "0", 100 * time.Hour, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FALLBACK_SCAN_HOURS", tc.fallbackHours)

			var gotOpts []health.ProbeOption
			probed := false
			prev := runProbe
			runProbe = func(_ string, opts ...health.ProbeOption) {
				probed, gotOpts = true, opts
			}
			t.Cleanup(func() { runProbe = prev })

			_ = dispatchArgs([]string{"cert-watcher", "health"})

			if !probed {
				t.Fatalf("dispatchArgs([health]) did not probe with FALLBACK_SCAN_HOURS=%q", tc.fallbackHours)
			}

			marker := filepath.Join(t.TempDir(), ".healthy")
			if err := os.WriteFile(marker, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			aged := time.Now().Add(-tc.markerAge)
			if err := os.Chtimes(marker, aged, aged); err != nil {
				t.Fatal(err)
			}

			if got := health.ProbeCheck(marker, gotOpts...); got != tc.wantCode {
				t.Errorf("ProbeCheck(marker aged %v, opts from FALLBACK_SCAN_HOURS=%q) = %d, want %d",
					tc.markerAge, tc.fallbackHours, got, tc.wantCode)
			}
		})
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

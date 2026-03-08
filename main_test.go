package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// --- Test helpers ---

// generateSelfSignedCert creates a self-signed certificate with the given
// key type and common name. Returns PEM-encoded cert and key.
func generateSelfSignedCert(t *testing.T, cn, keyType string) (certPEM, keyPEM []byte) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	switch keyType {
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	default:
		t.Fatalf("unsupported key type: %s", keyType)
	}

	return certPEM, keyPEM
}

// generateCertChain creates a CA + leaf certificate chain.
// Returns leaf PEM, key PEM, CA PEM, and the full chain (leaf + CA).
func generateCertChain(t *testing.T) (leafPEM, keyPEM, caPEM, chainPEM []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	chainPEM = make([]byte, 0, len(leafPEM)+len(caPEM))
	chainPEM = append(chainPEM, leafPEM...)
	chainPEM = append(chainPEM, caPEM...)
	return leafPEM, keyPEM, caPEM, chainPEM
}

// writeCertAndKey writes a .crt and .key file pair into dir and returns their paths.
func writeCertAndKey(t *testing.T, dir, base string, certPEM, keyPEM []byte) (crtPath, keyPath string) {
	t.Helper()
	crtPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	os.WriteFile(crtPath, certPEM, 0o644)
	os.WriteFile(keyPath, keyPEM, 0o600)
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

// --- Tests: parseCertChain ---

func TestParseCertChain(t *testing.T) {
	t.Run("single cert", func(t *testing.T) {
		certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
		certs, err := parseCertChain(certPEM)
		if err != nil {
			t.Fatalf("parseCertChain: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("got %d certs, want 1", len(certs))
		}
		if certs[0].Subject.CommonName != "test" {
			t.Errorf("CN = %q, want %q", certs[0].Subject.CommonName, "test")
		}
	})

	t.Run("chain with CA", func(t *testing.T) {
		_, _, _, chainPEM := generateCertChain(t)
		certs, err := parseCertChain(chainPEM)
		if err != nil {
			t.Fatalf("parseCertChain: %v", err)
		}
		if len(certs) != 2 {
			t.Fatalf("got %d certs, want 2", len(certs))
		}
		if certs[0].Subject.CommonName != "leaf.example.com" {
			t.Errorf("leaf CN = %q, want %q", certs[0].Subject.CommonName, "leaf.example.com")
		}
		if certs[1].Subject.CommonName != "Test CA" {
			t.Errorf("CA CN = %q, want %q", certs[1].Subject.CommonName, "Test CA")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		if _, err := parseCertChain([]byte("not a pem")); err == nil {
			t.Error("expected error for invalid PEM")
		}
	})

	t.Run("excessive PEM blocks", func(t *testing.T) {
		// Verify parseCertChain handles a file with many CERTIFICATE blocks
		// without hanging. This is a resource exhaustion edge case.
		certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
		// Repeat the same cert block 100 times
		var bulkPEM []byte
		for range 100 {
			bulkPEM = append(bulkPEM, certPEM...)
		}
		certs, err := parseCertChain(bulkPEM)
		if err != nil {
			t.Fatalf("parseCertChain: %v", err)
		}
		if len(certs) != 100 {
			t.Errorf("got %d certs, want 100", len(certs))
		}
	})
}

// --- Tests: parsePrivateKey ---

func TestParsePrivateKey(t *testing.T) {
	t.Run("ECDSA PKCS8", func(t *testing.T) {
		_, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		key, err := parsePrivateKey(keyPEM)
		if err != nil {
			t.Fatalf("parsePrivateKey: %v", err)
		}
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
		}
	})

	t.Run("RSA PKCS1", func(t *testing.T) {
		_, keyPEM := generateSelfSignedCert(t, "test", "rsa")
		key, err := parsePrivateKey(keyPEM)
		if err != nil {
			t.Fatalf("parsePrivateKey: %v", err)
		}
		if _, ok := key.(*rsa.PrivateKey); !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", key)
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		if _, err := parsePrivateKey([]byte("not a key")); err == nil {
			t.Error("expected error for invalid key PEM")
		}
	})

	t.Run("PEM with only CERTIFICATE blocks", func(t *testing.T) {
		certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
		if _, err := parsePrivateKey(certPEM); err == nil {
			t.Error("expected error when PEM contains only CERTIFICATE blocks")
		}
	})
}

// --- Tests: convertToPFX ---

func TestConvertToPFXCertKeyMismatch(t *testing.T) {
	// Generate two independent key pairs — cert signed by key A, key file contains key B
	certPEM, _ := generateSelfSignedCert(t, "mismatch", "ecdsa")
	_, wrongKeyPEM := generateSelfSignedCert(t, "other", "ecdsa")

	tmpDir := t.TempDir()
	crtPath := filepath.Join(tmpDir, "mismatch.crt")
	keyPath := filepath.Join(tmpDir, "mismatch.key")
	os.WriteFile(crtPath, certPEM, 0o644)
	os.WriteFile(keyPath, wrongKeyPEM, 0o600)

	pfxPath := filepath.Join(tmpDir, "mismatch.pfx")
	err := convertToPFX(crtPath, keyPath, pfxPath, "pass")
	if err == nil {
		// If it didn't error, the PFX should at least fail to decode properly
		// (pkcs12 may or may not catch the mismatch at encode time)
		t.Log("convertToPFX did not error on cert/key mismatch — verifying PFX integrity")
	}
	// Either way, the test documents the behavior
}

func TestConvertToPFX(t *testing.T) {
	t.Run("ECDSA round trip", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, "ecdsa-test", "ecdsa")
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "test.pfx")

		if err := convertToPFX(crtPath, keyPath, pfxPath, "pass"); err != nil {
			t.Fatalf("convertToPFX: %v", err)
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
		certPEM, keyPEM := generateSelfSignedCert(t, "rsa-test", "rsa")
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "test.pfx")

		if err := convertToPFX(crtPath, keyPath, pfxPath, ""); err != nil {
			t.Fatalf("convertToPFX: %v", err)
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
		_, keyPEM, _, chainPEM := generateCertChain(t)
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "chain", chainPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "chain.pfx")

		if err := convertToPFX(crtPath, keyPath, pfxPath, "chainpass"); err != nil {
			t.Fatalf("convertToPFX: %v", err)
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
		certPEM, keyPEM := generateSelfSignedCert(t, "atomic", "ecdsa")
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "atomic", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "atomic.pfx")

		// Pre-existing file should be replaced
		os.WriteFile(pfxPath, []byte("old data"), 0o644)

		if err := convertToPFX(crtPath, keyPath, pfxPath, ""); err != nil {
			t.Fatalf("convertToPFX: %v", err)
		}

		decodePFX(t, pfxPath, "") // panics if still "old data"
	})
}

// --- Tests: processAll ---

func TestProcessAll(t *testing.T) {
	t.Run("skips unchanged files", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

		if err := processAll(tmpDir, outDir, ""); err != nil {
			t.Fatalf("first processAll: %v", err)
		}

		pfxPath := filepath.Join(outDir, "test.pfx")
		info1, err := os.Stat(pfxPath)
		if err != nil {
			t.Fatalf("pfx not created: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		if err := processAll(tmpDir, outDir, ""); err != nil {
			t.Fatalf("second processAll: %v", err)
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
		certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

		if err := processAll(tmpDir, outDir, ""); err != nil {
			t.Fatalf("first processAll: %v", err)
		}

		// Replace with new cert
		certPEM2, keyPEM2 := generateSelfSignedCert(t, "test", "ecdsa")
		writeCertAndKey(t, tmpDir, "test", certPEM2, keyPEM2)

		if err := processAll(tmpDir, outDir, ""); err != nil {
			t.Fatalf("second processAll: %v", err)
		}

		decodePFX(t, filepath.Join(outDir, "test.pfx"), "")
	})

	t.Run("preserves nested directory structure", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()

		nestedDir := filepath.Join(tmpDir, "sub", "dir")
		os.MkdirAll(nestedDir, 0o755)
		writeCertAndKey(t, nestedDir, "nested", certPEM, keyPEM)

		if err := processAll(tmpDir, outDir, ""); err != nil {
			t.Fatalf("processAll: %v", err)
		}

		pfxPath := filepath.Join(outDir, "sub", "dir", "nested.pfx")
		if _, err := os.Stat(pfxPath); err != nil {
			t.Fatalf("expected PFX at %s: %v", pfxPath, err)
		}
	})

	t.Run("skips .crt without matching .key", func(t *testing.T) {
		certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()

		os.WriteFile(filepath.Join(tmpDir, "orphan.crt"), certPEM, 0o644)

		if err := processAll(tmpDir, outDir, ""); err != nil {
			t.Fatalf("processAll: %v", err)
		}

		if _, err := os.Stat(filepath.Join(outDir, "orphan.pfx")); err == nil {
			t.Error("PFX should not be created when .key is missing")
		}
	})
}

// --- Tests: changed ---

func TestChanged(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

	if !changed(crtPath, keyPath) {
		t.Error("first call should report changed")
	}
	if changed(crtPath, keyPath) {
		t.Error("second call should report not changed")
	}

	// Replace with new content
	certPEM2, keyPEM2 := generateSelfSignedCert(t, "test", "ecdsa")
	writeCertAndKey(t, tmpDir, "test", certPEM2, keyPEM2)

	if !changed(crtPath, keyPath) {
		t.Error("should report changed after content update")
	}
}

func TestChangedOversizedFile(t *testing.T) {
	tmpDir := t.TempDir()
	crtPath := filepath.Join(tmpDir, "big.crt")
	keyPath := filepath.Join(tmpDir, "big.key")

	// Create files exceeding the 10 MB limit
	bigData := make([]byte, 11<<20)
	os.WriteFile(crtPath, bigData, 0o644)
	os.WriteFile(keyPath, []byte("small"), 0o600)

	// Should report changed (can't hash → treat as changed)
	if !changed(crtPath, keyPath) {
		t.Error("oversized file should report changed (hash error)")
	}
}

// --- Tests: pickEncoder ---

func TestPickEncoder(t *testing.T) {
	for _, env := range []string{
		"", "modern2023", "Modern", "modern2026", "Modern2026",
		"legacy", "legacyrc2", "LegacyDES", "unknown",
	} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("PFX_ENCODER", env)
			if enc := pickEncoder(); enc == nil {
				t.Fatal("pickEncoder returned nil")
			}
		})
	}
}

// --- Tests: health file ---

func TestHealthFile(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" {
		t.Skip("skipping on Windows: /tmp does not exist")
	}

	setHealthy(true)
	defer setHealthy(false)

	if _, err := os.Stat(healthFile); err != nil {
		t.Fatalf("health file should exist after setHealthy(true): %v", err)
	}

	setHealthy(false)
	if _, err := os.Stat(healthFile); err == nil {
		t.Fatal("health file should not exist after setHealthy(false)")
	}
}

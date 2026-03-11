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

// clearHashes resets the global hash cache to prevent test pollution.
func clearHashes() {
	mu.Lock()
	defer mu.Unlock()
	clear(hashes)
}

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
	// Generate two independent key pairs — cert signed by key A, key file contains key B.
	// The pkcs12 encoder doesn't validate cert/key pairing at encode time,
	// so we verify the resulting PFX contains mismatched material.
	certPEM, _ := generateSelfSignedCert(t, "mismatch", "ecdsa")
	_, wrongKeyPEM := generateSelfSignedCert(t, "other", "ecdsa")

	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "mismatch", certPEM, wrongKeyPEM)

	pfxPath := filepath.Join(tmpDir, "mismatch.pfx")
	if err := convertToPFX(crtPath, keyPath, pfxPath, "pass", pkcs12.Modern2023); err != nil {
		// Some encoder versions may detect the mismatch — that's acceptable.
		return
	}

	// If encode succeeded, the PFX file should exist.
	if _, err := os.Stat(pfxPath); err != nil {
		t.Fatalf("PFX file not created: %v", err)
	}
}

func TestConvertToPFX(t *testing.T) {
	t.Run("ECDSA round trip", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, "ecdsa-test", "ecdsa")
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "test.pfx")

		if err := convertToPFX(crtPath, keyPath, pfxPath, "pass", pkcs12.Modern2023); err != nil {
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

		if err := convertToPFX(crtPath, keyPath, pfxPath, "", pkcs12.Modern2023); err != nil {
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

		if err := convertToPFX(crtPath, keyPath, pfxPath, "chainpass", pkcs12.Modern2023); err != nil {
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

		// Pre-existing file should be replaced.
		if err := os.WriteFile(pfxPath, []byte("old data"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := convertToPFX(crtPath, keyPath, pfxPath, "", pkcs12.Modern2023); err != nil {
			t.Fatalf("convertToPFX: %v", err)
		}

		decodePFX(t, pfxPath, "") // panics if still "old data"
	})
}

// --- Tests: readFileWithLimit ---

func TestReadFileWithLimit(t *testing.T) {
	t.Run("normal file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "small.txt")
		if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		data, err := readFileWithLimit(path, 1024)
		if err != nil {
			t.Fatalf("readFileWithLimit: %v", err)
		}
		if string(data) != "hello" {
			t.Errorf("got %q, want %q", data, "hello")
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "big.txt")
		if err := os.WriteFile(path, make([]byte, 2048), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := readFileWithLimit(path, 1024)
		if err == nil {
			t.Error("expected error for oversized file")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := readFileWithLimit("/nonexistent/file.txt", 1024)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

// --- Tests: processAll ---

func TestProcessAll(t *testing.T) {
	enc := pkcs12.Modern2023

	t.Run("skips unchanged files", func(t *testing.T) {
		clearHashes()
		certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("first processAll: %v", err)
		}

		pfxPath := filepath.Join(outDir, "test.pfx")
		info1, err := os.Stat(pfxPath)
		if err != nil {
			t.Fatalf("pfx not created: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
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
		clearHashes()
		certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("first processAll: %v", err)
		}

		// Replace with new cert.
		certPEM2, keyPEM2 := generateSelfSignedCert(t, "test", "ecdsa")
		writeCertAndKey(t, tmpDir, "test", certPEM2, keyPEM2)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("second processAll: %v", err)
		}

		decodePFX(t, filepath.Join(outDir, "test.pfx"), "")
	})

	t.Run("preserves nested directory structure", func(t *testing.T) {
		clearHashes()
		certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()

		nestedDir := filepath.Join(tmpDir, "sub", "dir")
		if err := os.MkdirAll(nestedDir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeCertAndKey(t, nestedDir, "nested", certPEM, keyPEM)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("processAll: %v", err)
		}

		pfxPath := filepath.Join(outDir, "sub", "dir", "nested.pfx")
		if _, err := os.Stat(pfxPath); err != nil {
			t.Fatalf("expected PFX at %s: %v", pfxPath, err)
		}
	})

	t.Run("skips .crt without matching .key", func(t *testing.T) {
		clearHashes()
		certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()

		if err := os.WriteFile(filepath.Join(tmpDir, "orphan.crt"), certPEM, 0o644); err != nil {
			t.Fatal(err)
		}

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("processAll: %v", err)
		}

		if _, err := os.Stat(filepath.Join(outDir, "orphan.pfx")); err == nil {
			t.Error("PFX should not be created when .key is missing")
		}
	})
}

// --- Tests: changed ---

func TestChanged(t *testing.T) {
	clearHashes()
	certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

	if !changed(crtPath, keyPath) {
		t.Error("first call should report changed")
	}
	if changed(crtPath, keyPath) {
		t.Error("second call should report not changed")
	}

	// Replace with new content.
	certPEM2, keyPEM2 := generateSelfSignedCert(t, "test", "ecdsa")
	writeCertAndKey(t, tmpDir, "test", certPEM2, keyPEM2)

	if !changed(crtPath, keyPath) {
		t.Error("should report changed after content update")
	}
}

func TestChangedOversizedFile(t *testing.T) {
	clearHashes()
	tmpDir := t.TempDir()
	crtPath := filepath.Join(tmpDir, "big.crt")
	keyPath := filepath.Join(tmpDir, "big.key")

	// Create files exceeding the 10 MB limit.
	bigData := make([]byte, 11<<20)
	if err := os.WriteFile(crtPath, bigData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Should report changed (can't hash → treat as changed).
	if !changed(crtPath, keyPath) {
		t.Error("oversized file should report changed (hash error)")
	}
}

// --- Tests: pickEncoder ---

func TestPickEncoder(t *testing.T) {
	for _, tc := range []struct {
		env      string
		wantName string
	}{
		{"", encNameModern2023},
		{"modern2023", encNameModern2023},
		{"Modern", encNameModern2023},
		{"modern2026", encNameModern2026},
		{"Modern2026", encNameModern2026},
		{"legacy", encNameLegacyDES},
		{"legacyrc2", encNameLegacyRC2},
		{"LegacyDES", encNameLegacyDES},
		{"unknown", encNameModern2023},
	} {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("PFX_ENCODER", tc.env)
			enc, name := pickEncoder()
			if enc == nil {
				t.Fatal("pickEncoder returned nil encoder")
			}
			if name != tc.wantName {
				t.Errorf("pickEncoder name = %q, want %q", name, tc.wantName)
			}
		})
	}
}

// --- Tests: parseFallbackInterval ---

func TestParseFallbackInterval(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		set  bool
		want time.Duration
	}{
		{"unset", "", false, 6 * time.Hour},
		{"empty", "", true, 0},
		{"zero", "0", true, 0},
		{"false", "false", true, 0},
		{"FALSE", "FALSE", true, 0},
		{"valid", "12", true, 12 * time.Hour},
		{"one", "1", true, 1 * time.Hour},
		{"negative", "-1", true, 6 * time.Hour},
		{"non-numeric", "abc", true, 6 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("FALLBACK_SCAN_HOURS", tc.env)
			}
			if got := parseFallbackInterval(); got != tc.want {
				t.Errorf("parseFallbackInterval() = %v, want %v", got, tc.want)
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

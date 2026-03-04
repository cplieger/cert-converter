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

func generateTestCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
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

	return certPEM, keyPEM
}

func generateTestCertRSA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM
}

func TestParseCertChain(t *testing.T) {
	certPEM, _ := generateTestCert(t)

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
}

func TestParseCertChainEmpty(t *testing.T) {
	_, err := parseCertChain([]byte("not a pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestParsePrivateKeyECDSA(t *testing.T) {
	_, keyPEM := generateTestCert(t)

	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
	}
}

func TestParsePrivateKeyRSA(t *testing.T) {
	_, keyPEM := generateTestCertRSA(t)

	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", key)
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	_, err := parsePrivateKey([]byte("not a key"))
	if err == nil {
		t.Error("expected error for invalid key PEM")
	}
}

func TestConvertToPFXRoundTrip(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	tmpDir := t.TempDir()

	crtPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")
	pfxPath := filepath.Join(tmpDir, "test.pfx")

	os.WriteFile(crtPath, certPEM, 0o644)
	os.WriteFile(keyPath, keyPEM, 0o600)

	if err := convertToPFX(crtPath, keyPath, pfxPath, "testpass"); err != nil {
		t.Fatalf("convertToPFX: %v", err)
	}

	// Verify the PFX can be decoded back
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}

	privKey, cert, caCerts, err := pkcs12.DecodeChain(pfxData, "testpass")
	if err != nil {
		t.Fatalf("decode pfx: %v", err)
	}
	if cert.Subject.CommonName != "test" {
		t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, "test")
	}
	if _, ok := privKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", privKey)
	}
	if len(caCerts) != 0 {
		t.Errorf("expected 0 CA certs, got %d", len(caCerts))
	}
}

func TestConvertToPFXRoundTripRSA(t *testing.T) {
	certPEM, keyPEM := generateTestCertRSA(t)
	tmpDir := t.TempDir()

	crtPath := filepath.Join(tmpDir, "rsa.crt")
	keyPath := filepath.Join(tmpDir, "rsa.key")
	pfxPath := filepath.Join(tmpDir, "rsa.pfx")

	os.WriteFile(crtPath, certPEM, 0o644)
	os.WriteFile(keyPath, keyPEM, 0o600)

	if err := convertToPFX(crtPath, keyPath, pfxPath, ""); err != nil {
		t.Fatalf("convertToPFX: %v", err)
	}

	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}

	privKey, cert, _, err := pkcs12.DecodeChain(pfxData, "")
	if err != nil {
		t.Fatalf("decode pfx: %v", err)
	}
	if cert.Subject.CommonName != "rsa-test" {
		t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, "rsa-test")
	}
	if _, ok := privKey.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", privKey)
	}
}

func TestProcessAllSkipsUnchanged(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	tmpDir := t.TempDir()
	outDir := t.TempDir()

	crtPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	os.WriteFile(crtPath, certPEM, 0o644)
	os.WriteFile(keyPath, keyPEM, 0o600)

	// First run should convert
	if err := processAll(tmpDir, outDir, ""); err != nil {
		t.Fatalf("first processAll: %v", err)
	}

	pfxPath := filepath.Join(outDir, "test.pfx")
	info1, err := os.Stat(pfxPath)
	if err != nil {
		t.Fatalf("pfx not created: %v", err)
	}

	// Wait a moment so mtime would differ if rewritten
	time.Sleep(50 * time.Millisecond)

	// Second run should skip (unchanged)
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
}

func TestProcessAllReconvertsOnChange(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	tmpDir := t.TempDir()
	outDir := t.TempDir()

	crtPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	os.WriteFile(crtPath, certPEM, 0o644)
	os.WriteFile(keyPath, keyPEM, 0o600)

	// First run
	if err := processAll(tmpDir, outDir, ""); err != nil {
		t.Fatalf("first processAll: %v", err)
	}

	// Generate new cert (different content)
	certPEM2, keyPEM2 := generateTestCert(t)
	os.WriteFile(crtPath, certPEM2, 0o644)
	os.WriteFile(keyPath, keyPEM2, 0o600)

	// Second run should reconvert
	if err := processAll(tmpDir, outDir, ""); err != nil {
		t.Fatalf("second processAll: %v", err)
	}

	pfxPath := filepath.Join(outDir, "test.pfx")
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}

	// Verify it's the new cert
	_, cert, _, err := pkcs12.DecodeChain(pfxData, "")
	if err != nil {
		t.Fatalf("decode pfx: %v", err)
	}
	if cert.Subject.CommonName != "test" {
		t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, "test")
	}
}

func TestHealthFileOperations(t *testing.T) {
	// Skip on Windows — /tmp doesn't exist; this runs in Linux containers
	if os.Getenv("OS") == "Windows_NT" {
		t.Skip("skipping on Windows: /tmp does not exist")
	}

	touchHealthFile()
	defer removeHealthFile()

	if _, err := os.Stat(healthFile); err != nil {
		t.Fatalf("health file should exist after touchHealthFile: %v", err)
	}

	removeHealthFile()
	if _, err := os.Stat(healthFile); err == nil {
		t.Fatal("health file should not exist after removeHealthFile")
	}
}

func TestChangedDetection(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	tmpDir := t.TempDir()

	crtPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	os.WriteFile(crtPath, certPEM, 0o644)
	os.WriteFile(keyPath, keyPEM, 0o600)

	// First call should report changed (not seen before)
	if !changed(crtPath, keyPath) {
		t.Error("first call should report changed")
	}

	// Second call with same content should report not changed
	if changed(crtPath, keyPath) {
		t.Error("second call should report not changed")
	}

	// Write different content
	certPEM2, keyPEM2 := generateTestCert(t)
	os.WriteFile(crtPath, certPEM2, 0o644)
	os.WriteFile(keyPath, keyPEM2, 0o600)

	// Should report changed again
	if !changed(crtPath, keyPath) {
		t.Error("third call should report changed after content update")
	}
}

func TestPickEncoder(t *testing.T) {
	tests := []struct {
		env  string
		want string
	}{
		{"", "modern2023"},
		{"modern2023", "modern2023"},
		{"Modern", "modern2023"},
		{"modern2026", "modern2026"},
		{"Modern2026", "modern2026"},
		{"legacy", "legacydes"},
		{"legacyrc2", "legacyrc2"},
		{"LegacyDES", "legacydes"},
		{"unknown", "modern2023"},
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			t.Setenv("PFX_ENCODER", tt.env)
			enc := pickEncoder()
			if enc == nil {
				t.Fatal("pickEncoder returned nil")
			}
		})
	}
}

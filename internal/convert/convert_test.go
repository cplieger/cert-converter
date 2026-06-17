package convert_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/cert-watcher/internal/convert"
	"github.com/cplieger/cert-watcher/internal/testcerts"
	"software.sslmate.com/src/go-pkcs12"
)

// --- Tests: convert.ParseCertChain ---

func TestParseCertChain(t *testing.T) {
	t.Parallel()
	t.Run("single cert", func(t *testing.T) {
		t.Parallel()
		certPEM, _ := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		certs, err := convert.ParseCertChain(certPEM)
		if err != nil {
			t.Fatalf("convert.ParseCertChain: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("got %d certs, want 1", len(certs))
		}
		if certs[0].Subject.CommonName != "test" {
			t.Errorf("CN = %q, want %q", certs[0].Subject.CommonName, "test")
		}
	})

	t.Run("chain with CA", func(t *testing.T) {
		t.Parallel()
		_, _, _, chainPEM := testcerts.GenerateCertChain(t)
		certs, err := convert.ParseCertChain(chainPEM)
		if err != nil {
			t.Fatalf("convert.ParseCertChain: %v", err)
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
		t.Parallel()
		if _, err := convert.ParseCertChain([]byte("not a pem")); err == nil {
			t.Error("expected error for invalid PEM")
		}
	})

	t.Run("excessive PEM blocks", func(t *testing.T) {
		t.Parallel()
		certPEM, _ := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		var bulkPEM []byte
		for range 100 {
			bulkPEM = append(bulkPEM, certPEM...)
		}
		certs, err := convert.ParseCertChain(bulkPEM)
		if err != nil {
			t.Fatalf("convert.ParseCertChain: %v", err)
		}
		if len(certs) != 100 {
			t.Errorf("got %d certs, want 100", len(certs))
		}
	})
}

func TestParseCertChain_corrupted_DER(t *testing.T) {
	t.Parallel()
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not valid DER"),
	})

	_, err := convert.ParseCertChain(badPEM)
	if err == nil {
		t.Fatal("convert.ParseCertChain should fail for corrupted DER inside CERTIFICATE block")
	}
}

func TestParseCertChain_skips_non_certificate_blocks(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "mixed", "ecdsa")

	mixed := make([]byte, 0, len(keyPEM)+len(certPEM))
	mixed = append(mixed, keyPEM...)
	mixed = append(mixed, certPEM...)

	certs, err := convert.ParseCertChain(mixed)
	if err != nil {
		t.Fatalf("convert.ParseCertChain(mixed PEM) = error %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("convert.ParseCertChain(mixed PEM) returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "mixed" {
		t.Errorf("convert.ParseCertChain(mixed PEM) CN = %q, want %q",
			certs[0].Subject.CommonName, "mixed")
	}
}

func TestParseCertChain_empty_input(t *testing.T) {
	t.Parallel()
	_, err := convert.ParseCertChain([]byte{})
	if err == nil {
		t.Fatal("convert.ParseCertChain(empty) should return error")
	}
	if !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("convert.ParseCertChain(empty) error = %q, want it to contain %q",
			err.Error(), "no certificate")
	}
}

func TestParseCertChain_round_trip(t *testing.T) {
	t.Parallel()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "round-trip", "ecdsa")

	certs, err := convert.ParseCertChain(certPEM)
	if err != nil {
		t.Fatalf("convert.ParseCertChain: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}

	reEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certs[0].Raw,
	})
	certs2, err := convert.ParseCertChain(reEncoded)
	if err != nil {
		t.Fatalf("convert.ParseCertChain(re-encoded): %v", err)
	}
	if certs2[0].Subject.CommonName != "round-trip" {
		t.Errorf("round trip CN = %q, want %q", certs2[0].Subject.CommonName, "round-trip")
	}
}

// --- Tests: convert.ParsePrivateKey ---

func TestParsePrivateKey(t *testing.T) {
	t.Parallel()
	t.Run("ECDSA PKCS8", func(t *testing.T) {
		t.Parallel()
		_, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		key, err := convert.ParsePrivateKey(keyPEM)
		if err != nil {
			t.Fatalf("convert.ParsePrivateKey: %v", err)
		}
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
		}
	})

	t.Run("RSA PKCS1", func(t *testing.T) {
		t.Parallel()
		_, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "rsa")
		key, err := convert.ParsePrivateKey(keyPEM)
		if err != nil {
			t.Fatalf("convert.ParsePrivateKey: %v", err)
		}
		if _, ok := key.(*rsa.PrivateKey); !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", key)
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		t.Parallel()
		if _, err := convert.ParsePrivateKey([]byte("not a key")); err == nil {
			t.Error("expected error for invalid key PEM")
		}
	})

	t.Run("PEM with only CERTIFICATE blocks", func(t *testing.T) {
		t.Parallel()
		certPEM, _ := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
		if _, err := convert.ParsePrivateKey(certPEM); err == nil {
			t.Error("expected error when PEM contains only CERTIFICATE blocks")
		}
	})
}

func TestParsePrivateKey_EC_SEC1(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	parsed, err := convert.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("convert.ParsePrivateKey(EC SEC1) = error %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("convert.ParsePrivateKey(EC SEC1) returned %T, want *ecdsa.PrivateKey", parsed)
	}
}

func TestParsePrivateKey_Ed25519_PKCS8(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := convert.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("convert.ParsePrivateKey(Ed25519 PKCS8) = error %v", err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Errorf("convert.ParsePrivateKey(Ed25519 PKCS8) returned %T, want ed25519.PrivateKey", parsed)
	}
}

func TestParsePrivateKey_unparseable_key_data(t *testing.T) {
	t.Parallel()
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("this is not valid DER"),
	})

	_, err := convert.ParsePrivateKey(keyPEM)
	if err == nil {
		t.Fatal("convert.ParsePrivateKey should fail for garbage DER data")
	}
	if !strings.Contains(err.Error(), "failed to parse private key") {
		t.Errorf("convert.ParsePrivateKey error = %q, want it to contain %q",
			err.Error(), "failed to parse private key")
	}
}

func TestParsePrivateKey_empty_input(t *testing.T) {
	t.Parallel()
	_, err := convert.ParsePrivateKey([]byte{})
	if err == nil {
		t.Fatal("convert.ParsePrivateKey(empty) should return error")
	}
	if !strings.Contains(err.Error(), "no private key") {
		t.Errorf("convert.ParsePrivateKey(empty) error = %q, want it to contain %q",
			err.Error(), "no private key")
	}
}

func TestParsePrivateKey_RSA_PKCS8(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := convert.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("convert.ParsePrivateKey(RSA PKCS8) = error %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("convert.ParsePrivateKey(RSA PKCS8) returned %T, want *rsa.PrivateKey", parsed)
	}
}

// --- Tests: convert.ReadFileWithLimit ---

func TestReadFileWithLimit(t *testing.T) {
	t.Parallel()
	t.Run("normal file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "small.txt")
		if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		data, err := convert.ReadFileWithLimit(t.Context(), path, 1024)
		if err != nil {
			t.Fatalf("convert.ReadFileWithLimit: %v", err)
		}
		if string(data) != "hello" {
			t.Errorf("got %q, want %q", data, "hello")
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "big.txt")
		if err := os.WriteFile(path, make([]byte, 2048), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := convert.ReadFileWithLimit(t.Context(), path, 1024)
		if err == nil {
			t.Error("expected error for oversized file")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()
		_, err := convert.ReadFileWithLimit(t.Context(), "/nonexistent/file.txt", 1024)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

func TestReadFileWithLimit_exact_limit(t *testing.T) {
	t.Parallel()
	content := []byte("exactly at limit")
	path := filepath.Join(t.TempDir(), "exact.txt")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	data, err := convert.ReadFileWithLimit(t.Context(), path, int64(len(content)))
	if err != nil {
		t.Fatalf("convert.ReadFileWithLimit at exact limit: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Errorf("convert.ReadFileWithLimit = %q, want %q", data, content)
	}
}

func TestReadFileWithLimit_one_byte_over(t *testing.T) {
	t.Parallel()
	content := []byte("one byte over the limit")
	path := filepath.Join(t.TempDir(), "over.txt")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := convert.ReadFileWithLimit(t.Context(), path, int64(len(content)-1))
	if err == nil {
		t.Fatal("convert.ReadFileWithLimit should reject file one byte over limit")
	}
}

func TestReadFileWithLimit_empty_file(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	data, err := convert.ReadFileWithLimit(t.Context(), path, 1024)
	if err != nil {
		t.Fatalf("convert.ReadFileWithLimit(empty) = error %v", err)
	}
	if len(data) != 0 {
		t.Errorf("convert.ReadFileWithLimit(empty) returned %d bytes, want 0", len(data))
	}
}

// --- Tests: convert.ToPFX ---

// TestToPFX_writes_decodable_pfx exercises the success path end-to-end: a valid
// key/cert pair must encode without error and land a PKCS#12 file that decodes
// back to the same leaf. This pins both error checks in ToPFX (encode + write):
// negating either to `err == nil` turns the success path into a returned error,
// which this assertion catches.
func TestToPFX_writes_decodable_pfx(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "topfx-test", "ecdsa")
	certs, err := convert.ParseCertChain(certPEM)
	if err != nil {
		t.Fatalf("setup: convert.ParseCertChain: %v", err)
	}
	privKey, err := convert.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("setup: convert.ParsePrivateKey: %v", err)
	}
	destPath := filepath.Join(t.TempDir(), "out.pfx")

	err = convert.ToPFX(t.Context(), privKey, certs[0], nil, destPath, "pw", pkcs12.Modern2023)
	if err != nil {
		t.Fatalf("convert.ToPFX(valid key/cert) = error %v, want nil", err)
	}
	pfxData, readErr := os.ReadFile(destPath)
	if readErr != nil {
		t.Fatalf("convert.ToPFX did not write a readable file: %v", readErr)
	}
	_, leaf, _, decErr := pkcs12.DecodeChain(pfxData, "pw")
	if decErr != nil {
		t.Fatalf("decode pfx written by convert.ToPFX: %v", decErr)
	}
	if leaf.Subject.CommonName != "topfx-test" {
		t.Errorf("convert.ToPFX wrote leaf CN = %q, want %q", leaf.Subject.CommonName, "topfx-test")
	}
}

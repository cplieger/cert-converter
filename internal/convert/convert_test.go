package convert_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
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

// --- Tests: convert.ReadBoundedFromRoot ---

func TestReadBoundedFromRoot(t *testing.T) {
	t.Parallel()
	t.Run("reads file within limit through root", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "in.pem"), []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		data, err := convert.ReadBoundedFromRoot(t.Context(), root, "in.pem", 1024)
		if err != nil {
			t.Fatalf("convert.ReadBoundedFromRoot: %v", err)
		}
		if !bytes.Equal(data, []byte("hello")) {
			t.Errorf("got %q, want %q", data, "hello")
		}
	})

	t.Run("rejects oversized file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "big.pem"), make([]byte, 2048), 0o644); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := convert.ReadBoundedFromRoot(t.Context(), root, "big.pem", 1024); err == nil {
			t.Error("expected error for oversized file")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := convert.ReadBoundedFromRoot(t.Context(), root, "missing.pem", 1024); err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("confines a symlink escaping the root", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink semantics differ on Windows")
		}
		t.Parallel()
		// The security guarantee of item l-f14: a symlink planted in the
		// watched directory that points outside it must not leak the target.
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("top secret"), 0o644); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "leak.pem")); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := convert.ReadBoundedFromRoot(t.Context(), root, "leak.pem", 1024); err == nil {
			t.Fatal("ReadBoundedFromRoot followed a symlink escaping the root; want a confinement error")
		}
	})
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

func TestParsePrivateKey_encrypted_block_returns_distinct_error(t *testing.T) {
	t.Parallel()
	encPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("opaque-ciphertext"),
	})
	_, err := convert.ParsePrivateKey(encPEM)
	if err == nil {
		t.Fatal("convert.ParsePrivateKey(ENCRYPTED PRIVATE KEY) = nil error, want error")
	}
	if !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("error = %q, want it to contain \"encrypted\"", err.Error())
	}
}

func TestParsePrivateKey_unsupported_pkcs8_type_rejected(t *testing.T) {
	t.Parallel()
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(xkey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_, err = convert.ParsePrivateKey(keyPEM)
	if err == nil {
		t.Fatal("ParsePrivateKey(X25519 PKCS8) = nil error, want error")
	}
	if !strings.Contains(err.Error(), "unsupported private key type in PKCS8 container") {
		t.Errorf("error = %q, want \"unsupported private key type in PKCS8 container\"",
			err.Error())
	}
}

func TestParsePrivateKey_traditional_openssl_encrypted_returns_distinct_error(t *testing.T) {
	t.Parallel()
	encPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF",
		},
		Bytes: []byte("opaque encrypted key material"),
	})

	_, err := convert.ParsePrivateKey(encPEM)
	if err == nil {
		t.Fatal("convert.ParsePrivateKey(traditional OpenSSL encrypted RSA key) = nil error, want error")
	}
	if !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("convert.ParsePrivateKey(encrypted) error = %q, want it to contain %q", err.Error(), "encrypted")
	}
}

func TestToPFX_returns_wrapped_error_on_write_failure(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "write-fail", "ecdsa")
	certs, err := convert.ParseCertChain(certPEM)
	if err != nil {
		t.Fatalf("setup: convert.ParseCertChain: %v", err)
	}
	privKey, err := convert.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("setup: convert.ParsePrivateKey: %v", err)
	}
	// Destination sits inside a directory that does not exist; ToPFX does
	// not create parents, so the atomic temp-file create fails.
	destPath := filepath.Join(t.TempDir(), "missing-subdir", "out.pfx")

	err = convert.ToPFX(t.Context(), privKey, certs[0], nil, destPath, "pw", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("convert.ToPFX(unwritable destination) = nil error, want a wrapped write error")
	}
	if !strings.Contains(err.Error(), "write pfx") {
		t.Errorf("convert.ToPFX(unwritable destination) error = %q, want it to contain %q", err.Error(), "write pfx")
	}
	if _, statErr := os.Stat(destPath); statErr == nil {
		t.Errorf("convert.ToPFX wrote a file at an unwritable destination; want none")
	}
}

// TestToPFX_encode_failure_is_wrapped pins the encode branch of ToPFX: a
// private key the PKCS#12 encoder cannot marshal must surface as a wrapped
// "encode pfx" error and must leave no file at destPath.
func TestToPFX_encode_failure_is_wrapped(t *testing.T) {
	t.Parallel()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "encode-fail", "ecdsa")
	certs, err := convert.ParseCertChain(certPEM)
	if err != nil {
		t.Fatalf("setup: convert.ParseCertChain: %v", err)
	}
	destPath := filepath.Join(t.TempDir(), "out.pfx")

	// A nil private key cannot be marshalled to PKCS#8, so the encoder fails
	// before any temp file is created.
	err = convert.ToPFX(t.Context(), nil, certs[0], nil, destPath, "pw", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("convert.ToPFX(nil private key) = nil error, want a wrapped encode error")
	}
	if !strings.Contains(err.Error(), "encode pfx") {
		t.Errorf("convert.ToPFX(nil private key) error = %q, want it to contain %q", err.Error(), "encode pfx")
	}
	if _, statErr := os.Stat(destPath); statErr == nil {
		t.Error("convert.ToPFX wrote a file after an encode failure; want none")
	}
}

// TestToPFX_round_trips_chain_for_every_encoder_profile pins the four PFX
// encoding profiles PFX_ENCODER can select and the CA-chain argument: each
// profile must produce a PKCS#12 file that decodes back to the same leaf AND
// the same CA chain, at mode 0600.
func TestToPFX_round_trips_chain_for_every_encoder_profile(t *testing.T) {
	t.Parallel()
	_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
	certs, err := convert.ParseCertChain(chainPEM)
	if err != nil {
		t.Fatalf("setup: convert.ParseCertChain: %v", err)
	}
	privKey, err := convert.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("setup: convert.ParsePrivateKey: %v", err)
	}

	profiles := map[string]*pkcs12.Encoder{
		"modern2023": pkcs12.Modern2023,
		"modern2026": pkcs12.Modern2026,
		"legacydes":  pkcs12.LegacyDES,
		"legacyrc2":  pkcs12.LegacyRC2,
	}
	for name, enc := range profiles {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			destPath := filepath.Join(t.TempDir(), name+".pfx")
			if err := convert.ToPFX(t.Context(), privKey, certs[0], certs[1:], destPath, "pw", enc); err != nil {
				t.Fatalf("convert.ToPFX(%s) = error %v, want nil", name, err)
			}
			info, err := os.Stat(destPath)
			if err != nil {
				t.Fatalf("convert.ToPFX(%s) did not write a file: %v", name, err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("convert.ToPFX(%s) wrote mode %o, want 600", name, perm)
			}
			pfxData, err := os.ReadFile(destPath)
			if err != nil {
				t.Fatalf("read pfx written by convert.ToPFX(%s): %v", name, err)
			}
			_, leaf, cas, err := pkcs12.DecodeChain(pfxData, "pw")
			if err != nil {
				t.Fatalf("decode pfx written by convert.ToPFX(%s): %v", name, err)
			}
			if leaf.Subject.CommonName != "leaf.example.com" {
				t.Errorf("convert.ToPFX(%s) leaf CN = %q, want %q", name, leaf.Subject.CommonName, "leaf.example.com")
			}
			if len(cas) != 1 {
				t.Fatalf("convert.ToPFX(%s) round-tripped %d CA certs, want 1", name, len(cas))
			}
			if cas[0].Subject.CommonName != "Test CA" {
				t.Errorf("convert.ToPFX(%s) CA CN = %q, want %q", name, cas[0].Subject.CommonName, "Test CA")
			}
		})
	}
}

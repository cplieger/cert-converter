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
	"syscall"
	"testing"
	"time"

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

func TestParseCertChain_ignores_marker_text_inside_prose(t *testing.T) {
	t.Parallel()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "prose", "ecdsa")

	// encoding/pem only treats a marker as a declaration when it occupies a
	// whole line, so prose mentioning the marker must not be counted as a
	// second declared block (which would make a valid chain look malformed).
	withProse := make([]byte, 0, len(certPEM)+64)
	withProse = append(withProse, certPEM...)
	withProse = append(withProse, []byte("see -----BEGIN CERTIFICATE----- above\n")...)

	certs, err := convert.ParseCertChain(withProse)
	if err != nil {
		t.Fatalf("convert.ParseCertChain(cert + prose) = error %v, want nil", err)
	}
	if len(certs) != 1 {
		t.Fatalf("convert.ParseCertChain(cert + prose) returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "prose" {
		t.Errorf("convert.ParseCertChain(cert + prose) CN = %q, want %q",
			certs[0].Subject.CommonName, "prose")
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

	t.Run("rejects a non-regular file without blocking", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("mkfifo is not available on Windows")
		}
		t.Parallel()
		// The guarantee of item h-f5: open(2) on a FIFO with no writer blocks
		// forever, and the scan runs on the watch loop's only goroutine, so a
		// FIFO planted in the watched tree must be rejected, not waited on.
		dir := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(dir, "evil.crt"), 0o600); err != nil {
			t.Fatalf("setup: mkfifo: %v", err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()

		done := make(chan error, 1)
		go func() {
			_, readErr := convert.ReadBoundedFromRoot(t.Context(), root, "evil.crt", 1024)
			done <- readErr
		}()
		select {
		case readErr := <-done:
			if readErr == nil {
				t.Fatal("ReadBoundedFromRoot read a FIFO; want a not-a-regular-file error")
			}
			if !strings.Contains(readErr.Error(), "not a regular file") {
				t.Errorf("ReadBoundedFromRoot(FIFO) error = %q, want it to mention %q",
					readErr.Error(), "not a regular file")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("ReadBoundedFromRoot blocked on a FIFO; the O_NONBLOCK open regressed")
		}
	})
}

// --- Tests: convert.PairInRoot ---

// TestPairInRoot_writes_decodable_pfx exercises the success path end-to-end: a
// valid key/cert pair must encode without error and land a PKCS#12 file that
// decodes back to the same leaf. This pins both error checks in the confined
// write path (encode + write): negating either to `err == nil` turns the success
// path into a returned error, which this assertion catches.
func TestPairInRoot_writes_decodable_pfx(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "topfx-test", "ecdsa")
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	destPath := filepath.Join(dir, "out.pfx")

	err = convert.PairInRoot(t.Context(), certPEM, keyPEM, root, "out.pfx", "pw", convert.EncNameModern2023)
	if err != nil {
		t.Fatalf("convert.PairInRoot(valid key/cert) = error %v, want nil", err)
	}
	pfxData, readErr := os.ReadFile(destPath)
	if readErr != nil {
		t.Fatalf("convert.PairInRoot did not write a readable file: %v", readErr)
	}
	_, leaf, _, decErr := pkcs12.DecodeChain(pfxData, "pw")
	if decErr != nil {
		t.Fatalf("decode pfx written by convert.PairInRoot: %v", decErr)
	}
	if leaf.Subject.CommonName != "topfx-test" {
		t.Errorf("convert.PairInRoot wrote leaf CN = %q, want %q", leaf.Subject.CommonName, "topfx-test")
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
	tests := map[string]map[string]string{
		"Proc-Type only with interior space": {"Proc-Type": "4, ENCRYPTED"},
		"Proc-Type only lowercase with tab":  {"proc-type": "4,\tencrypted"},
		"DEK-Info only":                      {"DEK-Info": "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF"},
		"DEK-Info only lowercase":            {"dek-info": "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF"},
	}
	for name, headers := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encPEM := pem.EncodeToMemory(&pem.Block{
				Type:    "RSA PRIVATE KEY",
				Headers: headers,
				Bytes:   []byte("opaque encrypted key material"),
			})
			_, err := convert.ParsePrivateKey(encPEM)
			if err == nil {
				t.Fatal("convert.ParsePrivateKey(traditional encrypted key) = nil error, want error")
			}
			if !strings.Contains(err.Error(), "encrypted") {
				t.Errorf("convert.ParsePrivateKey(traditional encrypted key) error = %q, want it to contain %q", err.Error(), "encrypted")
			}
		})
	}
}

// TestParsePrivateKey_malformed_labelled_block_names_its_own_format pins that
// the fallback error reports the parser matching the block's own PEM label, not
// the PKCS8 attempt every block starts with.
func TestParsePrivateKey_malformed_labelled_block_names_its_own_format(t *testing.T) {
	t.Parallel()
	for _, blockType := range []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"} {
		t.Run(blockType, func(t *testing.T) {
			t.Parallel()
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  blockType,
				Bytes: []byte("this is not valid DER"),
			})
			_, err := convert.ParsePrivateKey(keyPEM)
			if err == nil {
				t.Fatalf("convert.ParsePrivateKey(malformed %s) = nil error, want error", blockType)
			}
			if !strings.Contains(err.Error(), blockType) {
				t.Errorf("convert.ParsePrivateKey(malformed %s) error = %q, want it to name %q",
					blockType, err.Error(), blockType)
			}
		})
	}
}

func TestPairInRoot_returns_wrapped_error_on_write_failure(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "write-fail", "ecdsa")
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	// Destination sits inside a directory that does not exist; the confined
	// write does not create parents, so the atomic temp-file create fails.
	rel := filepath.Join("missing-subdir", "out.pfx")

	err = convert.PairInRoot(t.Context(), certPEM, keyPEM, root, rel, "pw", convert.EncNameModern2023)
	if err == nil {
		t.Fatal("convert.PairInRoot(unwritable destination) = nil error, want a wrapped write error")
	}
	if !strings.Contains(err.Error(), "write pfx") {
		t.Errorf("convert.PairInRoot(unwritable destination) error = %q, want it to contain %q", err.Error(), "write pfx")
	}
	if _, statErr := os.Stat(filepath.Join(dir, rel)); statErr == nil {
		t.Errorf("convert.PairInRoot wrote a file at an unwritable destination; want none")
	}
}

// TestPairInRoot_round_trips_chain_for_every_encoder_profile pins the four PFX
// encoding profiles PFX_ENCODER can select and the CA-chain handling: each
// profile must produce a PKCS#12 file that decodes back to the same leaf AND
// the same CA chain, at mode 0600.
func TestPairInRoot_round_trips_chain_for_every_encoder_profile(t *testing.T) {
	t.Parallel()
	_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)

	profiles := map[string]convert.EncoderType{
		"modern2023": convert.EncNameModern2023,
		"modern2026": convert.EncNameModern2026,
		"legacydes":  convert.EncNameLegacyDES,
		"legacyrc2":  convert.EncNameLegacyRC2,
	}
	for name, enc := range profiles {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			root, rootErr := os.OpenRoot(dir)
			if rootErr != nil {
				t.Fatalf("setup: os.OpenRoot: %v", rootErr)
			}
			defer root.Close()
			rel := name + ".pfx"
			destPath := filepath.Join(dir, rel)
			if err := convert.PairInRoot(t.Context(), chainPEM, keyPEM, root, rel, "pw", enc); err != nil {
				t.Fatalf("convert.PairInRoot(%s) = error %v, want nil", name, err)
			}
			info, err := os.Stat(destPath)
			if err != nil {
				t.Fatalf("convert.PairInRoot(%s) did not write a file: %v", name, err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("convert.PairInRoot(%s) wrote mode %o, want 600", name, perm)
			}
			pfxData, err := os.ReadFile(destPath)
			if err != nil {
				t.Fatalf("read pfx written by convert.PairInRoot(%s): %v", name, err)
			}
			_, leaf, cas, err := pkcs12.DecodeChain(pfxData, "pw")
			if err != nil {
				t.Fatalf("decode pfx written by convert.PairInRoot(%s): %v", name, err)
			}
			if leaf.Subject.CommonName != "leaf.example.com" {
				t.Errorf("convert.PairInRoot(%s) leaf CN = %q, want %q", name, leaf.Subject.CommonName, "leaf.example.com")
			}
			if len(cas) != 1 {
				t.Fatalf("convert.PairInRoot(%s) round-tripped %d CA certs, want 1", name, len(cas))
			}
			if cas[0].Subject.CommonName != "Test CA" {
				t.Errorf("convert.PairInRoot(%s) CA CN = %q, want %q", name, cas[0].Subject.CommonName, "Test CA")
			}
		})
	}
}

// TestPairInRoot_confines_the_write_to_the_output_root pins the guarantee of
// item h-f8 on the path production actually takes: the confined write must
// produce a decodable 0600 PFX, and a symlinked subdirectory under the output
// root must not redirect the private-key-bearing PFX outside it.
func TestPairInRoot_confines_the_write_to_the_output_root(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "confined", "ecdsa")

	t.Run("writes a decodable pfx at mode 0600", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if err := convert.PairInRoot(t.Context(), certPEM, keyPEM, root, "out.pfx", "pw", convert.EncNameModern2023); err != nil {
			t.Fatalf("convert.PairInRoot = error %v, want nil", err)
		}
		info, statErr := os.Stat(filepath.Join(dir, "out.pfx"))
		if statErr != nil {
			t.Fatalf("convert.PairInRoot did not write a file: %v", statErr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("convert.PairInRoot wrote mode %o, want 600", perm)
		}
		pfxData, readErr := os.ReadFile(filepath.Join(dir, "out.pfx"))
		if readErr != nil {
			t.Fatalf("read pfx written by convert.PairInRoot: %v", readErr)
		}
		_, leaf, _, decErr := pkcs12.DecodeChain(pfxData, "pw")
		if decErr != nil {
			t.Fatalf("decode pfx written by convert.PairInRoot: %v", decErr)
		}
		if leaf.Subject.CommonName != "confined" {
			t.Errorf("convert.PairInRoot leaf CN = %q, want %q", leaf.Subject.CommonName, "confined")
		}
	})

	t.Run("refuses a subdirectory symlinked outside the root", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink semantics differ on Windows")
		}
		t.Parallel()
		outside := t.TempDir()
		dir := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()

		writeErr := convert.PairInRoot(t.Context(), certPEM, keyPEM, root, "escape/out.pfx", "pw", convert.EncNameModern2023)
		if _, statErr := os.Stat(filepath.Join(outside, "out.pfx")); statErr == nil {
			t.Error("convert.PairInRoot wrote the PFX outside the output root through a symlinked subdirectory")
		}
		if writeErr == nil {
			t.Error("convert.PairInRoot(symlinked subdirectory) = nil error, want a confinement error")
		}
	})
}

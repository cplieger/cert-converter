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

func TestParseCertChain_rejects_a_declared_block_pem_drops_silently(t *testing.T) {
	t.Parallel()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "truncated-chain", "ecdsa")
	// The second block declares itself on a whole line but never terminates, so
	// pem.Decode drops it silently. Without the declared-count guard the caller
	// gets a chain one certificate shorter than the file declares, and the PFX
	// built from it fails validation obscurely at the consumer instead of here.
	truncated := append(append([]byte{}, certPEM...), []byte("-----BEGIN CERTIFICATE-----\nZm9v\n")...)

	certs, err := convert.ParseCertChain(truncated)
	if err == nil {
		t.Fatalf("convert.ParseCertChain(cert + unterminated armour) = %d certs, nil error; want a malformed-chain error", len(certs))
	}
	if !strings.Contains(err.Error(), "decoded 1 of 2 declared") {
		t.Errorf("convert.ParseCertChain(cert + unterminated armour) error = %q, want it to report %q",
			err.Error(), "decoded 1 of 2 declared")
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

func TestParseCertChain_key_only_input_reports_the_skipped_blocks(t *testing.T) {
	t.Parallel()
	_, keyPEM := testcerts.GenerateSelfSignedCert(t, "key-only", "ecdsa")

	// A key-only file declares no CERTIFICATE block, so the declared-count check
	// passes and the "no certificate" error must name how many PEM blocks were
	// skipped: that count is what tells the operator the .crt holds the key.
	_, err := convert.ParseCertChain(keyPEM)
	if err == nil {
		t.Fatal("convert.ParseCertChain(key-only PEM) = nil error, want error")
	}
	if !strings.Contains(err.Error(), "skipped 1 non-certificate PEM block(s)") {
		t.Errorf("convert.ParseCertChain(key-only PEM) error = %q, want it to contain %q",
			err.Error(), "skipped 1 non-certificate PEM block(s)")
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

	t.Run("refuses a parent-directory traversal in rel", func(t *testing.T) {
		t.Parallel()
		// The other half of the confinement contract: the read must not escape
		// through a ".." component either, which is why the open goes through
		// the *os.Root instead of filepath.Join + os.Open.
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "secret.pem"), []byte("top secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		dir, err := os.MkdirTemp(outside, "watched")
		if err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()

		data, err := convert.ReadBoundedFromRoot(t.Context(), root, "../secret.pem", 1024)
		if err == nil {
			t.Fatalf("convert.ReadBoundedFromRoot(%q) read %d bytes; want a confinement error", "../secret.pem", len(data))
		}
		if bytes.Contains(data, []byte("top secret")) {
			t.Error("convert.ReadBoundedFromRoot returned content from outside the root")
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

// TestPairInRoot_names_the_matching_certificate_for_a_leaf_last_chain pins the
// leaf-last chain diagnosis: when a LATER certificate in the chain matches the
// private key, the mismatch error keeps the base sentence as its prefix (existing
// log matching depends on it) and additionally names the position and subject of
// the certificate that does match. An unrelated key, where no certificate in the
// chain matches, must get the base sentence alone and no leaf-last claim.
func TestPairInRoot_names_the_matching_certificate_for_a_leaf_last_chain(t *testing.T) {
	t.Parallel()
	leafPEM, keyPEM, caPEM, _ := testcerts.GenerateCertChain(t)
	_, otherKeyPEM := testcerts.GenerateSelfSignedCert(t, "unrelated.example.com", "ecdsa")

	leafLast := append(append([]byte{}, caPEM...), leafPEM...)

	for _, tc := range []struct {
		name       string
		certPEM    []byte
		keyPEM     []byte
		wantInErr  []string
		notInError string
	}{
		{
			name:      "leaf-last chain names the certificate that does match",
			certPEM:   leafLast,
			keyPEM:    keyPEM,
			wantInErr: []string{"does not match the private key", "certificate 2 of 2", "leaf.example.com", "ordered leaf-last"},
		},
		{
			name:       "an unrelated key gets the plain mismatch error",
			certPEM:    leafLast,
			keyPEM:     otherKeyPEM,
			wantInErr:  []string{"does not match the private key"},
			notInError: "leaf-last",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			defer root.Close()

			err = convert.PairInRoot(t.Context(), tc.certPEM, tc.keyPEM, root, "out.pfx", "pw", convert.EncNameModern2023)
			if err == nil {
				t.Fatal("convert.PairInRoot(mismatched leaf) = nil error, want a mismatch error")
			}
			for _, want := range tc.wantInErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("convert.PairInRoot error = %q, want it to contain %q", err.Error(), want)
				}
			}
			if tc.notInError != "" && strings.Contains(err.Error(), tc.notInError) {
				t.Errorf("convert.PairInRoot error = %q, want it NOT to contain %q", err.Error(), tc.notInError)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "out.pfx")); statErr == nil {
				t.Error("convert.PairInRoot wrote a pfx for a mismatched pair; want no file written")
			}
		})
	}
}

// TestParseCertChain_counts_declarations_the_way_pem_recognises_them pins the
// line-normalisation half of the declared-block guard: a marker declares a block
// only when it occupies a complete line the way encoding/pem's getLine reads one,
// so CRLF armour and a marker line padded with trailing spaces or tabs must parse
// as a valid single-certificate chain, while a doubled carriage return, a
// carriage return followed by a space, and an indented marker must not be counted
// as declarations. The one deliberate divergence from getLine is also pinned: an
// unterminated final marker line still counts, so a truncated chain is reported
// rather than silently ignored.
func TestParseCertChain_counts_declarations_the_way_pem_recognises_them(t *testing.T) {
	t.Parallel()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "line-endings", "ecdsa")
	crlfPEM := bytes.ReplaceAll(certPEM, []byte("\n"), []byte("\r\n"))
	spacedPEM := bytes.Replace(certPEM,
		[]byte("-----BEGIN CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE----- \t \n"), 1)

	accepted := map[string][]byte{
		"CRLF armour counts as one declaration":            crlfPEM,
		"trailing spaces and tabs are stripped":            spacedPEM,
		"a doubled carriage return is no declaration":      append(append([]byte{}, certPEM...), []byte("-----BEGIN CERTIFICATE-----\r\r\n")...),
		"a carriage return then a space is no declaration": append(append([]byte{}, certPEM...), []byte("-----BEGIN CERTIFICATE-----\r \n")...),
		"an indented marker is no declaration":             append(append([]byte{}, certPEM...), []byte("  -----BEGIN CERTIFICATE-----\n")...),
	}
	for name, in := range accepted {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			certs, err := convert.ParseCertChain(in)
			if err != nil {
				t.Fatalf("convert.ParseCertChain(%s) = error %v, want nil", name, err)
			}
			if len(certs) != 1 {
				t.Fatalf("convert.ParseCertChain(%s) returned %d certs, want 1", name, len(certs))
			}
			if certs[0].Subject.CommonName != "line-endings" {
				t.Errorf("convert.ParseCertChain(%s) CN = %q, want %q", name, certs[0].Subject.CommonName, "line-endings")
			}
		})
	}

	rejected := map[string][]byte{
		"unterminated final marker":                 append(append([]byte{}, certPEM...), []byte("-----BEGIN CERTIFICATE-----")...),
		"unterminated final marker with a CR":       append(append([]byte{}, certPEM...), []byte("-----BEGIN CERTIFICATE-----\r")...),
		"unterminated CRLF marker after CRLF chain": append(append([]byte{}, crlfPEM...), []byte("-----BEGIN CERTIFICATE-----\r\n")...),
	}
	for name, in := range rejected {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			certs, err := convert.ParseCertChain(in)
			if err == nil {
				t.Fatalf("convert.ParseCertChain(%s) = %d certs, nil error; want a malformed-chain error", name, len(certs))
			}
			if !strings.Contains(err.Error(), "decoded 1 of 2 declared") {
				t.Errorf("convert.ParseCertChain(%s) error = %q, want it to report %q", name, err.Error(), "decoded 1 of 2 declared")
			}
		})
	}
}

// TestParsePrivateKey_recovers_from_an_unusable_first_key_block pins the
// documented multi-block contract: block selection and DER validation share one
// loop, so a key file whose first key-labelled block is unusable (malformed DER,
// an unsupported PKCS#8 key type, or encryption headers) must still yield the
// usable key from a later block, and the first parse failure must be reported
// only when no block decodes.
func TestParsePrivateKey_recovers_from_an_unusable_first_key_block(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	usable := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	malformed := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("this is not valid DER")})
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("opaque-ciphertext")})

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"malformed block before a usable key", append(append([]byte{}, malformed...), usable...)},
		{"encrypted block before a usable key", append(append([]byte{}, encrypted...), usable...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key, keyErr := convert.ParsePrivateKey(tc.in)
			if keyErr != nil {
				t.Fatalf("convert.ParsePrivateKey(%s) = error %v, want the usable later key", tc.name, keyErr)
			}
			parsed, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("convert.ParsePrivateKey(%s) returned %T, want *ecdsa.PrivateKey", tc.name, key)
			}
			if !parsed.Equal(ecKey) {
				t.Errorf("convert.ParsePrivateKey(%s) returned a different key than the usable block held", tc.name)
			}
		})
	}
}

// TestParsePrivateKey_reports_the_most_specific_reason pins the documented
// precedence of the no-usable-key diagnosis: a DER parse failure outranks "every
// key block was encrypted", which outranks "there were PEM blocks, none a key".
func TestParsePrivateKey_reports_the_most_specific_reason(t *testing.T) {
	t.Parallel()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "precedence", "ecdsa")
	malformed := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("this is not valid DER")})
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("opaque-ciphertext")})

	for _, tc := range []struct {
		name    string
		in      []byte
		wantErr string
	}{
		{
			name:    "a parse failure outranks an encrypted block",
			in:      append(append([]byte{}, malformed...), encrypted...),
			wantErr: "failed to parse private key",
		},
		{
			name:    "an encrypted block outranks a skipped certificate",
			in:      append(append([]byte{}, certPEM...), encrypted...),
			wantErr: "encrypted",
		},
		{
			name:    "a skipped certificate is named when nothing else applies",
			in:      certPEM,
			wantErr: "skipped 1 PEM block(s)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := convert.ParsePrivateKey(tc.in)
			if err == nil {
				t.Fatalf("convert.ParsePrivateKey(%s) = nil error, want %q", tc.name, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("convert.ParsePrivateKey(%s) error = %q, want it to contain %q", tc.name, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestParsePrivateKey_a_non_encryption_pem_header_still_parses pins the negative
// half of the encrypted-block detection: only "Proc-Type: 4,ENCRYPTED" and a
// NON-EMPTY DEK-Info mark ciphertext, so an RFC 1421 header carrying any other
// Proc-Type value (MIC-ONLY, CRL) or an empty DEK-Info must leave the block
// parseable and yield the key it actually holds, not the
// "decrypt it before use" diagnosis.
func TestParsePrivateKey_a_non_encryption_pem_header_still_parses(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	for name, headers := range map[string]map[string]string{
		"Proc-Type 4,MIC-ONLY": {"Proc-Type": "4,MIC-ONLY"},
		"Proc-Type 4,CRL":      {"Proc-Type": "4,CRL"},
		"empty DEK-Info value": {"DEK-Info": ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: headers, Bytes: ecDER})
			key, keyErr := convert.ParsePrivateKey(keyPEM)
			if keyErr != nil {
				t.Fatalf("convert.ParsePrivateKey(%s) = error %v, want the key the block holds", name, keyErr)
			}
			parsed, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("convert.ParsePrivateKey(%s) returned %T, want *ecdsa.PrivateKey", name, key)
			}
			if !parsed.Equal(ecKey) {
				t.Errorf("convert.ParsePrivateKey(%s) returned a different key than the block held", name)
			}
		})
	}
}

// TestPairInRoot_rejects_a_certificate_whose_public_key_type_is_unverifiable pins
// the supported=false half of the leaf/key correspondence check: crypto/x509
// leaves Certificate.PublicKey nil for an SPKI algorithm OID it does not
// recognise, so no Equal(crypto.PublicKey) method is available and the pair
// cannot be verified either way. Such a pair must be rejected as unverifiable --
// never silently treated as a match and encoded into a PFX, and never reported as
// a plain mismatch, which would send the operator after the wrong file -- and no
// file may be written.
func TestPairInRoot_rejects_a_certificate_whose_public_key_type_is_unverifiable(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "unverifiable", "ecdsa")
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("setup: the generated certificate PEM did not decode")
	}
	// id-ecPublicKey (1.2.840.10045.2.1) as DER, with its final arc bumped to an
	// unassigned value so crypto/x509 reports UnknownPublicKeyAlgorithm and leaves
	// PublicKey nil. ParseCertificate does not verify the signature, so patching
	// the SPKI OID in place is enough to build the input.
	ecPublicKeyOID := []byte{0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}
	unknownOID := []byte{0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x09}
	if n := bytes.Count(block.Bytes, ecPublicKeyOID); n != 1 {
		t.Fatalf("setup: found %d id-ecPublicKey OIDs in the certificate DER, want exactly 1", n)
	}
	patched := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: bytes.Replace(block.Bytes, ecPublicKeyOID, unknownOID, 1),
	})
	patchedBlock, _ := pem.Decode(patched)
	parsed, err := x509.ParseCertificate(patchedBlock.Bytes)
	if err != nil {
		t.Fatalf("setup: x509.ParseCertificate(patched cert) = error %v, want nil", err)
	}
	if parsed.PublicKey != nil {
		t.Fatalf("setup: patched certificate still carries a %T public key; the OID patch no longer yields an unknown algorithm", parsed.PublicKey)
	}

	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()

	err = convert.PairInRoot(t.Context(), patched, keyPEM, root, "out.pfx", "pw", convert.EncNameModern2023)
	if err == nil {
		t.Fatal("convert.PairInRoot(certificate with an unknown public key algorithm) = nil error, want an unverifiable-key-type error")
	}
	if !strings.Contains(err.Error(), "cannot be verified against the private key") {
		t.Errorf("convert.PairInRoot error = %q, want it to report the public key type as unverifiable", err.Error())
	}
	if strings.Contains(err.Error(), "does not match the private key") {
		t.Errorf("convert.PairInRoot error = %q, want the unverifiable-type error, not the plain mismatch error", err.Error())
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.pfx")); statErr == nil {
		t.Error("convert.PairInRoot wrote a pfx for an unverifiable pair; want no file written")
	}
}

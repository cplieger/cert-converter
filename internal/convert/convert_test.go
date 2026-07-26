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
		bulk := func(n int) []byte {
			var out []byte
			for range n {
				out = append(out, certPEM...)
			}
			return out
		}
		// At the bound the chain still parses: the limit exists to keep Analyse's
		// superlinear graph work bounded, not to reject a large-but-plausible chain.
		certs, err := convert.ParseCertChain(bulk(64))
		if err != nil {
			t.Fatalf("convert.ParseCertChain(64 blocks): %v", err)
		}
		if len(certs) != 64 {
			t.Errorf("got %d certs, want 64", len(certs))
		}
		// Past the bound the file is refused before any DER work: one 10 MB input
		// can otherwise declare ~19,000 certificates and spend hours of CPU in the
		// all-pairs candidate graph on the scan's only goroutine.
		if _, err := convert.ParseCertChain(bulk(100)); err == nil {
			t.Error("convert.ParseCertChain(100 blocks) = nil error, want a refusal past the block bound")
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

// TestConvertPair_round_trips_chain_for_every_encoder_profile pins the four PFX
// encoding profiles PFX_ENCODER can select and the CA-chain handling: each
// profile must produce a PKCS#12 file that decodes back to the same leaf AND
// the same CA chain, at mode 0600.
func TestConvertPair_round_trips_chain_for_every_encoder_profile(t *testing.T) {
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
			if _, err := convertPairInRoot(t.Context(), chainPEM, keyPEM, root, rel, "pw", enc); err != nil {
				t.Fatalf("convertPairInRoot(%s) = error %v, want nil", name, err)
			}
			info, err := os.Stat(destPath)
			if err != nil {
				t.Fatalf("convertPairInRoot(%s) did not write a file: %v", name, err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("convertPairInRoot(%s) wrote mode %o, want 600", name, perm)
			}
			pfxData, err := os.ReadFile(destPath)
			if err != nil {
				t.Fatalf("read pfx written by convertPairInRoot(%s): %v", name, err)
			}
			_, leaf, cas, err := pkcs12.DecodeChain(pfxData, "pw")
			if err != nil {
				t.Fatalf("decode pfx written by convertPairInRoot(%s): %v", name, err)
			}
			if leaf.Subject.CommonName != "leaf.example.com" {
				t.Errorf("convertPairInRoot(%s) leaf CN = %q, want %q", name, leaf.Subject.CommonName, "leaf.example.com")
			}
			if len(cas) != 1 {
				t.Fatalf("convertPairInRoot(%s) round-tripped %d CA certs, want 1", name, len(cas))
			}
			if cas[0].Subject.CommonName != "Test CA" {
				t.Errorf("convertPairInRoot(%s) CA CN = %q, want %q", name, cas[0].Subject.CommonName, "Test CA")
			}
		})
	}
}

// TestConvertPair_confines_the_write_to_the_output_root pins the guarantee of
// item h-f8 on the path production actually takes: the confined write must
// produce a decodable 0600 PFX, and a symlinked subdirectory under the output
// root must not redirect the private-key-bearing PFX outside it.
func TestConvertPair_confines_the_write_to_the_output_root(t *testing.T) {
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
		if _, err := convertPairInRoot(t.Context(), certPEM, keyPEM, root, "out.pfx", "pw", convert.EncNameModern2023); err != nil {
			t.Fatalf("convertPairInRoot = error %v, want nil", err)
		}
		info, statErr := os.Stat(filepath.Join(dir, "out.pfx"))
		if statErr != nil {
			t.Fatalf("convertPairInRoot did not write a file: %v", statErr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("convertPairInRoot wrote mode %o, want 600", perm)
		}
		pfxData, readErr := os.ReadFile(filepath.Join(dir, "out.pfx"))
		if readErr != nil {
			t.Fatalf("read pfx written by convertPairInRoot: %v", readErr)
		}
		_, leaf, _, decErr := pkcs12.DecodeChain(pfxData, "pw")
		if decErr != nil {
			t.Fatalf("decode pfx written by convertPairInRoot: %v", decErr)
		}
		if leaf.Subject.CommonName != "confined" {
			t.Errorf("convertPairInRoot leaf CN = %q, want %q", leaf.Subject.CommonName, "confined")
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

		_, writeErr := convertPairInRoot(t.Context(), certPEM, keyPEM, root, "escape/out.pfx", "pw", convert.EncNameModern2023)
		if _, statErr := os.Stat(filepath.Join(outside, "out.pfx")); statErr == nil {
			t.Error("convertPairInRoot wrote the PFX outside the output root through a symlinked subdirectory")
		}
		if writeErr == nil {
			t.Error("convertPairInRoot(symlinked subdirectory) = nil error, want a confinement error")
		}
	})
}

// TestConvertPair_names_the_matching_certificate_for_a_leaf_last_chain pins the
// leaf-last chain diagnosis: when a LATER certificate in the chain matches the
// private key, the mismatch error keeps the base sentence as its prefix (existing
// log matching depends on it) and additionally names the position and subject of
// the certificate that does match. An unrelated key, where no certificate in the
// chain matches, must get the base sentence alone and no leaf-last claim.
// TestConvertPair_resolves_a_leaf_last_chain_structurally pins the behaviour that
// replaced the old leaf-last DIAGNOSTIC. Identity selection is key-first, so the
// certificate the private key matches is the identity wherever it sits in the
// file: a bundle pasted root-first now converts correctly instead of failing with
// remediation advice, and the reordering is reported as an observation rather
// than an error. The emitted bundle must still be leaf-first, because PKCS#12
// stores an ordered bag sequence and decoders (go-pkcs12's own included) read the
// first certificate as the leaf.
//
// An unrelated key, where no certificate matches, still fails — and now says
// exactly what was examined instead of claiming the chain is misordered.
func TestConvertPair_resolves_a_leaf_last_chain_structurally(t *testing.T) {
	t.Parallel()
	leafPEM, keyPEM, caPEM, _ := testcerts.GenerateCertChain(t)
	_, otherKeyPEM := testcerts.GenerateSelfSignedCert(t, "unrelated.example.com", "ecdsa")

	leafLast := append(append([]byte{}, caPEM...), leafPEM...)

	t.Run("a leaf-last chain converts and reports the reordering", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatalf("setup: os.OpenRoot: %v", err)
		}
		defer root.Close()

		obs, err := convertPairInRoot(t.Context(), leafLast, keyPEM, root, "out.pfx", "pw", convert.EncNameModern2023)
		if err != nil {
			t.Fatalf("convertPairInRoot(leaf-last chain) = error %v, want nil: the key identifies the leaf regardless of position", err)
		}

		pfxData, err := os.ReadFile(filepath.Join(dir, "out.pfx"))
		if err != nil {
			t.Fatalf("read pfx: %v", err)
		}
		_, leaf, cas, err := pkcs12.DecodeChain(pfxData, "pw")
		if err != nil {
			t.Fatalf("decode pfx: %v", err)
		}
		// DecodeChain treats the FIRST bag as the leaf, so this assertion is also
		// what proves the emitted order was repaired, not merely accepted.
		if leaf.Subject.CommonName != "leaf.example.com" {
			t.Errorf("round-tripped leaf CN = %q, want %q: the bundle was not emitted leaf-first", leaf.Subject.CommonName, "leaf.example.com")
		}
		if len(cas) != 1 {
			t.Fatalf("round-tripped %d CA certs, want 1", len(cas))
		}
		if cas[0].Subject.CommonName != "Test CA" {
			t.Errorf("round-tripped CA CN = %q, want %q", cas[0].Subject.CommonName, "Test CA")
		}

		if !hasObservation(obs, convert.ObsLeafNotFirst) {
			t.Errorf("observations = %v, want one of kind %q", obs, convert.ObsLeafNotFirst)
		}
	})

	t.Run("an unrelated key reports what was examined", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatalf("setup: os.OpenRoot: %v", err)
		}
		defer root.Close()

		_, err = convertPairInRoot(t.Context(), leafLast, otherKeyPEM, root, "out.pfx", "pw", convert.EncNameModern2023)
		if err == nil {
			t.Fatal("convertPairInRoot(unrelated key) = nil error, want a no-match error")
		}
		got := err.Error()
		for _, want := range []string{"none of the 1 private key block(s)", "2 certificate(s)"} {
			if !strings.Contains(got, want) {
				t.Errorf("error = %q, want it to contain %q", got, want)
			}
		}
		// The old code guessed "the chain is ordered leaf-last" from any later
		// match. Nothing may claim an ordering conclusion it did not measure.
		if strings.Contains(got, "leaf-last") {
			t.Errorf("error = %q, want no leaf-last claim for a key that matches nothing", got)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "out.pfx")); statErr == nil {
			t.Error("convertPairInRoot wrote a pfx for a pair with no matching certificate; want no file written")
		}
	})
}

// hasObservation reports whether obs contains one of kind k.
func hasObservation(obs []convert.Observation, k convert.ObservationKind) bool {
	for _, o := range obs {
		if o.Kind == k {
			return true
		}
	}
	return false
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

// TestConvertPair_rejects_a_certificate_whose_public_key_type_is_unverifiable pins
// the supported=false half of the leaf/key correspondence check: crypto/x509
// leaves Certificate.PublicKey nil for an SPKI algorithm OID it does not
// recognise, so no Equal(crypto.PublicKey) method is available and the pair
// cannot be verified either way. Such a pair must be rejected as unverifiable --
// never silently treated as a match and encoded into a PFX, and never reported as
// a plain mismatch, which would send the operator after the wrong file -- and no
// file may be written.
func TestConvertPair_rejects_a_certificate_whose_public_key_type_is_unverifiable(t *testing.T) {
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

	_, err = convertPairInRoot(t.Context(), patched, keyPEM, root, "out.pfx", "pw", convert.EncNameModern2023)
	if err == nil {
		t.Fatal("convertPairInRoot(certificate with an unknown public key algorithm) = nil error, want an unverifiable-key-type error")
	}
	if !strings.Contains(err.Error(), "cannot be verified against the private key") {
		t.Errorf("convertPairInRoot error = %q, want it to report the public key type as unverifiable", err.Error())
	}
	if strings.Contains(err.Error(), "does not match the private key") {
		t.Errorf("convertPairInRoot error = %q, want the unverifiable-type error, not the plain mismatch error", err.Error())
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.pfx")); statErr == nil {
		t.Error("convertPairInRoot wrote a pfx for an unverifiable pair; want no file written")
	}
}

// TestInspectPasswordEncoding_classifies_all_unencodable_shapes pins the
// single home of the PKCS#12 UCS-2 password rule that both the conversion gate
// (toPFXInRoot) and the config startup diagnostic consume. The shapes are
// independent: invalid UTF-8 loses entropy silently, a non-BMP rune makes every
// Encode call fail, an interior NUL makes the generated PFX unopenable by any
// consumer that builds the NUL-terminated BMPString itself, and a password can
// carry several at once.
func TestInspectPasswordEncoding_classifies_all_unencodable_shapes(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		password        string
		wantInvalidUTF8 bool
		wantNonBMP      bool
		wantEmbeddedNUL bool
	}{
		"empty":               {password: ""},
		"plain ASCII":         {password: "correct-horse"},
		"BMP non-ASCII":       {password: "pässwörd-Ω"},
		"invalid UTF-8":       {password: string([]byte{0xff, 0xfe}) + "tail", wantInvalidUTF8: true},
		"non-BMP":             {password: "pw-\U0001F600", wantNonBMP: true},
		"invalid UTF-8 + BMP": {password: string([]byte{0x80}) + "pw", wantInvalidUTF8: true},
		"invalid UTF-8 + emoji": {
			password:        string([]byte{0xff}) + "pw-\U0001F600",
			wantInvalidUTF8: true,
			wantNonBMP:      true,
		},
		"interior NUL":      {password: "s3cret\x00", wantEmbeddedNUL: true},
		"NUL padded UTF-16": {password: "s\x00e\x00c\x00", wantEmbeddedNUL: true},
		"NUL + non-BMP": {
			password:        "pw\x00-\U0001F600",
			wantNonBMP:      true,
			wantEmbeddedNUL: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := convert.InspectPasswordEncoding(tc.password)
			want := convert.PasswordEncodingIssues{
				InvalidUTF8: tc.wantInvalidUTF8,
				NonBMP:      tc.wantNonBMP,
				EmbeddedNUL: tc.wantEmbeddedNUL,
			}
			if got != want {
				t.Errorf("convert.InspectPasswordEncoding(%q) = %+v, want %+v", tc.password, got, want)
			}
		})
	}
}

// TestParsePrivateKey_reports_truncated_declared_armour pins the
// undecoded-key-block arm of the failure message: a file that declares a
// private-key block encoding/pem silently drops must be diagnosed as damaged
// armour, not as holding no key at all.
func TestParsePrivateKey_reports_truncated_declared_armour(t *testing.T) {
	t.Parallel()
	truncated := []byte("-----BEGIN PRIVATE KEY-----\nZm9v\n")

	_, err := convert.ParsePrivateKey(truncated)
	if err == nil {
		t.Fatal("convert.ParsePrivateKey(truncated declared key) = nil error, want a damaged-armour error")
	}
	want := "declares 1 private-key PEM block(s) that could not be decoded"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("convert.ParsePrivateKey(truncated declared key) error = %q, want it to contain %q", err.Error(), want)
	}
}

// TestConvertPair_rejects_password_outside_BMP_without_writing pins the app-owned
// non-BMP password guard: the rejection must carry the actionable BMP
// constraint, must not echo the secret character, and must happen before any
// PFX is written.
func TestConvertPair_rejects_password_outside_BMP_without_writing(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "non-bmp-password", "ecdsa")
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()

	const password = "safe-\U0001F642-suffix"
	_, err = convertPairInRoot(t.Context(), certPEM, keyPEM, root, "out.pfx", password, convert.EncNameModern2023)
	if err == nil {
		t.Fatal("convertPairInRoot(non-BMP password) = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "outside the Basic Multilingual Plane") {
		t.Errorf("convertPairInRoot(non-BMP password) error = %q, want an actionable BMP constraint", err.Error())
	}
	if strings.Contains(err.Error(), "\U0001F642") {
		t.Errorf("convertPairInRoot(non-BMP password) error = %q, want the secret character omitted", err.Error())
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.pfx")); statErr == nil {
		t.Error("convertPairInRoot(non-BMP password) wrote a PFX; want no file")
	}
}

// TestConvertPair_bounds_the_certificate_subject_it_names pins the log-hygiene
// rule for certificate-controlled text. A subject comes out of a PEM file the app
// does not control and is capped only by the 10 MB input read bound
// internal/process applies, so it must be truncated
// before it reaches anything logged, and the cut must fall on a rune boundary so
// the %q form stays readable.
//
// The vehicle is the excluded-extras observation, which is where subjects now
// flow: identity selection is structural, so a certificate that is not an
// ancestor of the leaf is EXCLUDED from the bundle and named in an observation
// rather than silently embedded. That doubles as the regression test for the
// former `caCerts = chain[1:]` behaviour, which put every certificate after
// position 0 into the PFX whether or not it belonged to the chain.
func TestConvertPair_bounds_the_certificate_subject_it_names(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		extraCN       string
		wantNotInErr  string
		wantNoEscapes bool
	}{
		{
			name:         "an oversized subject is truncated before it reaches the log",
			extraCN:      strings.Repeat("a", 300) + ".tail-marker.example.com",
			wantNotInErr: "tail-marker",
		},
		{
			name:          "a multi-byte subject is cut on a rune boundary",
			extraCN:       strings.Repeat("é", 200),
			wantNoEscapes: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			identityCertPEM, identityKeyPEM := testcerts.GenerateSelfSignedCert(t, "identity.example.com", "ecdsa")
			extraCertPEM, _ := testcerts.GenerateSelfSignedCert(t, tc.extraCN, "ecdsa")
			bundle := append(append([]byte{}, identityCertPEM...), extraCertPEM...)

			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			defer root.Close()

			obs, err := convertPairInRoot(t.Context(), bundle, identityKeyPEM, root, "out.pfx", "pw", convert.EncNameModern2023)
			if err != nil {
				t.Fatalf("convertPairInRoot(bundle with an unrelated extra cert) = error %v, want nil: the extra is excluded, not fatal", err)
			}

			var detail string
			for _, o := range obs {
				if o.Kind == convert.ObsExtraCertsExcluded {
					detail = o.Detail
				}
			}
			if detail == "" {
				t.Fatalf("observations = %v, want one of kind %q naming the excluded certificate", obs, convert.ObsExtraCertsExcluded)
			}
			if !strings.Contains(detail, "...(truncated)") {
				t.Errorf("observation detail = %q, want the oversized subject marked as truncated", detail)
			}
			if len(detail) > 600 {
				t.Errorf("observation detail is %d bytes, want a bounded diagnostic (the subject is capped at 256 bytes)", len(detail))
			}
			if tc.wantNotInErr != "" && strings.Contains(detail, tc.wantNotInErr) {
				t.Errorf("observation detail = %q, want it NOT to contain %q from beyond the subject cap", detail, tc.wantNotInErr)
			}
			if tc.wantNoEscapes && strings.Contains(detail, `\x`) {
				t.Errorf("observation detail = %q, want no escaped partial rune: the cut must drop it", detail)
			}

			// The unrelated certificate must not reach the bundle: embedding it
			// would pollute the trust chain the consumer sees.
			pfxData, err := os.ReadFile(filepath.Join(dir, "out.pfx"))
			if err != nil {
				t.Fatalf("read pfx: %v", err)
			}
			_, leaf, cas, err := pkcs12.DecodeChain(pfxData, "pw")
			if err != nil {
				t.Fatalf("decode pfx: %v", err)
			}
			if leaf.Subject.CommonName != "identity.example.com" {
				t.Errorf("round-tripped leaf CN = %q, want %q", leaf.Subject.CommonName, "identity.example.com")
			}
			if len(cas) != 0 {
				t.Errorf("round-tripped %d CA cert(s), want 0: an unrelated certificate must be excluded, not embedded", len(cas))
			}
		})
	}
}

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
		// all-pairs candidate graph on the scan's only goroutine. One block past the
		// bound is the case that pins the limit to 64 rather than to a range, and the
		// message must name the number, because that is where an operator learns it.
		boundErr := func() error {
			_, err := convert.ParseCertChain(bulk(65))
			return err
		}()
		if boundErr == nil {
			t.Fatal("convert.ParseCertChain(65 blocks) = nil error, want a refusal one block past the bound")
		}
		if !strings.Contains(boundErr.Error(), "more than the 64 this app converts") {
			t.Errorf("convert.ParseCertChain(65 blocks) error = %q, want it to name the 64-block limit", boundErr.Error())
		}
	})
}

// TestParseCertChain_names_which_block_holds_the_corrupt_DER pins the block number
// in the chain-rejecting diagnostic. parseCertChain refuses the whole file rather
// than truncating it, so that number is the only thing telling an operator WHICH
// certificate in a bundle to replace; an off-by-one sends them to the wrong one and
// nothing else in the package would notice.
func TestParseCertChain_names_which_block_holds_the_corrupt_DER(t *testing.T) {
	t.Parallel()
	goodPEM, _ := testcerts.GenerateSelfSignedCert(t, "block-index", "ecdsa")
	corrupt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("this is not valid DER")})

	for _, tc := range []struct {
		name string
		in   []byte
		want string
	}{
		{"the first block is corrupt", append(bytes.Clone(corrupt), goodPEM...), "certificate PEM block 1:"},
		{"the second block is corrupt", append(bytes.Clone(goodPEM), corrupt...), "certificate PEM block 2:"},
		{"the third block is corrupt", append(append(bytes.Clone(goodPEM), goodPEM...), corrupt...), "certificate PEM block 3:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := convert.ParseCertChain(tc.in)
			if err == nil {
				t.Fatalf("convert.ParseCertChain(%s) = nil error, want the chain refused", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("convert.ParseCertChain(%s) error = %q, want it to contain %q", tc.name, err.Error(), tc.want)
			}
		})
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
}

// TestParsePrivateKey_bounds_the_declared_key_blocks pins the key-side half of
// the declaration bound. At the bound the file still parses; past it the file is
// refused before any DER work, because every extra key multiplies identity
// matching against every certificate in the chain.
func TestParsePrivateKey_bounds_the_declared_key_blocks(t *testing.T) {
	t.Parallel()
	_, keyPEM := testcerts.GenerateSelfSignedCert(t, "bounded", "ecdsa")
	bulk := func(n int) []byte {
		var out []byte
		for range n {
			out = append(out, keyPEM...)
		}
		return out
	}
	if _, err := convert.ParsePrivateKey(bulk(16)); err != nil {
		t.Fatalf("convert.ParsePrivateKey(16 blocks) = %v, want nil at the bound", err)
	}
	if _, err := convert.ParsePrivateKey(bulk(17)); err == nil {
		t.Error("convert.ParsePrivateKey(17 blocks) = nil error, want a refusal past the block bound")
	}
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

// TestParsePrivateKey_diagnoses_a_malformed_block_with_its_own_parser pins the
// label-specific error selection parsePrivateKeyBlock documents: a malformed
// block labelled "EC PRIVATE KEY" must report the SEC1 parser's failure, never
// the PKCS#8 one, because the PKCS#8 message points an operator at the wrong
// encoding while their file is a damaged SEC1 key.
func TestParsePrivateKey_diagnoses_a_malformed_block_with_its_own_parser(t *testing.T) {
	t.Parallel()
	badEC := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("this is not valid DER")})

	_, err := convert.ParsePrivateKey(badEC)
	if err == nil {
		t.Fatal("convert.ParsePrivateKey(malformed EC PRIVATE KEY block) = nil error, want a parse failure")
	}
	if !strings.Contains(err.Error(), "failed to parse EC private key") {
		t.Errorf("error = %q, want the SEC1 parser's own failure for an EC-labelled block", err.Error())
	}
	if strings.Contains(err.Error(), "pkcs8") {
		t.Errorf("error = %q, want no PKCS#8 diagnosis for an EC-labelled block: it names the wrong encoding", err.Error())
	}
}

// TestParsePrivateKey_diagnoses_a_malformed_RSA_block_with_the_PKCS1_parser is the
// RSA half of the label-specific error selection parsePrivateKeyBlock documents.
// The EC half is pinned above; without this one, reporting the PKCS#8 failure for
// an "RSA PRIVATE KEY" block would send an operator holding a damaged traditional
// OpenSSL key after the wrong encoding, and no test would fail.
func TestParsePrivateKey_diagnoses_a_malformed_RSA_block_with_the_PKCS1_parser(t *testing.T) {
	t.Parallel()
	badRSA := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("this is not valid DER")})

	_, err := convert.ParsePrivateKey(badRSA)
	if err == nil {
		t.Fatal("convert.ParsePrivateKey(malformed RSA PRIVATE KEY block) = nil error, want a parse failure")
	}
	got := err.Error()
	if !strings.Contains(got, "RSA PRIVATE KEY") {
		t.Errorf("error = %q, want it to name the block label it failed on", got)
	}
	// asn1's structure error names the Go type it could not fill, which is what
	// identifies the parser that produced it: pkcs1PrivateKey for PKCS#1.
	if !strings.Contains(got, "pkcs1PrivateKey") {
		t.Errorf("error = %q, want the PKCS#1 parser's own failure for an RSA-labelled block", got)
	}
	if strings.Contains(got, "pkcs8") || strings.Contains(got, "failed to parse EC private key") {
		t.Errorf("error = %q, want no PKCS#8 or SEC1 diagnosis: either names the wrong encoding", got)
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
// the same CA chain. The output file mode is not this package's contract: Encode
// returns bytes, and internal/process owns the confined write and its
// pfxFileMode.
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
		for _, want := range []string{"none of the 1 distinct private key(s) in the key file", "2 certificate(s)"} {
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
// (pair.go's unencodablePasswordError, called by Encode) and the config startup
// diagnostic consume. The shapes are
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
		"empty":         {password: ""},
		"plain ASCII":   {password: "correct-horse"},
		"BMP non-ASCII": {password: "pässwörd-Ω"},
		"invalid UTF-8": {password: string([]byte{0xff, 0xfe}) + "tail", wantInvalidUTF8: true},
		"non-BMP":       {password: "pw-\U0001F600", wantNonBMP: true},
		// The BMP boundary itself. U+FFFF is the last BMP code point, so UCS-2
		// carries it in one code unit and the password is encodable; U+10000 is the
		// first that needs a surrogate pair. Every other non-BMP fixture here is
		// U+1F600, ~125,000 code points past the edge, so an off-by-one in the
		// comparison refuses a legitimate password at startup with nothing failing.
		"at the BMP ceiling":       {password: "pw-\uFFFF"},
		"one past the BMP ceiling": {password: "pw-\U00010000", wantNonBMP: true},
		"invalid UTF-8 + BMP":      {password: string([]byte{0x80}) + "pw", wantInvalidUTF8: true},
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

// TestConvertPair_rejects_unencodable_passwords_without_writing pins the
// app-owned password guard for every shape PKCS#12 cannot carry: the rejection
// must name the shape found so an operator can act, must not echo the secret
// material, and must happen before any PFX is written.
//
// All three matter, not just the non-BMP one go-pkcs12 refuses itself: for
// invalid UTF-8 and an interior NUL the library encodes happily and writes a
// bundle protected by a different password than the one supplied, which is the
// worse outcome — it surfaces at whatever tries to open the bundle instead of
// here.
func TestConvertPair_rejects_unencodable_passwords_without_writing(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "unencodable-password", "ecdsa")

	for name, tc := range map[string]struct {
		password  string
		wantShape string
		wantNotIn string
	}{
		"non-BMP rune": {
			password:  "safe-\U0001F642-suffix",
			wantShape: "outside the Basic Multilingual Plane",
			wantNotIn: "\U0001F642",
		},
		"invalid UTF-8": {
			password:  "safe-" + string([]byte{0xff, 0xfe}) + "-suffix",
			wantShape: "not valid UTF-8",
			wantNotIn: "safe-",
		},
		"embedded NUL": {
			password:  "safe-\x00-suffix",
			wantShape: "contains a NUL byte",
			wantNotIn: "safe-",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			defer root.Close()

			_, err = convertPairInRoot(t.Context(), certPEM, keyPEM, root, "out.pfx", tc.password, convert.EncNameModern2023)
			if err == nil {
				t.Fatalf("convertPairInRoot(%s password) = nil error, want rejection", name)
			}
			if !strings.Contains(err.Error(), tc.wantShape) {
				t.Errorf("convertPairInRoot(%s password) error = %q, want it to name %q", name, err.Error(), tc.wantShape)
			}
			if strings.Contains(err.Error(), tc.wantNotIn) {
				t.Errorf("convertPairInRoot(%s password) error = %q, want the secret material %q omitted",
					name, err.Error(), tc.wantNotIn)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "out.pfx")); statErr == nil {
				t.Errorf("convertPairInRoot(%s password) wrote a PFX; want no file", name)
			}
		})
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

// TestPasswordEncodingIssues_Why_words_every_shape_once pins the wording both
// refusal channels now share: Encode's codec guard and internal/config's startup
// gate each contribute only a prefix or a sentinel, so this is the single place the
// shape's meaning and its remediation are asserted. A password that encodes
// faithfully must return "" (the presence check both callers make).
func TestPasswordEncodingIssues_Why_words_every_shape_once(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		shape           convert.PasswordEncodingIssues
		wantShape       string
		wantRemediation string
	}{
		"invalid UTF-8": {
			shape:           convert.PasswordEncodingIssues{InvalidUTF8: true},
			wantShape:       "not valid UTF-8",
			wantRemediation: "supply a text secret",
		},
		"non-BMP": {
			shape:           convert.PasswordEncodingIssues{NonBMP: true},
			wantShape:       "outside the Basic Multilingual Plane",
			wantRemediation: "choose a password made of BMP characters",
		},
		"embedded NUL": {
			shape:           convert.PasswordEncodingIssues{EmbeddedNUL: true},
			wantShape:       "contains a NUL byte",
			wantRemediation: "strip NUL bytes from the secret",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := tc.shape.Why()
			if !strings.Contains(got, tc.wantShape) || !strings.Contains(got, tc.wantRemediation) {
				t.Errorf("%+v.Why() = %q, want the shape %q and the remediation %q",
					tc.shape, got, tc.wantShape, tc.wantRemediation)
			}
		})
	}

	if got := (convert.PasswordEncodingIssues{}).Why(); got != "" {
		t.Errorf("PasswordEncodesFine.Explain() = %q, want \"\": both callers treat a non-empty result as a refusal", got)
	}
}

// TestParseCertChain_names_the_first_skipped_label_not_the_last pins
// skippedBlocks' documented rule -- keep the FIRST label seen -- which every
// diagnostic built on it words as `first %q`. Nothing asserted it: no existing case
// puts TWO distinct non-certificate labels in one file, so flipping the
// keep-the-first condition to keep-the-last leaves the whole package suite green.
//
// The failure is silent and operator-facing. The message still reads correctly, and it
// is the one thing that tells an operator WHAT the file held when a cert/key pair is
// swapped or an ssh-keygen-format file is mounted, so naming the wrong block sends the
// remedy at the wrong file.
func TestParseCertChain_names_the_first_skipped_label_not_the_last(t *testing.T) {
	t.Parallel()

	certFile := bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("opaque")}),
		pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: []byte("opaque")}),
	}, nil)

	_, err := convert.ParseCertChain(certFile)
	if err == nil {
		t.Fatal("ParseCertChain(two non-certificate blocks) = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), `first "OPENSSH PRIVATE KEY"`) {
		t.Errorf("ParseCertChain error = %q, want it to name the FIRST skipped label", err.Error())
	}
	if strings.Contains(err.Error(), "TRUSTED CERTIFICATE") {
		t.Errorf("ParseCertChain error = %q, want the later label absent from the diagnostic", err.Error())
	}
}

// TestParsePrivateKey_names_the_first_skipped_label_not_the_last is the key-file
// half of the same rule. parsePrivateKeys shares skippedBlocks with parseCertChain, so
// both diagnostics move together, but the two sentences are built separately
// (noPrivateKeyError composes its own) and a reader looking for the key-file contract
// should find it asserted here rather than inferred from the certificate case.
func TestParsePrivateKey_names_the_first_skipped_label_not_the_last(t *testing.T) {
	t.Parallel()

	keyFile := bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("opaque")}),
		pem.EncodeToMemory(&pem.Block{Type: "DH PARAMETERS", Bytes: []byte("opaque")}),
	}, nil)

	_, err := convert.ParsePrivateKey(keyFile)
	if err == nil {
		t.Fatal("ParsePrivateKey(two non-key blocks) = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), `first "OPENSSH PRIVATE KEY"`) {
		t.Errorf("ParsePrivateKey error = %q, want it to name the FIRST skipped label", err.Error())
	}
	if strings.Contains(err.Error(), "DH PARAMETERS") {
		t.Errorf("ParsePrivateKey error = %q, want the later label absent from the diagnostic", err.Error())
	}
}

// TestParsePrivateKey_names_the_unreadable_label_not_an_expected_companion pins the
// preference the failure path applies: the label named is the first one that names NO
// key format this app reads, not simply the first skipped one. It needs a fixture in
// which those two DIFFER, which is why the sibling test above cannot stand in for it
// -- there both blocks are unrelated, so either rule names the same one and reverting
// the preference leaves the suite green.
//
// The scenario is the combined cert+key file this app deliberately supports
// (isExpectedKeyFilePassenger), with an ssh-keygen-format key block appended. The
// CERTIFICATE comes FIRST in every file that has one, so naming the first skipped
// block sends the operator at the one block in the file that is fine.
func TestParsePrivateKey_names_the_unreadable_label_not_an_expected_companion(t *testing.T) {
	t.Parallel()

	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "companion", "ecdsa")
	keyFile := bytes.Join([][]byte{
		certPEM,
		pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("opaque")}),
	}, nil)

	_, err := convert.ParsePrivateKey(keyFile)
	if err == nil {
		t.Fatal("ParsePrivateKey(a certificate plus an ssh-keygen-format block) = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), `first "OPENSSH PRIVATE KEY"`) {
		t.Errorf("ParsePrivateKey error = %q, want it to name the block that names no key format this app reads: the CERTIFICATE is an expected companion of a combined cert+key file and explains nothing", err.Error())
	}
	if strings.Contains(err.Error(), "CERTIFICATE") {
		t.Errorf("ParsePrivateKey error = %q, want the expected companion's label absent: naming it sends the operator at the one block in the file that is fine", err.Error())
	}
	if !strings.Contains(err.Error(), "no private key PEM block found") {
		t.Errorf("ParsePrivateKey error = %q, want the base sentence kept as the prefix so existing log matching is unaffected", err.Error())
	}

	// EC PARAMETERS is the other expected companion, and it comes first for the same
	// reason, so the preference must hold for it too.
	ecFile := bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte("opaque")}),
		pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("opaque")}),
	}, nil)
	_, ecErr := convert.ParsePrivateKey(ecFile)
	if ecErr == nil || !strings.Contains(ecErr.Error(), `first "OPENSSH PRIVATE KEY"`) {
		t.Errorf("ParsePrivateKey(EC PARAMETERS plus an ssh-keygen-format block) = %v, want it to name the OPENSSH block", ecErr)
	}
}

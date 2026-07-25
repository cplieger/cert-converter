package convert_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

	"github.com/cplieger/cert-converter/internal/convert"
	"software.sslmate.com/src/go-pkcs12"
)

func FuzzParseCertChain(f *testing.F) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.Add(validPEM)
	f.Add([]byte("not a pem"))
	// A declaration encoding/pem drops silently (BEGIN line, no END) must be
	// rejected rather than yielding a chain shorter than the file declares.
	f.Add(append(append([]byte{}, validPEM...), []byte("-----BEGIN CERTIFICATE-----\nZm9v\n")...))
	// Prose that merely mentions the marker mid-line is not a declaration, so a
	// valid chain beside it must still parse.
	f.Add(append(append([]byte{}, validPEM...), []byte("see -----BEGIN CERTIFICATE----- above\n")...))
	// Two concatenated certs whose join lost its newline: the run-together
	// "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" line is neither a
	// valid END line nor a declaration, so pem decodes nothing while one
	// declaration is still counted and the declared-count guard rejects the
	// file.
	f.Add(append(append([]byte{}, bytes.TrimRight(validPEM, "\n")...), validPEM...))
	// CRLF armour must count identically to LF armour.
	f.Add(bytes.ReplaceAll(validPEM, []byte("\n"), []byte("\r\n")))

	f.Fuzz(func(t *testing.T, data []byte) {
		certs, err := convert.ParseCertChain(data)
		if err != nil {
			return
		}
		if len(certs) == 0 {
			t.Fatal("no error but zero certs returned")
		}
		var reEncoded []byte
		for i, c := range certs {
			if len(c.Raw) == 0 {
				t.Fatalf("cert[%d].Raw is empty", i)
			}
			// Re-marshal and re-parse to verify structural validity.
			reparsed, err := x509.ParseCertificate(c.Raw)
			if err != nil {
				t.Fatalf("cert[%d] re-parse failed: %v", i, err)
			}
			if !bytes.Equal(reparsed.Raw, c.Raw) {
				t.Fatalf("cert[%d] re-parsed Raw differs", i)
			}
			reEncoded = append(reEncoded, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
		// Chain-level round trip: a chain ParseCertChain accepts must survive
		// its own canonical re-encoding with the same certificates in the same
		// order. This pins the declared-block accounting end to end, which the
		// per-certificate checks above cannot see.
		reParsed, reErr := convert.ParseCertChain(reEncoded)
		if reErr != nil {
			t.Fatalf("re-parse of the re-encoded chain of %d cert(s) failed: %v", len(certs), reErr)
		}
		if len(reParsed) != len(certs) {
			t.Fatalf("re-parsed chain has %d cert(s), want %d", len(reParsed), len(certs))
		}
		for i := range certs {
			if !bytes.Equal(reParsed[i].Raw, certs[i].Raw) {
				t.Fatalf("cert[%d] changed across the chain round trip", i)
			}
		}
	})
}

func FuzzParsePrivateKey(f *testing.F) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8Bytes, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	f.Add(rsaPEM)

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecBytes, _ := x509.MarshalECPrivateKey(ecKey)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecBytes})
	f.Add(ecPEM)

	f.Add([]byte("garbage"))
	// The diagnosis branches the parser grew, kept reachable from the committed
	// corpus: a PKCS#8 encrypted container, a traditional OpenSSL key carrying
	// encryption headers, a malformed block labelled with its own format, and a
	// malformed block followed by a usable key (the later-block recovery path).
	// The weekly fuzz corpus is discarded after every run, so these seeds are the
	// durable reach into those branches.
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("opaque-ciphertext")}))
	f.Add(pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF"},
		Bytes:   []byte("opaque encrypted key material"),
	}))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("this is not valid DER")}))
	f.Add(append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("this is not valid DER")}), ecPEM...))

	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := convert.ParsePrivateKey(data)
		if err != nil {
			return
		}
		// Must implement crypto.Signer.
		if _, ok := key.(crypto.Signer); !ok {
			t.Fatal("key does not implement crypto.Signer")
		}
		// Must be one of the expected types.
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		default:
			t.Fatalf("unexpected key type: %T", key)
		}
	})
}

func FuzzToPFXRoundTrip(f *testing.F) {
	// Seed: valid cert+key PEM concatenation.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "roundtrip"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	f.Add(append(certPEM, keyPEM...))

	// A CA-signed leaf beside its own key: the only seed that reaches the
	// CA-count invariant below, which a self-signed seed leaves at 0 == 0.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "roundtrip CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "roundtrip leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafKeyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	chainSeed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chainSeed = append(chainSeed, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	chainSeed = append(chainSeed, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})...)
	f.Add(chainSeed)

	f.Fuzz(func(t *testing.T, data []byte) {
		certs, certErr := convert.ParseCertChain(data)
		if certErr != nil {
			return
		}
		if _, keyErr := convert.ParsePrivateKey(data); keyErr != nil {
			return
		}

		// Analyse owns identity selection, so the oracle asks IT what the pair is
		// instead of assuming certs[0]. Assuming a position was valid while the
		// production rule was positional; under structural selection it asserted
		// exactly the behaviour the rewrite removed (every certificate after the
		// first embedded in the PFX, chain membership unchecked), so a bundle with
		// an unrelated or duplicated certificate would fail this target for being
		// CORRECT.
		analysis, analyseErr := convert.Analyse(data, data)
		if analyseErr != nil {
			// A parseable certificate and key can still be an unresolvable pair
			// (no key matches, several identities, the key belongs to an issuer).
			// Those are legitimate rejections, not round-trip failures.
			return
		}

		dir := t.TempDir()
		root, rootErr := os.OpenRoot(dir)
		if rootErr != nil {
			t.Fatalf("open root: %v", rootErr)
		}
		defer root.Close()
		dest := filepath.Join(dir, "out.pfx")
		password := "test"

		if _, err := convertPairInRoot(t.Context(), data, data, root, "out.pfx", password, convert.EncNameModern2023); err != nil {
			t.Fatalf("convertPairInRoot rejected a pair Analyse resolved: %v", err)
		}

		pfxData, err := os.ReadFile(dest)
		if err != nil {
			t.Fatalf("read pfx: %v", err)
		}

		decodedKey, decodedLeaf, decodedCAs, err := pkcs12.DecodeChain(pfxData, password)
		if err != nil {
			t.Fatalf("decode pfx: %v", err)
		}

		// Invariant 1: the bundle round-trips the identity Analyse selected, and
		// DecodeChain reads the FIRST bag as the leaf, so this also proves the
		// emitted bag order is leaf-first.
		if !bytes.Equal(decodedLeaf.Raw, analysis.Leaf.Raw) {
			t.Fatal("round-tripped leaf is not the certificate Analyse selected")
		}

		// Invariant 2: the emitted chain is exactly Analyse's chain, in order.
		if len(decodedCAs) != len(analysis.Chain) {
			t.Fatalf("CA count mismatch: got %d, want %d", len(decodedCAs), len(analysis.Chain))
		}
		for i := range analysis.Chain {
			if !bytes.Equal(decodedCAs[i].Raw, analysis.Chain[i].Raw) {
				t.Fatalf("CA certificate %d changed across the PFX round trip", i)
			}
		}

		// Invariant 3: nothing is invented. Every emitted certificate came from
		// the input, and none is the leaf repeated.
		for i, ca := range decodedCAs {
			if bytes.Equal(ca.Raw, decodedLeaf.Raw) {
				t.Fatalf("CA certificate %d is the leaf repeated", i)
			}
			found := false
			for _, in := range certs {
				if bytes.Equal(ca.Raw, in.Raw) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("CA certificate %d is not present in the input", i)
			}
		}

		// Invariant 4: the embedded key is the private half of the embedded leaf,
		// which is the property that makes the bundle usable at all.
		wantKey, err := x509.MarshalPKCS8PrivateKey(analysis.Key)
		if err != nil {
			t.Fatalf("marshal selected private key: %v", err)
		}
		gotKey, err := x509.MarshalPKCS8PrivateKey(decodedKey)
		if err != nil {
			t.Fatalf("marshal decoded private key: %v", err)
		}
		if !bytes.Equal(gotKey, wantKey) {
			t.Fatal("private key changed across the PFX round trip")
		}
	})
}

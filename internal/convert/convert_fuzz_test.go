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
		parsedKey, keyErr := convert.ParsePrivateKey(data)
		if keyErr != nil {
			return
		}
		signer, ok := parsedKey.(crypto.Signer)
		if !ok {
			t.Fatalf("convert.ParsePrivateKey returned %T, want crypto.Signer", parsedKey)
		}
		matcher, ok := certs[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok {
			t.Fatalf("leaf public key %T cannot compare against the parsed private key", certs[0].PublicKey)
		}
		if !matcher.Equal(signer.Public()) {
			return
		}

		leaf := certs[0]
		var caCerts []*x509.Certificate
		if len(certs) > 1 {
			caCerts = certs[1:]
		}

		dir := t.TempDir()
		root, rootErr := os.OpenRoot(dir)
		if rootErr != nil {
			t.Fatalf("open root: %v", rootErr)
		}
		defer root.Close()
		dest := filepath.Join(dir, "out.pfx")
		password := "test"

		if err := convert.PairInRoot(t.Context(), data, data, root, "out.pfx", password, convert.EncNameModern2023); err != nil {
			t.Fatalf("PairInRoot rejected a parseable matching certificate and key: %v", err)
		}

		pfxData, err := os.ReadFile(dest)
		if err != nil {
			t.Fatalf("read pfx: %v", err)
		}

		decodedKey, decodedLeaf, decodedCAs, err := pkcs12.DecodeChain(pfxData, password)
		if err != nil {
			t.Fatalf("decode pfx: %v", err)
		}
		if !bytes.Equal(decodedLeaf.Raw, leaf.Raw) {
			t.Fatal("leaf certificate changed across the PFX round trip")
		}
		if len(decodedCAs) != len(caCerts) {
			t.Fatalf("CA count mismatch: got %d want %d", len(decodedCAs), len(caCerts))
		}
		for i := range caCerts {
			if !bytes.Equal(decodedCAs[i].Raw, caCerts[i].Raw) {
				t.Fatalf("CA certificate %d changed across the PFX round trip", i)
			}
		}
		wantKey, err := x509.MarshalPKCS8PrivateKey(parsedKey)
		if err != nil {
			t.Fatalf("marshal input private key: %v", err)
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

func FuzzReadBoundedFromRoot(f *testing.F) {
	f.Add([]byte("hello"), int64(10))
	f.Add([]byte("hello world"), int64(5))
	f.Add([]byte{}, int64(0))
	f.Add([]byte("x"), int64(1))
	f.Add([]byte("x"), int64(0))
	f.Add(bytes.Repeat([]byte("a"), 4096), int64(4095))

	f.Fuzz(func(t *testing.T, content []byte, limit int64) {
		if limit < 0 {
			limit = 0
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "input"), content, 0o644); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()

		data, err := convert.ReadBoundedFromRoot(t.Context(), root, "input", limit)
		oversized := int64(len(content)) > limit
		if err != nil {
			if !oversized {
				t.Fatalf("ReadBoundedFromRoot(%d bytes, limit %d) = error %v, want nil", len(content), limit, err)
			}
			return
		}
		if oversized {
			t.Fatalf("ReadBoundedFromRoot returned %d bytes for limit %d; want the size cap to reject it", len(data), limit)
		}
		if !bytes.Equal(data, content) {
			t.Fatalf("ReadBoundedFromRoot returned %d bytes that differ from the %d bytes written", len(data), len(content))
		}
	})
}

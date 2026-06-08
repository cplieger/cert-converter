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

	"github.com/cplieger/cert-watcher/internal/convert"
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

	f.Fuzz(func(t *testing.T, data []byte) {
		certs, err := convert.ParseCertChain(data)
		if err != nil {
			return
		}
		if len(certs) == 0 {
			t.Fatal("no error but zero certs returned")
		}
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

	f.Fuzz(func(t *testing.T, data []byte) {
		certs, certErr := convert.ParseCertChain(data)
		if certErr != nil {
			return
		}
		privKey, keyErr := convert.ParsePrivateKey(data)
		if keyErr != nil {
			return
		}

		leaf := certs[0]
		var caCerts []*x509.Certificate
		if len(certs) > 1 {
			caCerts = certs[1:]
		}

		dir := t.TempDir()
		dest := filepath.Join(dir, "out.pfx")
		password := "test"
		enc := pkcs12.Modern2023

		if err := convert.ToPFX(privKey, leaf, caCerts, dest, password, enc); err != nil {
			return // encoding may legitimately fail for mismatched key/cert
		}

		pfxData, err := os.ReadFile(dest)
		if err != nil {
			t.Fatalf("read pfx: %v", err)
		}

		_, decodedLeaf, decodedCAs, err := pkcs12.DecodeChain(pfxData, password)
		if err != nil {
			t.Fatalf("decode pfx: %v", err)
		}
		if decodedLeaf.Subject.CommonName != leaf.Subject.CommonName {
			t.Fatalf("CN mismatch: got %q want %q", decodedLeaf.Subject.CommonName, leaf.Subject.CommonName)
		}
		if len(decodedCAs) != len(caCerts) {
			t.Fatalf("CA count mismatch: got %d want %d", len(decodedCAs), len(caCerts))
		}
	})
}

func FuzzReadFileWithLimit(f *testing.F) {
	f.Add([]byte("hello"), int64(10))
	f.Add([]byte("hello world"), int64(5))
	f.Add([]byte{}, int64(0))
	f.Add([]byte("x"), int64(1))

	f.Fuzz(func(t *testing.T, content []byte, limit int64) {
		if limit < 0 {
			limit = 0
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "input")
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}

		data, err := convert.ReadFileWithLimit(path, limit)
		if err != nil {
			return
		}
		if int64(len(data)) > limit {
			t.Fatalf("returned %d bytes exceeding limit %d", len(data), limit)
		}
	})
}

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
		if _, keyErr := convert.ParsePrivateKey(data); keyErr != nil {
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
			return // parsing, cert/key matching or encoding may legitimately fail
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

package convert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"cert-watcher/internal/convert"
)

func FuzzParseCertChain(f *testing.F) {
	// Valid self-signed cert PEM seed.
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

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = convert.ParseCertChain(data)
	})
}

func FuzzParsePrivateKey(f *testing.F) {
	// RSA PKCS8 seed.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8Bytes, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	f.Add(rsaPEM)

	// EC key seed.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecBytes, _ := x509.MarshalECPrivateKey(ecKey)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecBytes})
	f.Add(ecPEM)

	f.Add([]byte("garbage"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = convert.ParsePrivateKey(data)
	})
}

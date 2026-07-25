// Package testcerts provides shared certificate generation helpers for tests.
package testcerts

import (
	"crypto"
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
)

// FatalTB is the minimal TB surface this helper needs. Satisfied by
// both *testing.T and *rapid.T (which lacks testing.TB methods like
// ArtifactDir, Helper, TempDir, etc.).
type FatalTB interface {
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// pemTypeCert, pemTypeKeyPKCS8 and pemTypeKeyPKCS1 are the PEM block types this
// helper emits: X.509 certificates, PKCS#8 private keys (the ECDSA path) and the
// legacy PKCS#1 RSA private key.
const (
	pemTypeCert     = "CERTIFICATE"
	pemTypeKeyPKCS8 = "PRIVATE KEY"
	pemTypeKeyPKCS1 = "RSA PRIVATE KEY"
)

// signCert signs template with parent (parent == template yields a self-signed
// certificate) and returns both the DER bytes and the PEM encoding.
func signCert(tb FatalTB, template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) (der, pemBytes []byte) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		tb.Fatal(err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: der})
}

// GenerateSelfSignedCert creates a self-signed certificate with the given
// key type ("rsa" or "ecdsa") and common name. Returns PEM-encoded cert and key.
func GenerateSelfSignedCert(tb FatalTB, cn, keyType string) (certPEM, keyPEM []byte) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	switch keyType {
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
		_, certPEM = signCert(tb, template, template, &key.PublicKey, key)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			tb.Fatal(err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: pemTypeKeyPKCS8, Bytes: keyDER})

	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			tb.Fatal(err)
		}
		_, certPEM = signCert(tb, template, template, &key.PublicKey, key)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: pemTypeKeyPKCS1, Bytes: x509.MarshalPKCS1PrivateKey(key)})

	default:
		tb.Fatalf("unsupported key type: %s", keyType)
	}

	return certPEM, keyPEM
}

// GenerateCertChain creates a CA + leaf certificate chain.
// Returns leaf PEM, key PEM, CA PEM, and the full chain (leaf + CA).
func GenerateCertChain(tb testing.TB) (leafPEM, keyPEM, caPEM, chainPEM []byte) {
	tb.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, caPEMBytes := signCert(tb, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caPEM = caPEMBytes
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		tb.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	_, leafPEM = signCert(tb, leafTemplate, caCert, &leafKey.PublicKey, caKey)

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		tb.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: pemTypeKeyPKCS8, Bytes: keyDER})

	// Concatenate leaf + CA into the chain. Build via append on a nil
	// slice rather than make([]byte, 0, len(a)+len(b)): the explicit
	// len+len capacity expression trips CodeQL's
	// go/allocation-size-overflow rule (it can't prove the sum doesn't
	// wrap), and append grows the backing array safely on its own.
	chainPEM = append(chainPEM, leafPEM...)
	chainPEM = append(chainPEM, caPEM...)
	return leafPEM, keyPEM, caPEM, chainPEM
}

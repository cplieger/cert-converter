// Package testcerts provides key-type-aware cert/key pairs and signing chains for
// cert-converter tests.
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
func signCert(tb testing.TB, template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) (der, pemBytes []byte) {
	tb.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		tb.Fatal(err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: der})
}

// Mint signs template with parent (a nil parent yields a self-signed certificate
// whose template is its own issuer) and returns the PEM encoding and the parsed
// certificate (whose Raw field carries the DER).
func Mint(tb testing.TB, template *x509.Certificate, pub crypto.PublicKey,
	parent *x509.Certificate, parentKey crypto.Signer,
) (pemBytes []byte, parsed *x509.Certificate) {
	tb.Helper()

	if parent == nil {
		parent = template // self-signed: the template is its own issuer
	}
	der, pemBytes := signCert(tb, template, parent, pub, parentKey)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return pemBytes, parsed
}

// KeyPEM marshals key as a PKCS#8 PRIVATE KEY block, the form cert-converter's
// key parser reads first.
func KeyPEM(tb testing.TB, key crypto.PrivateKey) []byte {
	tb.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeKeyPKCS8, Bytes: der})
}

// NewECDSAKey generates a P-256 key, the default fixture key type.
func NewECDSAKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return key
}

// GenerateSelfSignedCert creates a self-signed certificate with the given
// key type ("rsa" or "ecdsa") and common name. Returns PEM-encoded cert and key.
func GenerateSelfSignedCert(tb testing.TB, cn, keyType string) (certPEM, keyPEM []byte) {
	tb.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	switch keyType {
	case "ecdsa":
		key := NewECDSAKey(tb)
		_, certPEM = signCert(tb, template, template, &key.PublicKey, key)
		keyPEM = KeyPEM(tb, key)

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
func GenerateCertChain(tb testing.TB) (leafPEM, keyPEM, caPEM, chainPEM []byte) {
	tb.Helper()

	caKey := NewECDSAKey(tb)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caPEM, caCert := Mint(tb, caTemplate, &caKey.PublicKey, nil, caKey)

	leafKey := NewECDSAKey(tb)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	_, leafPEM = signCert(tb, leafTemplate, caCert, &leafKey.PublicKey, caKey)

	keyPEM = KeyPEM(tb, leafKey)

	// Concatenate leaf + CA into the chain.
	chainPEM = append(chainPEM, leafPEM...)
	chainPEM = append(chainPEM, caPEM...)
	return leafPEM, keyPEM, caPEM, chainPEM
}

// ChainMaterial carries every piece of a generated CA -> leaf chain that a test
// needs to assemble an adversarial bundle: each certificate's PEM, each private
// key's PEM, and two alternative leaves reusing the leaf's key.
type ChainMaterial struct {
	// CAPEM is the self-signed CA that issued LeafPEM.
	CAPEM []byte
	// CAKeyPEM is the CA's private key: the input that must be REJECTED as an
	// identity when the CA has issued another certificate in the same bundle.
	CAKeyPEM []byte
	// LeafPEM is the end-entity certificate, issued by CAPEM.
	LeafPEM []byte
	// LeafKeyPEM is LeafPEM's private key.
	LeafKeyPEM []byte
	// RenewedPEM is a second end-entity certificate reusing LeafKeyPEM with a
	// later NotBefore, both currently valid: the renewed-certificate tie.
	RenewedPEM []byte
	// FutureRenewedPEM reuses LeafKeyPEM with a NotBefore in the FUTURE.
	FutureRenewedPEM []byte
}

// GenerateChainMaterial builds a CA, a leaf it issued, and two alternative leaves
// that reuse the leaf's key (one currently valid, one future-dated).
func GenerateChainMaterial(tb testing.TB) ChainMaterial {
	tb.Helper()

	caKey := NewECDSAKey(tb)
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Material Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caPEM, caCert := Mint(tb, caTemplate, &caKey.PublicKey, nil, caKey)

	leafKey := NewECDSAKey(tb)

	// Three certificates over ONE key: the original, a renewal already in force,
	// and a renewal that has not started yet.
	newLeaf := func(serial int64, cn string, notBefore time.Time) []byte {
		tb.Helper()

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(24 * time.Hour),
		}
		_, leafPEM := signCert(tb, tmpl, caCert, &leafKey.PublicKey, caKey)
		return leafPEM
	}

	return ChainMaterial{
		CAPEM:            caPEM,
		CAKeyPEM:         KeyPEM(tb, caKey),
		LeafPEM:          newLeaf(2, "material-leaf.example.com", now.Add(-30*time.Minute)),
		LeafKeyPEM:       KeyPEM(tb, leafKey),
		RenewedPEM:       newLeaf(3, "material-renewed.example.com", now.Add(-10*time.Minute)),
		FutureRenewedPEM: newLeaf(4, "material-future.example.com", now.Add(12*time.Hour)),
	}
}

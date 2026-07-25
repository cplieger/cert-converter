// Package testcerts provides certificate generation helpers for cert-converter's
// tests: cert+key PAIRS and signing CHAINS, which is what a PKCS#12 conversion needs.
//
// This is deliberately NOT a general-purpose test-certificate library, and it is not a
// candidate for consolidation with httpx's certtest subpackage (deferred finding
// l-f52, dismissed). The two look similar because both call crypto/x509, but they
// serve different responsibilities and neither wants the other's features:
//
//   - certtest.SelfSignedCA is fixed at P-256, IsCA with KeyUsageCertSign, and
//     DISCARDS the private key. That is the point of it — its consumers pin a CA and
//     assert that certificates from separate calls are mutually untrusted. It has no
//     use for key-type selection or chain building.
//   - This package is parameterised by key type and CN, returns the key in the
//     encoding that key type requires (PKCS#8 for ECDSA, PKCS#1 for RSA), builds
//     non-CA leaves, and assembles a real signing hierarchy. It has no use for
//     certtest's write-a-CA-to-a-file helper: cert-converter's tests lay pairs out in
//     the /input naming contract themselves.
//
// The shared part is roughly eight lines of boilerplate (template, CreateCertificate,
// pem.EncodeToMemory), so a library extracted to deduplicate it would cost far more
// than it saves — and a wrong test fixture fails loudly and immediately, so unlike a
// shared RUNTIME library there are no latent bugs for consolidation to prevent.
//
// Revisit only on a concrete trigger: a THIRD consumer needing cert+key pairs, or
// httpx gaining a genuine need for a keypair. Neither exists today.
//
// Ed25519 is a supported production key type but is not generated here; the one test
// that needs it builds the key directly (internal/convert). Adding a third switch arm
// for a single caller is not worth it.
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

// ChainMaterial carries every piece of a generated CA -> leaf chain that a test
// needs to assemble an adversarial bundle: each certificate's PEM, each private
// key's PEM, and two alternative leaves reusing the leaf's key.
//
// GenerateCertChain deliberately exposes only the leaf's key, which is right for
// the happy path but cannot express the cases identity selection has to get
// right: a bundle whose supplied key belongs to the ISSUER, or one holding a
// renewed certificate that reuses its predecessor's key.
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
	// FutureRenewedPEM reuses LeafKeyPEM with a NotBefore in the FUTURE. It has
	// the latest NotBefore of the three, so a tie-break that ranked on NotBefore
	// alone would select a certificate no consumer will accept yet.
	FutureRenewedPEM []byte
}

// GenerateChainMaterial builds a CA, a leaf it issued, and two alternative leaves
// that reuse the leaf's key (one currently valid, one future-dated).
func GenerateChainMaterial(tb FatalTB) ChainMaterial {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
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
	caDER, caPEM := signCert(tb, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		tb.Fatal(err)
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		tb.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		tb.Fatal(err)
	}

	// Three certificates over ONE key: the original, a renewal already in force,
	// and a renewal that has not started yet.
	newLeaf := func(serial int64, cn string, notBefore time.Time) []byte {
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
		CAKeyPEM:         pem.EncodeToMemory(&pem.Block{Type: pemTypeKeyPKCS8, Bytes: caKeyDER}),
		LeafPEM:          newLeaf(2, "material-leaf.example.com", now.Add(-30*time.Minute)),
		LeafKeyPEM:       pem.EncodeToMemory(&pem.Block{Type: pemTypeKeyPKCS8, Bytes: leafKeyDER}),
		RenewedPEM:       newLeaf(3, "material-renewed.example.com", now.Add(-10*time.Minute)),
		FutureRenewedPEM: newLeaf(4, "material-future.example.com", now.Add(12*time.Hour)),
	}
}

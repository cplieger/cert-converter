package convert_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
)

// The shapes in this file all come from the dual-model adversarial review of the
// structural Analyse rewrite. Each one was REPRODUCED against the first
// implementation, so each test here fails without its fix.

// mint builds a certificate. parentCert/parentKey nil means self-signed.
func mint(t *testing.T, tmpl *x509.Certificate, pub *ecdsa.PublicKey,
	parentCert *x509.Certificate, parentKey *ecdsa.PrivateKey,
) (certPEM []byte, parsed *x509.Certificate) {
	t.Helper()
	if parentCert == nil {
		parentCert = tmpl // self-signed: the template is its own issuer
	}
	if parentKey == nil {
		t.Fatal("setup: mint needs a signing key")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, pub, parentKey)
	if err != nil {
		t.Fatalf("setup: CreateCertificate: %v", err)
	}
	parsed, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("setup: ParseCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), parsed
}

// keyPEMOf marshals an ECDSA key as a PKCS#8 PEM block.
func keyPEMOf(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("setup: MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// newKey generates a P-256 key.
func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}
	return k
}

// assertOrderInvariant runs Analyse over every rotation of certBlobs and asserts
// the selected identity and the emitted chain are byte-identical every time.
//
// Rotations rather than full permutations keeps the helper cheap while still
// placing each certificate first at least once, which is what every reproduced
// order defect turned on: the losing comparator fell back to "whichever came
// first in the file".
func assertOrderInvariant(t *testing.T, label string, certBlobs [][]byte, keyPEM []byte) {
	t.Helper()
	var wantLeaf []byte
	var wantChain [][]byte

	for r := range certBlobs {
		rotated := make([][]byte, 0, len(certBlobs))
		for i := range certBlobs {
			rotated = append(rotated, certBlobs[(i+r)%len(certBlobs)])
		}
		got, err := convert.Analyse(concatPEM(rotated...), keyPEM)
		if err != nil {
			t.Fatalf("%s: Analyse(rotation %d) = error %v, want nil", label, r, err)
		}
		chain := make([][]byte, 0, len(got.Chain))
		for _, c := range got.Chain {
			chain = append(chain, c.Raw)
		}

		if r == 0 {
			wantLeaf, wantChain = got.Leaf.Raw, chain
			continue
		}
		if !bytes.Equal(got.Leaf.Raw, wantLeaf) {
			t.Errorf("%s: rotation %d selected a DIFFERENT identity than rotation 0 (%q vs the first); selection depends on input order",
				label, r, got.Leaf.Subject.CommonName)
		}
		if len(chain) != len(wantChain) {
			t.Errorf("%s: rotation %d emitted a chain of %d, rotation 0 emitted %d", label, r, len(chain), len(wantChain))
			continue
		}
		for i := range chain {
			if !bytes.Equal(chain[i], wantChain[i]) {
				t.Errorf("%s: rotation %d chain[%d] differs from rotation 0; chain order depends on input order", label, r, i)
			}
		}
	}
}

// TestAnalyse_selects_the_same_identity_for_indistinguishable_renewals pins the
// identity comparator's total order. Two certificates reusing one key with the
// SAME subject and the SAME NotBefore are indistinguishable to every semantic
// ranking key, so before the fix the reduction kept whichever block came first.
// A subject comparison can never break this tie: a renewal shares its
// predecessor's subject by definition.
func TestAnalyse_selects_the_same_identity_for_indistinguishable_renewals(t *testing.T) {
	t.Parallel()
	caKey := newKey(t)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	caPEM, caCert := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Tie CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := newKey(t)
	// Identical subject AND identical NotBefore; only the serial differs.
	leafTmpl := func(serial int64) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "tie-leaf.example.com"},
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(24 * time.Hour),
		}
	}
	firstPEM, _ := mint(t, leafTmpl(10), &leafKey.PublicKey, caCert, caKey)
	secondPEM, _ := mint(t, leafTmpl(11), &leafKey.PublicKey, caCert, caKey)

	assertOrderInvariant(t, "indistinguishable renewals",
		[][]byte{firstPEM, secondPEM, caPEM}, keyPEMOf(t, leafKey))
}

// TestAnalyse_selects_the_same_parent_for_indistinguishable_issuers pins the
// parent comparator's total order. Every candidate parent at a branch reached it
// by matching the child's RawIssuer against its own RawSubject, so all candidates
// share a subject and a subject comparison is inert BY CONSTRUCTION. RFC 5280
// permits a CA to hold several certificates under one name, so real branches with
// equal distance and equal NotAfter exist.
func TestAnalyse_selects_the_same_parent_for_indistinguishable_issuers(t *testing.T) {
	t.Parallel()
	caKey := newKey(t)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	caTmpl := func(serial int64) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: "Duplicate CA"},
			NotBefore:             notBefore,
			NotAfter:              notBefore.Add(48 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}
	// Two self-signed CA certificates: same subject, same key, same NotAfter, so
	// both are valid issuers of the leaf and neither is semantically preferable.
	caAPEM, caACert := mint(t, caTmpl(20), &caKey.PublicKey, nil, caKey)
	caBPEM, _ := mint(t, caTmpl(21), &caKey.PublicKey, nil, caKey)

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(30),
		Subject:      pkix.Name{CommonName: "branch-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caACert, caKey)

	assertOrderInvariant(t, "indistinguishable issuers",
		[][]byte{leafPEM, caAPEM, caBPEM}, keyPEMOf(t, leafKey))
}

// TestAnalyse_handles_a_cross_certification_cycle pins cycle safety. The first
// implementation memoised its cycle guard's "unreachable" answer, so a node that
// was merely FORBIDDEN on the current path was permanently recorded as having no
// route to a root — and which node that happened to be depended on input order.
// Cycles are real: RFC 4158 describes mesh PKIs with bidirectional
// cross-certification.
func TestAnalyse_handles_a_cross_certification_cycle(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	keyA, keyB := newKey(t), newKey(t)

	caTmpl := func(serial int64, cn string) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             notBefore,
			NotAfter:              notBefore.Add(48 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		return tmpl
	}

	// Root: self-signed under subject "CA-B", holding keyB. This is the cycle's
	// exit to a trust anchor.
	rootPEM, rootCert := mint(t, caTmpl(40, "CA-B"), &keyB.PublicKey, nil, keyB)
	// CA-A, issued by CA-B.
	caAPEM, caACert := mint(t, caTmpl(41, "CA-A"), &keyA.PublicKey, rootCert, keyB)
	// CA-B again, this time issued by CA-A: the second half of the cycle.
	caBPEM, _ := mint(t, caTmpl(42, "CA-B"), &keyB.PublicKey, caACert, keyA)

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(50),
		Subject:      pkix.Name{CommonName: "cycle-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caACert, keyA)

	assertOrderInvariant(t, "cross-certification cycle",
		[][]byte{leafPEM, caAPEM, caBPEM, rootPEM}, keyPEMOf(t, leafKey))
}

// TestAnalyse_accepts_a_regenerated_self_signed_certificate pins the key-reuse
// exclusion in the issuance graph. `openssl req -x509` sets basicConstraints
// CA:TRUE by default, so a regenerated self-signed certificate left beside the
// one it replaces gives two certificates that share a subject AND a key. Each
// verifies against the other, so a naive rule records a MUTUAL issuance edge,
// both look like issuers, and the role check rejects the identity — turning an
// input the old positional code converted into a hard failure, which withholds
// the health marker and restart-loops the container.
//
// Key reuse is not issuance: a certificate cannot have issued another
// certificate carrying its own key.
func TestAnalyse_accepts_a_regenerated_self_signed_certificate(t *testing.T) {
	t.Parallel()
	key := newKey(t)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	tmpl := func(serial int64) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "selfsigned.example.com"},
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(24 * time.Hour),
			// The openssl req -x509 default, and the trigger for the defect.
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}
	oldPEM, _ := mint(t, tmpl(60), &key.PublicKey, nil, key)
	newPEM, _ := mint(t, tmpl(61), &key.PublicKey, nil, key)

	got, err := convert.Analyse(concatPEM(oldPEM, newPEM), keyPEMOf(t, key))
	if err != nil {
		t.Fatalf("Analyse(regenerated self-signed cert beside its predecessor) = error %v, want nil", err)
	}
	if got.Leaf.Subject.CommonName != "selfsigned.example.com" {
		t.Errorf("selected identity = %q, want the self-signed certificate", got.Leaf.Subject.CommonName)
	}
	if !hasObservation(got.Observations, convert.ObsRenewedCertTie) {
		t.Errorf("observations = %v, want the renewed-certificate tie to be reported", got.Observations)
	}
	// The pair is a legal identity, so the CA assertion is worth surfacing but
	// must not be fatal.
	if !hasObservation(got.Observations, convert.ObsCAAsIdentity) {
		t.Errorf("observations = %v, want the IsCA assertion reported", got.Observations)
	}
	assertKeyMatchesLeaf(t, got)

	// And it must be order-invariant, since the two are indistinguishable apart
	// from their serial.
	assertOrderInvariant(t, "regenerated self-signed", [][]byte{oldPEM, newPEM}, keyPEMOf(t, key))
}

// TestAnalyse_reports_a_key_that_belongs_to_an_issuer keeps the diagnosis that
// the key-reuse exclusion must NOT weaken: a key belonging to a genuine issuer of
// another certificate in the bundle is still rejected, and the message says so.
func TestAnalyse_reports_a_key_that_belongs_to_an_issuer(t *testing.T) {
	t.Parallel()
	caKey := newKey(t)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	caPEM, caCert := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(70),
		Subject:               pkix.Name{CommonName: "Real Issuer CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(71),
		Subject:      pkix.Name{CommonName: "issued-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	_, err := convert.Analyse(concatPEM(leafPEM, caPEM), keyPEMOf(t, caKey))
	if err == nil {
		t.Fatal("Analyse(CA key beside a certificate it issued) = nil error, want a rejection")
	}
	if !strings.Contains(err.Error(), "is an issuer of another certificate in this bundle") {
		t.Errorf("error = %q, want it to name the issuer role", err.Error())
	}
}

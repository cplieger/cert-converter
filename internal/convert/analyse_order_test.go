package convert_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// Order-invariance and total-order comparator regressions: an Analyse result must
// not depend on the order the certificates appear in the input file.

// TestAnalyse_selects_the_same_identity_for_indistinguishable_renewals pins the
// identity comparator's total order. Two certificates reusing one key with the
// SAME subject and the SAME NotBefore are indistinguishable to every semantic
// ranking key, so before the fix the reduction kept whichever block came first.
// A subject comparison can never break this tie: a renewal shares its
// predecessor's subject by definition.
func TestAnalyse_selects_the_same_identity_for_indistinguishable_renewals(t *testing.T) {
	t.Parallel()
	caKey := testcerts.NewECDSAKey(t)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Tie CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	// Identical subject AND identical NotBefore; only the serial differs.
	leafTmpl := func(serial int64) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "tie-leaf.example.com"},
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(24 * time.Hour),
		}
	}
	firstPEM, _ := testcerts.Mint(t, leafTmpl(10), &leafKey.PublicKey, caCert, caKey)
	secondPEM, _ := testcerts.Mint(t, leafTmpl(11), &leafKey.PublicKey, caCert, caKey)

	assertOrderInvariant(t, "indistinguishable renewals",
		[][]byte{firstPEM, secondPEM, caPEM}, testcerts.KeyPEM(t, leafKey))
}

// TestAnalyse_selects_the_same_parent_for_indistinguishable_issuers pins the
// parent comparator's total order. Every candidate parent at a branch reached it
// by matching the child's RawIssuer against its own RawSubject, so all candidates
// share a subject and a subject comparison is inert BY CONSTRUCTION. RFC 5280
// permits a CA to hold several certificates under one name, so real branches with
// equal distance and equal NotAfter exist.
func TestAnalyse_selects_the_same_parent_for_indistinguishable_issuers(t *testing.T) {
	t.Parallel()
	caKey := testcerts.NewECDSAKey(t)
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
	caAPEM, caACert := testcerts.Mint(t, caTmpl(20), &caKey.PublicKey, nil, caKey)
	caBPEM, _ := testcerts.Mint(t, caTmpl(21), &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(30),
		Subject:      pkix.Name{CommonName: "branch-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caACert, caKey)

	assertOrderInvariant(t, "indistinguishable issuers",
		[][]byte{leafPEM, caAPEM, caBPEM}, testcerts.KeyPEM(t, leafKey))
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
	keyA, keyB := testcerts.NewECDSAKey(t), testcerts.NewECDSAKey(t)

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
	rootPEM, rootCert := testcerts.Mint(t, caTmpl(40, "CA-B"), &keyB.PublicKey, nil, keyB)
	// CA-A, issued by CA-B.
	caAPEM, caACert := testcerts.Mint(t, caTmpl(41, "CA-A"), &keyA.PublicKey, rootCert, keyB)
	// CA-B again, this time issued by CA-A: the second half of the cycle.
	caBPEM, _ := testcerts.Mint(t, caTmpl(42, "CA-B"), &keyB.PublicKey, caACert, keyA)

	leafKey := testcerts.NewECDSAKey(t)
	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(50),
		Subject:      pkix.Name{CommonName: "cycle-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caACert, keyA)

	assertOrderInvariant(t, "cross-certification cycle",
		[][]byte{leafPEM, caAPEM, caBPEM, rootPEM}, testcerts.KeyPEM(t, leafKey))
}

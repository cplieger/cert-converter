package convert_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// The shapes in this file all come from adversarial review of the structural
// Analyse rewrite, and of the guards later added to it. Each one was REPRODUCED
// against the implementation it found wanting, so each test here fails without its
// fix.
//
// The certificate/key fixtures come from internal/testcerts (Mint, KeyPEM,
// NewECDSAKey): how this app mints a test certificate has one home, so a change to
// it (a new default extension, a signature-algorithm pin) is made once.

// oversizedRSAPublicKey fabricates an RSA public key whose modulus is exactly bits
// bits long. The modulus is not a product of primes and nothing can sign with it,
// which is all an over-ceiling issuer needs to be: the key size is read out of the
// SubjectPublicKeyInfo, and the point of the ceiling is that no signature is ever
// checked against such a key. Generating a real 16k-bit RSA key costs minutes, so
// no test may do that.
func oversizedRSAPublicKey(bits uint) *rsa.PublicKey {
	// Lsh(1, bits-1) is the smallest integer of that bit length; +1 makes it odd,
	// as a real modulus is, and keeps it the positive value x509 requires.
	n := new(big.Int).Lsh(big.NewInt(1), bits-1)
	return &rsa.PublicKey{N: n.Add(n, big.NewInt(1)), E: 65537}
}

// chainSerials renders an emitted chain's serial numbers. Serials are what tell
// two same-subject candidates apart in a failure message, where the subject by
// definition cannot.
func chainSerials(chain []*x509.Certificate) []string {
	out := make([]string, 0, len(chain))
	for _, c := range chain {
		out = append(out, c.SerialNumber.String())
	}
	return out
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
		chain := make([][]byte, 0, len(got.Chain()))
		for _, c := range got.Chain() {
			chain = append(chain, c.Raw)
		}

		if r == 0 {
			wantLeaf, wantChain = got.Leaf().Raw, chain
			continue
		}
		if !bytes.Equal(got.Leaf().Raw, wantLeaf) {
			t.Errorf("%s: rotation %d selected a DIFFERENT identity than rotation 0 (%q vs the first); selection depends on input order",
				label, r, got.Leaf().Subject.CommonName)
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
	caKey := testcerts.NewECDSAKey(t)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
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
	_, firstPEM, _ := testcerts.Mint(t, leafTmpl(10), &leafKey.PublicKey, caCert, caKey)
	_, secondPEM, _ := testcerts.Mint(t, leafTmpl(11), &leafKey.PublicKey, caCert, caKey)

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
	_, caAPEM, caACert := testcerts.Mint(t, caTmpl(20), &caKey.PublicKey, nil, caKey)
	_, caBPEM, _ := testcerts.Mint(t, caTmpl(21), &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
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
	_, rootPEM, rootCert := testcerts.Mint(t, caTmpl(40, "CA-B"), &keyB.PublicKey, nil, keyB)
	// CA-A, issued by CA-B.
	_, caAPEM, caACert := testcerts.Mint(t, caTmpl(41, "CA-A"), &keyA.PublicKey, rootCert, keyB)
	// CA-B again, this time issued by CA-A: the second half of the cycle.
	_, caBPEM, _ := testcerts.Mint(t, caTmpl(42, "CA-B"), &keyB.PublicKey, caACert, keyA)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(50),
		Subject:      pkix.Name{CommonName: "cycle-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caACert, keyA)

	assertOrderInvariant(t, "cross-certification cycle",
		[][]byte{leafPEM, caAPEM, caBPEM, rootPEM}, testcerts.KeyPEM(t, leafKey))
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
	key := testcerts.NewECDSAKey(t)
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
	_, oldPEM, _ := testcerts.Mint(t, tmpl(60), &key.PublicKey, nil, key)
	_, newPEM, _ := testcerts.Mint(t, tmpl(61), &key.PublicKey, nil, key)

	got, err := convert.Analyse(concatPEM(oldPEM, newPEM), testcerts.KeyPEM(t, key))
	if err != nil {
		t.Fatalf("Analyse(regenerated self-signed cert beside its predecessor) = error %v, want nil", err)
	}
	if got.Leaf().Subject.CommonName != "selfsigned.example.com" {
		t.Errorf("selected identity = %q, want the self-signed certificate", got.Leaf().Subject.CommonName)
	}
	if !hasObservation(got.Observations(), convert.ObsRenewedCertTie) {
		t.Errorf("observations = %v, want the renewed-certificate tie to be reported", got.Observations())
	}
	// The pair is a legal identity, so the CA assertion is worth surfacing but
	// must not be fatal.
	if !hasObservation(got.Observations(), convert.ObsCAAsIdentity) {
		t.Errorf("observations = %v, want the IsCA assertion reported", got.Observations())
	}
	assertKeyMatchesLeaf(t, got)

	// And it must be order-invariant, since the two are indistinguishable apart
	// from their serial.
	assertOrderInvariant(t, "regenerated self-signed", [][]byte{oldPEM, newPEM}, testcerts.KeyPEM(t, key))
}

// TestAnalyse_reports_a_key_that_belongs_to_an_issuer keeps the diagnosis that
// the key-reuse exclusion must NOT weaken: a key belonging to a genuine issuer of
// another certificate in the bundle is still rejected, and the message says so.
func TestAnalyse_reports_a_key_that_belongs_to_an_issuer(t *testing.T) {
	t.Parallel()
	caKey := testcerts.NewECDSAKey(t)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(70),
		Subject:               pkix.Name{CommonName: "Real Issuer CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(71),
		Subject:      pkix.Name{CommonName: "issued-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	_, err := convert.Analyse(concatPEM(leafPEM, caPEM), testcerts.KeyPEM(t, caKey))
	if err == nil {
		t.Fatal("Analyse(CA key beside a certificate it issued) = nil error, want a rejection")
	}
	if !strings.Contains(err.Error(), "is an issuer of another certificate in this bundle") {
		t.Errorf("error = %q, want it to name the issuer role", err.Error())
	}
}

// TestAnalyse_converts_a_key_shared_by_a_ca_and_its_leaf pins the other arm of the
// same rule: when a supplied key matches BOTH an issuer and an end-entity
// certificate in the bundle, the end-entity certificate is the identity and the
// issuer is passed over, rather than the whole pair being refused.
//
// An internal PKI that mints everything from one key produces exactly this input,
// and the refusal was decided by a tie-break: the renewal ranking prefers the later
// NotBefore, so a CA minted after the leaf it signed won the selection and the
// end-entity role check then rejected the bundle. The pair carries exactly one
// usable identity, so it must convert.
//
// Both records it emits are asserted: the issuer match that was set aside, and the
// key reuse that filtering the match out would otherwise leave unreported. The
// whole-set version of this bundle, in the ordinary cadence where the CA is the
// OLDER certificate, is pinned below.
func TestAnalyse_converts_a_key_shared_by_a_ca_and_its_leaf(t *testing.T) {
	t.Parallel()
	sharedKey := testcerts.NewECDSAKey(t)
	leafNotBefore := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	caNotBefore := leafNotBefore.Add(time.Hour)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(72),
		Subject:               pkix.Name{CommonName: "Shared Key CA"},
		NotBefore:             caNotBefore,
		NotAfter:              caNotBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &sharedKey.PublicKey, nil, sharedKey)

	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(73),
		Subject:      pkix.Name{CommonName: "shared-key-leaf.example.com"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotBefore.Add(24 * time.Hour),
	}, &sharedKey.PublicKey, caCert, sharedKey)

	got, err := convert.Analyse(concatPEM(leafPEM, caPEM), testcerts.KeyPEM(t, sharedKey))
	if err != nil {
		t.Fatalf("Analyse(one key for a CA and the leaf it signed) = %v, want the leaf to be selected", err)
	}
	if got.Leaf().Subject.CommonName != "shared-key-leaf.example.com" {
		t.Errorf("selected identity = %q, want the end-entity certificate", got.Leaf().Subject.CommonName)
	}
	if len(got.Chain()) != 1 {
		t.Fatalf("chain length = %d, want 1: the CA belongs in the chain", len(got.Chain()))
	}
	if got.Chain()[0].Subject.CommonName != "Shared Key CA" {
		t.Errorf("chain[0] = %q, want the CA", got.Chain()[0].Subject.CommonName)
	}
	if !hasObservation(got.Observations(), convert.ObsIssuerMatchIgnored) {
		t.Errorf("observations = %v, want the passed-over issuer match reported", got.Observations())
	}
	if !hasObservation(got.Observations(), convert.ObsKeyReusedAcrossCerts) {
		t.Errorf("observations = %v, want the shared key reported as reuse", got.Observations())
	}
}

// observationKinds lists the kinds an analysis reported, in the order it reported
// them, so a test can pin the whole SET rather than the presence of one member. A
// membership assertion cannot see an observation that STOPPED being emitted, which
// is exactly how a filtering change silently swapped one WARN for another.
func observationKinds(obs []convert.Observation) []convert.ObservationKind {
	kinds := make([]convert.ObservationKind, 0, len(obs))
	for _, o := range obs {
		kinds = append(kinds, o.Kind)
	}
	return kinds
}

// TestAnalyse_reports_the_shared_key_as_reuse_when_the_issuer_match_is_dropped pins
// the whole observation set for the bundle an internal PKI mints from one key, in
// the ordinary cadence where the CA is minted BEFORE the leaf it signs.
//
// Dropping the issuer match collapses the candidate set to one, so
// resolveAmbiguousMatches — the only other place that says "one private key matches
// several certificates" — is never reached, and the fact that the operator's CA key
// is also an end-entity key went unreported anywhere. Two records are emitted
// because they are two different facts: a match was set aside for identity
// selection, AND one key serves two certificates. Neither calls the CA a renewal of
// the leaf, which is what reporting this through ObsRenewedCertTie claimed.
func TestAnalyse_reports_the_shared_key_as_reuse_when_the_issuer_match_is_dropped(t *testing.T) {
	t.Parallel()
	sharedKey := testcerts.NewECDSAKey(t)
	caNotBefore := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	leafNotBefore := caNotBefore.Add(time.Hour)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(9000),
		Subject:               pkix.Name{CommonName: "Reused Key CA"},
		NotBefore:             caNotBefore,
		NotAfter:              caNotBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &sharedKey.PublicKey, nil, sharedKey)

	_, leafPEM, leafCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(9001),
		Subject:      pkix.Name{CommonName: "reused-key-leaf.example.com"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotBefore.Add(24 * time.Hour),
	}, &sharedKey.PublicKey, caCert, sharedKey)
	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("setup: CA did not actually sign the leaf: %v", err)
	}

	got, err := convert.Analyse(concatPEM(leafPEM, caPEM), testcerts.KeyPEM(t, sharedKey))
	if err != nil {
		t.Fatalf("Analyse(one key for a CA and the leaf it signed) = %v, want the leaf selected", err)
	}
	if got.Leaf().SerialNumber.Cmp(big.NewInt(9001)) != 0 {
		t.Errorf("selected identity serial = %s, want 9001 (the end-entity certificate)", got.Leaf().SerialNumber)
	}
	if len(got.Chain()) != 1 || got.Chain()[0].SerialNumber.Cmp(big.NewInt(9000)) != 0 {
		t.Errorf("chain serials = %v, want [9000]", chainSerials(got.Chain()))
	}
	want := []convert.ObservationKind{convert.ObsIssuerMatchIgnored, convert.ObsKeyReusedAcrossCerts}
	if kinds := observationKinds(got.Observations()); !slices.Equal(kinds, want) {
		t.Errorf("observation kinds = %v, want exactly %v", kinds, want)
	}
	var reuse string
	for _, o := range got.Observations() {
		if o.Kind == convert.ObsKeyReusedAcrossCerts {
			reuse = o.Detail
		}
	}
	if !strings.Contains(reuse, "Reused Key CA") {
		t.Errorf("key-reuse detail = %q, want the CA that shares the key named", reuse)
	}
	// The miswording that made this a deferred decision rather than a fix: the CA is
	// an issuer of the identity, not an older version of it.
	if strings.Contains(strings.ToLower(reuse), "renew") {
		t.Errorf("key-reuse detail = %q, want no renewal wording for an issuer", reuse)
	}
}

// TestAnalyse_reports_both_a_renewal_tie_and_key_reuse pins the shape that keeps
// the genuine renewal tie honest: two end-entity certificates sharing one key (a
// renewal) plus the CA that signed them, minted from the SAME key. The issuer match
// is dropped, two end-entity matches survive, so the renewal tie is still reported
// — and the key reuse across the CA is reported beside it. A change that restored
// the tie by keeping the issuer match, or that reported reuse INSTEAD of the tie,
// would lose one of the two facts here.
func TestAnalyse_reports_both_a_renewal_tie_and_key_reuse(t *testing.T) {
	t.Parallel()
	sharedKey := testcerts.NewECDSAKey(t)
	caNotBefore := time.Now().Add(-4 * time.Hour).Truncate(time.Second)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(9100),
		Subject:               pkix.Name{CommonName: "Renewal Tie CA"},
		NotBefore:             caNotBefore,
		NotAfter:              caNotBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &sharedKey.PublicKey, nil, sharedKey)

	_, oldLeafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(9101),
		Subject:      pkix.Name{CommonName: "tie-leaf.example.com"},
		NotBefore:    caNotBefore.Add(time.Hour),
		NotAfter:     caNotBefore.Add(48 * time.Hour),
	}, &sharedKey.PublicKey, caCert, sharedKey)
	_, newLeafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(9102),
		Subject:      pkix.Name{CommonName: "tie-leaf.example.com"},
		NotBefore:    caNotBefore.Add(2 * time.Hour),
		NotAfter:     caNotBefore.Add(72 * time.Hour),
	}, &sharedKey.PublicKey, caCert, sharedKey)

	got, err := convert.Analyse(concatPEM(oldLeafPEM, newLeafPEM, caPEM), testcerts.KeyPEM(t, sharedKey))
	if err != nil {
		t.Fatalf("Analyse(renewed leaf pair plus their shared-key CA) = %v, want the newest leaf selected", err)
	}
	if got.Leaf().SerialNumber.Cmp(big.NewInt(9102)) != 0 {
		t.Errorf("selected identity serial = %s, want 9102 (the newer renewal)", got.Leaf().SerialNumber)
	}
	for _, want := range []convert.ObservationKind{
		convert.ObsIssuerMatchIgnored,
		convert.ObsKeyReusedAcrossCerts,
		convert.ObsRenewedCertTie,
	} {
		if !hasObservation(got.Observations(), want) {
			t.Errorf("observations = %v, want %q reported", got.Observations(), want)
		}
	}
}

// TestAnalyse_reports_no_key_reuse_when_the_key_file_holds_two_keys guards the other
// direction of the same rule: a key file carrying the leaf's key AND the CA's key is
// two keys doing one job each, so the issuer match is still set aside but there is no
// key-reuse fact to report. Emitting one here would WARN about correct PKI hygiene on
// every scan.
func TestAnalyse_reports_no_key_reuse_when_the_key_file_holds_two_keys(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	caKey := testcerts.NewECDSAKey(t)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(9200),
		Subject:               pkix.Name{CommonName: "Two Key CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(9201),
		Subject:      pkix.Name{CommonName: "two-key-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	got, err := convert.Analyse(
		concatPEM(leafPEM, caPEM),
		concatPEM(testcerts.KeyPEM(t, leafKey), testcerts.KeyPEM(t, caKey)),
	)
	if err != nil {
		t.Fatalf("Analyse(leaf and issuer certificates with both private keys) = %v, want the leaf selected", err)
	}
	want := []convert.ObservationKind{convert.ObsMultipleKeys, convert.ObsIssuerMatchIgnored}
	if kinds := observationKinds(got.Observations()); !slices.Equal(kinds, want) {
		t.Errorf("observation kinds = %v, want exactly %v: two distinct keys are not key reuse", kinds, want)
	}
}

// TestAnalyse_converts_when_key_file_holds_leaf_and_issuer_keys pins the second
// reachable input dropIssuerMatches documents: the key file carries the leaf key AND
// the CA key, so each certificate in the bundle has its own matching key. Without the
// issuer matches being discarded before distinct-identity resolution, this bundle
// looks like two identities, the pair is refused, conversion fails and the health
// marker stays unset — while the shared-key test above stays green, because it only
// covers one key matching both certificates.
func TestAnalyse_converts_when_key_file_holds_leaf_and_issuer_keys(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	caKey := testcerts.NewECDSAKey(t)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(74),
		Subject:               pkix.Name{CommonName: "Separate Key CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(75),
		Subject:      pkix.Name{CommonName: "separate-key-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	got, err := convert.Analyse(
		concatPEM(leafPEM, caPEM),
		concatPEM(testcerts.KeyPEM(t, leafKey), testcerts.KeyPEM(t, caKey)),
	)
	if err != nil {
		t.Fatalf("Analyse(leaf and issuer certificates with both private keys) = %v, want the leaf selected", err)
	}
	if got.Leaf().Subject.CommonName != "separate-key-leaf.example.com" {
		t.Errorf("selected identity = %q, want the end-entity certificate", got.Leaf().Subject.CommonName)
	}
	if len(got.Chain()) != 1 || got.Chain()[0].Subject.CommonName != "Separate Key CA" {
		t.Errorf("chain subjects = %v, want [Separate Key CA]", subjectCNs(got.Chain()))
	}
	if !hasObservation(got.Observations(), convert.ObsIssuerMatchIgnored) {
		t.Errorf("observations = %v, want the passed-over issuer match reported", got.Observations())
	}
}

// TestAnalyse_keeps_certificates_when_the_issuer_cannot_be_established pins the
// additive-only fallback.
//
// Structural chain building can fail to prove a relationship that genuinely
// exists: Go refuses to verify a SHA-1 signature at all, and RFC 5280 permits
// issuer and subject names to be encoded differently in ways a byte comparison
// rejects. The first implementation treated "could not prove related" the same as
// "proved unrelated" and dropped the certificate, silently removing a CA that the
// previous positional code shipped — which breaks path building at the consumer
// after nothing more than an image bump.
//
// So when no issuer for a non-self-signed identity can be established at all, the
// remaining certificates are KEPT. That makes the structural rewrite additive: it
// can improve a chain, never quietly shrink one.
func TestAnalyse_keeps_certificates_when_the_issuer_cannot_be_established(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	// An issuer that is NOT placed in the bundle, so the leaf's issuer name
	// matches nothing present: the same observable state a signature we cannot
	// verify produces.
	absentCAKey := testcerts.NewECDSAKey(t)
	_, _, absentCACert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(80),
		Subject:               pkix.Name{CommonName: "Absent Issuer CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &absentCAKey.PublicKey, nil, absentCAKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(81),
		Subject:      pkix.Name{CommonName: "orphaned-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentCACert, absentCAKey)

	// Some other certificate sits in the bundle. Under the old positional rule it
	// would have been embedded; it must still be embedded rather than dropped,
	// because we cannot show it is off the chain.
	otherKey := testcerts.NewECDSAKey(t)
	_, otherPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(82),
		Subject:               pkix.Name{CommonName: "Possibly Related CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &otherKey.PublicKey, nil, otherKey)

	got, err := convert.Analyse(concatPEM(leafPEM, otherPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(leaf whose issuer is absent) = error %v, want nil", err)
	}
	if got.Leaf().Subject.CommonName != "orphaned-leaf.example.com" {
		t.Errorf("selected identity = %q, want the leaf", got.Leaf().Subject.CommonName)
	}
	if len(got.Chain()) != 1 {
		t.Fatalf("chain length = %d, want 1: an unprovable certificate must be kept, not dropped", len(got.Chain()))
	}
	if got.Chain()[0].Subject.CommonName != "Possibly Related CA" {
		t.Errorf("chain[0] = %q, want the kept certificate", got.Chain()[0].Subject.CommonName)
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra holds %d certificate(s), want 0: nothing was shown to be off the chain", len(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want one of kind %q so the operator knows the chain was not verified",
			got.Observations(), convert.ObsChainUnverified)
	}
	// The split between the two terminus kinds is what leftovers decide: here a
	// certificate this app could not place was carried into the bundle anyway, which is
	// the warning's subject. The informational anchor-absent kind is for the bundle
	// where nothing was left over at all.
	if hasObservation(got.Observations(), convert.ObsChainTrustAnchorAbsent) {
		t.Errorf("observations = %v, want no %q: a certificate was kept whose ancestry is unestablished, which is more than an absent anchor",
			got.Observations(), convert.ObsChainTrustAnchorAbsent)
	}
	if got := convert.ObsChainUnverified.Class(); got != convert.ObservationClassWarning {
		t.Errorf("ObsChainUnverified.Class() = %q, want %q: this signal must not be quietened by the class split",
			got, convert.ObservationClassWarning)
	}
}

// TestAnalyse_still_excludes_an_unrelated_cert_from_a_self_signed_identity keeps
// the fallback narrow. A self-signed identity has no issuer BY CONSTRUCTION, so
// an empty chain is proof rather than a failure to prove, and the fallback must
// not fire — otherwise the unrelated-certificate exclusion (the whole point of
// replacing `caCerts = chain[1:]`) would be undone for every self-signed input.
func TestAnalyse_still_excludes_an_unrelated_cert_from_a_self_signed_identity(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	key := testcerts.NewECDSAKey(t)
	_, identityPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(90),
		Subject:      pkix.Name{CommonName: "self.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &key.PublicKey, nil, key)

	strangerKey := testcerts.NewECDSAKey(t)
	_, strangerPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(91),
		Subject:      pkix.Name{CommonName: "stranger.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &strangerKey.PublicKey, nil, strangerKey)

	got, err := convert.Analyse(concatPEM(identityPEM, strangerPEM), testcerts.KeyPEM(t, key))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if len(got.Chain()) != 0 {
		t.Errorf("chain length = %d, want 0: a self-signed identity has no chain", len(got.Chain()))
	}
	if len(got.Extra()) != 1 {
		t.Fatalf("Extra holds %d certificate(s), want 1", len(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want the exclusion reported", got.Observations())
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want NO chain-unverified fallback for a self-signed identity", got.Observations())
	}
}

// TestAnalyse_prefers_the_certificate_that_actually_signed_the_leaf pins edge
// STRENGTH as the top ranking key in chain assembly.
//
// The inclusive candidate signal (name chaining or key-identifier match) exists so
// a relationship we cannot verify — a SHA-1 signature Go refuses, a permitted
// name-encoding difference — does not cause a real CA to be dropped. But it also
// admits an IMPOSTOR: a certificate sharing the issuer's subject while holding a
// different key satisfies name chaining without having signed anything. Ranking
// only on validity, root distance and NotAfter let such a certificate win, emitting
// a chain no consumer can verify. Reproduced by the GPT adversary.
func TestAnalyse_prefers_the_certificate_that_actually_signed_the_leaf(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	realKey := testcerts.NewECDSAKey(t)
	realTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Contested CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	_, realPEM, realCert := testcerts.Mint(t, realTmpl, &realKey.PublicKey, nil, realKey)

	// Same subject, different key, and a LATER NotAfter so every ranking key below
	// edge strength would prefer it.
	impostorKey := testcerts.NewECDSAKey(t)
	_, impostorPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "Contested CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &impostorKey.PublicKey, nil, impostorKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: "contested-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, realCert, realKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"impostor first", [][]byte{leafPEM, impostorPEM, realPEM}},
		{"real first", [][]byte{leafPEM, realPEM, impostorPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) == 0 {
				t.Fatal("chain is empty; want the issuing CA")
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(100)) != 0 {
				t.Errorf("chain[0] serial = %s, want 100 (the certificate that actually signed the leaf, not the same-subject impostor with the later NotAfter)",
					got.Chain()[0].SerialNumber)
			}
		})
	}
}

// TestAnalyse_role_check_ignores_an_unverified_claim keeps the strict signal strict
// in the other direction: an identity must not be rejected because some unrelated
// certificate merely NAMES it as issuer. Only a verified signature makes a
// certificate an issuer.
func TestAnalyse_role_check_ignores_an_unverified_claim(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	// A perfectly ordinary self-signed identity.
	idKey := testcerts.NewECDSAKey(t)
	_, idPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(110),
		Subject:      pkix.Name{CommonName: "Claimed Issuer"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &idKey.PublicKey, nil, idKey)

	// A stranger that CLAIMS the identity as its issuer by name but was signed by
	// its own key. Name chaining alone would make the identity look like an issuer
	// and reject it.
	strangerKey := testcerts.NewECDSAKey(t)
	strangerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(111),
		Subject:      pkix.Name{CommonName: "Freeloader"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}
	strangerSelf := &x509.Certificate{
		SerialNumber: big.NewInt(111),
		Subject:      pkix.Name{CommonName: "Claimed Issuer"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}
	_, strangerPEM, _ := testcerts.Mint(t, strangerTmpl, &strangerKey.PublicKey, strangerSelf, strangerKey)

	got, err := convert.Analyse(concatPEM(idPEM, strangerPEM), testcerts.KeyPEM(t, idKey))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil: a certificate merely CLAIMING this one as issuer must not make it an issuer", err)
	}
	if got.Leaf().SerialNumber.Cmp(big.NewInt(110)) != 0 {
		t.Errorf("selected identity serial = %s, want 110", got.Leaf().SerialNumber)
	}
}

// TestAnalyse_prefers_the_issuer_whose_route_to_a_root_verifies is the verified
// -distance case: a candidate whose DIRECT signature over the child checks out can
// still have an unverifiable continuation above it.
//
// Two intermediates share a subject AND a public key, so both genuinely verify
// their signature over the leaf and the branch is real. Only one of them was signed
// by a root included in the bundle; the other names a same-subject root whose
// included certificate holds a different key. Ranking on the inclusive, name-based
// distance to a root cannot tell them apart, so the later-expiring decoy won and
// the emitted chain carried an intermediate that does not verify under the root
// shipped beside it — while the fully verified path sat in the same input.
func TestAnalyse_prefers_the_issuer_whose_route_to_a_root_verifies(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		sharedRootCN  = "Shared Root"
		sharedInterCN = "Shared Intermediate"
	)

	ca := func(serial int64, cn string, notAfter time.Time) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}

	// The root that actually signed the good intermediate.
	realRootKey := testcerts.NewECDSAKey(t)
	_, realRootPEM, realRootCert := testcerts.Mint(t, ca(200, sharedRootCN, notBefore.Add(240*time.Hour)),
		&realRootKey.PublicKey, nil, realRootKey)

	// A same-named root holding a DIFFERENT key. Present in the bundle, so a
	// name-only walk reaches a "root" through it, but it signed nothing here.
	fakeRootKey := testcerts.NewECDSAKey(t)
	_, fakeRootPEM, _ := testcerts.Mint(t, ca(201, sharedRootCN, notBefore.Add(240*time.Hour)),
		&fakeRootKey.PublicKey, nil, fakeRootKey)

	// A third same-named root that is NOT in the bundle. It signs the decoy
	// intermediate, so no included certificate can verify that intermediate.
	absentRootKey := testcerts.NewECDSAKey(t)
	_, _, absentRootCert := testcerts.Mint(t, ca(202, sharedRootCN, notBefore.Add(240*time.Hour)),
		&absentRootKey.PublicKey, nil, absentRootKey)

	// One key across both intermediates: that is what makes both of them verify the
	// leaf, so edge strength at the leaf's own hop cannot separate them.
	interKey := testcerts.NewECDSAKey(t)
	_, goodInterPEM, goodInterCert := testcerts.Mint(t, ca(203, sharedInterCN, notBefore.Add(24*time.Hour)),
		&interKey.PublicKey, realRootCert, realRootKey)
	// The decoy expires LATER, so every ranking key below route strength prefers it.
	_, decoyInterPEM, _ := testcerts.Mint(t, ca(204, sharedInterCN, notBefore.Add(72*time.Hour)),
		&interKey.PublicKey, absentRootCert, absentRootKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(205),
		Subject:      pkix.Name{CommonName: "verified-route-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, goodInterCert, interKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"decoy first", [][]byte{leafPEM, decoyInterPEM, fakeRootPEM, goodInterPEM, realRootPEM}},
		{"verified first", [][]byte{leafPEM, goodInterPEM, realRootPEM, decoyInterPEM, fakeRootPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) != 2 {
				t.Fatalf("chain length = %d, want 2 (the verified intermediate and the root that signed it)", len(got.Chain()))
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(203)) != 0 {
				t.Errorf("chain[0] serial = %s, want 203 (the intermediate whose route to an included root verifies, not the later-expiring decoy)",
					got.Chain()[0].SerialNumber)
			}
			// The contract the ranking exists to protect: every emitted hop verifies,
			// so a consumer can build a path out of the bundle it was handed.
			if err := got.Leaf().CheckSignatureFrom(got.Chain()[0]); err != nil {
				t.Errorf("leaf does not verify under chain[0] (serial %s): %v", got.Chain()[0].SerialNumber, err)
			}
			if err := got.Chain()[0].CheckSignatureFrom(got.Chain()[1]); err != nil {
				t.Errorf("chain[0] (serial %s) does not verify under chain[1] (serial %s): %v; the emitted chain cannot be validated by a consumer",
					got.Chain()[0].SerialNumber, got.Chain()[1].SerialNumber, err)
			}
		})
	}
}

// TestAnalyse_refuses_an_over_ceiling_rsa_issuer pins the refusal that the key
// ceiling has to carry, and with it the invariant
// TestAnalyse_prefers_the_certificate_that_actually_signed_the_leaf states.
//
// The ceiling stops a file from dictating CPU cost: no signature is verified
// against an RSA key above maxVerifiableKeyBits, because one modexp with an
// oversized modulus runs for seconds to minutes on the scan's only goroutine and
// cannot be cancelled. Leaving such an edge merely UNVERIFIED, the way the SHA-1
// and name-encoding cases are, is what created a second defect: a same-subject
// certificate holding an ordinary key satisfies the identical name match, so both
// candidate edges are unverified, and betterParent then ranks them on keys the
// impostor wins — it is a self-signed root (which the ceiling denies the oversized
// certificate), it expires later, or it takes the DER tie-break. The PFX written
// from that carries a chain no consumer can verify, from input that resolved
// correctly before the ceiling existed.
//
// So the bundle is refused, naming the size observed. Both input orders are
// asserted: a refusal that depended on which candidate came first would be the
// same order-dependence every other test in this file exists to prevent.
func TestAnalyse_refuses_an_over_ceiling_rsa_issuer(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		contestedCN   = "Oversized Issuer CA"
		oversizedBits = convert.MaxVerifiableKeyBits + 17
	)

	ca := func(serial int64, notAfter time.Time) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: contestedCN},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}

	// The over-ceiling candidate issuer: the leaf's issuer name over a modulus past
	// the ceiling. Its own signature is from a throwaway key, because nothing here
	// reads that signature — the refusal is decided on the modulus in the
	// SubjectPublicKeyInfo — and minting it for real would mean generating a
	// 16k-bit RSA key, which costs minutes.
	throwawayKey := testcerts.NewECDSAKey(t)
	_, oversizedPEM, oversizedCert := testcerts.Mint(t, ca(210, notBefore.Add(240*time.Hour)),
		oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	if k, ok := oversizedCert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != oversizedBits {
		t.Fatalf("setup: minted certificate carries a %T, want a %d-bit RSA modulus; x509 no longer parses one that large",
			oversizedCert.PublicKey, oversizedBits)
	}

	// The same-subject decoy with an ordinary key. Self-signed, so it reaches a root
	// in zero hops and outranks the oversized certificate on every key left once
	// neither edge can be verified.
	decoyKey := testcerts.NewECDSAKey(t)
	_, decoyPEM, _ := testcerts.Mint(t, ca(211, notBefore.Add(72*time.Hour)), &decoyKey.PublicKey, nil, decoyKey)

	// The leaf's real signer shares that subject and is NOT in the bundle, so
	// neither candidate edge verifies — the state the ceiling produces for a leaf
	// whose genuine issuer is the oversized one.
	absentKey := testcerts.NewECDSAKey(t)
	_, _, absentCACert := testcerts.Mint(t, ca(212, notBefore.Add(240*time.Hour)), &absentKey.PublicKey, nil, absentKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(213),
		Subject:      pkix.Name{CommonName: "oversized-issuer-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentCACert, absentKey)

	// The same oversized key under extensions that DISQUALIFY it from issuing.
	// candidateEdge admits a non-eligible parent only on a PROVEN signature, which
	// the ceiling forbids, so these variants never gain a children[] entry — a
	// refusal keyed on candidate survival skipped them while the decoy still won the
	// chain, which is precisely the substitution the refusal exists to prevent.
	oversizedNoCA := ca(220, notBefore.Add(240*time.Hour))
	oversizedNoCA.IsCA = false
	_, noCAPEM, _ := testcerts.Mint(t, oversizedNoCA, oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	oversizedNoBC := ca(221, notBefore.Add(240*time.Hour))
	oversizedNoBC.BasicConstraintsValid = false
	_, noBCPEM, _ := testcerts.Mint(t, oversizedNoBC, oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"oversized first", [][]byte{leafPEM, oversizedPEM, decoyPEM}},
		{"decoy first", [][]byte{leafPEM, decoyPEM, oversizedPEM}},
		{"CA false, oversized first", [][]byte{leafPEM, noCAPEM, decoyPEM}},
		{"CA false, decoy first", [][]byte{leafPEM, decoyPEM, noCAPEM}},
		{"no basic constraints, oversized first", [][]byte{leafPEM, noBCPEM, decoyPEM}},
		{"no basic constraints, decoy first", [][]byte{leafPEM, decoyPEM, noBCPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err == nil {
				t.Fatalf("Analyse(leaf + a %d-bit RSA issuer + a same-subject ordinary-key certificate) = nil error and a chain of serial(s) %v, want a refusal: with the oversized edge left unverified the decoy (serial 211) outranks it, so the emitted chain does not verify",
					oversizedBits, chainSerials(got.Chain()))
			}
			// The size and the subject are what make the refusal actionable: which
			// certificate to remove, and the fact that its key is why.
			for _, want := range []string{fmt.Sprintf("%d-bit", oversizedBits), contestedCN} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Analyse error = %q, want it to name %q", err.Error(), want)
				}
			}
		})
	}
}

// TestAnalyse_refuses_an_over_ceiling_issuer_whose_alternative_is_cycle_excluded
// pins the resolution witness against the walk that actually spends it. A proven
// alternative parent only exempts the bundle if selection can still USE it:
// pathFrom carries an onPath set and bestParent skips every candidate already on it,
// so a proven candidate that leads back to the child through candidate edges is the
// one the walk has already consumed by the time the child's own hop is chosen — and
// the unverifiable oversized edge wins that hop unopposed.
//
// Shape: leaf -> A proven, A -> C proven, C -> A proven (a mutually-signed pair, both
// reachable from the leaf), plus an oversized same-subject decoy for A. C's only
// other proven candidate is A, which is on the path when C is reached, so C is NOT
// resolved without the oversized edge and the bundle must be refused. Before the
// cycle check the witness was accepted and Analyse emitted A, C, oversized.
func TestAnalyse_refuses_an_over_ceiling_issuer_whose_alternative_is_cycle_excluded(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		cycleACN      = "Cycle CA A"
		cycleCCN      = "Cycle CA C"
		oversizedBits = convert.MaxVerifiableKeyBits + 17
	)

	keyA := testcerts.NewECDSAKey(t)
	keyC := testcerts.NewECDSAKey(t)

	// A scaffold for C, used only as the issuer template A is minted against: it
	// carries C's subject and C's key, so A's signature verifies under the C that
	// ships in the bundle.
	_, _, scaffoldC := testcerts.Mint(t,
		unverifiableCA(240, cycleCCN, notBefore, notBefore.Add(480*time.Hour)),
		&keyC.PublicKey, nil, keyC)

	_, cyclePEMA, certA := testcerts.Mint(t,
		unverifiableCA(241, cycleACN, notBefore, notBefore.Add(240*time.Hour)),
		&keyA.PublicKey, scaffoldC, keyC)
	// C is signed by A, closing the cycle: A's issuer is C's subject and C's issuer
	// is A's subject, and both signatures verify.
	_, cyclePEMC, _ := testcerts.Mint(t,
		unverifiableCA(242, cycleCCN, notBefore, notBefore.Add(480*time.Hour)),
		&keyC.PublicKey, certA, keyA)

	// The oversized same-subject decoy for A: a linked candidate parent of the leaf
	// AND of C, and no signature may ever be checked against it.
	throwawayKey := testcerts.NewECDSAKey(t)
	_, oversizedPEM, oversizedCert := testcerts.Mint(t,
		unverifiableCA(243, cycleACN, notBefore, notBefore.Add(720*time.Hour)),
		oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	if k, ok := oversizedCert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != oversizedBits {
		t.Fatalf("setup: minted certificate carries a %T, want a %d-bit RSA modulus", oversizedCert.PublicKey, oversizedBits)
	}

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(244),
		Subject:      pkix.Name{CommonName: "cycle-issuer-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, certA, keyA)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"oversized last", [][]byte{leafPEM, cyclePEMA, cyclePEMC, oversizedPEM}},
		{"oversized first", [][]byte{leafPEM, oversizedPEM, cyclePEMA, cyclePEMC}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err == nil {
				t.Fatalf("Analyse(a mutually-signed pair + a same-subject %d-bit decoy) = nil error and a chain of serial(s) %v, want a refusal: the only proven alternative for the second hop is excluded by cycle avoidance, so the oversized edge is guessed",
					oversizedBits, chainSerials(got.Chain()))
			}
			for _, want := range []string{fmt.Sprintf("%d-bit", oversizedBits), cycleACN} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Analyse error = %q, want it to name %q", err.Error(), want)
				}
			}
		})
	}
}

// TestAnalyse_converts_when_a_proven_parent_outranks_an_over_ceiling_namesake pins
// the OTHER edge of that refusal: it fires on a guess, not on the mere presence of
// an unverifiable key.
//
// Shape: a leaf, the ordinary CA that really signed it, and a same-subject
// over-ceiling decoy. The decoy carries the leaf's issuer name, so it is a linked
// candidate parent — but the real CA's signature over the leaf verifies, so nothing
// about this chain has to be guessed and the decoy can only be excluded. Refusing
// here (which keying the refusal on "is anything named as its issuer" did) failed a
// bundle the app resolves correctly, withholding the health marker over an input
// whose every emitted hop is proven.
func TestAnalyse_converts_when_a_proven_parent_outranks_an_over_ceiling_namesake(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		contestedCN   = "Resolvable Issuer CA"
		oversizedBits = convert.MaxVerifiableKeyBits + 1
	)

	// The CA that really signs the leaf, self-signed so it is a root in its own
	// right and needs no parent of its own.
	caKey := testcerts.NewECDSAKey(t)
	_, caPEM, caCert := testcerts.Mint(t,
		unverifiableCA(230, contestedCN, notBefore, notBefore.Add(240*time.Hour)),
		&caKey.PublicKey, nil, caKey)

	// The same-subject over-ceiling decoy. Its signature is from a throwaway key
	// because nothing reads it: the ceiling is decided on the modulus in the
	// SubjectPublicKeyInfo, and minting a real 16k-bit RSA key costs minutes.
	throwawayKey := testcerts.NewECDSAKey(t)
	_, oversizedPEM, oversizedCert := testcerts.Mint(t,
		unverifiableCA(231, contestedCN, notBefore, notBefore.Add(480*time.Hour)),
		oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	if k, ok := oversizedCert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != oversizedBits {
		t.Fatalf("setup: minted certificate carries a %T, want a %d-bit RSA modulus", oversizedCert.PublicKey, oversizedBits)
	}

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(232),
		Subject:      pkix.Name{CommonName: "resolvable-issuer-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"oversized first", [][]byte{leafPEM, oversizedPEM, caPEM}},
		{"proven CA first", [][]byte{leafPEM, caPEM, oversizedPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse(leaf + its proven CA + a same-subject %d-bit decoy) = error %v, want the bundle converted: the proven edge leaves nothing to guess",
					oversizedBits, err)
			}
			if serials := strings.Join(chainSerials(got.Chain()), ","); serials != "230" {
				t.Fatalf("chain serials = %s, want 230: the CA whose signature verifies is the only emitted hop", serials)
			}
			for _, c := range got.Chain() {
				if c.SerialNumber.Cmp(big.NewInt(231)) == 0 {
					t.Errorf("chain holds the over-ceiling decoy (serial 231), want it excluded: no signature can be checked against it")
				}
			}
		})
	}
}

// TestAnalyse_converts_when_the_path_enters_a_signed_cycle_at_its_proven_hop pins the
// OTHER entry order into a mutually-signed pair, the one a graph-wide reachability
// question refused.
//
// Shape: leaf -> C proven, C -> P proven, P -> C proven, plus an over-ceiling
// same-subject namesake of P. pathFrom enters at C, so C's own hop spends the proven
// C -> P edge and P's only candidate parent (C) is already onPath, which ends the
// walk. Every emitted hop is proven and the namesake competes for nothing, so the
// bundle must convert.
//
// TestAnalyse_refuses_an_over_ceiling_issuer_whose_alternative_is_cycle_excluded is
// the mirror: the same cycle entered at P, where C's proven parent IS consumed before
// C is reached and the guessed hop is real. The two differ only in where the path
// enters, which is why the question is asked of the selected path's hops rather than
// of the graph — reachability holds in both orders and cannot tell them apart.
func TestAnalyse_converts_when_the_path_enters_a_signed_cycle_at_its_proven_hop(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		cycleCCN      = "Entered Cycle CA C"
		cyclePCN      = "Entered Cycle CA P"
		oversizedBits = convert.MaxVerifiableKeyBits + 17
	)

	keyC := testcerts.NewECDSAKey(t)
	keyP := testcerts.NewECDSAKey(t)

	// A scaffold for P, used only as the issuer template C is minted against: it
	// carries P's subject and P's key, so C's signature verifies under the P that
	// ships in the bundle.
	_, _, scaffoldP := testcerts.Mint(t,
		unverifiableCA(250, cyclePCN, notBefore, notBefore.Add(480*time.Hour)),
		&keyP.PublicKey, nil, keyP)

	_, cyclePEMC, certC := testcerts.Mint(t,
		unverifiableCA(251, cycleCCN, notBefore, notBefore.Add(240*time.Hour)),
		&keyC.PublicKey, scaffoldP, keyP)
	// P is signed by C, closing the cycle.
	_, cyclePEMP, _ := testcerts.Mint(t,
		unverifiableCA(252, cyclePCN, notBefore, notBefore.Add(480*time.Hour)),
		&keyP.PublicKey, certC, keyC)

	// The over-ceiling namesake of P: a linked candidate parent of C, and no
	// signature may ever be checked against it.
	throwawayKey := testcerts.NewECDSAKey(t)
	_, oversizedPEM, oversizedCert := testcerts.Mint(t,
		unverifiableCA(253, cyclePCN, notBefore, notBefore.Add(720*time.Hour)),
		oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	if k, ok := oversizedCert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != oversizedBits {
		t.Fatalf("setup: minted certificate carries a %T, want a %d-bit RSA modulus", oversizedCert.PublicKey, oversizedBits)
	}

	// The leaf is signed by C, so the path ENTERS the cycle at C.
	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(254),
		Subject:      pkix.Name{CommonName: "entered-cycle-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, certC, keyC)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"oversized last", [][]byte{leafPEM, cyclePEMC, cyclePEMP, oversizedPEM}},
		{"oversized first", [][]byte{leafPEM, oversizedPEM, cyclePEMC, cyclePEMP}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse(a mutually-signed pair entered at its proven hop + a same-subject %d-bit namesake) = error %v, want the bundle converted: every hop the path selects is proven, so nothing is guessed",
					oversizedBits, err)
			}
			if serials := chainSerials(got.Chain()); len(serials) < 2 || serials[0] != "251" || serials[1] != "252" {
				t.Errorf("chain serials = %v, want it to BEGIN 251,252: the path enters at C and spends the proven C -> P edge", serials)
			}
			// The namesake may still be APPENDED by the additive fallback (it is
			// issuer-eligible and unplaceable, which assembleChain reports as its own
			// observation). What must not happen is it winning a HOP: it is not part
			// of the proven prefix above.
		})
	}
}

// TestAnalyse_converts_beside_an_over_ceiling_certificate_that_issues_nothing keeps
// the refusal narrow, the way the self-signed carve-out keeps the additive fallback
// narrow. A certificate this bundle names as nobody's issuer is never a parent in a
// signature check, so its key size decides nothing: it can only be excluded (said
// out loud) or kept by the additive fallback (also said out loud). Refusing the
// whole pair over it would turn a convertible input into a conversion failure,
// which withholds the health marker and restart-loops the container.
func TestAnalyse_converts_beside_an_over_ceiling_certificate_that_issues_nothing(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	identityKey := testcerts.NewECDSAKey(t)
	_, identityPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(214),
		Subject:      pkix.Name{CommonName: "narrow-refusal.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &identityKey.PublicKey, nil, identityKey)

	// Oversized, and unrelated to the identity by name and by key identifier, so it
	// is a candidate issuer of nothing here.
	throwawayKey := testcerts.NewECDSAKey(t)
	_, strangerPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(215),
		Subject:               pkix.Name{CommonName: "Unrelated Oversized CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(240 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, oversizedRSAPublicKey(convert.MaxVerifiableKeyBits+17), nil, throwawayKey)

	got, err := convert.Analyse(concatPEM(identityPEM, strangerPEM), testcerts.KeyPEM(t, identityKey))
	if err != nil {
		t.Fatalf("Analyse(self-signed identity + an unrelated oversized certificate) = error %v, want nil: an oversized certificate that issues nothing here cannot influence the chain", err)
	}
	if len(got.Chain()) != 0 {
		t.Errorf("chain length = %d, want 0: a self-signed identity has no chain", len(got.Chain()))
	}
	if len(got.Extra()) != 1 {
		t.Fatalf("Extra holds %d certificate(s), want the unrelated oversized certificate excluded", len(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want the exclusion reported", got.Observations())
	}
}

// TestAnalyse_ranks_verified_issuers_by_validity_then_expiry pins the two
// chain-selection keys betterParent documents but nothing else exercises:
// currently-valid beats not-yet-valid, and among equally valid candidates the
// later NotAfter wins. Both rows use two same-subject, same-key self-signed
// issuers so signature strength and root distance tie and only the ranking under
// test can decide the emitted chain.
func TestAnalyse_ranks_verified_issuers_by_validity_then_expiry(t *testing.T) {
	t.Parallel()
	now := time.Now()

	tests := map[string]struct {
		firstNotBefore  time.Time
		firstNotAfter   time.Time
		secondNotBefore time.Time
		secondNotAfter  time.Time
		wantSerial      int64
	}{
		"a current issuer outranks a future-dated issuer with a later expiry": {
			firstNotBefore:  now.Add(48 * time.Hour),
			firstNotAfter:   now.Add(72 * time.Hour),
			secondNotBefore: now.Add(-time.Hour),
			secondNotAfter:  now.Add(24 * time.Hour),
			wantSerial:      221,
		},
		"the later expiry breaks a tie between two current issuers": {
			firstNotBefore:  now.Add(-time.Hour),
			firstNotAfter:   now.Add(48 * time.Hour),
			secondNotBefore: now.Add(-time.Hour),
			secondNotAfter:  now.Add(24 * time.Hour),
			wantSerial:      220,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			issuerKey := testcerts.NewECDSAKey(t)
			issuer := func(serial int64, notBefore, notAfter time.Time) *x509.Certificate {
				return &x509.Certificate{
					SerialNumber:          big.NewInt(serial),
					Subject:               pkix.Name{CommonName: "Ranked Issuer CA"},
					NotBefore:             notBefore,
					NotAfter:              notAfter,
					IsCA:                  true,
					BasicConstraintsValid: true,
					KeyUsage:              x509.KeyUsageCertSign,
				}
			}
			_, firstPEM, _ := testcerts.Mint(t, issuer(220, tt.firstNotBefore, tt.firstNotAfter),
				&issuerKey.PublicKey, nil, issuerKey)
			_, secondPEM, secondCert := testcerts.Mint(t, issuer(221, tt.secondNotBefore, tt.secondNotAfter),
				&issuerKey.PublicKey, nil, issuerKey)

			leafKey := testcerts.NewECDSAKey(t)
			_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
				SerialNumber: big.NewInt(222),
				Subject:      pkix.Name{CommonName: "ranked-issuer-leaf.example.com"},
				NotBefore:    now.Add(-time.Hour),
				NotAfter:     now.Add(24 * time.Hour),
			}, &leafKey.PublicKey, secondCert, issuerKey)

			got, err := convert.Analyse(concatPEM(leafPEM, firstPEM, secondPEM), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) != 1 {
				t.Fatalf("chain length = %d, want 1", len(got.Chain()))
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(tt.wantSerial)) != 0 {
				t.Errorf("chain[0] serial = %s, want %d", got.Chain()[0].SerialNumber, tt.wantSerial)
			}
		})
	}
}

// unverifiableCA builds the certificate template every candidate issuer in the
// inclusive-route tests uses: a CA with the given subject and validity window.
func unverifiableCA(serial int64, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
}

// TestAnalyse_prefers_an_unverified_issuer_with_a_route_to_a_root pins the FIRST
// of the two inclusive-distance ranking keys in betterParent, the pair that only
// decides anything once NEITHER candidate has a verified route to a root -- the
// documented SHA-1 and name-encoding fallback, where no signature can be checked
// at all. Every other ranking test gives at least one candidate a verified route,
// so a mutation that drops or inverts this key emits a chain whose top link has
// no route to any root in the bundle, with no error and no observation.
//
// Both candidate issuers here carry the leaf's issuer name without having signed
// it (the leaf's real signer is absent), so the leaf's own hop cannot separate
// them. Only one of them chains by name to a root present in the bundle. The
// stranded candidate expires LATER, so every ranking key BELOW this one prefers
// it: if the route-presence key stops deciding, the emitted chain changes.
func TestAnalyse_prefers_an_unverified_issuer_with_a_route_to_a_root(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		sharedRootCN = "Shared Root"
		contestedCN  = "Contested CA"
	)

	// A root present in the bundle, and a same-named root that is NOT, holding a
	// different key. The absent one signs the routed candidate, so that candidate's
	// route to the included root is a NAME match no signature can confirm.
	fakeRootKey := testcerts.NewECDSAKey(t)
	_, fakeRootPEM, _ := testcerts.Mint(t, unverifiableCA(300, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&fakeRootKey.PublicKey, nil, fakeRootKey)
	absentRootKey := testcerts.NewECDSAKey(t)
	_, _, absentRootCert := testcerts.Mint(t, unverifiableCA(301, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentRootKey.PublicKey, nil, absentRootKey)

	// The routed candidate: names the included root as its issuer, so it has an
	// inclusive route to a root.
	routedKey := testcerts.NewECDSAKey(t)
	_, routedPEM, _ := testcerts.Mint(t, unverifiableCA(302, contestedCN, notBefore, notBefore.Add(24*time.Hour)),
		&routedKey.PublicKey, absentRootCert, absentRootKey)

	// The stranded candidate: names an issuer nothing in the bundle carries, so it
	// has no route to a root at all -- and it expires later, which is what every
	// lower-ranked key would reward.
	absentOtherKey := testcerts.NewECDSAKey(t)
	_, _, absentOtherCert := testcerts.Mint(t, unverifiableCA(303, "Nobody CA", notBefore, notBefore.Add(240*time.Hour)),
		&absentOtherKey.PublicKey, nil, absentOtherKey)
	strandedKey := testcerts.NewECDSAKey(t)
	_, strandedPEM, _ := testcerts.Mint(t, unverifiableCA(304, contestedCN, notBefore, notBefore.Add(72*time.Hour)),
		&strandedKey.PublicKey, absentOtherCert, absentOtherKey)

	// The leaf's real signer shares the contested subject and is absent, so neither
	// candidate verifies the leaf's signature.
	absentSignerKey := testcerts.NewECDSAKey(t)
	_, _, absentSignerCert := testcerts.Mint(t, unverifiableCA(305, contestedCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentSignerKey.PublicKey, nil, absentSignerKey)
	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(306),
		Subject:      pkix.Name{CommonName: "inclusive-route-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentSignerCert, absentSignerKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"stranded first", [][]byte{leafPEM, strandedPEM, routedPEM, fakeRootPEM}},
		{"routed first", [][]byte{leafPEM, routedPEM, strandedPEM, fakeRootPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) == 0 {
				t.Fatal("chain is empty; want the candidate issuer that chains to a root")
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(302)) != 0 {
				t.Errorf("chain[0] serial = %s, want 302 (the unverified candidate with a route to a root in the bundle, not the later-expiring candidate with none)",
					got.Chain()[0].SerialNumber)
			}
		})
	}
}

// TestAnalyse_prefers_the_shorter_inclusive_route pins the SECOND inclusive
// ranking key: with neither candidate verifiable and BOTH chaining by name to a
// root, the shorter route wins. Same reachability as the test above -- nothing
// else in the suite gets two unverified candidates that both reach a root, so a
// mutation that inverts this comparison silently emits the longer, later-expiring
// route instead.
func TestAnalyse_prefers_the_shorter_inclusive_route(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		sharedRootCN = "Shared Root"
		midCN        = "Mid CA"
		contestedCN  = "Contested CA"
	)

	fakeRootKey := testcerts.NewECDSAKey(t)
	_, fakeRootPEM, _ := testcerts.Mint(t, unverifiableCA(310, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&fakeRootKey.PublicKey, nil, fakeRootKey)
	absentRootKey := testcerts.NewECDSAKey(t)
	_, _, absentRootCert := testcerts.Mint(t, unverifiableCA(311, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentRootKey.PublicKey, nil, absentRootKey)

	// One name-hop from the included root.
	nearKey := testcerts.NewECDSAKey(t)
	_, nearPEM, _ := testcerts.Mint(t, unverifiableCA(312, contestedCN, notBefore, notBefore.Add(24*time.Hour)),
		&nearKey.PublicKey, absentRootCert, absentRootKey)

	// An intermediate one name-hop from the root, and the far candidate below it:
	// two hops, and a LATER expiry so the NotAfter key would reward it.
	midKey := testcerts.NewECDSAKey(t)
	_, midPEM, _ := testcerts.Mint(t, unverifiableCA(313, midCN, notBefore, notBefore.Add(240*time.Hour)),
		&midKey.PublicKey, absentRootCert, absentRootKey)
	absentMidKey := testcerts.NewECDSAKey(t)
	_, _, absentMidCert := testcerts.Mint(t, unverifiableCA(314, midCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentMidKey.PublicKey, nil, absentMidKey)
	farKey := testcerts.NewECDSAKey(t)
	_, farPEM, _ := testcerts.Mint(t, unverifiableCA(315, contestedCN, notBefore, notBefore.Add(72*time.Hour)),
		&farKey.PublicKey, absentMidCert, absentMidKey)

	absentSignerKey := testcerts.NewECDSAKey(t)
	_, _, absentSignerCert := testcerts.Mint(t, unverifiableCA(316, contestedCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentSignerKey.PublicKey, nil, absentSignerKey)
	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(317),
		Subject:      pkix.Name{CommonName: "shorter-route-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentSignerCert, absentSignerKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"far first", [][]byte{leafPEM, farPEM, midPEM, nearPEM, fakeRootPEM}},
		{"near first", [][]byte{leafPEM, nearPEM, fakeRootPEM, farPEM, midPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) == 0 {
				t.Fatal("chain is empty; want the nearer candidate issuer")
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(312)) != 0 {
				t.Errorf("chain[0] serial = %s, want 312 (the candidate one name-hop from a root in the bundle, not the later-expiring candidate two hops away)",
					got.Chain()[0].SerialNumber)
			}
		})
	}
}

// TestAnalyse_excludes_a_certificate_that_cannot_issue_certificates keeps the
// additive fallback from emitting chain material nothing supports.
//
// The rule this pins is narrow, and the narrowing is the point. RFC 5280
// eligibility on its own never removes a certificate — a CA that demonstrably
// SIGNED the leaf is emitted whatever its extensions claim, with
// ObsChainCertCannotIssue naming it
// (TestAnalyse_keeps_a_signing_CA_that_is_not_issuer_eligible pins that half).
// What is excluded here is a certificate for which BOTH kinds of evidence are
// absent: it signed nothing in this bundle, and its own extensions say it could not
// have. With the leaf's real issuer absent and a same-named certificate asserting
// CA:false beside it, the reproduced defect emitted that stranger as the sole CA
// bag, so every consumer's path validation rejected the generated PFX while
// conversion reported success. A certificate that is merely unverifiable must still
// be kept (TestAnalyse_keeps_certificates_when_the_issuer_cannot_be_established pins
// that half).
func TestAnalyse_excludes_a_certificate_that_cannot_issue_certificates(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	for _, tc := range []struct {
		name string
		// disqualify shapes the decoy's issuing-related fields.
		disqualify func(*x509.Certificate)
	}{
		{
			name: "basic constraints say CA:false",
			disqualify: func(c *x509.Certificate) {
				c.BasicConstraintsValid = true
				c.IsCA = false
				c.KeyUsage = x509.KeyUsageCertSign
			},
		},
		{
			name: "v3 certificate with no basic constraints",
			disqualify: func(c *x509.Certificate) {
				c.BasicConstraintsValid = false
				c.IsCA = false
				c.KeyUsage = x509.KeyUsageCertSign
			},
		},
		{
			name: "stated key usage omits certificate signing",
			disqualify: func(c *x509.Certificate) {
				c.BasicConstraintsValid = true
				c.IsCA = true
				c.KeyUsage = x509.KeyUsageDigitalSignature
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The leaf's real issuer is NOT in the bundle, so nothing present can
			// be proven to be its issuer.
			absentCAKey := testcerts.NewECDSAKey(t)
			_, _, absentCACert := testcerts.Mint(t, &x509.Certificate{
				SerialNumber:          big.NewInt(400),
				Subject:               pkix.Name{CommonName: "Absent Encoding CA"},
				NotBefore:             notBefore,
				NotAfter:              notBefore.Add(48 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}, &absentCAKey.PublicKey, nil, absentCAKey)

			leafKey := testcerts.NewECDSAKey(t)
			_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
				SerialNumber: big.NewInt(401),
				Subject:      pkix.Name{CommonName: "disqualified-issuer-leaf.example.com"},
				NotBefore:    notBefore,
				NotAfter:     notBefore.Add(24 * time.Hour),
			}, &leafKey.PublicKey, absentCACert, absentCAKey)

			// A decoy carrying the absent issuer's NAME, so name chaining alone
			// admits it, but disqualified from issuing certificates by its own
			// extensions.
			decoyKey := testcerts.NewECDSAKey(t)
			decoy := &x509.Certificate{
				SerialNumber: big.NewInt(402),
				Subject:      pkix.Name{CommonName: "Absent Encoding CA"},
				NotBefore:    notBefore,
				NotAfter:     notBefore.Add(48 * time.Hour),
			}
			tc.disqualify(decoy)
			_, decoyPEM, _ := testcerts.Mint(t, decoy, &decoyKey.PublicKey, nil, decoyKey)

			got, err := convert.Analyse(concatPEM(leafPEM, decoyPEM), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse(leaf beside a %s) = error %v, want nil", tc.name, err)
			}
			if len(got.Chain()) != 0 {
				t.Errorf("chain = %v, want empty: a certificate that cannot issue certificates is no chain material",
					chainSerials(got.Chain()))
			}
			if len(got.Extra()) != 1 {
				t.Fatalf("Extra holds %d certificate(s), want 1 (the disqualified decoy)", len(got.Extra()))
			}
			if !hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
				t.Errorf("observations = %v, want the exclusion reported", got.Observations())
			}
			if !hasObservation(got.Observations(), convert.ObsChainUnverified) {
				t.Errorf("observations = %v, want the unverified chain reported too", got.Observations())
			}
		})
	}
}

// utf8SubjectView returns a parent VIEW of c whose subject is the same name encoded
// as a UTF8String rather than c's own canonical encoding, with the subject key
// identifier removed.
//
// A certificate minted against this view therefore carries an issuer name that is
// SEMANTICALLY equal to c's subject but byte-distinct, and no authority key
// identifier — exactly the RFC 5280 permitted-encoding difference that defeats both
// of the inclusive edge signals while the signature itself stays valid.
func utf8SubjectView(c *x509.Certificate, cn string) *x509.Certificate {
	view := *c
	view.RawSubject = nil
	view.SubjectKeyId = nil
	view.Subject = pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{
		Type: oidCommonName,
		Value: asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagUTF8String,
			Bytes: []byte(cn),
		},
	}}}
	return &view
}

// TestAnalyse_reports_an_unproven_edge_linked_only_by_key_identifier pins the
// key-identifier arm of the unproven-edge diagnostic. The emitted chain here is
// linked to its issuer by AKI/SKI alone -- the names differ -- so a regression that
// collapsed the two arms would tell the operator the issuer name matches when it
// does not, pointing them at a field they can check and find wrong. Every other
// unproven-edge test covers the name-linked arm, so that collapse passes the suite.
func TestAnalyse_reports_an_unproven_edge_linked_only_by_key_identifier(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	keyID := []byte{0x01, 0x23, 0x45, 0x67}

	absentKey := testcerts.NewECDSAKey(t)
	absentTemplate := unverifiableCA(870, "Absent AKI Signer", notBefore, notBefore.Add(48*time.Hour))
	absentTemplate.SubjectKeyId = keyID
	_, _, absentCert := testcerts.Mint(t, absentTemplate, &absentKey.PublicKey, nil, absentKey)

	decoyKey := testcerts.NewECDSAKey(t)
	decoyTemplate := unverifiableCA(871, "Different Subject CA", notBefore, notBefore.Add(48*time.Hour))
	decoyTemplate.SubjectKeyId = keyID
	_, decoyPEM, decoyCert := testcerts.Mint(t, decoyTemplate, &decoyKey.PublicKey, nil, decoyKey)

	leafKey := testcerts.NewECDSAKey(t)
	leafTemplate := unverifiableCA(872, "aki-only-leaf.example.com", notBefore, notBefore.Add(24*time.Hour))
	leafTemplate.IsCA = false
	leafTemplate.BasicConstraintsValid = false
	leafTemplate.KeyUsage = 0
	_, leafPEM, leafCert := testcerts.Mint(t, leafTemplate, &leafKey.PublicKey, absentCert, absentKey)

	if bytes.Equal(leafCert.RawIssuer, decoyCert.RawSubject) {
		t.Fatal("setup: issuer and subject names match, so the key-identifier-only branch is not reached")
	}
	if !bytes.Equal(leafCert.AuthorityKeyId, decoyCert.SubjectKeyId) {
		t.Fatal("setup: authority and subject key identifiers differ, so no candidate edge exists")
	}

	got, err := convert.Analyse(concatPEM(leafPEM, decoyPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if serials := strings.Join(chainSerials(got.Chain()), ","); serials != "871" {
		t.Fatalf("chain serials = %s, want 871: the AKI/SKI-linked decoy is the emitted unproven edge", serials)
	}
	detail, ok := observationDetail(got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	if !ok {
		t.Fatalf("observations = %v, want %q", got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	}
	if !strings.Contains(detail, "carries the subject key identifier named as the authority key identifier of") {
		t.Errorf("observation detail = %q, want the AKI/SKI evidence named", detail)
	}
	if strings.Contains(detail, "matches the issuer name of") {
		t.Errorf("observation detail = %q, want no issuer-name claim for an edge whose names differ", detail)
	}
}

// TestAnalyse_drops_a_shared_key_issuer_across_a_name_encoding_difference pins
// identity role against a bundle where the ONLY evidence of issuance is the
// signature itself: one ECDSA key belongs to both a CA and the leaf it signed, and
// the leaf's issuer name is the CA's subject in a permitted but byte-distinct
// encoding, so neither candidate-edge signal fires. Judging role off the candidate
// graph alone read the CA as a non-issuer, let it compete for identity, and let it
// win on its later NotBefore — emitting a zero-chain PFX for the CA instead of the
// leaf the operator asked to convert.
func TestAnalyse_drops_a_shared_key_issuer_across_a_name_encoding_difference(t *testing.T) {
	t.Parallel()
	sharedKey := testcerts.NewECDSAKey(t)
	now := time.Now().Truncate(time.Second)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(600), Subject: pkix.Name{CommonName: "Shared Encoding CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &sharedKey.PublicKey, nil, sharedKey)
	_, leafPEM, leafCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(601), Subject: pkix.Name{CommonName: "encoding-leaf.example.com"},
		NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(24 * time.Hour),
	}, &sharedKey.PublicKey, utf8SubjectView(caCert, "Shared Encoding CA"), sharedKey)
	if bytes.Equal(leafCert.RawIssuer, caCert.RawSubject) {
		t.Fatal("setup: issuer and subject encodings unexpectedly match")
	}
	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("setup: CA did not actually sign leaf: %v", err)
	}
	got, err := convert.Analyse(concatPEM(leafPEM, caPEM), testcerts.KeyPEM(t, sharedKey))
	if err != nil {
		t.Fatalf("Analyse = %v, want the end-entity identity", err)
	}
	if got.Leaf().SerialNumber.Cmp(big.NewInt(601)) != 0 {
		t.Errorf("selected identity serial = %s, want 601", got.Leaf().SerialNumber)
	}
	if len(got.Chain()) != 1 || got.Chain()[0].SerialNumber.Cmp(big.NewInt(600)) != 0 {
		t.Errorf("chain serials = %v, want [600]", chainSerials(got.Chain()))
	}
	if !hasObservation(got.Observations(), convert.ObsIssuerMatchIgnored) {
		t.Errorf("observations = %v, want the passed-over issuer match reported", got.Observations())
	}
}

// rdnSequence builds a distinguished name as an explicit RDN SEQUENCE, one
// single-valued RDN per attribute in the order given, encoded as PrintableStrings.
//
// The order is the point: pkix.Name cannot express it (ToRDNSequence rebuilds the
// attributes it knows in a fixed order), so a test that needs two names holding the
// same values in a DIFFERENT order has to marshal the sequence itself.
func rdnSequence(attrs ...pkix.AttributeTypeAndValue) pkix.RDNSequence {
	seq := make(pkix.RDNSequence, 0, len(attrs))
	for _, at := range attrs {
		seq = append(seq, pkix.RelativeDistinguishedNameSET{at})
	}
	return seq
}

// printableAttr is one RDN attribute carrying a PrintableString value.
func printableAttr(oid asn1.ObjectIdentifier, value string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: oid, Value: asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagPrintableString,
		Bytes: []byte(value),
	}}
}

var (
	oidCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}  // id-at-commonName
	oidOrganisation = asn1.ObjectIdentifier{2, 5, 4, 10} // id-at-organizationName
)

// rawNameOf marshals an RDN sequence to DER for use as a template's RawSubject.
func rawNameOf(t *testing.T, seq pkix.RDNSequence) []byte {
	t.Helper()
	der, err := asn1.Marshal(seq)
	if err != nil {
		t.Fatalf("setup: marshal RDNSequence: %v", err)
	}
	return der
}

// reorderedSubjectView returns a parent VIEW of c whose subject is seq rather than
// c's own, with the subject key identifier removed.
//
// A certificate minted against this view carries an issuer name that is byte- AND
// semantically distinct from c's subject (a different RDN order is a different DN
// under RFC 5280) while c's key still signs it, and no authority key identifier —
// the shape that separates "this CA's key signed it" from "this CA issued it".
func reorderedSubjectView(t *testing.T, c *x509.Certificate, seq pkix.RDNSequence) *x509.Certificate {
	t.Helper()
	view := *c
	view.RawSubject = rawNameOf(t, seq)
	view.SubjectKeyId = nil
	view.Subject = pkix.Name{}
	return &view
}

// TestAnalyse_keeps_a_ca_identity_whose_subject_only_matches_an_issuer_name_approximately
// pins the semantic-name fallback against the OTHER half of RFC 5280 name equality:
// two DNs holding the same attribute values in a different RDN order are different
// names, and a CA whose key happens to have signed a certificate naming that other
// DN did not issue it.
//
// Comparing pkix.Name.ToRDNSequence() conflated the two — crypto/x509 documents
// pkix.Name as an approximation, and the round trip rebuilds known attributes in a
// fixed order — so the fallback read this CA as an issuer of the co-bundled
// certificate. As the only match for the supplied key it then hit the role check
// and the whole conversion was refused, with an error telling the operator to
// remove certificates this CA never issued.
func TestAnalyse_keeps_a_ca_identity_whose_subject_only_matches_an_issuer_name_approximately(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	caKey := testcerts.NewECDSAKey(t)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(700),
		// O then CN.
		RawSubject: rawNameOf(t, rdnSequence(
			printableAttr(oidOrganisation, "Reordered Name Ltd"),
			printableAttr(oidCommonName, "Reordered Name CA"),
		)),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	// Signed by the CA's key, but naming an issuer whose RDNs are in the other
	// order: CN then O.
	otherKey := testcerts.NewECDSAKey(t)
	_, otherPEM, otherCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(701),
		Subject:      pkix.Name{CommonName: "reordered-leaf.example.com"},
		NotBefore:    now.Add(-2 * time.Hour), NotAfter: now.Add(24 * time.Hour),
	}, &otherKey.PublicKey, reorderedSubjectView(t, caCert, rdnSequence(
		printableAttr(oidCommonName, "Reordered Name CA"),
		printableAttr(oidOrganisation, "Reordered Name Ltd"),
	)), caKey)

	if bytes.Equal(otherCert.RawIssuer, caCert.RawSubject) {
		t.Fatal("setup: the co-bundled certificate's issuer name matches the CA's subject byte for byte, so this bundle does not reproduce a distinct DN")
	}
	if len(otherCert.AuthorityKeyId) > 0 {
		t.Fatal("setup: the co-bundled certificate carries an authority key identifier, so a candidate edge would exist and the fallback would never be asked")
	}
	if err := otherCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("setup: the CA's key did not sign the co-bundled certificate, so the fallback's signature gate would answer instead of its name comparison: %v", err)
	}
	// The trap being pinned: the pkix approximation of the two names collides even
	// though the names differ. Without this the test would pass against the
	// approximate comparison too and prove nothing.
	if !bytes.Equal(rawNameOf(t, caCert.Subject.ToRDNSequence()), rawNameOf(t, otherCert.Issuer.ToRDNSequence())) {
		t.Fatal("setup: the pkix.Name approximations of the two names differ, so this bundle no longer reproduces the false issuer match")
	}

	got, err := convert.Analyse(concatPEM(caPEM, otherPEM), testcerts.KeyPEM(t, caKey))
	if err != nil {
		t.Fatalf("Analyse(CA whose subject only approximately matches a co-bundled issuer name) = error %v, want the CA identity: it issued nothing in this bundle", err)
	}
	if got.Leaf().SerialNumber.Cmp(big.NewInt(700)) != 0 {
		t.Errorf("selected identity serial = %s, want 700 (the CA, the only certificate the supplied key matches)", got.Leaf().SerialNumber)
	}
	if !hasObservation(got.Observations(), convert.ObsCAAsIdentity) {
		t.Errorf("observations = %v, want the CA-as-identity observation", got.Observations())
	}
}

// observationDetail returns the detail of the first observation of kind k. Tests
// that assert an observation NAMES a certificate need the text, not just the kind:
// a diagnostic that fires without saying which certificate is at fault costs the
// operator the same investigation as no diagnostic at all.
func observationDetail(obs []convert.Observation, k convert.ObservationKind) (string, bool) {
	for _, o := range obs {
		if o.Kind == k {
			return o.Detail, true
		}
	}
	return "", false
}

// TestAnalyse_keeps_a_signing_CA_that_is_not_issuer_eligible pins the split
// between what a certificate DID and what its extensions say it SHOULD have done.
//
// The shape is an internal CA minted by a bare `openssl req -x509`: self-signed,
// no basicConstraints extension at all, and it genuinely signed the leaf. RFC 5280
// 4.2.1.9 says such a key must not be used to verify certificate signatures, which
// is why crypto/x509's CheckSignatureFrom refuses it as a parent, so no VERIFIED
// edge to it can ever exist. Applying that eligibility rule to candidacy as well
// removed the certificate from the graph outright: the emitted PFX lost its only CA
// bag, and the operator was told the chain was unverified and the CA excluded --
// worse than the silence that preceded it, because the material was gone too.
//
// This app converts formats and holds no trust store; PKCS#12 CA bags are a bag of
// certificates, not a validated path. So a signature is ground truth and eligibility
// is a diagnostic: the CA is emitted, and ObsChainCertCannotIssue tells the operator
// their CA is non-compliant and that a strict consumer will reject the chain. The
// fallback observations must be absent, because there is nothing unestablished here
// -- the chain was proven by signature.
func TestAnalyse_keeps_a_signing_CA_that_is_not_issuer_eligible(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	// A self-signed CA with NO basic constraints: BasicConstraintsValid false emits
	// no extension, and a zero KeyUsage emits none either, so its only
	// disqualification is the missing basicConstraints RFC 5280 requires of a v3
	// issuer. This is what `openssl req -x509` produces without CA flags.
	caKey := testcerts.NewECDSAKey(t)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(500),
		Subject:      pkix.Name{CommonName: "No-BC Internal CA"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(72 * time.Hour),
	}, &caKey.PublicKey, nil, caKey)
	if caCert.BasicConstraintsValid {
		t.Fatal("setup: the CA fixture carries basic constraints; the shape under test is a CA without them")
	}

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(501),
		Subject:      pkix.Name{CommonName: "no-bc-ca-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	got, err := convert.Analyse(concatPEM(leafPEM, caPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(leaf signed by a CA with no basic constraints) = error %v, want nil", err)
	}

	if len(got.Chain()) != 1 {
		t.Fatalf("chain = %v, want the signing CA as the one CA bag: a certificate that demonstrably signed the leaf is chain material whatever its extensions claim",
			chainSerials(got.Chain()))
	}
	if !bytes.Equal(got.Chain()[0].Raw, caCert.Raw) {
		t.Errorf("chain[0] = %q, want %q", got.Chain()[0].Subject.CommonName, caCert.Subject.CommonName)
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra holds %d certificate(s), want 0: the CA belongs in the chain, not beside it", len(got.Extra()))
	}

	detail, ok := observationDetail(got.Observations(), convert.ObsChainCertCannotIssue)
	if !ok {
		t.Fatalf("observations = %v, want %q: carrying a non-compliant CA silently is the defect that preceded the exclusion",
			got.Observations(), convert.ObsChainCertCannotIssue)
	}
	if !strings.Contains(detail, "No-BC Internal CA") {
		t.Errorf("%s detail = %q, want it to name the non-compliant CA", convert.ObsChainCertCannotIssue, detail)
	}
	if !strings.Contains(detail, "basicConstraints") {
		t.Errorf("%s detail = %q, want it to name the missing extension the operator has to fix", convert.ObsChainCertCannotIssue, detail)
	}

	// The chain IS established -- by signature -- so neither fallback observation
	// applies, and nothing may report the emitted CA as excluded.
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: the CA's signature over the leaf establishes the chain",
			got.Observations(), convert.ObsChainUnverified)
	}
	if excluded, ok := observationDetail(got.Observations(), convert.ObsExtraCertsExcluded); ok {
		t.Errorf("observations report %q = %q, want no exclusion: the only other certificate is in the emitted chain",
			convert.ObsExtraCertsExcluded, excluded)
	}
}

// TestAnalyse_emits_a_compliant_chain_unchanged_and_silently is the common-path
// guard for the eligibility/signature split: an ordinary leaf + intermediate + root
// bundle must emit exactly the same three bags in the same order it always did, and
// say nothing at all.
//
// Both halves are load-bearing. The bag sequence is a PKCS#12 contract (decoders
// read it positionally), so it is asserted on the DER rather than on subject names.
// The silence is what keeps the new non-compliance diagnostic from becoming noise:
// a warning that fires on every well-formed renewal in the deployment would be
// tuned out long before the one bundle that needs it appears.
func TestAnalyse_emits_a_compliant_chain_unchanged_and_silently(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	rootKey := testcerts.NewECDSAKey(t)
	_, rootPEM, rootCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(510),
		Subject:               pkix.Name{CommonName: "Compliant Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &rootKey.PublicKey, nil, rootKey)

	interKey := testcerts.NewECDSAKey(t)
	_, interPEM, interCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(511),
		Subject:               pkix.Name{CommonName: "Compliant Intermediate CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &interKey.PublicKey, rootCert, rootKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(512),
		Subject:      pkix.Name{CommonName: "compliant-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, interCert, interKey)

	got, err := convert.Analyse(concatPEM(leafPEM, interPEM, rootPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(compliant leaf+intermediate+root) = error %v, want nil", err)
	}

	want := []*x509.Certificate{interCert, rootCert}
	if len(got.Chain()) != len(want) {
		t.Fatalf("chain = %v, want %v (intermediate then root)", chainSerials(got.Chain()), chainSerials(want))
	}
	for i := range want {
		if !bytes.Equal(got.Chain()[i].Raw, want[i].Raw) {
			t.Errorf("chain[%d] = serial %s, want serial %s", i, got.Chain()[i].SerialNumber, want[i].SerialNumber)
		}
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra holds %d certificate(s), want 0", len(got.Extra()))
	}
	if len(got.Observations()) != 0 {
		t.Errorf("observations = %v, want none: every certificate here is well-formed, in order and current", got.Observations())
	}
}

// TestAnalyse_orders_a_chain_proven_across_a_name_encoding_difference is the
// behaviour the unified evidence graph exists for, asserted on ORDER rather than
// membership.
//
// Shape: leaf -> lower CA -> upper CA -> root, with the lower CA naming the upper
// one through a permitted but byte-distinct DirectoryString encoding and no key
// identifiers, and the CAs listed in the file in an order that is NOT ancestry
// order. While issuance was decided by raw DER names for the chain and by decoded
// names only for identity/role selection, the app could PROVE the upper CA signed
// the lower one when it picked the identity and still fail to place that edge in the
// chain: the certificates arrived through the additive fallback, which appends what
// it keeps in INPUT order, so the emitted bag sequence stopped matching ancestry --
// and go-pkcs12's decoder reads that sequence positionally.
//
// With one graph carrying name linkage at both fidelities, every hop here is proven,
// the path walk emits nearest-parent-first, and the fallback never fires. Membership
// alone cannot see this: the OLD code also emitted all three CAs.
func TestAnalyse_orders_a_chain_proven_across_a_name_encoding_difference(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	rootKey := testcerts.NewECDSAKey(t)
	_, rootPEM, rootCert := testcerts.Mint(t, unverifiableCA(800, "Ordered Encoding Root CA", notBefore, notBefore.Add(96*time.Hour)),
		&rootKey.PublicKey, nil, rootKey)
	upperKey := testcerts.NewECDSAKey(t)
	_, upperPEM, upperCert := testcerts.Mint(t, unverifiableCA(801, "Ordered Encoding Upper CA", notBefore, notBefore.Add(72*time.Hour)),
		&upperKey.PublicKey, rootCert, rootKey)
	lowerKey := testcerts.NewECDSAKey(t)
	_, lowerPEM, lowerCert := testcerts.Mint(t, unverifiableCA(802, "Ordered Encoding Lower CA", notBefore, notBefore.Add(48*time.Hour)),
		&lowerKey.PublicKey, utf8SubjectView(upperCert, "Ordered Encoding Upper CA"), upperKey)
	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(803),
		Subject:      pkix.Name{CommonName: "ordered-encoding-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, lowerCert, lowerKey)

	if bytes.Equal(lowerCert.RawIssuer, upperCert.RawSubject) {
		t.Fatal("setup: the lower CA's issuer name matches the upper CA's subject byte for byte, so this bundle does not reproduce the encoding difference")
	}
	if len(lowerCert.AuthorityKeyId) > 0 {
		t.Fatal("setup: the lower CA carries an authority key identifier, so the key-identifier signal would find the upper CA without the name comparison")
	}
	if err := upperCert.CheckSignature(lowerCert.SignatureAlgorithm, lowerCert.RawTBSCertificate, lowerCert.Signature); err != nil {
		t.Fatalf("setup: the upper CA did not sign the lower CA, so there is no proof for the graph to find: %v", err)
	}

	// Input order deliberately breaks ancestry: root before upper. The additive
	// fallback would emit 802,800,801.
	got, err := convert.Analyse(concatPEM(leafPEM, lowerPEM, rootPEM, upperPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(chain proven across an encoding difference) = error %v, want nil", err)
	}
	if serials := strings.Join(chainSerials(got.Chain()), ","); serials != "802,801,800" {
		t.Errorf("chain serials = %s, want 802,801,800 (ancestry order from the path walk, not the input order an additive tail would emit)",
			serials)
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra holds %d certificate(s), want 0", len(got.Extra()))
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: every edge in this bundle is proven by signature",
			got.Observations(), convert.ObsChainUnverified)
	}
	if len(got.Observations()) != 0 {
		t.Errorf("observations = %v, want none for a fully proven, in-window bundle", got.Observations())
	}
}

// TestAnalyse_keeps_an_unproven_name_match_from_being_promoted holds the other side
// of the widened name signal: teaching the graph semantically-equal names must not
// let a name alone stand in for a signature.
//
// Both halves were reproduced against a model that compared decoded names without
// re-applying the exclusions the raw-name model already had.
func TestAnalyse_keeps_an_unproven_name_match_from_being_promoted(t *testing.T) {
	t.Parallel()

	// Proof outranks name fidelity: the certificate that actually signed the leaf is
	// linked to it only SEMANTICALLY, while an impostor matching the leaf's issuer
	// name byte for byte holds a different key and expires later, so every ranking
	// key below edge strength -- and any rule preferring an exact name match to a
	// decoded one -- would emit the impostor as the leaf's CA.
	t.Run("an exact name match does not outrank a proven signature", func(t *testing.T) {
		t.Parallel()
		notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

		realKey := testcerts.NewECDSAKey(t)
		_, realPEM, realCert := testcerts.Mint(t, unverifiableCA(810, "Promoted Encoding CA", notBefore, notBefore.Add(48*time.Hour)),
			&realKey.PublicKey, nil, realKey)
		leafKey := testcerts.NewECDSAKey(t)
		_, leafPEM, leafCert := testcerts.Mint(t, &x509.Certificate{
			SerialNumber: big.NewInt(811),
			Subject:      pkix.Name{CommonName: "promoted-encoding-leaf.example.com"},
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(24 * time.Hour),
		}, &leafKey.PublicKey, utf8SubjectView(realCert, "Promoted Encoding CA"), realKey)

		// The impostor's subject is the leaf's issuer name EXACTLY, copied from the
		// leaf so the DER cannot drift, and it signed nothing here.
		impostorKey := testcerts.NewECDSAKey(t)
		impostor := unverifiableCA(812, "", notBefore, notBefore.Add(240*time.Hour))
		impostor.RawSubject = leafCert.RawIssuer
		_, impostorPEM, impostorCert := testcerts.Mint(t, impostor, &impostorKey.PublicKey, nil, impostorKey)

		if !bytes.Equal(impostorCert.RawSubject, leafCert.RawIssuer) {
			t.Fatal("setup: the impostor's subject is not the leaf's issuer name byte for byte, so it is not the exact-match candidate under test")
		}
		if bytes.Equal(realCert.RawSubject, leafCert.RawIssuer) {
			t.Fatal("setup: the real signer's subject matches the leaf's issuer name byte for byte, so the semantic signal is not exercised")
		}

		for _, order := range []struct {
			name  string
			certs [][]byte
		}{
			{"impostor first", [][]byte{leafPEM, impostorPEM, realPEM}},
			{"real signer first", [][]byte{leafPEM, realPEM, impostorPEM}},
		} {
			t.Run(order.name, func(t *testing.T) {
				t.Parallel()
				got, err := convert.Analyse(concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
				if err != nil {
					t.Fatalf("Analyse = error %v, want nil", err)
				}
				if len(got.Chain()) == 0 {
					t.Fatal("chain is empty; want the CA that signed the leaf")
				}
				if got.Chain()[0].SerialNumber.Cmp(big.NewInt(810)) != 0 {
					t.Errorf("chain[0] serial = %s, want 810 (the proven signer named through an encoding difference, not the byte-exact same-name impostor)",
						got.Chain()[0].SerialNumber)
				}
			})
		}
	})

	// The key-reuse exclusion has to survive the decoded comparison too. Two
	// self-signed certificates holding ONE key, the second re-encoding the same
	// subject, are a regenerated certificate beside its predecessor: each verifies
	// against the other, so without the exclusion both read as issuers, both matches
	// are dropped, and the role check refuses a bundle that converts fine today.
	t.Run("key reuse across an encoding difference is not issuance", func(t *testing.T) {
		t.Parallel()
		notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
		sharedKey := testcerts.NewECDSAKey(t)

		_, firstPEM, firstCert := testcerts.Mint(t, unverifiableCA(820, "Regenerated Encoding CA", notBefore, notBefore.Add(48*time.Hour)),
			&sharedKey.PublicKey, nil, sharedKey)
		// Same name, encoded the other permitted way, same key: a regeneration.
		reissued := unverifiableCA(821, "", notBefore.Add(time.Minute), notBefore.Add(96*time.Hour))
		reissuedView := utf8SubjectView(firstCert, "Regenerated Encoding CA")
		reissued.RawSubject = nil
		reissued.Subject = reissuedView.Subject
		_, secondPEM, secondCert := testcerts.Mint(t, reissued, &sharedKey.PublicKey, reissuedView, sharedKey)

		if bytes.Equal(firstCert.RawSubject, secondCert.RawSubject) {
			t.Fatal("setup: both certificates encode the subject identically, so the raw-name exclusion alone would cover this bundle")
		}
		if !bytes.Equal(secondCert.RawSubject, secondCert.RawIssuer) {
			t.Fatal("setup: the regenerated certificate is not self-signed under its own re-encoded name")
		}

		got, err := convert.Analyse(concatPEM(firstPEM, secondPEM), testcerts.KeyPEM(t, sharedKey))
		if err != nil {
			t.Fatalf("Analyse(a regenerated self-signed certificate re-encoding its own subject) = error %v, want nil: reusing a key is not issuing a certificate", err)
		}
		if got.Leaf().SerialNumber.Cmp(big.NewInt(821)) != 0 {
			t.Errorf("selected identity serial = %s, want 821 (the later-issued certificate of the pair)", got.Leaf().SerialNumber)
		}
		if len(got.Chain()) != 0 {
			t.Errorf("chain = %v, want empty: a self-signed identity has no chain, and its predecessor did not issue it",
				chainSerials(got.Chain()))
		}
	})
}

// TestAnalyse_excludes_a_stranger_once_the_encoding_gap_is_proven names the emitted
// content this change moves, which is the reason it is a decision and not a cleanup.
//
// The additive fallback keeps every issuer-eligible extra whenever the discovered
// path does not reach a proven self-signed terminus. While a permitted name-encoding
// difference blocked the leaf's own edge, that condition held for this bundle, so an
// unrelated CA sitting beside the real one was swept into the PFX as well. Proving
// the edge ends the path at a self-signed root, so the fallback does not fire and the
// stranger is excluded and named instead.
//
// This is the fallback's over-inclusion shrinking to the bundles that are genuinely
// unprovable; the fallback's own policy for those is unchanged
// (TestAnalyse_keeps_certificates_when_the_issuer_cannot_be_established still pins
// it).
func TestAnalyse_excludes_a_stranger_once_the_encoding_gap_is_proven(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	caKey := testcerts.NewECDSAKey(t)
	_, caPEM, caCert := testcerts.Mint(t, unverifiableCA(830, "Proven Gap CA", notBefore, notBefore.Add(48*time.Hour)),
		&caKey.PublicKey, nil, caKey)
	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, leafCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(831),
		Subject:      pkix.Name{CommonName: "proven-gap-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, utf8SubjectView(caCert, "Proven Gap CA"), caKey)
	strangerKey := testcerts.NewECDSAKey(t)
	_, strangerPEM, _ := testcerts.Mint(t, unverifiableCA(832, "Unrelated Bystander CA", notBefore, notBefore.Add(240*time.Hour)),
		&strangerKey.PublicKey, nil, strangerKey)

	if bytes.Equal(leafCert.RawIssuer, caCert.RawSubject) {
		t.Fatal("setup: issuer and subject encodings unexpectedly match, so the gap under test is absent")
	}

	got, err := convert.Analyse(concatPEM(leafPEM, caPEM, strangerPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if serials := strings.Join(chainSerials(got.Chain()), ","); serials != "830" {
		t.Errorf("chain serials = %s, want 830 alone: the proven CA is the whole chain, and the bystander is not part of it", serials)
	}
	if len(got.Extra()) != 1 || got.Extra()[0].SerialNumber.Cmp(big.NewInt(832)) != 0 {
		t.Fatalf("Extra = %v, want the unrelated bystander alone", chainSerials(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want the exclusion reported: a certificate left out of the bundle is never silent", got.Observations())
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: the leaf's issuer is proven", got.Observations(), convert.ObsChainUnverified)
	}
}

// TestAnalyse_reports_an_unproven_emitted_chain_edge pins the observation for the
// shape ObsChainUnverified cannot reach: the discovered path ends at a certificate
// that IS proven self-signed, so the additive fallback branch is skipped, while the
// hop below it rests on a name match alone. Here the leaf's real signer is absent
// and a same-subject self-signed decoy holding a different key wins the chain, so
// the emitted issuer never signed anything in this bundle. The chain is deliberate
// (bestParent falls back to a merely-linked candidate when no proven one exists),
// but before this observation existed the whole bundle converted with ZERO
// observations, and a PKCS#12 CA bag a consumer imports into a trust store is the
// wrong place for that to be silent.
func TestAnalyse_reports_an_unproven_emitted_chain_edge(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const issuerCN = "Absent Signer CA"

	// The real signer, absent from the bundle.
	absentKey := testcerts.NewECDSAKey(t)
	_, _, absentCert := testcerts.Mint(t, unverifiableCA(840, issuerCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentKey.PublicKey, nil, absentKey)

	// The decoy: same subject, different key, self-signed - so it is a proven root
	// and the path terminates on it, while its key never signed the leaf.
	decoyKey := testcerts.NewECDSAKey(t)
	_, decoyPEM, _ := testcerts.Mint(t, unverifiableCA(841, issuerCN, notBefore, notBefore.Add(240*time.Hour)),
		&decoyKey.PublicKey, nil, decoyKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(842),
		Subject:      pkix.Name{CommonName: "unproven-edge-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentCert, absentKey)

	got, err := convert.Analyse(concatPEM(leafPEM, decoyPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if serials := strings.Join(chainSerials(got.Chain()), ","); serials != "841" {
		t.Fatalf("chain serials = %s, want 841 alone: the setup's premise is that the decoy wins the chain", serials)
	}
	if !hasObservation(got.Observations(), convert.ObsChainEdgeUnprovenIssuer) {
		t.Errorf("observations = %v, want %q: the emitted issuer never signed the leaf, and nothing else in the output says so",
			got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	}
}

// TestAnalyse_treats_a_reencoded_self_issued_certificate_as_its_own_root pins the
// positive direction of the decoded self-issuance rule (checkSelfSigned): a
// certificate whose own subject and issuer differ only in a permitted
// DirectoryString encoding is self-signed, so the additive fallback stays quiet
// and an unrelated eligible bystander is EXCLUDED rather than kept. Under the
// byte-only rule this bundle read as rootless: ObsChainUnverified fired and the
// bystander was appended to the chain.
func TestAnalyse_treats_a_reencoded_self_issued_certificate_as_its_own_root(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	key := testcerts.NewECDSAKey(t)
	tmpl := unverifiableCA(860, "Self Encoding Root CA", notBefore, notBefore.Add(48*time.Hour))
	// Sign against a view of the SAME template whose subject is the UTF8String
	// encoding, so RawIssuer is a permitted re-encoding of RawSubject.
	_, selfPEM, selfCert := testcerts.Mint(t, tmpl, &key.PublicKey,
		utf8SubjectView(tmpl, "Self Encoding Root CA"), key)
	if bytes.Equal(selfCert.RawSubject, selfCert.RawIssuer) {
		t.Fatal("setup: subject and issuer encode identically, so the branch under test is not reached")
	}

	strangerKey := testcerts.NewECDSAKey(t)
	_, strangerPEM, _ := testcerts.Mint(t, unverifiableCA(861, "Unrelated Bystander CA", notBefore, notBefore.Add(48*time.Hour)),
		&strangerKey.PublicKey, nil, strangerKey)

	got, err := convert.Analyse(concatPEM(selfPEM, strangerPEM), testcerts.KeyPEM(t, key))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if len(got.Chain()) != 0 {
		t.Errorf("chain = %v, want empty: a self-issued certificate is its own root", chainSerials(got.Chain()))
	}
	if len(got.Extra()) != 1 || got.Extra()[0].SerialNumber.Cmp(big.NewInt(861)) != 0 {
		t.Fatalf("Extra = %v, want the bystander alone", chainSerials(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want %q: the bystander's exclusion is never silent",
			got.Observations(), convert.ObsExtraCertsExcluded)
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: the identity is proven self-signed, so the additive fallback must not fire",
			got.Observations(), convert.ObsChainUnverified)
	}
}

// TestAnalyse_reports_an_unfinished_chain_with_nothing_left_over pins the fact the
// terminus diagnostic was once gated on leftovers for: a CA-signed leaf ALONE has an
// unfinished chain and no leftover certificate to append, so the diagnostic branch was
// skipped and the app's only input-diagnostic channel said nothing about the missing
// issuer. Conversion still succeeds with an empty chain - a PFX holding just the
// identity is a legitimate output - but it must not be silent.
//
// Which KIND it is not silent with was settled separately: nothing was left over, so
// there is nothing this app failed to place, and the only fact is that the issuer above
// the leaf is absent. That is ObsChainTrustAnchorAbsent at the informational class, and
// ObsChainUnverified (a warning about certificates carried without established
// ancestry) must NOT fire here - it was reporting a leftover disposition for a bundle
// with no leftovers.
func TestAnalyse_reports_an_unfinished_chain_with_nothing_left_over(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	caKey := testcerts.NewECDSAKey(t)
	_, _, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(870),
		Subject:               pkix.Name{CommonName: "Absent Issuing CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(871),
		Subject:      pkix.Name{CommonName: "lonely-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	got, err := convert.Analyse(leafPEM, testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(a CA-signed leaf alone) = error %v, want nil", err)
	}
	if len(got.Chain()) != 0 {
		t.Errorf("chain = %v, want empty: the issuer is not in the bundle", chainSerials(got.Chain()))
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra = %v, want empty: there is nothing besides the identity", chainSerials(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainTrustAnchorAbsent) {
		t.Errorf("observations = %v, want %q: the leaf is not self-signed and its issuer could not be established",
			got.Observations(), convert.ObsChainTrustAnchorAbsent)
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: nothing was left over, so nothing was carried without established ancestry",
			got.Observations(), convert.ObsChainUnverified)
	}
	if got := convert.ObsChainTrustAnchorAbsent.Class(); got != convert.ObservationClassInfo {
		t.Errorf("ObsChainTrustAnchorAbsent.Class() = %q, want %q: an absent anchor is the documented fullchain shape, not a warning",
			got, convert.ObservationClassInfo)
	}
	// The sentence must name THIS bundle: the identity ships alone, so a consumer that
	// does not already hold the issuer cannot build a path. Saying "every certificate
	// supplied is in the chain" here claimed the opposite of the operator's situation,
	// because the emitted chain is empty.
	if detail, ok := observationDetail(got.Observations(), convert.ObsChainTrustAnchorAbsent); !ok ||
		!strings.Contains(detail, "no chain certificates at all") {
		t.Errorf("anchor-absent detail = %q, want it to name that no chain certificate was supplied at all", detail)
	}
	if hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want no %q: no certificate was held back",
			got.Observations(), convert.ObsExtraCertsExcluded)
	}
}

// TestAnalyse_reports_an_unfinished_chain_when_only_the_root_is_absent is the same
// gap one link further up, and it is this app's PRIMARY DOCUMENTED INPUT: a Caddy/ACME
// fullchain is leaf + intermediate with the root deliberately absent. The
// leaf-to-intermediate hop is PROVEN, so the path walk consumes every parsed
// certificate and leaves nothing over, and the terminus is still not self-signed. The
// intermediate must stay in the chain and the missing root must be named.
//
// Named at the INFORMATIONAL class, not as a warning: the operator has nothing to act
// on (the consumer is expected to hold the root), and the condition recurs on first
// sight, after every renewal and after every restart, so ObsChainUnverified's warning
// here was log noise on the app's most ordinary input.
func TestAnalyse_reports_an_unfinished_chain_when_only_the_root_is_absent(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	rootKey := testcerts.NewECDSAKey(t)
	_, _, rootCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(872),
		Subject:               pkix.Name{CommonName: "Absent Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &rootKey.PublicKey, nil, rootKey)

	interKey := testcerts.NewECDSAKey(t)
	_, interPEM, interCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(873),
		Subject:               pkix.Name{CommonName: "Present Intermediate CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &interKey.PublicKey, rootCert, rootKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(874),
		Subject:      pkix.Name{CommonName: "rootless-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, interCert, interKey)

	got, err := convert.Analyse(concatPEM(leafPEM, interPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(a proven leaf/intermediate pair without its root) = error %v, want nil", err)
	}
	if len(got.Chain()) != 1 || got.Chain()[0].SerialNumber.Cmp(big.NewInt(873)) != 0 {
		t.Fatalf("chain = %v, want the intermediate alone", chainSerials(got.Chain()))
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra = %v, want empty: every parsed certificate is on the path", chainSerials(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainTrustAnchorAbsent) {
		t.Errorf("observations = %v, want %q: the intermediate's own issuer is absent",
			got.Observations(), convert.ObsChainTrustAnchorAbsent)
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: a fullchain's absent root is not an unplaceable leftover, and warning about it on every renewal is noise",
			got.Observations(), convert.ObsChainUnverified)
	}
	if hasObservation(got.Observations(), convert.ObsChainEdgeUnprovenIssuer) {
		t.Errorf("observations = %v, want no %q: the one emitted edge is proven by signature",
			got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	}
	// The fullchain shape carries chain material, so it must NOT get the sentence
	// written for a bundle holding the identity alone: this operator has nothing to do.
	if detail, ok := observationDetail(got.Observations(), convert.ObsChainTrustAnchorAbsent); !ok ||
		strings.Contains(detail, "no chain certificates at all") {
		t.Errorf("anchor-absent detail = %q, want no claim that chain material is missing: the intermediate is in the bundle", detail)
	}
}

// TestAnalyse_reports_a_terminus_whose_self_signature_does_not_verify pins the THIRD
// terminus fact, the one both absent-anchor kinds mis-stated: the chain ends at a
// certificate that names ITSELF as its own issuer, so its anchor is PRESENT, but this
// app could not verify that self-signature (a corrupt or re-signed certificate, an
// algorithm crypto/x509 refuses such as MD5 or DSA, or a key above the verification
// ceilings).
//
// Before ObsChainAnchorUnverifiable this shape was reported as
// ObsChainTrustAnchorAbsent - the INFORMATIONAL kind minted for the normal Caddy/ACME
// fullchain - with a Detail claiming "whose issuer is not in the bundle" about a
// certificate whose issuer IS in the bundle. A trust anchor whose own signature does
// not verify was therefore indistinguishable in the log from a healthy fullchain,
// while a consumer validating the chain will reject it, so it is a warning.
//
// The root's signature over the LEAF is left intact, so the leaf->root hop stays
// proven and ObsChainEdgeUnprovenIssuer does not fire: the only broken thing is the
// root's signature over itself.
func TestAnalyse_reports_a_terminus_whose_self_signature_does_not_verify(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	rootKey := testcerts.NewECDSAKey(t)
	rootDER, _, rootCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(875),
		Subject:               pkix.Name{CommonName: "legacy-root.example.com"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &rootKey.PublicKey, nil, rootKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(876),
		Subject:      pkix.Name{CommonName: "broken-anchor-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, rootCert, rootKey)

	// Flip one bit inside the root's own signature. ParseCertificate never decodes a
	// signature's contents, so the certificate still parses; only CheckSignature over
	// its own TBS fails, which is exactly the condition isSelfSigned collapses into
	// "not self-signed".
	tampered := bytes.Clone(rootDER)
	at := bytes.Index(tampered, rootCert.Signature)
	if at < 0 {
		t.Fatalf("the root's signature was not found in its own DER, so it cannot be tampered with")
	}
	tampered[at] ^= 0x01
	brokenRootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tampered})

	got, err := convert.Analyse(concatPEM(leafPEM, brokenRootPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(a leaf under a root whose self-signature is broken) = error %v, want nil", err)
	}
	if len(got.Chain()) != 1 || got.Chain()[0].SerialNumber.Cmp(big.NewInt(875)) != 0 {
		t.Fatalf("chain = %v, want the tampered root alone: it is still the leaf's proven issuer", chainSerials(got.Chain()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainAnchorUnverifiable) {
		t.Errorf("observations = %v, want %q: the anchor is present and its self-signature could not be verified",
			got.Observations(), convert.ObsChainAnchorUnverifiable)
	}
	if got := convert.ObsChainAnchorUnverifiable.Class(); got != convert.ObservationClassWarning {
		t.Errorf("ObsChainAnchorUnverifiable.Class() = %q, want %q: a consumer validating the chain will reject this anchor",
			got, convert.ObservationClassWarning)
	}
	if hasObservation(got.Observations(), convert.ObsChainTrustAnchorAbsent) {
		t.Errorf("observations = %v, want no %q: the issuer of the terminus IS in the bundle - it is the terminus itself",
			got.Observations(), convert.ObsChainTrustAnchorAbsent)
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: nothing was left over to carry without established ancestry",
			got.Observations(), convert.ObsChainUnverified)
	}
	if hasObservation(got.Observations(), convert.ObsChainEdgeUnprovenIssuer) {
		t.Errorf("observations = %v, want no %q: the root's signature over the leaf is intact",
			got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	}
}

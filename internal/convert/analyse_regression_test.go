package convert_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
)

// The shapes in this file all come from adversarial review of the structural
// Analyse rewrite, and of the guards later added to it. Each one was REPRODUCED
// against the implementation it found wanting, so each test here fails without its
// fix.

// mint builds a certificate. parentCert/parentKey nil means self-signed.
//
// pub is a crypto.PublicKey rather than an *ecdsa.PublicKey because the subject's
// key and the SIGNING key are independent inputs to x509.CreateCertificate: an
// adversarial bundle needs a certificate carrying an RSA key it could not possibly
// have signed with. Every ordinary caller still passes &key.PublicKey.
func mint(t *testing.T, tmpl *x509.Certificate, pub crypto.PublicKey,
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
func TestAnalyse_converts_a_key_shared_by_a_ca_and_its_leaf(t *testing.T) {
	t.Parallel()
	sharedKey := newKey(t)
	leafNotBefore := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	caNotBefore := leafNotBefore.Add(time.Hour)
	caPEM, caCert := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(72),
		Subject:               pkix.Name{CommonName: "Shared Key CA"},
		NotBefore:             caNotBefore,
		NotAfter:              caNotBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &sharedKey.PublicKey, nil, sharedKey)

	leafPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(73),
		Subject:      pkix.Name{CommonName: "shared-key-leaf.example.com"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotBefore.Add(24 * time.Hour),
	}, &sharedKey.PublicKey, caCert, sharedKey)

	got, err := convert.Analyse(concatPEM(leafPEM, caPEM), keyPEMOf(t, sharedKey))
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

	caKey := newKey(t)
	caPEM, caCert := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(74),
		Subject:               pkix.Name{CommonName: "Separate Key CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(75),
		Subject:      pkix.Name{CommonName: "separate-key-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	got, err := convert.Analyse(
		concatPEM(leafPEM, caPEM),
		concatPEM(keyPEMOf(t, leafKey), keyPEMOf(t, caKey)),
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
	absentCAKey := newKey(t)
	_, absentCACert := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(80),
		Subject:               pkix.Name{CommonName: "Absent Issuer CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &absentCAKey.PublicKey, nil, absentCAKey)

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(81),
		Subject:      pkix.Name{CommonName: "orphaned-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentCACert, absentCAKey)

	// Some other certificate sits in the bundle. Under the old positional rule it
	// would have been embedded; it must still be embedded rather than dropped,
	// because we cannot show it is off the chain.
	otherKey := newKey(t)
	otherPEM, _ := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(82),
		Subject:               pkix.Name{CommonName: "Possibly Related CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &otherKey.PublicKey, nil, otherKey)

	got, err := convert.Analyse(concatPEM(leafPEM, otherPEM), keyPEMOf(t, leafKey))
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
}

// TestAnalyse_still_excludes_an_unrelated_cert_from_a_self_signed_identity keeps
// the fallback narrow. A self-signed identity has no issuer BY CONSTRUCTION, so
// an empty chain is proof rather than a failure to prove, and the fallback must
// not fire — otherwise the unrelated-certificate exclusion (the whole point of
// replacing `caCerts = chain[1:]`) would be undone for every self-signed input.
func TestAnalyse_still_excludes_an_unrelated_cert_from_a_self_signed_identity(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	key := newKey(t)
	identityPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(90),
		Subject:      pkix.Name{CommonName: "self.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &key.PublicKey, nil, key)

	strangerKey := newKey(t)
	strangerPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(91),
		Subject:      pkix.Name{CommonName: "stranger.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &strangerKey.PublicKey, nil, strangerKey)

	got, err := convert.Analyse(concatPEM(identityPEM, strangerPEM), keyPEMOf(t, key))
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

	realKey := newKey(t)
	realTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Contested CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	realPEM, realCert := mint(t, realTmpl, &realKey.PublicKey, nil, realKey)

	// Same subject, different key, and a LATER NotAfter so every ranking key below
	// edge strength would prefer it.
	impostorKey := newKey(t)
	impostorPEM, _ := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "Contested CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &impostorKey.PublicKey, nil, impostorKey)

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
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
			got, err := convert.Analyse(concatPEM(order.certs...), keyPEMOf(t, leafKey))
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
	idKey := newKey(t)
	idPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(110),
		Subject:      pkix.Name{CommonName: "Claimed Issuer"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &idKey.PublicKey, nil, idKey)

	// A stranger that CLAIMS the identity as its issuer by name but was signed by
	// its own key. Name chaining alone would make the identity look like an issuer
	// and reject it.
	strangerKey := newKey(t)
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
	strangerPEM, _ := mint(t, strangerTmpl, &strangerKey.PublicKey, strangerSelf, strangerKey)

	got, err := convert.Analyse(concatPEM(idPEM, strangerPEM), keyPEMOf(t, idKey))
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
	realRootKey := newKey(t)
	realRootPEM, realRootCert := mint(t, ca(200, sharedRootCN, notBefore.Add(240*time.Hour)),
		&realRootKey.PublicKey, nil, realRootKey)

	// A same-named root holding a DIFFERENT key. Present in the bundle, so a
	// name-only walk reaches a "root" through it, but it signed nothing here.
	fakeRootKey := newKey(t)
	fakeRootPEM, _ := mint(t, ca(201, sharedRootCN, notBefore.Add(240*time.Hour)),
		&fakeRootKey.PublicKey, nil, fakeRootKey)

	// A third same-named root that is NOT in the bundle. It signs the decoy
	// intermediate, so no included certificate can verify that intermediate.
	absentRootKey := newKey(t)
	_, absentRootCert := mint(t, ca(202, sharedRootCN, notBefore.Add(240*time.Hour)),
		&absentRootKey.PublicKey, nil, absentRootKey)

	// One key across both intermediates: that is what makes both of them verify the
	// leaf, so edge strength at the leaf's own hop cannot separate them.
	interKey := newKey(t)
	goodInterPEM, goodInterCert := mint(t, ca(203, sharedInterCN, notBefore.Add(24*time.Hour)),
		&interKey.PublicKey, realRootCert, realRootKey)
	// The decoy expires LATER, so every ranking key below route strength prefers it.
	decoyInterPEM, _ := mint(t, ca(204, sharedInterCN, notBefore.Add(72*time.Hour)),
		&interKey.PublicKey, absentRootCert, absentRootKey)

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
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
			got, err := convert.Analyse(concatPEM(order.certs...), keyPEMOf(t, leafKey))
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
	throwawayKey := newKey(t)
	oversizedPEM, oversizedCert := mint(t, ca(210, notBefore.Add(240*time.Hour)),
		oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	if k, ok := oversizedCert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != oversizedBits {
		t.Fatalf("setup: minted certificate carries a %T, want a %d-bit RSA modulus; x509 no longer parses one that large",
			oversizedCert.PublicKey, oversizedBits)
	}

	// The same-subject decoy with an ordinary key. Self-signed, so it reaches a root
	// in zero hops and outranks the oversized certificate on every key left once
	// neither edge can be verified.
	decoyKey := newKey(t)
	decoyPEM, _ := mint(t, ca(211, notBefore.Add(72*time.Hour)), &decoyKey.PublicKey, nil, decoyKey)

	// The leaf's real signer shares that subject and is NOT in the bundle, so
	// neither candidate edge verifies — the state the ceiling produces for a leaf
	// whose genuine issuer is the oversized one.
	absentKey := newKey(t)
	_, absentCACert := mint(t, ca(212, notBefore.Add(240*time.Hour)), &absentKey.PublicKey, nil, absentKey)

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(213),
		Subject:      pkix.Name{CommonName: "oversized-issuer-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentCACert, absentKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"oversized first", [][]byte{leafPEM, oversizedPEM, decoyPEM}},
		{"decoy first", [][]byte{leafPEM, decoyPEM, oversizedPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(concatPEM(order.certs...), keyPEMOf(t, leafKey))
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

	identityKey := newKey(t)
	identityPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(214),
		Subject:      pkix.Name{CommonName: "narrow-refusal.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &identityKey.PublicKey, nil, identityKey)

	// Oversized, and unrelated to the identity by name and by key identifier, so it
	// is a candidate issuer of nothing here.
	throwawayKey := newKey(t)
	strangerPEM, _ := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(215),
		Subject:               pkix.Name{CommonName: "Unrelated Oversized CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(240 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, oversizedRSAPublicKey(convert.MaxVerifiableKeyBits+17), nil, throwawayKey)

	got, err := convert.Analyse(concatPEM(identityPEM, strangerPEM), keyPEMOf(t, identityKey))
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
			issuerKey := newKey(t)
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
			firstPEM, _ := mint(t, issuer(220, tt.firstNotBefore, tt.firstNotAfter),
				&issuerKey.PublicKey, nil, issuerKey)
			secondPEM, secondCert := mint(t, issuer(221, tt.secondNotBefore, tt.secondNotAfter),
				&issuerKey.PublicKey, nil, issuerKey)

			leafKey := newKey(t)
			leafPEM, _ := mint(t, &x509.Certificate{
				SerialNumber: big.NewInt(222),
				Subject:      pkix.Name{CommonName: "ranked-issuer-leaf.example.com"},
				NotBefore:    now.Add(-time.Hour),
				NotAfter:     now.Add(24 * time.Hour),
			}, &leafKey.PublicKey, secondCert, issuerKey)

			got, err := convert.Analyse(concatPEM(leafPEM, firstPEM, secondPEM), keyPEMOf(t, leafKey))
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
	fakeRootKey := newKey(t)
	fakeRootPEM, _ := mint(t, unverifiableCA(300, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&fakeRootKey.PublicKey, nil, fakeRootKey)
	absentRootKey := newKey(t)
	_, absentRootCert := mint(t, unverifiableCA(301, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentRootKey.PublicKey, nil, absentRootKey)

	// The routed candidate: names the included root as its issuer, so it has an
	// inclusive route to a root.
	routedKey := newKey(t)
	routedPEM, _ := mint(t, unverifiableCA(302, contestedCN, notBefore, notBefore.Add(24*time.Hour)),
		&routedKey.PublicKey, absentRootCert, absentRootKey)

	// The stranded candidate: names an issuer nothing in the bundle carries, so it
	// has no route to a root at all -- and it expires later, which is what every
	// lower-ranked key would reward.
	absentOtherKey := newKey(t)
	_, absentOtherCert := mint(t, unverifiableCA(303, "Nobody CA", notBefore, notBefore.Add(240*time.Hour)),
		&absentOtherKey.PublicKey, nil, absentOtherKey)
	strandedKey := newKey(t)
	strandedPEM, _ := mint(t, unverifiableCA(304, contestedCN, notBefore, notBefore.Add(72*time.Hour)),
		&strandedKey.PublicKey, absentOtherCert, absentOtherKey)

	// The leaf's real signer shares the contested subject and is absent, so neither
	// candidate verifies the leaf's signature.
	absentSignerKey := newKey(t)
	_, absentSignerCert := mint(t, unverifiableCA(305, contestedCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentSignerKey.PublicKey, nil, absentSignerKey)
	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
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
			got, err := convert.Analyse(concatPEM(order.certs...), keyPEMOf(t, leafKey))
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

	fakeRootKey := newKey(t)
	fakeRootPEM, _ := mint(t, unverifiableCA(310, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&fakeRootKey.PublicKey, nil, fakeRootKey)
	absentRootKey := newKey(t)
	_, absentRootCert := mint(t, unverifiableCA(311, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentRootKey.PublicKey, nil, absentRootKey)

	// One name-hop from the included root.
	nearKey := newKey(t)
	nearPEM, _ := mint(t, unverifiableCA(312, contestedCN, notBefore, notBefore.Add(24*time.Hour)),
		&nearKey.PublicKey, absentRootCert, absentRootKey)

	// An intermediate one name-hop from the root, and the far candidate below it:
	// two hops, and a LATER expiry so the NotAfter key would reward it.
	midKey := newKey(t)
	midPEM, _ := mint(t, unverifiableCA(313, midCN, notBefore, notBefore.Add(240*time.Hour)),
		&midKey.PublicKey, absentRootCert, absentRootKey)
	absentMidKey := newKey(t)
	_, absentMidCert := mint(t, unverifiableCA(314, midCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentMidKey.PublicKey, nil, absentMidKey)
	farKey := newKey(t)
	farPEM, _ := mint(t, unverifiableCA(315, contestedCN, notBefore, notBefore.Add(72*time.Hour)),
		&farKey.PublicKey, absentMidCert, absentMidKey)

	absentSignerKey := newKey(t)
	_, absentSignerCert := mint(t, unverifiableCA(316, contestedCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentSignerKey.PublicKey, nil, absentSignerKey)
	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
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
			got, err := convert.Analyse(concatPEM(order.certs...), keyPEMOf(t, leafKey))
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
// additive fallback from emitting chain material RFC 5280 positively disqualifies.
//
// The inclusive edge signal exists so an UNPROVABLE relationship does not drop a
// real CA, and the fallback keeps whatever is left for the same reason. Neither may
// keep a certificate whose own extensions say it cannot have issued anything: with
// the leaf's real issuer absent and a same-named certificate asserting CA:false
// beside it, the reproduced defect emitted that certificate as the sole CA bag, so
// every consumer's path validation rejected the generated PFX while conversion
// reported success. A certificate that is merely unverifiable must still be kept
// (TestAnalyse_keeps_certificates_when_the_issuer_cannot_be_established pins that
// half); only positive disqualification excludes.
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
			absentCAKey := newKey(t)
			_, absentCACert := mint(t, &x509.Certificate{
				SerialNumber:          big.NewInt(400),
				Subject:               pkix.Name{CommonName: "Absent Encoding CA"},
				NotBefore:             notBefore,
				NotAfter:              notBefore.Add(48 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}, &absentCAKey.PublicKey, nil, absentCAKey)

			leafKey := newKey(t)
			leafPEM, _ := mint(t, &x509.Certificate{
				SerialNumber: big.NewInt(401),
				Subject:      pkix.Name{CommonName: "disqualified-issuer-leaf.example.com"},
				NotBefore:    notBefore,
				NotAfter:     notBefore.Add(24 * time.Hour),
			}, &leafKey.PublicKey, absentCACert, absentCAKey)

			// A decoy carrying the absent issuer's NAME, so name chaining alone
			// admits it, but disqualified from issuing certificates by its own
			// extensions.
			decoyKey := newKey(t)
			decoy := &x509.Certificate{
				SerialNumber: big.NewInt(402),
				Subject:      pkix.Name{CommonName: "Absent Encoding CA"},
				NotBefore:    notBefore,
				NotAfter:     notBefore.Add(48 * time.Hour),
			}
			tc.disqualify(decoy)
			decoyPEM, _ := mint(t, decoy, &decoyKey.PublicKey, nil, decoyKey)

			got, err := convert.Analyse(concatPEM(leafPEM, decoyPEM), keyPEMOf(t, leafKey))
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
		Type: asn1.ObjectIdentifier{2, 5, 4, 3}, // id-at-commonName
		Value: asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagUTF8String,
			Bytes: []byte(cn),
		},
	}}}
	return &view
}

// TestAnalyse_keeps_the_upper_chain_when_a_middle_issuer_cannot_be_established
// makes the additive fallback depend on whether the discovered path reached a
// self-signed terminus, not on whether it found anything at all.
//
// Reproduced shape: leaf -> lower CA -> upper CA -> root, where the lower CA's
// issuer name is a permitted but byte-distinct encoding of the upper CA's subject
// and no key-identifier edge exists. The leaf-to-lower edge is discovered, so the
// old `len(chain) == 0` gate never fired, and the upper CA and the root were
// reported as unrelated and EXCLUDED — the silent chain shrink the fallback exists
// to prevent, one link further up. A consumer of the PFX then cannot build the path
// that was present in the PEM bundle.
func TestAnalyse_keeps_the_upper_chain_when_a_middle_issuer_cannot_be_established(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	rootKey := newKey(t)
	rootPEM, rootCert := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(500),
		Subject:               pkix.Name{CommonName: "Encoding Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &rootKey.PublicKey, nil, rootKey)

	upperKey := newKey(t)
	upperPEM, upperCert := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(501),
		Subject:               pkix.Name{CommonName: "Encoding Upper CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &upperKey.PublicKey, rootCert, rootKey)

	// Signed by the upper CA, but naming it through the other permitted encoding.
	lowerKey := newKey(t)
	lowerPEM, lowerCert := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(502),
		Subject:               pkix.Name{CommonName: "Encoding Lower CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &lowerKey.PublicKey, utf8SubjectView(upperCert, "Encoding Upper CA"), upperKey)

	if bytes.Equal(lowerCert.RawIssuer, upperCert.RawSubject) {
		t.Fatal("setup: the lower CA's issuer name matches the upper CA's subject byte for byte, so this bundle does not reproduce the encoding difference")
	}
	if len(lowerCert.AuthorityKeyId) > 0 {
		t.Fatal("setup: the lower CA carries an authority key identifier, so the key-identifier edge signal would find the upper CA anyway")
	}

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(503),
		Subject:      pkix.Name{CommonName: "middle-gap-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, lowerCert, lowerKey)

	got, err := convert.Analyse(concatPEM(leafPEM, lowerPEM, upperPEM, rootPEM), keyPEMOf(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(chain with an unestablishable middle edge) = error %v, want nil", err)
	}
	if len(got.Chain()) != 3 {
		t.Fatalf("chain = %v, want all 3 CA certificates kept: an unprovable middle edge must not truncate the chain",
			chainSerials(got.Chain()))
	}
	// The emitted ORDER is the contract Analysis.chain documents for the fallback:
	// the certificates whose ancestry IS established come first, then the remaining
	// issuer-eligible ones in INPUT order. Nothing else pins the tail, so a fallback
	// that appended the kept certificates ahead of the discovered path, or in
	// reverse, would emit CA bags in an order no test notices while go-pkcs12's
	// decoder reads the sequence positionally.
	if serials := strings.Join(chainSerials(got.Chain()), ","); serials != "502,501,500" {
		t.Errorf("chain serials = %s, want 502,501,500 (the discovered lower CA first, then the kept remainder in input order)",
			serials)
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra holds %d certificate(s), want 0: neither the upper CA nor the root was shown to be off the chain",
			len(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want the unverified upper chain reported", got.Observations())
	}
	if hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want NO exclusion: nothing was proven unrelated", got.Observations())
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
	sharedKey := newKey(t)
	now := time.Now().Truncate(time.Second)
	caPEM, caCert := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(600), Subject: pkix.Name{CommonName: "Shared Encoding CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &sharedKey.PublicKey, nil, sharedKey)
	leafPEM, leafCert := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(601), Subject: pkix.Name{CommonName: "encoding-leaf.example.com"},
		NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(24 * time.Hour),
	}, &sharedKey.PublicKey, utf8SubjectView(caCert, "Shared Encoding CA"), sharedKey)
	if bytes.Equal(leafCert.RawIssuer, caCert.RawSubject) {
		t.Fatal("setup: issuer and subject encodings unexpectedly match")
	}
	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("setup: CA did not actually sign leaf: %v", err)
	}
	got, err := convert.Analyse(concatPEM(leafPEM, caPEM), keyPEMOf(t, sharedKey))
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
	caKey := newKey(t)
	caPEM, caCert := mint(t, &x509.Certificate{
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
	otherKey := newKey(t)
	otherPEM, otherCert := mint(t, &x509.Certificate{
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

	got, err := convert.Analyse(concatPEM(caPEM, otherPEM), keyPEMOf(t, caKey))
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

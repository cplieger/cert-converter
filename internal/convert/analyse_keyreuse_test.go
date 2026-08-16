package convert_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// Key-reuse and issuer-match regressions: what Analyse does when one key belongs to
// more than one certificate in the bundle, or the key file holds more than one key.

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
	oldPEM, _ := testcerts.Mint(t, tmpl(60), &key.PublicKey, nil, key)
	newPEM, _ := testcerts.Mint(t, tmpl(61), &key.PublicKey, nil, key)

	got, err := convert.Analyse(t.Context(), concatPEM(oldPEM, newPEM), testcerts.KeyPEM(t, key))
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
	caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(70),
		Subject:               pkix.Name{CommonName: "Real Issuer CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(71),
		Subject:      pkix.Name{CommonName: "issued-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	_, err := convert.Analyse(t.Context(), concatPEM(leafPEM, caPEM), testcerts.KeyPEM(t, caKey))
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
// The record it emits is asserted: the issuer match that was set aside.
func TestAnalyse_converts_a_key_shared_by_a_ca_and_its_leaf(t *testing.T) {
	t.Parallel()
	sharedKey := testcerts.NewECDSAKey(t)
	leafNotBefore := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	caNotBefore := leafNotBefore.Add(time.Hour)
	caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(72),
		Subject:               pkix.Name{CommonName: "Shared Key CA"},
		NotBefore:             caNotBefore,
		NotAfter:              caNotBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &sharedKey.PublicKey, nil, sharedKey)

	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(73),
		Subject:      pkix.Name{CommonName: "shared-key-leaf.example.com"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotBefore.Add(24 * time.Hour),
	}, &sharedKey.PublicKey, caCert, sharedKey)

	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, caPEM), testcerts.KeyPEM(t, sharedKey))
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

// TestAnalyse_reports_a_renewal_tie_beside_a_dropped_issuer_match pins the shape that
// keeps the genuine renewal tie honest: two end-entity certificates sharing one key (a
// renewal) plus the CA that signed them, minted from the SAME key. The issuer match is
// dropped, two end-entity matches survive, so the renewal tie is still reported. A
// change that restored the tie by keeping the issuer match would lose that fact here.
func TestAnalyse_reports_a_renewal_tie_beside_a_dropped_issuer_match(t *testing.T) {
	t.Parallel()
	sharedKey := testcerts.NewECDSAKey(t)
	caNotBefore := time.Now().Add(-4 * time.Hour).Truncate(time.Second)
	caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(9100),
		Subject:               pkix.Name{CommonName: "Renewal Tie CA"},
		NotBefore:             caNotBefore,
		NotAfter:              caNotBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &sharedKey.PublicKey, nil, sharedKey)

	oldLeafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(9101),
		Subject:      pkix.Name{CommonName: "tie-leaf.example.com"},
		NotBefore:    caNotBefore.Add(time.Hour),
		NotAfter:     caNotBefore.Add(48 * time.Hour),
	}, &sharedKey.PublicKey, caCert, sharedKey)
	newLeafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(9102),
		Subject:      pkix.Name{CommonName: "tie-leaf.example.com"},
		NotBefore:    caNotBefore.Add(2 * time.Hour),
		NotAfter:     caNotBefore.Add(72 * time.Hour),
	}, &sharedKey.PublicKey, caCert, sharedKey)

	got, err := convert.Analyse(t.Context(), concatPEM(oldLeafPEM, newLeafPEM, caPEM), testcerts.KeyPEM(t, sharedKey))
	if err != nil {
		t.Fatalf("Analyse(renewed leaf pair plus their shared-key CA) = %v, want the newest leaf selected", err)
	}
	if got.Leaf().SerialNumber.Cmp(big.NewInt(9102)) != 0 {
		t.Errorf("selected identity serial = %s, want 9102 (the newer renewal)", got.Leaf().SerialNumber)
	}
	for _, want := range []convert.ObservationKind{
		convert.ObsIssuerMatchIgnored,
		convert.ObsRenewedCertTie,
	} {
		if !hasObservation(got.Observations(), want) {
			t.Errorf("observations = %v, want %q reported", got.Observations(), want)
		}
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
	caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(74),
		Subject:               pkix.Name{CommonName: "Separate Key CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(75),
		Subject:      pkix.Name{CommonName: "separate-key-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	got, err := convert.Analyse(t.Context(),
		concatPEM(leafPEM, caPEM),
		concatPEM(testcerts.KeyPEM(t, leafKey), testcerts.KeyPEM(t, caKey)))
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

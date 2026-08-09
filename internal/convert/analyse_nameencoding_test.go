package convert_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// Name-encoding regressions: the semantic name link, and what happens when two
// certificates spell the same name with different ASN.1 string encodings.

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
	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, caPEM), testcerts.KeyPEM(t, sharedKey))
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

	got, err := convert.Analyse(t.Context(), concatPEM(caPEM, otherPEM), testcerts.KeyPEM(t, caKey))
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
	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, lowerPEM, rootPEM, upperPEM), testcerts.KeyPEM(t, leafKey))
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

	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, caPEM, strangerPEM), testcerts.KeyPEM(t, leafKey))
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

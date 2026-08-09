package convert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// ASN.1 SET-member order and name equality. An RDN is a SET, so the order its
// attributes were encoded in carries no meaning, and canonicalName folds the
// orderings together on purpose. Nothing pinned that rule when it arrived, which is
// what these tests fix — it is a deliberate semantic, not an accident of
// encoding/asn1's setEncoder, and it must not be "fixed" back to a positional
// comparison.

// setOrderAttrs is the pair of attributes both fixtures carry inside ONE
// multi-valued RDN. Their order in the encoded SET is the only difference between the
// two names under test.
func setOrderAttrs() (cn, org pkix.AttributeTypeAndValue) {
	printable := func(oid asn1.ObjectIdentifier, value string) pkix.AttributeTypeAndValue {
		return pkix.AttributeTypeAndValue{Type: oid, Value: asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagPrintableString,
			Bytes: []byte(value),
		}}
	}
	return printable(asn1.ObjectIdentifier{2, 5, 4, 3}, "set-order.example.com"),
		printable(asn1.ObjectIdentifier{2, 5, 4, 10}, "Set Order Ltd")
}

// multiValuedRDNName hand-encodes a one-RDN distinguished name holding attrs in
// EXACTLY the given order.
//
// It cannot go through asn1.Marshal of a pkix.RDNSequence, which is the whole
// difficulty: that path runs the setEncoder, which sorts the SET members, so both
// orderings would come out byte-identical and a test built on it would assert
// nothing (it would pass through nameLink's raw-bytes fast path without ever
// reaching the canonical comparison). Marshalling each attribute on its own — a
// SEQUENCE, so no SET is involved and nothing is sorted — and then wrapping the
// concatenation in a SET and a SEQUENCE header preserves the caller's order into the
// DER.
func multiValuedRDNName(t *testing.T, attrs ...pkix.AttributeTypeAndValue) []byte {
	t.Helper()
	return wrapSequence(t, rdnSET(t, attrs...))
}

// setOrderNames returns the two byte-distinct encodings of one distinguished name,
// and fails the test if they are NOT byte-distinct — which is the guard that keeps
// every test below from passing vacuously through a raw-bytes fast path.
func setOrderNames(t *testing.T) (cnFirst, orgFirst []byte) {
	t.Helper()

	cn, org := setOrderAttrs()
	cnFirst = multiValuedRDNName(t, cn, org)
	orgFirst = multiValuedRDNName(t, org, cn)
	if bytes.Equal(cnFirst, orgFirst) {
		t.Fatal("setup: the two SET member orderings encoded to identical DER, so every" +
			" assertion below would pass through the raw-bytes fast path without testing the rule")
	}
	return cnFirst, orgFirst
}

// leafCN is a plain single-attribute common name, for a leaf whose own subject is not
// what the test is about.
func leafCN(suffix string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagPrintableString,
		Bytes: []byte("set-order-leaf-" + suffix + ".example.com"),
	}}
}

// certWithRawNames mints a real certificate carrying caller-supplied subject and
// issuer DER. crypto/x509 honours a non-empty template.RawSubject, and takes the
// issuer from the parent's RawSubject, so a view of the template with the other
// ordering is enough to produce a byte-distinct issuer name.
func certWithRawNames(t *testing.T, serial int64, rawSubject, rawIssuer []byte,
	key *ecdsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		RawSubject:            rawSubject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerView := *template
	issuerView.RawSubject = rawIssuer
	der, err := x509.CreateCertificate(rand.Reader, template, &issuerView, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("setup: create certificate %d: %v", serial, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("setup: parse certificate %d: %v", serial, err)
	}
	if !bytes.Equal(c.RawSubject, rawSubject) {
		t.Fatalf("setup: certificate %d did not keep the caller-supplied RawSubject", serial)
	}
	if !bytes.Equal(c.RawIssuer, rawIssuer) {
		t.Fatalf("setup: certificate %d did not keep the caller-supplied RawIssuer", serial)
	}
	return c
}

// TestCanonicalName_treats_SET_member_order_as_insignificant pins the rule
// canonicalName's doc now states: two names differing ONLY by attribute order inside
// one multi-valued RDN are the same name, because an ASN.1 SET is unordered. It also
// pins the half that must NOT change with it — RDNSequence order stays significant,
// so the rule cannot be read as "order never matters".
//
// This test fails when its subject is reverted. Checked by making canonicalName
// return its input unchanged (the positional/raw comparison this rule replaced):
// the same-name assertion then fails on both the key comparison and
// sameCanonicalName, because the two encodings are byte-distinct. The setup guard in
// setOrderNames is what makes that true rather than vacuous.
func TestCanonicalName_treats_SET_member_order_as_insignificant(t *testing.T) {
	t.Parallel()

	cnFirst, orgFirst := setOrderNames(t)

	keyA, okA := canonicalName(cnFirst)
	if !okA {
		t.Fatal("canonicalName(CN-first multi-valued RDN) could not be keyed")
	}
	keyB, okB := canonicalName(orgFirst)
	if !okB {
		t.Fatal("canonicalName(O-first multi-valued RDN) could not be keyed")
	}
	if !bytes.Equal(keyA, keyB) {
		t.Errorf("canonicalName keyed two SET member orderings of one name differently:\n"+
			" CN-first: %x\n O-first:  %x\nAn RDN is an ASN.1 SET, so member order carries no"+
			" meaning and both spellings must canonicalise to one key", keyA, keyB)
	}
	if !sameCanonicalName(keyA, okA, keyB, okB) {
		t.Error("sameCanonicalName reported two SET member orderings of one name as different names")
	}

	// The other half of the rule: an RDNSequence is a SEQUENCE, so ITS order is
	// significant. Two single-valued RDNs in the opposite order are genuinely two
	// different names and must stay distinct.
	cn, org := setOrderAttrs()
	seqCNFirst := rawRDNSequence(t, cn, org)
	seqOrgFirst := rawRDNSequence(t, org, cn)
	seqKeyA, seqOKA := canonicalName(seqCNFirst)
	seqKeyB, seqOKB := canonicalName(seqOrgFirst)
	if sameCanonicalName(seqKeyA, seqOKA, seqKeyB, seqOKB) {
		t.Error("canonicalName folded two RDNs in the opposite SEQUENCE order onto one key:" +
			" an RDNSequence is ordered, so those are two different DNs under RFC 5280")
	}
}

// rawRDNSequence encodes attrs as a sequence of SINGLE-valued RDNs in the order
// given, which is the ordered-SEQUENCE counterpart to multiValuedRDNName's one
// unordered SET.
func rawRDNSequence(t *testing.T, attrs ...pkix.AttributeTypeAndValue) []byte {
	t.Helper()

	var rdns []byte
	for _, at := range attrs {
		rdns = append(rdns, rdnSET(t, at)...)
	}
	return wrapSequence(t, rdns)
}

// rdnSET encodes attrs as ONE RDN — an ASN.1 SET — preserving the caller's member
// order, because each attribute is marshalled on its own (a SEQUENCE, so the
// setEncoder never sees the members together and never sorts them).
func rdnSET(t *testing.T, attrs ...pkix.AttributeTypeAndValue) []byte {
	t.Helper()

	var members []byte
	for _, at := range attrs {
		der, err := asn1.Marshal(at)
		if err != nil {
			t.Fatalf("setup: marshal attribute %v: %v", at.Type, err)
		}
		members = append(members, der...)
	}
	set, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: members,
	})
	if err != nil {
		t.Fatalf("setup: marshal RDN SET: %v", err)
	}
	return set
}

// wrapSequence wraps encoded RDNs in the enclosing RDNSequence SEQUENCE.
func wrapSequence(t *testing.T, rdns []byte) []byte {
	t.Helper()

	seq, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: rdns,
	})
	if err != nil {
		t.Fatalf("setup: marshal RDNSequence: %v", err)
	}
	return seq
}

// TestSETMemberOrder_is_one_rule_across_all_three_name_consumers pins that the
// SET-order semantic is shared rather than restated: nameLink, sameNameSameKey and
// selfIssuedByName all reach it through subjectName/issuerName, so one canonical key
// answers for all three. A consumer that grew its own decoded comparison would
// disagree with the other two about whether a reordered SET is the same name, and
// this test is what catches that.
//
// This test fails when its subject is reverted. Checked the same way as the test
// above — with canonicalName returning its input unchanged, all three consumers fall
// through to their raw-bytes comparison and every assertion here fails, which is
// exactly the "each consumer decides for itself" state the shared key prevents.
func TestSETMemberOrder_is_one_rule_across_all_three_name_consumers(t *testing.T) {
	t.Parallel()

	cnFirst, orgFirst := setOrderNames(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: generate key: %v", err)
	}

	// Both certificates carry the same name in the two orderings, and the same public
	// key: subject cnFirst / issuer orgFirst on one, the mirror on the other. That one
	// pair of fixtures exercises all three consumers.
	first := certWithRawNames(t, 900, cnFirst, orgFirst, key)
	second := certWithRawNames(t, 901, orgFirst, cnFirst, key)
	g := newCertGraph([]*x509.Certificate{first, second}, time.Now())

	// selfIssuedByName: each certificate's own subject and issuer are one name in the
	// two orderings, so each is self-issued by name.
	for i, c := range []*x509.Certificate{first, second} {
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			t.Fatalf("setup: certificate %d has byte-identical subject and issuer", i)
		}
		if !g.selfIssuedByName(i) {
			t.Errorf("selfIssuedByName(%d) = false: the certificate's subject and issuer are one"+
				" name spelled with the SET members in the other order, so it names itself", i)
		}
	}

	// nameLink: the link must be found through the canonical key, so the child's issuer
	// and the parent's subject have to be byte-DISTINCT spellings. first and second
	// cannot serve here (first's issuer IS second's subject, byte for byte, which is the
	// exact arm), so each direction gets its own leaf.
	leafCNIssuer := certWithRawNames(t, 902, rawRDNSequence(t, leafCN("a")), cnFirst, key)
	leafOrgIssuer := certWithRawNames(t, 903, rawRDNSequence(t, leafCN("b")), orgFirst, key)
	g = newCertGraph([]*x509.Certificate{first, second, leafCNIssuer, leafOrgIssuer}, time.Now())

	for _, tc := range []struct {
		name          string
		child, parent int
	}{
		{"CN-first issuer against an O-first subject", 2, 1},
		{"O-first issuer against a CN-first subject", 3, 0},
	} {
		if bytes.Equal(g.certs[tc.child].RawIssuer, g.certs[tc.parent].RawSubject) {
			t.Fatalf("setup: %s — the two names are byte-identical, so this case would pass"+
				" through the raw-bytes fast path", tc.name)
		}
		if got := g.nameLink(tc.child, tc.parent); got != nameLinkSemantic {
			t.Errorf("nameLink(%d, %d) [%s] = %v, want nameLinkSemantic: the child's issuer name is"+
				" the parent's subject name with the SET members in the other order",
				tc.child, tc.parent, tc.name, got)
		}
	}

	// sameNameSameKey: same public key under the same subject name, spelled with the
	// members in the other order.
	if !g.sameNameSameKey(0, 1) {
		t.Error("sameNameSameKey(0, 1) = false: both certificates hold one key under one subject" +
			" name, differing only by SET member order")
	}
}

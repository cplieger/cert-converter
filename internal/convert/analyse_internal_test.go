package convert

import (
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
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestVerifiableKey_bounds_rsa_only pins the cost guard the graph runs every signature
// verification behind. Two halves matter and neither is observable from Analyse's result:
// the RSA ceiling (an unbounded modulus is a file-controlled modexp - 184ms at 131072 bits,
// 11.9s at 1 Mbit, on the scan's only goroutine), and the non-RSA default. Inverting the
// default would refuse verification for every ECDSA and Ed25519 bundle, silently demoting
// chain selection to the inclusive candidate path with no error and no log line.
func TestVerifiableKey_bounds_rsa_only(t *testing.T) {
	t.Parallel()

	// Lsh(1, n) has BitLen n+1, so the shift is one below the ceiling for the
	// at-limit key and exactly the ceiling for the one past it.
	atLimit := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), maxVerifiableKeyBits-1), E: 65537}
	oversized := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), maxVerifiableKeyBits), E: 65537}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}

	if got := atLimit.N.BitLen(); got != maxVerifiableKeyBits {
		t.Fatalf("setup: at-limit modulus is %d bits, want %d", got, maxVerifiableKeyBits)
	}
	if !verifiableKey(atLimit) {
		t.Errorf("verifiableKey(a %d-bit RSA key) = false, want true: the ceiling is inclusive", maxVerifiableKeyBits)
	}
	if verifiableKey(oversized) {
		t.Errorf("verifiableKey(a %d-bit RSA key) = true, want false: one modexp with it costs the scan goroutine hundreds of ms", maxVerifiableKeyBits+1)
	}
	if verifiableKey(&rsa.PublicKey{E: 65537}) {
		t.Error("verifiableKey(an RSA key with no modulus) = true, want false: BitLen on a nil modulus panics")
	}
	// The exponent is the other half of the cost: it sets the NUMBER of squarings
	// crypto/rsa pays, so a file-supplied 2^31-1 triples one verification at the
	// modulus ceiling. Both boundaries are inclusive.
	atExponentLimit := &rsa.PublicKey{N: atLimit.N, E: maxVerifiablePublicExponent}
	pastExponentLimit := &rsa.PublicKey{N: atLimit.N, E: maxVerifiablePublicExponent + 1}
	if !verifiableKey(atExponentLimit) {
		t.Errorf("verifiableKey(an RSA key with exponent %d) = false, want true: the exponent ceiling is inclusive", maxVerifiablePublicExponent)
	}
	if verifiableKey(pastExponentLimit) {
		t.Errorf("verifiableKey(an RSA key with exponent %d) = true, want false: the exponent sets the squaring count and exceeds the cost this app permits an input to dictate", maxVerifiablePublicExponent+1)
	}
	if !verifiableKey(&ecKey.PublicKey) {
		t.Error("verifiableKey(an ECDSA key) = false, want true: only RSA is size-unbounded, and refusing the rest would demote every chain to unverified edges")
	}
}

// testSelfSignedPEM builds a self-signed certificate over an exact validity
// window. Validity is the only property that varies here, so the template
// carries nothing else: no basic constraints (the shape `openssl req -x509`
// produces without CA flags) and no extensions Analyse consults.
//
// Only the template shape is local; the minting itself is internal/testcerts's
// Mint, so how this app signs and PEM-encodes a test certificate has one home.
func testSelfSignedPEM(t *testing.T, key *ecdsa.PrivateKey, cn string, serial int64, notBefore, notAfter time.Time) []byte {
	t.Helper()
	_, certPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}, &key.PublicKey, nil, key)
	return certPEM
}

// testValidityKinds reports the identity-validity observations in a, dropping the
// chain-shaped ones so a fixture's chain arrangement cannot move the assertion.
func testValidityKinds(a *Analysis) []ObservationKind {
	var kinds []ObservationKind
	for _, o := range a.observations {
		if o.Kind == ObsIdentityNotYetValid || o.Kind == ObsIdentityExpired {
			kinds = append(kinds, o.Kind)
		}
	}
	return kinds
}

// TestAnalyseAt_reports_every_input_defect_in_discovery_order pins the
// observation contract prepareAnalysisInput documents: the input-phase findings
// are emitted in the order the defects are discovered in the file, and one defect
// never suppresses another. Every existing test exercises these four one at a
// time, so a refactor that turned the four independent reports into an if/else
// chain - or reordered them - keeps the whole suite green while an operator with a
// multi-defect input silently loses the mid-rotation damaged-key signal that is
// the only warning before the next renewal fails.
func TestAnalyseAt_reports_every_input_defect_in_discovery_order(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}
	now := time.Date(2030, 3, 1, 0, 0, 0, 0, time.UTC)
	certPEM := testSelfSignedPEM(t, key, "multi-defect.example.com", 1, now.Add(-time.Hour), now.Add(time.Hour))

	// One file carrying all four defects: a block that is neither a certificate
	// nor a key, the same certificate twice, a second distinct key, and a key
	// declaration whose armour is cut off mid-body.
	certFile := slices.Concat(
		pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: []byte("not a certificate")}),
		certPEM, certPEM,
	)
	keyFile := slices.Concat(
		testcerts.KeyPEM(t, key),
		testcerts.KeyPEM(t, other),
		[]byte("-----BEGIN PRIVATE KEY-----\nZm9v\n"),
	)

	a, err := analyseAt(certFile, keyFile, now)
	if err != nil {
		t.Fatalf("analyseAt(a bundle carrying every input defect) = error %v, want a resolved analysis", err)
	}

	var got []ObservationKind
	for _, o := range a.observations {
		switch o.Kind {
		case ObsUnrelatedBlocksSkipped, ObsDuplicateCerts, ObsMultipleKeys, ObsUnusableKeyBlocksSkipped:
			got = append(got, o.Kind)
		}
	}
	want := []ObservationKind{ObsUnrelatedBlocksSkipped, ObsDuplicateCerts, ObsMultipleKeys, ObsUnusableKeyBlocksSkipped}
	if !slices.Equal(got, want) {
		t.Errorf("input-phase observations = %v, want %v (every defect reported, in file-discovery order)", got, want)
	}
}

// TestAnalyseAt_validity_window_is_inclusive_at_both_edges pins the inclusivity of
// validAt at the exact instants the boundaries sit on. Analyse reads the clock, so
// through the exported entry point a fixture can only be placed loosely before or
// after a moving now, and the two edge instants -- where a certificate is valid ON
// its NotBefore and still valid ON its NotAfter -- are exactly the ones that are
// unreachable that way. An off-by-one here would report a freshly issued
// certificate as not-yet-valid on every scan in its first second.
func TestAnalyseAt_validity_window_is_inclusive_at_both_edges(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}
	// Whole seconds: DER encodes validity at second granularity, so a fixture with
	// sub-second components would not round-trip and the boundary would move.
	notBefore := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(24 * time.Hour)
	certPEM := testSelfSignedPEM(t, key, "boundary.example.com", 1, notBefore, notAfter)
	keyPEM := testcerts.KeyPEM(t, key)

	tests := map[string]struct {
		now  time.Time
		want []ObservationKind
	}{
		"one nanosecond before NotBefore": {notBefore.Add(-time.Nanosecond), []ObservationKind{ObsIdentityNotYetValid}},
		"exactly NotBefore":               {notBefore, nil},
		"exactly NotAfter":                {notAfter, nil},
		"one nanosecond after NotAfter":   {notAfter.Add(time.Nanosecond), []ObservationKind{ObsIdentityExpired}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, err := analyseAt(certPEM, keyPEM, tt.now)
			if err != nil {
				t.Fatalf("analyseAt(_, _, %s) = error %v, want a resolved analysis", tt.now.UTC().Format(time.RFC3339Nano), err)
			}
			if got := testValidityKinds(&a); !slices.Equal(got, tt.want) {
				t.Errorf("analyseAt at %s produced validity observations %v, want %v",
					tt.now.UTC().Format(time.RFC3339Nano), got, tt.want)
			}
		})
	}
}

// testUncomparablePublicKey stands in for a public key type crypto/x509 parses
// but that carries no Equal(crypto.PublicKey) bool method, which is what makes a
// certificate unverifiable against a key rather than mismatched with it. The
// production shape is a legacy DSA certificate: crypto/x509 parses a
// SubjectPublicKeyInfo carrying the DSA OID into a *dsa.PublicKey, and crypto/dsa
// declares no methods at all. The stand-in pins the same branch while keeping the
// deprecated crypto/dsa package out of the test.
type testUncomparablePublicKey struct{}

// TestNoMatchError_names_a_public_key_type_that_cannot_be_compared pins the
// unverifiable-key-type half of the no-match diagnosis. Its sibling - a
// certificate whose algorithm OID crypto/x509 does not recognise at all, leaving
// PublicKey nil - is covered end to end; this arm, where the key WAS parsed into a
// type without Equal, is not, so a diagnosis that fell through to "none of the N
// key block(s) matches any of the M certificate(s)" would send the operator to
// check the wrong file while every test still passed.
func TestNoMatchError_names_a_public_key_type_that_cannot_be_compared(t *testing.T) {
	t.Parallel()
	g := &certGraph{certs: []*x509.Certificate{{
		Subject:   pkix.Name{CommonName: "legacy-dsa.example.com"},
		PublicKey: testUncomparablePublicKey{},
	}}}

	err := g.noMatchError(1, 0, keyDefects{}, skippedBlocks{})
	if err == nil {
		t.Fatal("noMatchError(1, 0, keyDefects{}, skippedBlocks{}) = nil, want the unverifiable-key-type diagnosis")
	}
	want := `certificate "CN=legacy-dsa.example.com" has a public key of type convert.testUncomparablePublicKey that cannot be verified against the private key`
	if got := err.Error(); got != want {
		t.Errorf("noMatchError(1, 0, keyDefects{}, skippedBlocks{}) = %q, want %q", got, want)
	}
}

// TestAnalyseAt_renewed_cert_tie_turns_on_validity_at_the_instant pins the tie
// transition betterIdentity's first key exists for: one key matching two
// certificates picks the one usable AT THE SCAN INSTANT, not the newest. Both
// arrangements are the same input, so only the supplied instant can decide, and
// crossing the transition is what proves NotBefore alone is not the ranking key --
// ranking on it would return the future-dated certificate at both instants and
// produce a bundle no consumer accepts yet.
func TestAnalyseAt_renewed_cert_tie_turns_on_validity_at_the_instant(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}
	// A renewal reusing its key: same subject, same key, later window. Key reuse is
	// not issuance, so neither certificate is the other's issuer and the pair
	// reaches the tie-break rather than the role check.
	current := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	renewalStart := current.Add(48 * time.Hour)
	certPEM := slices.Concat(
		testSelfSignedPEM(t, key, "renewed.example.com", 1, current.Add(-24*time.Hour), current.Add(24*time.Hour)),
		testSelfSignedPEM(t, key, "renewed.example.com", 2, renewalStart, renewalStart.Add(24*time.Hour)),
	)
	keyPEM := testcerts.KeyPEM(t, key)

	tests := map[string]struct {
		now           time.Time
		wantNotBefore time.Time
	}{
		"before the renewal starts, the current certificate wins": {current, current.Add(-24 * time.Hour)},
		"once the current one has expired, the renewal wins":      {renewalStart.Add(time.Hour), renewalStart},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, err := analyseAt(certPEM, keyPEM, tt.now)
			if err != nil {
				t.Fatalf("analyseAt(_, _, %s) = error %v, want a resolved analysis", tt.now.UTC().Format(time.RFC3339), err)
			}
			if got := a.leaf.NotBefore.UTC(); !got.Equal(tt.wantNotBefore.UTC()) {
				t.Errorf("analyseAt at %s selected the certificate with NotBefore %s, want %s",
					tt.now.UTC().Format(time.RFC3339), got.Format(time.RFC3339), tt.wantNotBefore.UTC().Format(time.RFC3339))
			}
		})
	}
}

// testEvidenceCert builds one certificate for the evidence-model tests and returns
// it parsed. A nil parent means self-signed.
//
// The internal tests need names the pkix.Name template cannot express -- an explicit
// RDN order, a chosen DirectoryString tag -- so the template carries RawSubject
// directly and the parent is passed as a view whose RawSubject is the issuer name to
// embed. That convention is the only thing local: the signing and parsing are
// internal/testcerts's Mint, so how this app mints a test certificate has one home.
func testEvidenceCert(t *testing.T, tmpl *x509.Certificate, key *ecdsa.PrivateKey,
	parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parentKey = key // self-signed: Mint takes the template as its own issuer
	}
	_, _, got := testcerts.Mint(t, tmpl, &key.PublicKey, parent, parentKey)
	return got
}

// testRDN is one attribute of a distinguished name for testRawDN.
type testRDN struct {
	oid   asn1.ObjectIdentifier
	value string
}

var (
	testOIDOrg = asn1.ObjectIdentifier{2, 5, 4, 10} // id-at-organizationName
	testOIDCN  = asn1.ObjectIdentifier{2, 5, 4, 3}  // id-at-commonName
)

// testRawDN marshals rdns as one RDN SEQUENCE, one single-valued RDN each, in the
// order given and with the DirectoryString tag given. Both are the point: the same
// attributes in a different RDN ORDER are a different DN, while a different TAG over
// the same values is the same DN, and pkix.Name can express neither.
func testRawDN(t *testing.T, tag int, rdns ...testRDN) []byte {
	t.Helper()
	seq := make(pkix.RDNSequence, 0, len(rdns))
	for _, r := range rdns {
		seq = append(seq, pkix.RelativeDistinguishedNameSET{{
			Type: r.oid,
			Value: asn1.RawValue{
				Class: asn1.ClassUniversal,
				Tag:   tag,
				Bytes: []byte(r.value),
			},
		}})
	}
	der, err := asn1.Marshal(seq)
	if err != nil {
		t.Fatalf("setup: marshal RDNSequence: %v", err)
	}
	return der
}

// testNameLinkGraph builds a graph over certs at a fixed instant.
func testNameLinkGraph(t *testing.T, certs ...*x509.Certificate) *certGraph {
	t.Helper()
	g, err := newCertGraph(certs, time.Now())
	if err != nil {
		t.Fatalf("setup: newCertGraph: %v", err)
	}
	return g
}

// TestNameLink_separates_a_re_encoded_name_from_a_reordered_one pins the name half of
// the evidence model at both ends, because the two failure directions cost opposite
// things and one comparison decides both.
//
// Too strict (a byte comparison alone) and a leaf naming its issuer as a UTF8String
// where the CA's subject uses the canonical encoding records no linkage, which is the
// permitted-encoding case RFC 5280 allows and which cost the app a chain it could
// prove. Too loose (pkix.Name.ToRDNSequence, which rebuilds known attributes in a
// FIXED order and flattens multi-valued RDNs) and `O=Acme,CN=x` compares equal to
// `CN=x,O=Acme` -- two different DNs -- so a CA whose key happened to sign a
// certificate naming that OTHER DN reads as its issuer. crypto/x509 documents
// pkix.Name as an approximation and says accurate name work must unmarshal the raw
// names, which is what nameLink does.
func TestNameLink_separates_a_re_encoded_name_from_a_reordered_one(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(900),
		RawSubject:            testRawDN(t, asn1.TagPrintableString, testRDN{testOIDOrg, "Acme"}, testRDN{testOIDCN, "Evidence CA"}),
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	ca := testEvidenceCert(t, caTmpl, caKey, nil, nil)

	// A view of the CA whose subject is the given name and which carries no subject
	// key identifier, so a certificate minted against it embeds that issuer name and
	// no authority key identifier: the name comparison then decides alone.
	view := func(raw []byte) *x509.Certificate {
		v := *ca
		v.RawSubject = raw
		v.SubjectKeyId = nil
		v.Subject = pkix.Name{}
		return &v
	}
	child := func(serial int64, issuer []byte) *x509.Certificate {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatalf("setup: GenerateKey: %v", keyErr)
		}
		return testEvidenceCert(t, &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: fmt.Sprintf("child-%d.example.com", serial)},
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(24 * time.Hour),
		}, key, view(issuer), caKey)
	}

	exact := child(901, testRawDN(t, asn1.TagPrintableString, testRDN{testOIDOrg, "Acme"}, testRDN{testOIDCN, "Evidence CA"}))
	reEncoded := child(902, testRawDN(t, asn1.TagUTF8String, testRDN{testOIDOrg, "Acme"}, testRDN{testOIDCN, "Evidence CA"}))
	reordered := testEvidenceCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(903),
		Subject:      pkix.Name{CommonName: "child-903.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, caKey, view(testRawDN(t, asn1.TagPrintableString, testRDN{testOIDCN, "Evidence CA"}, testRDN{testOIDOrg, "Acme"})), caKey)

	g := testNameLinkGraph(t, ca, exact, reEncoded, reordered)
	const caIdx = 0
	for _, tc := range []struct {
		name  string
		child int
		want  nameLinkage
	}{
		{"byte-identical issuer name", 1, nameLinkExact},
		{"same name, other DirectoryString encoding", 2, nameLinkSemantic},
		{"same attribute values in a different RDN order", 3, nameLinkNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.nameLink(tc.child, caIdx); got != tc.want {
				t.Errorf("nameLink(%s) = %d, want %d", tc.name, got, tc.want)
			}
			if got := g.edge(tc.child, caIdx).linked(); got != (tc.want != nameLinkNone) {
				t.Errorf("edge(%s).linked() = %t, want %t", tc.name, got, tc.want != nameLinkNone)
			}
		})
	}

	// The reordered name is the trap: assert the pkix approximation of the two names
	// COLLIDES, so a comparison built on it would have called them equal and this
	// test would prove nothing.
	approxCA, approxIssuer := ca.Subject.ToRDNSequence(), reordered.Issuer.ToRDNSequence()
	if !reflect.DeepEqual(approxCA, approxIssuer) {
		t.Fatal("setup: the pkix.Name approximations of the two names differ, so this fixture no longer reproduces the ToRDNSequence collision")
	}
	// And assert the CA's key really did sign it, so only the name comparison keeps
	// the pair unlinked.
	if err := ca.CheckSignature(reordered.SignatureAlgorithm, reordered.RawTBSCertificate, reordered.Signature); err != nil {
		t.Fatalf("setup: the CA's key did not sign the reordered-name certificate: %v", err)
	}
	if g.isIssuer(caIdx) != true {
		t.Error("isIssuer(the CA) = false, want true: it signed two certificates whose issuer name IS its own")
	}
}

// TestCertGraph_never_verifies_a_signature_for_an_unlinked_pair pins the model's cost
// contract: name and key linkage are cheap comparisons and are computed for every
// pair, but the signature is expensive and is only ever asked about a pair something
// already links.
//
// This is unobservable from Analyse's result -- an eager all-pairs verification
// returns the same chain -- and it is exactly what the RSA modulus and public-exponent
// ceilings exist to bound: one verification runs to milliseconds at the ceilings, and
// a 64-certificate bundle has 4032 ordered pairs. The fixture is the strongest form of
// the case: the CA's key genuinely signed the other certificate, so a model that
// verified first and asked about names afterwards would find a valid signature here,
// and only the linkage gate stops it looking.
func TestCertGraph_never_verifies_a_signature_for_an_unlinked_pair(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}

	ca := testEvidenceCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(910),
		RawSubject:            testRawDN(t, asn1.TagPrintableString, testRDN{testOIDOrg, "Acme"}, testRDN{testOIDCN, "Unlinked CA"}),
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, caKey, nil, nil)

	// Signed by the CA's key, but naming an issuer whose RDNs are in the other order:
	// a different DN, so nothing links the pair.
	strangerView := *ca
	strangerView.RawSubject = testRawDN(t, asn1.TagPrintableString, testRDN{testOIDCN, "Unlinked CA"}, testRDN{testOIDOrg, "Acme"})
	strangerView.SubjectKeyId = nil
	strangerView.Subject = pkix.Name{}
	strangerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}
	stranger := testEvidenceCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(911),
		Subject:      pkix.Name{CommonName: "unlinked-stranger.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, strangerKey, &strangerView, caKey)

	if err := ca.CheckSignature(stranger.SignatureAlgorithm, stranger.RawTBSCertificate, stranger.Signature); err != nil {
		t.Fatalf("setup: the CA's key did not sign the stranger, so this fixture cannot show a verifiable signature going unchecked: %v", err)
	}

	g := testNameLinkGraph(t, ca, stranger)
	const strangerIdx, caIdx = 1, 0
	if g.edge(strangerIdx, caIdx).linked() {
		t.Fatal("setup: the pair is linked, so the cost contract under test does not apply to it")
	}
	if got := g.proofChecks; got != 0 {
		t.Errorf("building the graph paid for %d signature verification(s), want 0: no pair here is linked", got)
	}
	if g.proven(strangerIdx, caIdx) {
		t.Error("proven(stranger, CA) = true, want false: a signature is not evidence of issuance for a pair no name or key identifier links")
	}
	if got := g.proofChecks; got != 0 {
		t.Errorf("asking about an unlinked pair paid for %d signature verification(s), want 0", got)
	}
}

// TestNameLink_refuses_a_name_it_cannot_decode pins the guard nameLink documents:
// "a name that cannot be decoded matches nothing". Two undecodable names both decode
// to a nil RDNSequence and reflect.DeepEqual(nil, nil) is true, so a decode whose
// failure is not honoured turns EVERY pair of unreadable names into a SEMANTIC name
// match: two unrelated certificates become linked, the pair earns a candidate parent
// edge plus a signature verification, and a stranger can be ranked into the emitted
// chain. Nothing else in the suite reaches decodedName's failure return, and no
// mutation of the condition survives it either (flipping the whole condition breaks
// the decodable names every other test uses), so this direction is only reachable by
// asserting it directly.
func TestNameLink_refuses_a_name_it_cannot_decode(t *testing.T) {
	t.Parallel()
	decodable := testRawDN(t, asn1.TagPrintableString, testRDN{testOIDCN, "Decodable CA"})
	// Both halves of the decode guard: an ASN.1 NULL, which is no RDNSequence at all,
	// and a well-formed RDNSequence carrying one trailing byte.
	notASequence := []byte{0x05, 0x00}
	trailingByte := append(slices.Clone(decodable), 0x00)

	for _, tc := range []struct {
		name          string
		childIssuer   []byte
		parentSubject []byte
		want          nameLinkage
	}{
		{"neither name decodes", notASequence, trailingByte, nameLinkNone},
		{"the child's issuer name does not decode", notASequence, decodable, nameLinkNone},
		{"the parent's subject name does not decode", decodable, trailingByte, nameLinkNone},
		{"undecodable but byte-identical names still match exactly", notASequence, notASequence, nameLinkExact},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := &certGraph{
				certs: []*x509.Certificate{
					{RawIssuer: tc.childIssuer},
					{RawSubject: tc.parentSubject},
				},
				decodedSubjects: make([]decodedDN, 2),
				decodedIssuers:  make([]decodedDN, 2),
			}
			if got := g.nameLink(0, 1); got != tc.want {
				t.Errorf("nameLink(child issuer %x, parent subject %x) = %d, want %d",
					tc.childIssuer, tc.parentSubject, got, tc.want)
			}
		})
	}
}

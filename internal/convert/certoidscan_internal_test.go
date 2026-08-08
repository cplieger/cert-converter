package convert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// The certificate identifier guard's tests live in the internal package because the
// guard is deliberately not on the package surface: it is a step inside
// certScan.visit, and both halves of its contract — the sites it measures and the
// shapes it refuses to read — are only observable from here.
//
// Every fixture below is built by hand rather than by x509.CreateCertificate,
// because the sites that matter most (the signature and public-key algorithm
// identifiers, an access method, a policy qualifier) are ones CreateCertificate
// writes itself and gives no template field for. The builder's own honesty is
// pinned by TestCertificateFixture_builds_a_certificate_x509_parses_every_site_of,
// which asserts x509.ParseCertificate reads each site out of the default fixture.

// Identifiers the fixtures name at each site, as the DER CONTENT bytes the walk
// compares and measures (no tag, no length).
var (
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPrime256v1      = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCommonName      = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidServerAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidCPSQualifier    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
	oidOCSPAccess      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidPrivatePolicy   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	oidPrivateMapA     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}
	oidPrivateMapB     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 3}
	oidPrivateExtn     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

// wideLegalOIDArcs is the arc count of the identifier that reproduced the guard's
// first defect: 2 leading arcs plus 9 arcs of 2^28-1, which encode to four base-128
// bytes each, for 37 content bytes. RFC 5280 places no limit on either number, and
// x509.CreateCertificate writes it and x509.ParseCertificate reads it back.
const wideLegalOIDArcs = 11

// legalOIDContent returns the content bytes of a legal identifier with arcs-2 arcs
// of 2^28-1 after the 1.2 prefix, so a test can ask for an identifier of a chosen
// width without hardcoding bytes. Every sub-identifier stays inside the 31 bits
// crypto/x509 accepts, so the result is an identifier the parser really decodes
// rather than one it would refuse on its own.
func legalOIDContent(t testing.TB, arcs int) []byte {
	t.Helper()
	oid := asn1.ObjectIdentifier{1, 2}
	for range arcs - 2 {
		oid = append(oid, 268435455)
	}
	return oidContentBytes(t, oid)
}

// oidContentBytes is oidContent with a test failure instead of a nil return, so a
// fixture cannot silently name an empty identifier.
func oidContentBytes(t testing.TB, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	content := oidContent(oid)
	if len(content) == 0 {
		t.Fatalf("setup: oidContent(%v) is empty", oid)
	}
	return content
}

// oversizedOIDContent returns the content bytes of a legal identifier just past
// maxCertificateOIDBytes: 65 arcs of 2^28-1 after the 1.2 prefix, 257 bytes. Legal
// is the point — the guard is a resource policy, so the certificate it refuses has
// to be one crypto/x509 would otherwise decode.
func oversizedOIDContent(t testing.TB) []byte {
	t.Helper()
	content := legalOIDContent(t, 2+(maxCertificateOIDBytes/4)+1)
	if len(content) <= maxCertificateOIDBytes {
		t.Fatalf("setup: oversizedOIDContent built %d bytes, want more than the %d-byte ceiling",
			len(content), maxCertificateOIDBytes)
	}
	return content
}

// --- fixture ---

// certificateFixture builds one certificate's DER with an identifier of the test's
// choosing at each site the walk covers. The zero value is not useful; start from
// legalCertificateFixture and override one field per case.
//
// Field order groups the sites in the order the walk visits them, which is the
// order the DER carries them.
// An algorithm field holds an identifier's CONTENT bytes; a parameters field holds
// the whole ENCODED parameters element (nil for absent), because a test needs to put
// shapes other than a bare identifier there — RSASSA-PSS keeps two more
// AlgorithmIdentifiers inside its parameters.
type certificateFixture struct {
	signatureAlgorithm    []byte
	signatureParameters   []byte
	publicKeyAlgorithm    []byte
	publicKeyParameters   []byte
	publicKeyBits         []byte
	issuerAttribute       []byte
	subjectAttribute      []byte
	unknownExtensionID    []byte
	unknownExtensionValue []byte
	// criticalExtendedKeyUsage marks the extended key usage extension critical,
	// which inserts the BOOLEAN the walk has to step over between an extnID and its
	// value. Only that one, because x509 refuses a critical authority information
	// access or subject key identifier outright.
	criticalExtendedKeyUsage bool
	// uniqueIDs adds the optional [1] issuerUniqueID and [2] subjectUniqueID, the
	// fields that can sit between the public key and the extensions.
	uniqueIDs            bool
	extendedKeyUsage     []byte
	certificatePolicy    []byte
	policyQualifier      []byte
	policyMappingIssuer  []byte
	policyMappingSubject []byte
	accessMethod         []byte
}

// legalCertificateFixture is an ordinary ECDSA certificate carrying one of every
// extension the walk descends into, with a real P-256 public key so the parser's
// public-key path runs for real.
func legalCertificateFixture(t testing.TB) *certificateFixture {
	t.Helper()
	return &certificateFixture{
		signatureAlgorithm:    oidContentBytes(t, oidECDSAWithSHA256),
		publicKeyAlgorithm:    oidContentBytes(t, oidECPublicKey),
		publicKeyParameters:   derOID(t, oidContentBytes(t, oidPrime256v1)),
		publicKeyBits:         testP256PublicKeyBits(t),
		issuerAttribute:       oidContentBytes(t, oidCommonName),
		subjectAttribute:      oidContentBytes(t, oidCommonName),
		unknownExtensionID:    oidContentBytes(t, oidPrivateExtn),
		unknownExtensionValue: []byte{0x04, 0x02, 0x01, 0x02},
		extendedKeyUsage:      oidContentBytes(t, oidServerAuth),
		certificatePolicy:     oidContentBytes(t, oidPrivatePolicy),
		policyQualifier:       oidContentBytes(t, oidCPSQualifier),
		policyMappingIssuer:   oidContentBytes(t, oidPrivateMapA),
		policyMappingSubject:  oidContentBytes(t, oidPrivateMapB),
		accessMethod:          oidContentBytes(t, oidOCSPAccess),
	}
}

// testP256PublicKeyBits returns the uncompressed point of a fresh P-256 key, taken
// out of a real SPKI so the fixture's public key is one crypto/ecdsa accepts.
func testP256PublicKeyBits(t testing.TB) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: ecdsa.GenerateKey = error %v, want nil", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("setup: MarshalPKIXPublicKey = error %v, want nil", err)
	}
	var parsed struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &parsed); err != nil {
		t.Fatalf("setup: unmarshal the marshalled SPKI = error %v, want nil", err)
	}
	return parsed.PublicKey.Bytes
}

// build assembles the fixture into certificate DER: SEQUENCE { TBSCertificate,
// AlgorithmIdentifier, BIT STRING }. The signature bytes are arbitrary, because
// x509.ParseCertificate does not verify a signature — only its encoding.
//
// The outer AlgorithmIdentifier is always the TBS copy verbatim: x509 requires the
// two byte-for-byte equal and the walk descends only into the TBS one (see
// walkCertificate), so there is no case a differing outer copy could express.
func (f *certificateFixture) build(t testing.TB) []byte {
	t.Helper()
	return derSequenceOf(t,
		f.buildTBS(t),
		derAlgorithmIdentifier(t, f.signatureAlgorithm, f.signatureParameters),
		derBitString(t, []byte{0xde, 0xad, 0xbe, 0xef}),
	)
}

// buildTBS assembles the TBSCertificate: a v3 certificate, so the extensions field
// is one the parser reads.
func (f *certificateFixture) buildTBS(t testing.TB) []byte {
	t.Helper()
	fields := [][]byte{
		derContextCompound(t, 0, derInteger(t, 2)), // version v3
		derInteger(t, 42),                          // serialNumber
		derAlgorithmIdentifier(t, f.signatureAlgorithm, f.signatureParameters),
		derName(t, f.issuerAttribute, "fixture-issuer.example.com"),
		derValidity(t),
		derName(t, f.subjectAttribute, "fixture-subject.example.com"),
		derSequenceOf(t,
			derAlgorithmIdentifier(t, f.publicKeyAlgorithm, f.publicKeyParameters),
			derBitString(t, f.publicKeyBits),
		),
	}
	if f.uniqueIDs {
		// [1] and [2] are IMPLICIT BIT STRINGs, so the tag replaces the BIT STRING's
		// and the content still opens with its unused-bit count.
		fields = append(fields,
			derContextPrimitive(t, 1, []byte{0x00, 0xa5}),
			derContextPrimitive(t, 2, []byte{0x00, 0x5a}),
		)
	}
	return derSequenceOf(t, append(fields, derContextCompound(t, 3, f.buildExtensions(t)))...)
}

// buildExtensions assembles one of every extension the walk knows a schema for,
// plus an unknown noncritical one whose value is opaque bytes.
func (f *certificateFixture) buildExtensions(t testing.TB) []byte {
	t.Helper()
	noncritical := func(extnID, value []byte) []byte {
		return derExtension(t, extnID, false, value)
	}
	return derSequenceOf(t,
		noncritical(f.unknownExtensionID, f.unknownExtensionValue),
		derExtension(t, extKeyUsageExtnID, f.criticalExtendedKeyUsage,
			derSequenceOf(t, derOID(t, f.extendedKeyUsage))),
		noncritical(certificatePoliciesExtnID, derSequenceOf(t,
			derSequenceOf(t,
				derOID(t, f.certificatePolicy),
				derSequenceOf(t, derSequenceOf(t,
					derOID(t, f.policyQualifier),
					derIA5String(t, "https://cps.example.com"),
				)),
			),
		)),
		noncritical(policyMappingsExtnID, derSequenceOf(t, derSequenceOf(t,
			derOID(t, f.policyMappingIssuer),
			derOID(t, f.policyMappingSubject),
		))),
		noncritical(authorityInfoAccessExtnID, derSequenceOf(t, derSequenceOf(t,
			derOID(t, f.accessMethod),
			derContextPrimitive(t, 6, []byte("https://ocsp.example.com")),
		))),
	)
}

// --- DER helpers ---
//
// testing.TB rather than *testing.T so a rapid property can build a fixture too
// (rapid.T cannot implement testing.TB, so a property passes the outer *testing.T;
// every helper here only ever fails on a marshal error, which is impossible for
// these shapes).

func derRawValue(t testing.TB, class, tag int, compound bool, content []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: content})
	if err != nil {
		t.Fatalf("setup: marshal class %d tag %d = error %v, want nil", class, tag, err)
	}
	return der
}

func derSequenceOf(t testing.TB, elements ...[]byte) []byte {
	t.Helper()
	return derRawValue(t, asn1.ClassUniversal, asn1.TagSequence, true, bytes.Join(elements, nil))
}

func derSetOf(t testing.TB, elements ...[]byte) []byte {
	t.Helper()
	return derRawValue(t, asn1.ClassUniversal, asn1.TagSet, true, bytes.Join(elements, nil))
}

func derOID(t testing.TB, content []byte) []byte {
	t.Helper()
	return derRawValue(t, asn1.ClassUniversal, asn1.TagOID, false, content)
}

func derOctetString(t testing.TB, content []byte) []byte {
	t.Helper()
	return derRawValue(t, asn1.ClassUniversal, asn1.TagOctetString, false, content)
}

func derContextCompound(t testing.TB, tag int, content []byte) []byte {
	t.Helper()
	return derRawValue(t, asn1.ClassContextSpecific, tag, true, content)
}

func derContextPrimitive(t testing.TB, tag int, content []byte) []byte {
	t.Helper()
	return derRawValue(t, asn1.ClassContextSpecific, tag, false, content)
}

func derInteger(t testing.TB, value int64) []byte {
	t.Helper()
	der, err := asn1.Marshal(big.NewInt(value))
	if err != nil {
		t.Fatalf("setup: marshal integer %d = error %v, want nil", value, err)
	}
	return der
}

func derBitString(t testing.TB, content []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(asn1.BitString{Bytes: content, BitLength: 8 * len(content)})
	if err != nil {
		t.Fatalf("setup: marshal bit string = error %v, want nil", err)
	}
	return der
}

func derIA5String(t testing.TB, value string) []byte {
	t.Helper()
	return derRawValue(t, asn1.ClassUniversal, asn1.TagIA5String, false, []byte(value))
}

func derPrintableString(t testing.TB, value string) []byte {
	t.Helper()
	return derRawValue(t, asn1.ClassUniversal, asn1.TagPrintableString, false, []byte(value))
}

// derAlgorithmIdentifier builds SEQUENCE { algorithm OBJECT IDENTIFIER,
// parameters ANY DEFINED BY algorithm OPTIONAL } from an identifier's content bytes
// and an already-encoded parameters element, omitting the parameters when there are
// none.
func derAlgorithmIdentifier(t testing.TB, algorithm, parameters []byte) []byte {
	t.Helper()
	if parameters == nil {
		return derSequenceOf(t, derOID(t, algorithm))
	}
	return derSequenceOf(t, derOID(t, algorithm), parameters)
}

// derPSSParameters builds RSASSA-PSS parameters (RFC 4055 3.1) naming hash as both
// the message digest and the MGF1 digest, which is the shape crypto/x509 requires
// before it will recognise a PSS signature algorithm. It is the deepest identifier
// nest the parser decodes out of an AlgorithmIdentifier: the MGF1 digest sits inside
// an AlgorithmIdentifier inside the maskGenAlgorithm inside the parameters.
func derPSSParameters(t testing.TB, hash []byte) []byte {
	t.Helper()
	digest := derSequenceOf(t, derOID(t, hash), derNull(t))
	return derSequenceOf(t,
		derContextCompound(t, 0, digest),
		derContextCompound(t, 1, derSequenceOf(t, derOID(t, oidContentBytes(t, oidMGF1)), digest)),
		derContextCompound(t, 2, derInteger(t, 32)),
	)
}

// derNull is the ASN.1 NULL an AlgorithmIdentifier's parameters carry when the
// algorithm takes none.
func derNull(t testing.TB) []byte {
	t.Helper()
	return derRawValue(t, asn1.ClassUniversal, asn1.TagNull, false, nil)
}

// derName builds a one-attribute RDNSequence: SEQUENCE OF SET OF SEQUENCE
// { type OID, value PrintableString }.
func derName(t testing.TB, attributeType []byte, value string) []byte {
	t.Helper()
	return derSequenceOf(t, derSetOf(t, derSequenceOf(t,
		derOID(t, attributeType),
		derPrintableString(t, value),
	)))
}

// derValidity builds SEQUENCE { notBefore UTCTime, notAfter UTCTime }, in a window
// that does not move with the clock.
func derValidity(t testing.TB) []byte {
	t.Helper()
	notBefore, err := asn1.Marshal(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("setup: marshal notBefore = error %v, want nil", err)
	}
	notAfter, err := asn1.Marshal(time.Date(2036, time.January, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("setup: marshal notAfter = error %v, want nil", err)
	}
	return derSequenceOf(t, notBefore, notAfter)
}

// derExtension builds SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
// extnValue OCTET STRING }, omitting the critical flag at its default the way a CA
// does — and emitting it when a case needs the walk to step over it.
func derExtension(t testing.TB, extnID []byte, critical bool, value []byte) []byte {
	t.Helper()
	if !critical {
		return derSequenceOf(t, derOID(t, extnID), derOctetString(t, value))
	}
	return derSequenceOf(t, derOID(t, extnID), derBoolean(t, true), derOctetString(t, value))
}

// derBoolean is the DER BOOLEAN an extension's critical flag is.
func derBoolean(t testing.TB, value bool) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("setup: marshal boolean %v = error %v, want nil", value, err)
	}
	return der
}

// certificateBlock wraps DER as the PEM block the guard is handed.
func certificateBlock(der []byte) *pem.Block {
	return &pem.Block{Type: pemTypeCertificate, Bytes: der}
}

// --- the fixture's own honesty ---

// TestCertificateFixture_builds_a_certificate_x509_parses_every_site_of is what
// makes every other test in this file mean something: it asserts crypto/x509 not
// only ACCEPTS the default fixture but reads an identifier out of each site the
// walk covers, so a case that plants an oversized identifier at one of those sites
// is planting it where the parser really decodes one.
//
// It is also half of the drift guard: if a future crypto/x509 stops populating one
// of these, the site's entry here fails and the walk's coverage claim is re-read
// against the new parser.
func TestCertificateFixture_builds_a_certificate_x509_parses_every_site_of(t *testing.T) {
	t.Parallel()
	der := legalCertificateFixture(t).build(t)
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(the default fixture) = error %v, want nil: every case in this file builds on it", err)
	}

	if err := oversizedCertificateOIDError(certificateBlock(der)); err != nil {
		t.Errorf("oversizedCertificateOIDError(an ordinary certificate) = %v, want nil: nothing legitimate may be refused", err)
	}

	for site, observed := range map[string]bool{
		siteSignatureAlgorithm: certificate.SignatureAlgorithm == x509.ECDSAWithSHA256,
		sitePublicKeyAlgorithm: certificate.PublicKeyAlgorithm == x509.ECDSA,
		sitePublicKeyParameter: certificate.PublicKey != nil,
		siteIssuerAttribute:    certificate.Issuer.CommonName == "fixture-issuer.example.com",
		siteSubjectAttribute:   certificate.Subject.CommonName == "fixture-subject.example.com",
		siteExtensionID:        len(certificate.Extensions) == 5,
		siteExtendedKeyUsage:   slices.Contains(certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth),
		siteCertificatePolicy: len(certificate.Policies) == 1 &&
			len(certificate.PolicyIdentifiers) == 1 &&
			certificate.PolicyIdentifiers[0].Equal(oidPrivatePolicy),
		sitePolicyMapping: len(certificate.PolicyMappings) == 1,
		siteAuthorityInfoAccessMethod: len(certificate.OCSPServer) == 1 &&
			certificate.OCSPServer[0] == "https://ocsp.example.com",
	} {
		if !observed {
			t.Errorf("x509.ParseCertificate did not read the %s out of the fixture; the cases that plant an oversized identifier there prove nothing until the fixture is fixed", site)
		}
	}
}

// TestCertificateFixture_pss_parameters_hold_identifiers_x509_decodes proves the
// nested-parameter site is real rather than defensive. crypto/x509 can only reach
// the SHA256WithRSAPSS verdict by decoding the hash identifier inside the
// parameters, the MGF identifier beside it, and the hash identifier nested inside
// the MGF's own parameters, and comparing all three — so a certificate it names
// SHA256WithRSAPSS is one whose parameters it decoded three identifiers out of.
func TestCertificateFixture_pss_parameters_hold_identifiers_x509_decodes(t *testing.T) {
	t.Parallel()
	fixture := legalCertificateFixture(t)
	fixture.signatureAlgorithm = oidContentBytes(t, oidRSASSAPSS)
	fixture.signatureParameters = derPSSParameters(t, oidContentBytes(t, oidSHA256))
	der := fixture.build(t)

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(an RSASSA-PSS fixture) = error %v, want nil", err)
	}
	if certificate.SignatureAlgorithm != x509.SHA256WithRSAPSS {
		t.Errorf("SignatureAlgorithm = %v, want SHA256WithRSAPSS: the parser no longer decodes the identifiers nested in the signature parameters, so the site row for them proves nothing",
			certificate.SignatureAlgorithm)
	}
	if err := oversizedCertificateOIDError(certificateBlock(der)); err != nil {
		t.Errorf("oversizedCertificateOIDError(an ordinary RSASSA-PSS certificate) = %v, want nil", err)
	}
}

// --- the two defects this walk replaced a byte-recursive guard to fix ---

// TestOversizedCertificateOIDError_accepts_a_wide_but_legal_identifier is the
// regression test for the first defect: the guard refused VALID certificates.
//
// The ceiling it compared against was profile.go's maxOIDBytes, which is sized
// against the four PKCS#12 profiles this app itself writes (9 bytes at most).
// Nothing in X.509 bounds an identifier's total length or arc count — the only
// structural limit is per sub-identifier — so a certificate naming a wide-but-legal
// identifier is one x509.CreateCertificate writes and x509.ParseCertificate reads,
// and refusing it meant a renewal this app could not convert with no way for the
// operator to fix the certificate.
func TestOversizedCertificateOIDError_accepts_a_wide_but_legal_identifier(t *testing.T) {
	t.Parallel()

	wide := legalOIDContent(t, wideLegalOIDArcs)
	if len(wide) != 37 {
		t.Fatalf("setup: the %d-arc identifier is %d content bytes, want the 37 the defect was reproduced with",
			wideLegalOIDArcs, len(wide))
	}

	for name, plant := range map[string]func(f *certificateFixture){
		"as an extension identifier":  func(f *certificateFixture) { f.unknownExtensionID = wide },
		"as a subject attribute type": func(f *certificateFixture) { f.subjectAttribute = wide },
		"as an extended key usage":    func(f *certificateFixture) { f.extendedKeyUsage = wide },
		"as a certificate policy":     func(f *certificateFixture) { f.certificatePolicy = wide },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := legalCertificateFixture(t)
			plant(fixture)
			der := fixture.build(t)
			if _, err := x509.ParseCertificate(der); err != nil {
				t.Fatalf("x509.ParseCertificate(a certificate naming a 37-byte identifier %s) = error %v, want nil: the identifier is legal", name, err)
			}
			if err := oversizedCertificateOIDError(certificateBlock(der)); err != nil {
				t.Errorf("oversizedCertificateOIDError(a certificate naming a 37-byte identifier %s) = %v, want nil: X.509 sets no limit on an identifier's width and the parser accepts this certificate", name, err)
			}
		})
	}
}

// TestOversizedCertificateOIDError_ignores_an_unknown_extensions_opaque_value is
// the regression test for the second defect: the guard read opaque bytes as DER.
//
// The walk it replaced descended into every OCTET STRING's content, so an unknown
// noncritical extension whose value happens to open with an identifier tag and a
// plausible length was measured as an identifier. That value is bytes whose meaning
// belongs to whoever minted the extension; crypto/x509 hands it to the caller
// untouched and never decodes an identifier out of it. Measured before this change:
// 8 of 4000 valid certificates carrying 512 bytes of random opaque extension data
// were refused.
func TestOversizedCertificateOIDError_ignores_an_unknown_extensions_opaque_value(t *testing.T) {
	t.Parallel()

	// The worst case, built rather than stumbled upon: an identifier tag, a
	// minimal long-form length, and content wider than the ceiling.
	content := bytes.Repeat([]byte{0x01}, 2*maxCertificateOIDBytes)
	opaque := append([]byte{0x06, 0x82, byte(len(content) >> 8), byte(len(content))}, content...)

	fixture := legalCertificateFixture(t)
	fixture.unknownExtensionValue = opaque
	der := fixture.build(t)
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatalf("x509.ParseCertificate(a certificate with opaque extension bytes) = error %v, want nil", err)
	}
	if err := oversizedCertificateOIDError(certificateBlock(der)); err != nil {
		t.Errorf("oversizedCertificateOIDError(opaque extension bytes shaped like a %d-byte identifier) = %v, want nil: an unknown extension's value is not DER this app may read",
			len(content), err)
	}

	// The same claim across arbitrary opaque values lives in
	// FuzzCertificateOIDGuard_opaqueExtensionValueMovesNoVerdict below: the defect was
	// found as a rate rather than as a case, and a durable committed corpus is what a
	// rate needs.
}

// FuzzCertificateOIDGuard_opaqueExtensionValueMovesNoVerdict is the arbitrary-value
// half of the claim above, in BOTH directions: an unknown extension's value may not
// produce a refusal, and it may not suppress or re-attribute one either.
//
// It replaced a loop over twelve crypto/rand values, which could not do the job for
// two reasons. It was unseeded, so a failure named an input the next run would not
// see again — and this is the one defect in this file's history that was found as a
// RATE (8 of 4000 valid certificates), which is exactly the shape you must be able
// to reproduce. And uniform random bytes are almost never DER: the values that
// actually reach an identifier-measuring regression are well-formed elements, and
// the committed seeds below are those. A guard that reads an unknown extnValue only
// when it happens to be a valid SEQUENCE leaves every other test in this package
// green and is caught by seed 4 on every PR.
//
// The second direction is not otherwise asserted anywhere: record() keeps only the
// widest identifier it saw, so a value read as DER does not merely add a refusal, it
// can take over the site the diagnostic names and send an operator to the wrong
// field.
func FuzzCertificateOIDGuard_opaqueExtensionValueMovesNoVerdict(f *testing.F) {
	base := legalCertificateFixture(f)
	oversized := oversizedOIDContent(f)
	bareOID := derOID(f, oversized)

	f.Add([]byte(nil))
	f.Add([]byte{0x04, 0x02, 0x01, 0x02})
	f.Add(bareOID)
	f.Add(derSequenceOf(f, bareOID))
	f.Add(derSequenceOf(f, derSequenceOf(f, bareOID, derSequenceOf(f, bareOID))))
	f.Add(derSetOf(f, derSequenceOf(f, bareOID, derPrintableString(f, "x"))))
	f.Add(derOctetString(f, derSequenceOf(f, bareOID)))
	f.Add(derContextCompound(f, 3, derSequenceOf(f, derSequenceOf(f, bareOID))))
	f.Add(append([]byte{0x06, 0x82, 0x02, 0x00}, bytes.Repeat([]byte{0x01}, 2*maxCertificateOIDBytes)...))
	f.Add([]byte{0x30, 0x7f, 0x06, 0x7d})
	f.Add(bytes.Repeat([]byte{0xff}, 1024))

	f.Fuzz(func(t *testing.T, opaque []byte) {
		ordinary := *base
		ordinary.unknownExtensionValue = opaque
		if err := oversizedCertificateOIDError(certificateBlock(ordinary.build(t))); err != nil {
			t.Fatalf("oversizedCertificateOIDError(an ordinary certificate carrying %d opaque extension byte(s)) = %v, want nil: an unknown extension's value is bytes whose meaning belongs to whoever minted the extension, and reading them as DER is what refused valid certificates",
				len(opaque), err)
		}

		planted := *base
		planted.unknownExtensionValue = opaque
		planted.subjectAttribute = oversized
		err := oversizedCertificateOIDError(certificateBlock(planted.build(t)))
		if err == nil {
			t.Fatalf("oversizedCertificateOIDError(an oversized subject attribute type beside %d opaque extension byte(s)) = nil, want a refusal",
				len(opaque))
		}
		if !strings.Contains(err.Error(), siteSubjectAttribute) {
			t.Fatalf("error = %q, want it to name the %q site: an unknown extension's value must not be measured as an identifier, and it must not take the widest-site diagnostic either",
				err, siteSubjectAttribute)
		}
	})
}

// --- site coverage ---

// TestOversizedCertificateOIDError_refuses_an_oversized_identifier_at_every_site
// walks the whole list of sites the guard claims to cover and plants an oversized
// identifier at each one. Every row must be refused AND the refusal must name that
// site, which is what keeps the diagnostic honest as the walk grows.
//
// parserAccepts records whether crypto/x509 accepts the same DER. Where it does,
// the row proves the GUARD refuses a certificate the parser would have decoded
// (the resource policy doing its job). Where it does not, the row is a site the
// parser decodes and THEN rejects for its own reasons — the allocation is still
// paid before the rejection, which is exactly why the site is covered.
func TestOversizedCertificateOIDError_refuses_an_oversized_identifier_at_every_site(t *testing.T) {
	t.Parallel()
	oversized := oversizedOIDContent(t)

	cases := map[string]struct {
		plant         func(f *certificateFixture)
		wantSite      string
		parserAccepts bool
	}{
		"the signature algorithm identifier": {
			plant:         func(f *certificateFixture) { f.signatureAlgorithm = oversized },
			wantSite:      siteSignatureAlgorithm,
			parserAccepts: true,
		},
		"the signature algorithm parameters": {
			plant:         func(f *certificateFixture) { f.signatureParameters = derOID(t, oversized) },
			wantSite:      siteSignatureParameter,
			parserAccepts: true,
		},
		"an identifier nested inside RSASSA-PSS signature parameters": {
			// The deepest identifier the parser decodes out of an
			// AlgorithmIdentifier, and the only place the walk still recurses:
			// getSignatureAlgorithmFromAI unmarshals the PSS parameters and then
			// the MGF1 parameters, decoding an identifier at each level, before it
			// can conclude the algorithm is one it does not recognise.
			plant: func(f *certificateFixture) {
				f.signatureAlgorithm = oidContentBytes(t, oidRSASSAPSS)
				f.signatureParameters = derPSSParameters(t, oversized)
			},
			wantSite:      siteSignatureParameter,
			parserAccepts: true,
		},
		"the public key algorithm identifier": {
			plant:         func(f *certificateFixture) { f.publicKeyAlgorithm = oversized },
			wantSite:      sitePublicKeyAlgorithm,
			parserAccepts: true,
		},
		"the public key algorithm parameters": {
			// An EC key's named curve. The parser decodes it and then refuses the
			// certificate for naming a curve it does not implement.
			plant:    func(f *certificateFixture) { f.publicKeyParameters = derOID(t, oversized) },
			wantSite: sitePublicKeyParameter,
		},
		"an issuer attribute type": {
			plant:         func(f *certificateFixture) { f.issuerAttribute = oversized },
			wantSite:      siteIssuerAttribute,
			parserAccepts: true,
		},
		"a subject attribute type": {
			plant:         func(f *certificateFixture) { f.subjectAttribute = oversized },
			wantSite:      siteSubjectAttribute,
			parserAccepts: true,
		},
		"an extension identifier": {
			plant:         func(f *certificateFixture) { f.unknownExtensionID = oversized },
			wantSite:      siteExtensionID,
			parserAccepts: true,
		},
		"an extended key usage identifier": {
			plant:         func(f *certificateFixture) { f.extendedKeyUsage = oversized },
			wantSite:      siteExtendedKeyUsage,
			parserAccepts: true,
		},
		"a certificate policy identifier": {
			plant:         func(f *certificateFixture) { f.certificatePolicy = oversized },
			wantSite:      siteCertificatePolicy,
			parserAccepts: true,
		},
		"a policy mapping identifier": {
			plant:         func(f *certificateFixture) { f.policyMappingSubject = oversized },
			wantSite:      sitePolicyMapping,
			parserAccepts: true,
		},
		"an authority information access method": {
			plant:         func(f *certificateFixture) { f.accessMethod = oversized },
			wantSite:      siteAuthorityInfoAccessMethod,
			parserAccepts: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := legalCertificateFixture(t)
			tc.plant(fixture)
			der := fixture.build(t)

			_, parseErr := x509.ParseCertificate(der)
			if tc.parserAccepts != (parseErr == nil) {
				t.Errorf("x509.ParseCertificate(an oversized identifier at %s) error = %v, want accepted = %v: the case's premise about the parser moved",
					name, parseErr, tc.parserAccepts)
			}

			err := oversizedCertificateOIDError(certificateBlock(der))
			if err == nil {
				t.Fatalf("oversizedCertificateOIDError(a %d-byte identifier at %s) = nil, want a refusal: the walk does not cover this site",
					len(oversized), name)
			}
			if !strings.Contains(err.Error(), tc.wantSite) {
				t.Errorf("error = %q, want it to name the %q site", err, tc.wantSite)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(len(oversized))) {
				t.Errorf("error = %q, want it to name the %d-byte identifier it measured", err, len(oversized))
			}
		})
	}

	// Every site the walk claims must have a row above, so a site added to
	// certOIDScan without a fixture that reaches it cannot pass unnoticed. The rows
	// are what prove the walk RECORDS at a site; the drift guards below prove
	// crypto/x509 still DECODES there.
	covered := make([]string, 0, len(cases))
	for _, tc := range cases {
		covered = append(covered, tc.wantSite)
	}
	for _, site := range certificateWalkSites() {
		if !slices.Contains(covered, site) {
			t.Errorf("no case plants an oversized identifier at the %q site, so nothing proves the walk still reaches it", site)
		}
	}
}

// TestCertificateExtnIDBytes_name_the_extensions_the_walk_descends_into pins the
// content bytes the walk recognises an extension by. They are derived from the
// dotted identifiers at init, so this is the check that the derivation produced
// anything at all: oidContent returns nil rather than panicking on the impossible
// marshal failure, and a nil here would silently stop the walk descending into that
// extension's value — a hole no other test in this file would notice, because every
// verdict the walk cannot reach is a fail-open nil.
func TestCertificateExtnIDBytes_name_the_extensions_the_walk_descends_into(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		got  []byte
		want asn1.ObjectIdentifier
	}{
		"extended key usage":         {extKeyUsageExtnID, oidExtensionExtKeyUsage},
		"certificate policies":       {certificatePoliciesExtnID, oidExtensionCertificatePolicies},
		"policy mappings":            {policyMappingsExtnID, oidExtensionPolicyMappings},
		"authority information acc.": {authorityInfoAccessExtnID, oidExtensionAuthorityInfoAccess},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if len(tc.got) == 0 {
				t.Fatalf("the %s extnID bytes are empty: the walk would never descend into that extension's value", name)
			}
			var decoded asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(derOID(t, tc.got), &decoded); err != nil {
				t.Fatalf("the %s extnID bytes do not decode: %v", name, err)
			}
			if !decoded.Equal(tc.want) {
				t.Errorf("the %s extnID bytes decode to %v, want %v", name, decoded, tc.want)
			}
		})
	}
}

// --- the walk's own bounds ---

// legalOIDContentOfSize returns the content bytes of a legal object identifier of
// EXACTLY size bytes, so a case can sit one byte either side of
// maxCertificateOIDBytes. legalOIDContent can only build widths of the form 4n+1,
// which is why neither boundary is expressible with it.
//
// Every sub-identifier stays inside the 31 bits crypto/x509 accepts, so the result
// is an identifier the parser really decodes rather than one it refuses on its own.
func legalOIDContentOfSize(t testing.TB, size int) []byte {
	t.Helper()
	oid := asn1.ObjectIdentifier{1, 2} // the 1.2 prefix: one content byte
	remaining := size - 1
	for ; remaining >= 4; remaining -= 4 {
		oid = append(oid, 1<<28-1) // four base-128 bytes
	}
	switch remaining {
	case 1:
		oid = append(oid, 1) // one base-128 byte
	case 2:
		oid = append(oid, 1<<7) // two
	case 3:
		oid = append(oid, 1<<14) // three
	}
	content := oidContentBytes(t, oid)
	if len(content) != size {
		t.Fatalf("setup: legalOIDContentOfSize(%d) built %d content byte(s)", size, len(content))
	}
	return content
}

// TestOversizedCertificateOIDError_pins_the_ceiling_as_a_boundary pins
// maxCertificateOIDBytes as the BOUNDARY it is documented to be, the way the salt,
// iteration and safe-bag bounds in this package are already pinned: one case at
// exactly the ceiling that must be ACCEPTED, one a single byte past it that must be
// REFUSED.
//
// Nothing else pins the comparison. The accepted case is 37 bytes and the refused
// one 257, so the whole gap between them is unasserted: with the comparison written
// >= instead of >, every test in this package stays green while a certificate naming
// an identifier of exactly the ceiling is refused -- the over-rejection this
// constant replaced, on the one width the policy says it admits.
func TestOversizedCertificateOIDError_pins_the_ceiling_as_a_boundary(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		size        int
		wantRefused bool
	}{
		"an identifier of exactly the ceiling": {maxCertificateOIDBytes, false},
		"an identifier one byte past it":       {maxCertificateOIDBytes + 1, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := legalCertificateFixture(t)
			fixture.subjectAttribute = legalOIDContentOfSize(t, tc.size)
			der := fixture.build(t)
			if _, parseErr := x509.ParseCertificate(der); parseErr != nil {
				t.Fatalf("x509.ParseCertificate(a certificate naming a %d-byte identifier as its subject attribute type) = error %v, want nil: the guard is a resource policy, so both cases have to be certificates the parser itself decodes",
					tc.size, parseErr)
			}

			err := oversizedCertificateOIDError(certificateBlock(der))
			if tc.wantRefused {
				if err == nil {
					t.Fatalf("oversizedCertificateOIDError(a %d-byte identifier) = nil, want a refusal", tc.size)
				}
				if !strings.Contains(err.Error(), siteSubjectAttribute) {
					t.Errorf("error = %q, want it to name the %q site", err, siteSubjectAttribute)
				}
				return
			}
			if err != nil {
				t.Errorf("oversizedCertificateOIDError(a %d-byte identifier) = %v, want nil: %d bytes is the widest identifier the ceiling admits, and refusing it is the over-rejection this constant replaced",
					tc.size, err, maxCertificateOIDBytes)
			}
		})
	}
}

// TestOversizedCertificateOIDError_fails_open_on_what_it_cannot_read pins the half
// of the contract that says a guard is not a parser: every shape the walk cannot
// follow must return nil so the block reaches x509.ParseCertificate and earns the
// parser's own verdict, rather than being refused on a guess.
func TestOversizedCertificateOIDError_fails_open_on_what_it_cannot_read(t *testing.T) {
	t.Parallel()
	oversized := oversizedOIDContent(t)

	for name, der := range map[string][]byte{
		"empty input":               nil,
		"not DER at all":            []byte("this is not a certificate"),
		"not a sequence":            derInteger(t, 7),
		"a sequence holding no tbs": derSequenceOf(t, derInteger(t, 7)),
		"a truncated tbs":           derSequenceOf(t, derSequenceOf(t, derContextCompound(t, 0, derInteger(t, 2)))),
		"an oversized identifier at no site the parser reads": derSequenceOf(t,
			derSequenceOf(t, derOID(t, oversized)),
		),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := oversizedCertificateOIDError(certificateBlock(der)); err != nil {
				t.Errorf("oversizedCertificateOIDError(%s) = %v, want nil: a shape the walk cannot read is the parser's verdict to make", name, err)
			}
		})
	}
}

// TestOversizedCertificateOIDError_measures_a_later_site_behind_a_dense_earlier_field
// pins what withSubtreeBudget buys, which nothing else in this package does: each
// unbounded region of the schema walks on its OWN element budget, so a block that
// spends a whole budget describing an EARLY field cannot stop the walk from measuring
// a LATER site.
//
// Without it the fix is unpinned in both directions. With withSubtreeBudget reduced to
// a bare walk() every other test in this package stays green, and the starvation bypass
// reopens: a dense issuer exhausts the shared budget, walkTBSCertificate returns on the
// next expect, and the subject attribute type, the SPKI algorithm and the whole
// extensions subtree all reach x509.ParseCertificate unmeasured.
func TestOversizedCertificateOIDError_measures_a_later_site_behind_a_dense_earlier_field(t *testing.T) {
	t.Parallel()

	fixture := legalCertificateFixture(t)
	// A structurally valid issuer whose RDNSequence costs three elements per attribute,
	// so this exhausts one whole budget several times over.
	attribute := derSetOf(t, derSequenceOf(t,
		derOID(t, oidContentBytes(t, oidCommonName)),
		derPrintableString(t, "dense-issuer.example.com"),
	))
	denseIssuer := derRawValue(t, asn1.ClassUniversal, asn1.TagSequence, true,
		bytes.Repeat(attribute, maxCertificateOIDElements))
	oversized := oversizedOIDContent(t)

	der := derSequenceOf(t,
		derSequenceOf(t,
			derContextCompound(t, 0, derInteger(t, 2)),
			derInteger(t, 42),
			derAlgorithmIdentifier(t, fixture.signatureAlgorithm, fixture.signatureParameters),
			denseIssuer,
			derValidity(t),
			derName(t, oversized, "fixture-subject.example.com"),
			derSequenceOf(t,
				derAlgorithmIdentifier(t, fixture.publicKeyAlgorithm, fixture.publicKeyParameters),
				derBitString(t, fixture.publicKeyBits),
			),
			derContextCompound(t, 3, fixture.buildExtensions(t)),
		),
		derAlgorithmIdentifier(t, fixture.signatureAlgorithm, fixture.signatureParameters),
		derBitString(t, []byte{0xde, 0xad, 0xbe, 0xef}),
	)

	err := oversizedCertificateOIDError(certificateBlock(der))
	if err == nil {
		t.Fatal("oversizedCertificateOIDError(an oversized subject attribute type behind a budget-exhausting issuer) = nil, want a refusal: each subtree walks on its own element budget, so a dense issuer must not starve the subject")
	}
	if !strings.Contains(err.Error(), siteSubjectAttribute) {
		t.Errorf("error = %q, want it to name the %q site", err, siteSubjectAttribute)
	}
}

// TestOversizedCertificateOIDError_stops_at_the_element_budget pins the bound whose
// subject is the WALK rather than the certificate. Every element the walk reads
// costs one asn1.Unmarshal into an asn1.RawValue, and the schema it follows contains
// SEQUENCE OF loops a structurally valid certificate may fill without limit — a
// subject naming hundreds of thousands of attributes is the cheapest — so without
// maxCertificateOIDElements the guard becomes the amplification it exists to
// prevent, the way maxRSAKeyElements closes that door on the key side.
//
// Both halves are pinned: an element-dense certificate returns promptly and FAILS
// OPEN, and an oversized identifier sitting within the budget is still refused, so
// the budget cannot be read as a way past the guard.
func TestOversizedCertificateOIDError_stops_at_the_element_budget(t *testing.T) {
	t.Parallel()

	// A structurally valid subject whose RDNSequence holds far more attributes
	// than the budget allows: the shape that costs the walk everything.
	attribute := derSetOf(t, derSequenceOf(t,
		derOID(t, oidContentBytes(t, oidCommonName)),
		derPrintableString(t, "dense.example.com"),
	))
	dense := bytes.Repeat(attribute, maxCertificateOIDElements*4)
	fixture := legalCertificateFixture(t)
	der := derSequenceOf(t,
		derSequenceOf(t,
			derContextCompound(t, 0, derInteger(t, 2)),
			derInteger(t, 42),
			derAlgorithmIdentifier(t, fixture.signatureAlgorithm, nil),
			derName(t, fixture.issuerAttribute, "dense-issuer.example.com"),
			derValidity(t),
			derRawValue(t, asn1.ClassUniversal, asn1.TagSequence, true, dense),
			derSequenceOf(t,
				derAlgorithmIdentifier(t, fixture.publicKeyAlgorithm, fixture.publicKeyParameters),
				derBitString(t, fixture.publicKeyBits),
			),
		),
		derAlgorithmIdentifier(t, fixture.signatureAlgorithm, nil),
		derBitString(t, []byte{0x01}),
	)

	done := make(chan error, 1)
	go func() { done <- oversizedCertificateOIDError(certificateBlock(der)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("oversizedCertificateOIDError(an element-dense certificate) = %v, want nil: exhausting the element budget FAILS OPEN, so the block goes to the parser", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("oversizedCertificateOIDError did not return on an element-dense certificate: the element budget regressed and the guard is now the amplification it exists to prevent")
	}

	// The budget must not become a bypass: an oversized identifier among few
	// elements is still refused.
	oversizedFixture := legalCertificateFixture(t)
	oversizedFixture.subjectAttribute = oversizedOIDContent(t)
	if err := oversizedCertificateOIDError(certificateBlock(oversizedFixture.build(t))); err == nil {
		t.Error("oversizedCertificateOIDError(an oversized identifier within the budget) = nil, want a refusal")
	}
}

// TestOversizedCertificateOIDError_reads_past_the_optional_fields covers the two
// optional shapes that sit between the walk and a site, and that an ordinary
// certificate does not carry: an extension's critical BOOLEAN, which stands between
// an extnID and the value the walk descends into, and the [1]/[2] unique-ID fields,
// which stand between the public key and the extensions. Both are skips, and a skip
// that stops working fails OPEN — the walk would simply stop before the extensions.
func TestOversizedCertificateOIDError_reads_past_the_optional_fields(t *testing.T) {
	t.Parallel()
	oversized := oversizedOIDContent(t)

	for name, shape := range map[string]func(f *certificateFixture){
		"an extension marked critical": func(f *certificateFixture) { f.criticalExtendedKeyUsage = true },
		"a certificate carrying both unique IDs": func(f *certificateFixture) {
			f.uniqueIDs = true
		},
		"both": func(f *certificateFixture) { f.criticalExtendedKeyUsage, f.uniqueIDs = true, true },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			legal := legalCertificateFixture(t)
			shape(legal)
			if _, err := x509.ParseCertificate(legal.build(t)); err != nil {
				t.Fatalf("x509.ParseCertificate(%s) = error %v, want nil: the case's premise about the parser moved", name, err)
			}

			fixture := legalCertificateFixture(t)
			shape(fixture)
			fixture.extendedKeyUsage = oversized
			err := oversizedCertificateOIDError(certificateBlock(fixture.build(t)))
			if err == nil {
				t.Fatalf("oversizedCertificateOIDError(an oversized extended key usage in %s) = nil, want a refusal: the walk stopped at the optional field instead of stepping over it", name)
			}
			if !strings.Contains(err.Error(), siteExtendedKeyUsage) {
				t.Errorf("error = %q, want it to name the %q site", err, siteExtendedKeyUsage)
			}
		})
	}
}

// TestParseCertChain_refuses_an_oversized_identifier_before_the_parser is the one
// test that proves the guard is WIRED. Every other case here calls
// oversizedCertificateOIDError directly, so all of them would still pass if the call
// inside certScan.visit were removed and every certificate went straight to
// x509.ParseCertificate. It also pins the diagnostic an operator actually sees: the
// block number the chain parser adds, and the site the guard names.
func TestParseCertChain_refuses_an_oversized_identifier_before_the_parser(t *testing.T) {
	t.Parallel()

	fixture := legalCertificateFixture(t)
	fixture.subjectAttribute = oversizedOIDContent(t)
	encoded := pem.EncodeToMemory(certificateBlock(fixture.build(t)))

	_, _, err := parseCertChain(encoded)
	if err == nil {
		t.Fatal("parseCertChain(a certificate naming an oversized identifier) = nil, want a refusal: the guard is not wired into the chain parser")
	}
	for _, want := range []string{"certificate PEM block 1", siteSubjectAttribute} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q", err, want)
		}
	}
}

// --- drift guard ---
//
// Option C's one real risk is that this walk is a MIRROR of crypto/x509's schema,
// and a mirror that falls behind a Go release fails OPEN: the new site simply is
// not walked, no test complains, and an oversized identifier reaches the parser
// again. The two tests below are the mitigation. The first watches the identifiers
// the parser RETAINS (a new OID-bearing field on x509.Certificate is a new site);
// the second watches the parser's SOURCE (a new identifier decode is a new site,
// retained or not). Between them, a Go release that adds an identifier site fails
// the suite instead of silently widening the hole.

// certificateOIDFields maps every OID-bearing field crypto/x509's certificate
// parser can populate to the walk site that bounds it. It is the expected result of
// the reflective sweep below; anything the sweep finds that is not here is drift.
var certificateOIDFields = map[string]string{
	"Certificate.Issuer.Names[].Type":                  siteIssuerAttribute,
	"Certificate.Subject.Names[].Type":                 siteSubjectAttribute,
	"Certificate.Extensions[].Id":                      siteExtensionID,
	"Certificate.UnhandledCriticalExtensions[]":        siteExtensionID,
	"Certificate.UnknownExtKeyUsage[]":                 siteExtendedKeyUsage,
	"Certificate.PolicyIdentifiers[]":                  siteCertificatePolicy,
	"Certificate.Policies[]":                           siteCertificatePolicy,
	"Certificate.PolicyMappings[].IssuerDomainPolicy":  sitePolicyMapping,
	"Certificate.PolicyMappings[].SubjectDomainPolicy": sitePolicyMapping,

	// Marshal-side only: x509.CreateCertificate reads these, ParseCertificate
	// never writes them, so they are not identifier sites in a file this app
	// reads. Listed rather than filtered, so a Go release that starts populating
	// one of them is a deliberate re-read of this line rather than a silent pass.
	"Certificate.Issuer.ExtraNames[].Type":  "",
	"Certificate.Subject.ExtraNames[].Type": "",
	"Certificate.ExtraExtensions[].Id":      "",
}

// certificateOIDSitesNotRetained are the sites crypto/x509 decodes an identifier at
// and then DISCARDS, so no field on x509.Certificate reflects them and the sweep
// below cannot see them. Each is covered by a row of
// TestOversizedCertificateOIDError_refuses_an_oversized_identifier_at_every_site
// and by the parser-source guard.
var certificateOIDSitesNotRetained = []string{
	siteSignatureAlgorithm,
	siteSignatureParameter,
	sitePublicKeyAlgorithm,
	sitePublicKeyParameter,
	siteAuthorityInfoAccessMethod,
}

// TestCertificateOIDWalk_covers_every_oid_bearing_field_x509_parses is the
// retained-identifier half of the drift guard. It sweeps x509.Certificate's type
// for every field that holds an object identifier and requires each one to be
// accounted for by certificateOIDFields, so a Go release that adds an OID-bearing
// field to the parsed certificate breaks this test instead of quietly leaving the
// walk one site short.
func TestCertificateOIDWalk_covers_every_oid_bearing_field_x509_parses(t *testing.T) {
	t.Parallel()

	found := oidBearingFields(reflect.TypeFor[x509.Certificate](), "Certificate", nil)
	for _, path := range found {
		site, known := certificateOIDFields[path]
		if !known {
			t.Errorf("crypto/x509 (%s) gained OID-bearing field %s: crypto/x509 decodes an identifier at a site this app's certificate guard may not walk, and an uncovered site FAILS OPEN — an oversized identifier there reaches x509.ParseCertificate unbounded. Add the site to certOIDScan's walk in certoidscan.go, add a row to TestOversizedCertificateOIDError_refuses_an_oversized_identifier_at_every_site, then map the field here.",
				runtime.Version(), path)
			continue
		}
		if site == "" {
			continue // marshal-side only; see certificateOIDFields
		}
		if !slices.Contains(certificateWalkSites(), site) {
			t.Errorf("field %s maps to site %q, which is not a site certOIDScan walks", path, site)
		}
	}

	for path := range certificateOIDFields {
		if !slices.Contains(found, path) {
			t.Errorf("certificateOIDFields lists %s, which x509.Certificate no longer has: the walk's coverage claim is written against a crypto/x509 that has moved, so re-read the parser before trusting the rest of this file", path)
		}
	}

	// The two lists must together account for every site the walk records at:
	// either the parser RETAINS the identifier (so a field above maps to it) or it
	// discards it (so it is listed as not retained). A site in neither is a site
	// whose coverage claim rests on nothing.
	accounted := slices.Clone(certificateOIDSitesNotRetained)
	for _, site := range certificateOIDFields {
		if site != "" && !slices.Contains(accounted, site) {
			accounted = append(accounted, site)
		}
	}
	for _, site := range certificateWalkSites() {
		if !slices.Contains(accounted, site) {
			t.Errorf("certOIDScan records at %q, which neither certificateOIDFields nor certificateOIDSitesNotRetained accounts for: nothing checks that crypto/x509 still decodes an identifier there", site)
		}
	}
	for _, site := range accounted {
		if !slices.Contains(certificateWalkSites(), site) {
			t.Errorf("%q is accounted for as a walked site, but certOIDScan does not record there: an identifier at that site is UNBOUNDED", site)
		}
	}
}

// certificateWalkSites is every site certOIDScan records at, as the walk's own
// list. Enumerated rather than derived, so adding a site to the walk is a
// deliberate two-line change that the tests above check against both the parser's
// fields and its source.
func certificateWalkSites() []string {
	return []string{
		siteSignatureAlgorithm,
		siteSignatureParameter,
		sitePublicKeyAlgorithm,
		sitePublicKeyParameter,
		siteIssuerAttribute,
		siteSubjectAttribute,
		siteExtensionID,
		siteExtendedKeyUsage,
		siteCertificatePolicy,
		sitePolicyMapping,
		siteAuthorityInfoAccessMethod,
	}
}

// oidBearingFields returns the dotted path of every field of typ that holds an
// object identifier, descending through pointers, slices and structs. A slice is
// spelled "[]" in the path, which is what makes the paths stable enough to list.
func oidBearingFields(typ reflect.Type, path string, visited []reflect.Type) []string {
	switch typ {
	case reflect.TypeFor[asn1.ObjectIdentifier](), reflect.TypeFor[x509.OID]():
		return []string{path}
	}
	if slices.Contains(visited, typ) {
		return nil
	}
	var found []string
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		found = oidBearingFields(typ.Elem(), path+"[]", append(visited, typ))
	case reflect.Struct:
		for field := range typ.Fields() {
			found = append(found, oidBearingFields(field.Type, path+"."+field.Name, append(visited, typ))...)
		}
	}
	return found
}

// certificateParserOIDDecodes is how many identifier decodes crypto/x509's
// certificate parser performs, per function, as audited for the Go version this
// app builds against. The counts are the shape of the walk's coverage claim:
//
//   - parseName: the attribute type of every issuer and subject RDN.
//   - parseAI: the algorithm of the signature and public-key AlgorithmIdentifiers.
//   - parseExtension: every extnID.
//   - parsePublicKey: an EC key's named curve, out of the SPKI parameters.
//   - parseExtKeyUsageExtension: every usage.
//   - parseCertificatePoliciesExtension: every policy identifier.
//   - processExtensions: both halves of every policy mapping, and every authority
//     information access method.
var certificateParserOIDDecodes = map[string]int{
	"parseName":                         1,
	"parseAI":                           1,
	"parseExtension":                    1,
	"parsePublicKey":                    1,
	"parseExtKeyUsageExtension":         1,
	"parseCertificatePoliciesExtension": 1,
	"processExtensions":                 3,
}

// TestCertificateOIDWalk_covers_every_identifier_the_x509_parser_decodes is the
// source half of the drift guard, and the one that catches a site the parser
// decodes without retaining (an access method, a named curve, a PSS hash). It reads
// crypto/x509's own parser out of GOROOT and counts the identifier decodes per
// function, so a Go release that adds one fails here.
//
// It SKIPS when the toolchain's source is not readable, because a skip is honest
// about what it checked: the reflective guard above and the per-site rows still run.
func TestCertificateOIDWalk_covers_every_identifier_the_x509_parser_decodes(t *testing.T) {
	t.Parallel()

	root, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Skipf("cannot locate the toolchain's GOROOT (%v); the reflective drift guard still runs", err)
	}
	parser := filepath.Join(strings.TrimSpace(string(root)), "src", "crypto", "x509", "parser.go")
	source, err := os.ReadFile(parser)
	if err != nil {
		t.Skipf("crypto/x509 source not readable at %s (%v); the reflective drift guard still runs", parser, err)
	}

	found := map[string]int{}
	var function string
	for line := range strings.Lines(string(source)) {
		if name, isDeclaration := declaredFuncName(line); isDeclaration {
			function = name
		}
		if strings.Contains(line, "ReadASN1ObjectIdentifier(") ||
			strings.Contains(line, "cryptobyte_asn1.OBJECT_IDENTIFIER)") {
			found[function]++
		}
	}
	if len(found) == 0 {
		t.Fatalf("found no identifier decode in %s: the audit below cannot be checked, so the scan itself is broken rather than the parser unchanged", parser)
	}

	for function, want := range certificateParserOIDDecodes {
		if found[function] != want {
			t.Errorf("crypto/x509 (%s) decodes %d identifier(s) in %s, audited at %d: the parser gained or moved an identifier site the certificate guard must cover. An uncovered site FAILS OPEN, so re-read %s, extend certOIDScan's walk in certoidscan.go and its site rows, then correct this audit.",
				runtime.Version(), found[function], function, want, parser)
		}
		delete(found, function)
	}
	for function, count := range found {
		t.Errorf("crypto/x509 (%s) decodes %d identifier(s) in %s, which this app's audit does not know about: Go gained an identifier site the certificate guard must cover, and an uncovered site FAILS OPEN. Read %s, extend certOIDScan's walk in certoidscan.go, then add the function here.",
			runtime.Version(), count, function, parser)
	}
}

// declaredFuncName returns the name a "func ..." source line declares, for a plain
// function or a method, so the scan above can attribute each identifier decode to
// the function that performs it.
func declaredFuncName(line string) (string, bool) {
	rest, isDeclaration := strings.CutPrefix(line, "func ")
	if !isDeclaration {
		return "", false
	}
	if afterReceiver, isMethod := strings.CutPrefix(rest, "("); isMethod {
		_, afterReceiver, isMethod = strings.Cut(afterReceiver, ")")
		if !isMethod {
			return "", false
		}
		rest = strings.TrimSpace(afterReceiver)
	}
	name, _, hasParameters := strings.Cut(rest, "(")
	if !hasParameters || name == "" {
		return "", false
	}
	return name, true
}

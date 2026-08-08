package convert

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// maxCertificateOIDBytes caps the content length of an object identifier this app
// will hand crypto/x509 from a CERTIFICATE block. It is the certificate side's OWN
// bound and is deliberately NOT profile.go's maxOIDBytes: that 32-byte ceiling is
// sized against the four PKCS#12 profiles this app itself writes, where every
// identifier is 9 bytes or fewer, and a certificate is not a file this app wrote.
//
// This is a RESOURCE POLICY, not a validity rule. RFC 5280 sets no limit on an
// identifier's total length or on how many arcs it may name; the only structural
// limit in play is per-SUB-identifier (crypto/x509 refuses a sub-identifier wider
// than 31 bits), and a certificate naming a wide-but-legal identifier is a
// certificate x509.CreateCertificate will write and x509.ParseCertificate will
// read. So refusing one is this app declining to spend memory on it, and the
// number has to be chosen high enough that the refusal cannot be mistaken for a
// standards verdict:
//
//   - The widest legal identifier this guard has been measured against is 49
//     content bytes: 14 arcs of 2^28-1, a certificate x509.CreateCertificate
//     writes and x509.ParseCertificate reads back. The defect that retired the old
//     ceiling was reproduced with a 37-byte one. So 255 is about five times the
//     widest shape anyone has built here, and about 28 times the 9 bytes a normal
//     certificate names.
//   - 255 is the largest content length one DER length byte can express
//     (0x81 0xFF). An identifier above it needs a multi-byte length, which is a
//     shape no certificate a CA issues has any reason to reach.
//   - What the cap buys is GRANULARITY, not a smaller total. encoding/asn1 and
//     x509.OID.toASN1OID both size their []int from the encoded LENGTH (one int
//     per byte), so an identifier costs roughly eight bytes of heap per encoded
//     byte at EVERY width, and the identifiers a parsed certificate RETAINS
//     (every extension id, every subject and issuer attribute type, every policy
//     identifier) stay live for as long as the chain does. The aggregate is
//     therefore bounded by the reader's MaxInputBytes cap times that factor -
//     roughly 80 MB - with or without this ceiling: a block packed with 255-byte
//     identifiers retains as much as one packed with a single huge identifier.
//     What the ceiling removes is the single contiguous multi-megabyte []int, and
//     it refuses the obvious shape cheaply. It is also best-effort: exhausting
//     maxCertificateOIDElements fails open for the subtree that exhausted it, and
//     withSubtreeBudget gives the signature algorithm, the issuer, the subject, the
//     SPKI and the extensions a budget each — so what a block can still blind is one
//     unbounded region from the inside, the extension LIST being the one that matters,
//     leaving the identifiers after its padding unmeasured. Treat the ceiling as a
//     per-identifier resource policy the walk applies where it can see, never as the
//     app's memory bound - MaxInputBytes is that bound.
//
// Raising it is safe for correctness and only widens what one identifier may
// spend; lowering it starts refusing certificates other tools accept, which is the
// mistake this constant replaced.
const maxCertificateOIDBytes = 255

// maxCertificateOIDDepth bounds the only recursive descent the certificate walk
// still performs: an AlgorithmIdentifier's parameters field, whose content is ANY
// DEFINED BY algorithm and therefore DER rather than opaque bytes. crypto/x509
// decodes identifiers out of it in two shapes — an EC named curve one level down,
// and RSASSA-PSS's nested hash and MGF identifiers three levels down — so 10 is
// headroom rather than a policy. Every other site the walk visits is reached
// through the certificate's own schema, at a fixed depth, so this is what stops a
// crafted parameters field from making the walk recurse without bound.
const maxCertificateOIDDepth = 10

// maxCertificateOIDElements bounds how many DER elements each independently
// budgeted certificate-walk subtree reads. It is the certificate-side twin of
// maxRSAKeyElements: the subject of the bound is the WALK rather than the
// certificate. Every element costs one asn1.Unmarshal into an asn1.RawValue, and
// the walk's schema admits several unbounded SEQUENCE OF loops a structurally valid
// certificate may fill — the issuer and subject RDNSequences, the extension list,
// and the identifier lists inside the extensions x509 decodes — so a block that is
// legitimately shaped but holds hundreds of thousands of one-attribute RDNs would
// otherwise make the guard the expensive operation it exists to prevent. The budget
// is charged PER SUBTREE (withSubtreeBudget), not once for the whole walk: each
// unbounded region is entered exactly once from a fixed position in the schema, so
// the total stays bounded, while a shared total let the FIRST such region — the
// signature algorithm's parameters, or the issuer name — consume the whole
// allowance and leave every later site unmeasured.
//
// Exhaustion of one subtree's budget FAILS OPEN for that subtree, like every other
// verdict this walk cannot reach: what it already measured still stands, and the sites
// outside it are still measured. It does NOT fall back on the parser for this axis —
// crypto/x509 imposes no limit on an identifier's length (see maxCertificateOIDBytes),
// which is why the ceiling exists at all. A real certificate's walk visits under 200
// elements, so no real certificate reaches any of these budgets.
const maxCertificateOIDElements = 4096

// The identifier sites the walk visits, named for the diagnostic. These are
// positions in the certificate's schema, not certificate-supplied text, so they
// reach the error message as-is.
const (
	siteSignatureAlgorithm        = "signature algorithm identifier"
	siteSignatureParameter        = "signature algorithm parameter identifier"
	sitePublicKeyAlgorithm        = "subject public key algorithm identifier"
	sitePublicKeyParameter        = "subject public key algorithm parameter identifier"
	siteIssuerAttribute           = "issuer attribute type"
	siteSubjectAttribute          = "subject attribute type"
	siteExtensionID               = "extension identifier"
	siteExtendedKeyUsage          = "extended key usage identifier"
	siteCertificatePolicy         = "certificate policy identifier"
	sitePolicyMapping             = "policy mapping identifier"
	siteAuthorityInfoAccessMethod = "authority information access method identifier"
)

// The extensions crypto/x509 decodes further identifiers OUT OF, recognised by the
// CONTENT bytes of their extnID so that recognising one costs no decode. Naming
// them as asn1.ObjectIdentifier keeps them readable; oidContent turns each into the
// bytes the walk compares, and certoidscan's tests pin those bytes so a typo here
// cannot silently stop the walk descending.
var (
	oidExtensionExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtensionPolicyMappings      = asn1.ObjectIdentifier{2, 5, 29, 33}
	oidExtensionAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

	extKeyUsageExtnID         = oidContent(oidExtensionExtKeyUsage)
	certificatePoliciesExtnID = oidContent(oidExtensionCertificatePolicies)
	policyMappingsExtnID      = oidContent(oidExtensionPolicyMappings)
	authorityInfoAccessExtnID = oidContent(oidExtensionAuthorityInfoAccess)
)

// oidContent returns the DER CONTENT bytes of a compile-time identifier — the
// bytes an extnID carries without its tag and length — so the walk can recognise
// an extension by comparison instead of decoding what a file supplied.
//
// A marshal failure is impossible for the constants above and returns nil rather
// than panicking. Note that nil is NOT a safe sentinel here: bytes.Equal treats a
// nil slice and a zero-length one as equal, and a two-byte 06 00 element parses
// into a primitive OBJECT IDENTIFIER whose content is empty, so a nil constant
// would MATCH such an extnID and make the walk read that extension's opaque
// extnValue as DER — the refusal-of-valid-certificates defect walkCertificate
// describes. What rules that out is not the nil value but the requirement that
// these four constants are non-empty, which certoidscan's tests assert; keep that
// assertion, because it is the whole guarantee.
func oidContent(oid asn1.ObjectIdentifier) []byte {
	der, err := asn1.Marshal(oid)
	if err != nil {
		return nil
	}
	elem, _, ok := asn1Element(der)
	if !ok {
		return nil
	}
	return elem.Bytes
}

// oversizedCertificateOIDError refuses a CERTIFICATE block that names an object
// identifier wider than maxCertificateOIDBytes at one of the sites crypto/x509
// decodes an identifier from, and reports nil for every block whose DER this walk
// cannot read.
//
// It exists for the reason decodeOID and oversizedKeyAlgorithmOIDError exist:
// x509.ParseCertificate decodes an identifier by allocating one int per encoded
// byte, before anything can reject it, on the scan's only goroutine and with no
// cancellation path — and half of what it allocates is RETAINED with the parsed
// chain. The bound is the app's own resource policy (see maxCertificateOIDBytes),
// not an X.509 validity rule.
//
// Two properties are deliberate. The walk visits SITES rather than bytes, so an
// unknown extension's opaque extnValue is never read as DER; and every verdict it
// cannot reach FAILS OPEN, so a block it cannot understand goes to the parser with
// its own limits rather than being refused on a guess.
func oversizedCertificateOIDError(block *pem.Block) error {
	scan := certOIDScan{budget: maxCertificateOIDElements}
	scan.walkCertificate(block.Bytes)
	if scan.widest > maxCertificateOIDBytes {
		return fmt.Errorf("certificate names a %d-byte object identifier as its %s, above the %d-byte ceiling this app decodes an identifier at (this app's own resource bound rather than an X.509 limit: the parser allocates one int per encoded byte, and keeps it for as long as the chain)",
			scan.widest, scan.site, maxCertificateOIDBytes)
	}
	return nil
}

// certOIDScan carries one certificate walk: the widest identifier found so far,
// the site it sits at (which the refusal names, so an operator learns WHICH field
// is oversized), and the shared element budget.
//
// Field order is chosen for pointer-region packing (govet fieldalignment): the
// string leads, then the counters.
type certOIDScan struct {
	site   string
	budget int
	widest int
}

// walkCertificate mirrors the structure of Certificate (RFC 5280 4.1) as far as
// the identifier sites go: SEQUENCE { tbsCertificate, signatureAlgorithm,
// signatureValue }.
//
// The walk deliberately DOES mirror x509's schema, which the byte-recursive guard
// this replaced deliberately did not: its contract was "refuse an oversized
// identifier, not become a second certificate parser", and reading every OCTET
// STRING's content as DER is what that bought — an unknown extension's opaque
// value whose bytes happened to open with an identifier tag read as an oversized
// identifier, and a certificate no parser objects to was refused. So the walk now
// mirrors the SITES, and only the sites: it descends where crypto/x509 itself
// decodes an identifier, and nowhere else. That is a narrower job than parsing, and
// it is what makes the verdict about a field a parser will really decode instead of
// about a coincidence in someone's opaque bytes. The cost is a schema that has to
// keep up with crypto/x509, which is why it has a drift guard
// (certoidscan_internal_test.go) rather than only per-site tests.
func (s *certOIDScan) walkCertificate(der []byte) {
	certificate, _, ok := s.expect(der, asn1.TagSequence)
	if !ok {
		return
	}
	tbs, _, ok := s.expect(certificate.Bytes, asn1.TagSequence)
	if !ok {
		return
	}
	// The TBS copy is the only signature AlgorithmIdentifier x509 decodes. It reads
	// the outer copy solely to require it byte-for-byte equal to this one — that
	// comparison runs on the raw DER, before either identifier is parsed — so a
	// block whose copies differ is rejected by the parser without allocating, and
	// walking the outer copy could not prevent an allocation this ceiling exists to
	// prevent.
	s.walkTBSCertificate(tbs.Bytes)
}

// walkTBSCertificate mirrors TBSCertificate (RFC 5280 4.1.2) field by field, in
// the order x509's parser reads them, and stops at the first field that is not the
// shape the parser requires — which is also the point the parser itself would
// error, so nothing beyond it is ever decoded.
func (s *certOIDScan) walkTBSCertificate(der []byte) {
	der = s.skipVersion(der)
	_, der, ok := s.expect(der, asn1.TagInteger) // serialNumber
	if !ok {
		return
	}
	signature, der, ok := s.expect(der, asn1.TagSequence)
	if !ok {
		return
	}
	s.withSubtreeBudget(func() {
		s.walkAlgorithmIdentifier(signature.Bytes, siteSignatureAlgorithm, siteSignatureParameter)
	})
	issuer, der, ok := s.expect(der, asn1.TagSequence)
	if !ok {
		return
	}
	s.withSubtreeBudget(func() { s.walkName(issuer.Bytes, siteIssuerAttribute) })
	_, der, ok = s.expect(der, asn1.TagSequence) // validity
	if !ok {
		return
	}
	subject, der, ok := s.expect(der, asn1.TagSequence)
	if !ok {
		return
	}
	s.withSubtreeBudget(func() { s.walkName(subject.Bytes, siteSubjectAttribute) })
	spki, der, ok := s.expect(der, asn1.TagSequence)
	if !ok {
		return
	}
	s.withSubtreeBudget(func() { s.walkSubjectPublicKeyInfo(spki.Bytes) })
	s.withSubtreeBudget(func() { s.walkExtensionsField(der) })
}

// skipVersion steps over the optional [0] EXPLICIT version field, and returns der
// unchanged when it is absent (a v1 certificate, which then carries no extensions
// either).
func (s *certOIDScan) skipVersion(der []byte) []byte {
	if version, rest, ok := s.element(der); ok && isContextCompound(version, 0) {
		return rest
	}
	return der
}

// walkExtensionsField finds the extensions field among what remains of the
// TBSCertificate: the optional [1] issuerUniqueID and [2] subjectUniqueID may sit
// in front of the [3] EXPLICIT extensions the identifiers live in.
func (s *certOIDScan) walkExtensionsField(der []byte) {
	for len(der) > 0 {
		field, rest, ok := s.element(der)
		if !ok {
			return
		}
		if isContextCompound(field, 3) {
			s.forEachElementOf(field.Bytes, func(extension asn1.RawValue) {
				if isASN1(extension, asn1.TagSequence) && extension.IsCompound {
					s.walkExtension(extension.Bytes)
				}
			})
			return
		}
		der = rest
	}
}

// walkExtension reads one Extension — SEQUENCE { extnID OBJECT IDENTIFIER,
// critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING } — recording the extnID
// x509 decodes for every extension, and descending into extnValue ONLY for the
// extensions x509 itself decodes identifiers out of.
//
// The extnValue of anything else is opaque bytes as far as this app is concerned:
// its content is defined by whoever minted the extension, it may be any encoding at
// all, and x509 hands it to the caller untouched. Reading it as DER is what made
// the previous guard refuse valid certificates.
func (s *certOIDScan) walkExtension(der []byte) {
	extnID, rest, ok := s.element(der)
	if !ok || !isPrimitiveOID(extnID) {
		return
	}
	s.record(extnID, siteExtensionID)
	// critical BOOLEAN DEFAULT FALSE: read the next element once and, when it IS
	// that boolean, step to the element after it. Reading it and then re-reading
	// the same bytes as extnValue charges the shared element budget twice for one
	// field, so the walk would stop measuring sooner than maxCertificateOIDElements
	// says it does.
	value, afterValue, ok := s.element(rest)
	if !ok {
		return
	}
	if isASN1(value, asn1.TagBoolean) {
		if value, _, ok = s.element(afterValue); !ok {
			return
		}
	}
	if !isASN1(value, asn1.TagOctetString) || value.IsCompound {
		return
	}
	s.walkKnownExtensionValue(extnID.Bytes, value.Bytes)
}

// walkKnownExtensionValue descends into the value of an extension whose schema
// x509 reads identifiers out of, and does nothing for any other extnID. The four
// are the whole set for a certificate: extended key usage (each usage), certificate
// policies (each policy identifier), policy mappings (both halves of each mapping),
// and authority information access (each access method).
func (s *certOIDScan) walkKnownExtensionValue(extnID, value []byte) {
	switch {
	case bytes.Equal(extnID, extKeyUsageExtnID):
		s.forEachElementOf(value, func(usage asn1.RawValue) {
			s.record(usage, siteExtendedKeyUsage)
		})
	case bytes.Equal(extnID, certificatePoliciesExtnID):
		s.forEachElementOf(value, func(information asn1.RawValue) {
			s.walkPolicyInformation(information)
		})
	case bytes.Equal(extnID, policyMappingsExtnID):
		s.forEachElementOf(value, func(mapping asn1.RawValue) {
			s.walkPair(mapping, sitePolicyMapping)
		})
	case bytes.Equal(extnID, authorityInfoAccessExtnID):
		s.forEachElementOf(value, func(description asn1.RawValue) {
			s.walkLeadingOID(description, siteAuthorityInfoAccessMethod)
		})
	}
}

// walkPolicyInformation reads one PolicyInformation — SEQUENCE {
// policyIdentifier OBJECT IDENTIFIER, policyQualifiers SEQUENCE OF
// PolicyQualifierInfo OPTIONAL } — recording the policy identifier only.
//
// x509 decodes the policy identifier itself (into Certificate.Policies, and again
// into the deprecated PolicyIdentifiers, which allocates an int per byte). It does
// NOT decode anything out of a qualifier, so the qualifiers are opaque as far as
// this app is concerned: walking them would refuse a certificate the parser accepts
// without protecting any allocation the parser makes. The parser-source drift guard
// is what watches for a future Go release that starts reading them.
func (s *certOIDScan) walkPolicyInformation(information asn1.RawValue) {
	if !isASN1(information, asn1.TagSequence) || !information.IsCompound {
		return
	}
	policy, _, ok := s.element(information.Bytes)
	if !ok {
		return
	}
	s.record(policy, siteCertificatePolicy)
}

// walkLeadingOID records the identifier that opens a constructed element, the shape
// of AccessDescription { accessMethod, accessLocation }: the identifier x509 reads
// first, followed by a value this walk has no business reading.
func (s *certOIDScan) walkLeadingOID(elem asn1.RawValue, site string) {
	if !isASN1(elem, asn1.TagSequence) || !elem.IsCompound {
		return
	}
	if leading, _, ok := s.element(elem.Bytes); ok {
		s.record(leading, site)
	}
}

// walkPair records both identifiers of a two-identifier SEQUENCE, the shape of a
// PolicyMapping { issuerDomainPolicy, subjectDomainPolicy }.
func (s *certOIDScan) walkPair(elem asn1.RawValue, site string) {
	if !isASN1(elem, asn1.TagSequence) || !elem.IsCompound {
		return
	}
	first, rest, ok := s.element(elem.Bytes)
	if !ok {
		return
	}
	s.record(first, site)
	if second, _, secondOK := s.element(rest); secondOK {
		s.record(second, site)
	}
}

// walkName reads a Name — RDNSequence ::= SEQUENCE OF SET OF
// AttributeTypeAndValue — recording each attribute TYPE, which is what x509
// decodes for the Subject and Issuer of every certificate. The attribute VALUE is
// a string, not an identifier, and is left alone.
//
// content is the RDNSequence's content: the caller has already read the SEQUENCE
// header, because it is the same element whose raw bytes x509 keeps as RawSubject
// and RawIssuer.
func (s *certOIDScan) walkName(content []byte, site string) {
	s.forEachIn(content, func(set asn1.RawValue) {
		if !isASN1(set, asn1.TagSet) || !set.IsCompound {
			return
		}
		s.forEachIn(set.Bytes, func(attribute asn1.RawValue) {
			if !isASN1(attribute, asn1.TagSequence) || !attribute.IsCompound {
				return
			}
			if attributeType, _, ok := s.element(attribute.Bytes); ok {
				s.record(attributeType, site)
			}
		})
	})
}

// walkSubjectPublicKeyInfo reads SubjectPublicKeyInfo ::= SEQUENCE {
// algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }. The key bits are a
// BIT STRING x509 hands to the algorithm's own parser and hold no identifier.
func (s *certOIDScan) walkSubjectPublicKeyInfo(content []byte) {
	if algorithm, _, ok := s.expect(content, asn1.TagSequence); ok {
		s.walkAlgorithmIdentifier(algorithm.Bytes, sitePublicKeyAlgorithm, sitePublicKeyParameter)
	}
}

// walkAlgorithmIdentifier reads AlgorithmIdentifier ::= SEQUENCE { algorithm
// OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }, recording the
// algorithm identifier and then walking the parameters.
//
// The parameters field is walked as DER because that is what it is — ANY DEFINED BY
// algorithm, structured by the algorithm the identifier beside it names — and
// because x509 decodes identifiers out of it: an EC named curve (via
// parsePublicKey), and RSASSA-PSS's hash and MGF identifiers (via
// getSignatureAlgorithmFromAI). That is the opposite case from an unknown
// extension's extnValue, which is opaque by definition.
func (s *certOIDScan) walkAlgorithmIdentifier(content []byte, algorithmSite, parameterSite string) {
	algorithm, parameters, ok := s.element(content)
	if !ok {
		return
	}
	s.record(algorithm, algorithmSite)
	s.walkAlgorithmParameters(parameters, maxCertificateOIDDepth, parameterSite)
}

// walkAlgorithmParameters records every identifier in an AlgorithmIdentifier's
// parameters, descending through CONSTRUCTED elements only (PSS keeps its hash and
// MGF identifiers inside nested AlgorithmIdentifiers) and never into an OCTET
// STRING: explicit EC parameters carry field elements and a base point in OCTET
// STRINGs, and those are numbers, not DER.
func (s *certOIDScan) walkAlgorithmParameters(der []byte, depth int, site string) {
	if depth <= 0 {
		return
	}
	s.forEachIn(der, func(elem asn1.RawValue) {
		switch {
		case isPrimitiveOID(elem):
			s.record(elem, site)
		case elem.IsCompound:
			s.walkAlgorithmParameters(elem.Bytes, depth-1, site)
		}
	})
}

// forEachElementOf unwraps a SEQUENCE and visits each of its elements. It is the
// SEQUENCE OF loop every list in the schema above is: the extension list, the
// usages in an extended key usage, the policies, the mappings, the access
// descriptions.
func (s *certOIDScan) forEachElementOf(der []byte, visit func(elem asn1.RawValue)) {
	sequence, _, ok := s.expect(der, asn1.TagSequence)
	if !ok {
		return
	}
	s.forEachIn(sequence.Bytes, visit)
}

// forEachIn visits each element in an already-unwrapped content region, stopping
// at the first element it cannot read or when the element budget runs out — the
// fail-open behaviour that keeps a walk over a damaged file from becoming a verdict
// about it.
func (s *certOIDScan) forEachIn(content []byte, visit func(elem asn1.RawValue)) {
	for len(content) > 0 {
		elem, rest, ok := s.element(content)
		if !ok {
			return
		}
		visit(elem)
		content = rest
	}
}

// expect reads one element and requires the given universal tag, so a caller
// mirroring the schema can say "the next field is a SEQUENCE" in one line and stop
// where the parser would.
func (s *certOIDScan) expect(der []byte, tag int) (asn1.RawValue, []byte, bool) {
	elem, rest, ok := s.element(der)
	if !ok || !isASN1(elem, tag) {
		return asn1.RawValue{}, nil, false
	}
	return elem, rest, true
}

// element reads one tag-length-value header off der against the shared element
// budget. An exhausted budget reports the same "cannot read" as malformed DER, so
// every caller's fail-open path covers it without a second check.
func (s *certOIDScan) element(der []byte) (asn1.RawValue, []byte, bool) {
	if s.budget <= 0 {
		return asn1.RawValue{}, nil, false
	}
	s.budget--
	return asn1Element(der)
}

// withSubtreeBudget runs one subtree walk on its own element budget, so a block that
// spends its allowance describing an early FIELD cannot stop the walk from measuring the
// fields after it. Each of the five regions it wraps is entered exactly once from a fixed
// position in the schema, so the walk's total stays bounded at six budgets, while
// nesting inside a subtree keeps sharing that subtree's budget — which is what stops a
// per-loop cap from multiplying.
//
// It does NOT make the ceiling complete, and must not be read as if it did. The extension
// LIST is itself an unbounded SEQUENCE OF inside one of those subtrees: at three elements
// per extension, ~1,365 minimal extensions exhaust the extensions budget and every
// extension after them goes unmeasured. Measured: a 14 KB block of 1,400 empty unknown
// extensions followed by one naming a 257-byte identifier is accepted here, and
// x509.ParseCertificate decodes that identifier and retains it in Certificate.Extensions.
// Closing that axis has no cheap shape — a per-extension budget multiplies with the
// element count, which is the cost this budget exists to bound, and failing CLOSED would
// refuse valid certificates — so the residual stands: the app's memory bound is the
// reader's MaxInputBytes cap (see maxCertificateOIDBytes), and this ceiling is a
// best-effort resource policy the walk applies where it can see.
func (s *certOIDScan) withSubtreeBudget(walk func()) {
	outerBudget := s.budget
	s.budget = maxCertificateOIDElements
	walk()
	s.budget = outerBudget
}

// record measures one identifier site. Anything that is not a primitive OBJECT
// IDENTIFIER is not an identifier x509 will decode (encoding/asn1 and cryptobyte
// both refuse a constructed one without allocating), so it contributes nothing.
func (s *certOIDScan) record(elem asn1.RawValue, site string) {
	if !isPrimitiveOID(elem) || len(elem.Bytes) <= s.widest {
		return
	}
	s.widest, s.site = len(elem.Bytes), site
}

// isPrimitiveOID reports whether v is the shape a decoded identifier comes from.
func isPrimitiveOID(v asn1.RawValue) bool {
	return isASN1(v, asn1.TagOID) && !v.IsCompound
}

// isContextCompound reports whether v is the constructed context-specific element
// with the given tag number — how TBSCertificate marks its version and extensions
// fields.
func isContextCompound(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassContextSpecific && v.Tag == tag && v.IsCompound
}

// Package convert provides PEM parsing and PFX encoding utilities.
package convert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strings"

	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/runesafe"
)

// PEM block type constants.
const (
	pemTypeCertificate         = "CERTIFICATE"
	pemTypePrivateKey          = "PRIVATE KEY"
	pemTypeRSAPrivateKey       = "RSA PRIVATE KEY"
	pemTypeECPrivateKey        = "EC PRIVATE KEY"
	pemTypeEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
	pemTypeECParameters        = "EC PARAMETERS"
)

// --- Certificate chain parsing ---

// maxChainCerts bounds how many CERTIFICATE blocks one input file may declare.
const maxChainCerts = 64

// maxKeyBlocks bounds how many private-key blocks one key file may declare.
const maxKeyBlocks = 16

// MaxInputBytes is the largest certificate or key file this package's acceptance
// bounds are calibrated against: maxChainCerts, maxKeyBlocks, maxRSAPrimeFactors
// and the log-text bounds are each sized from the worst case a file this large can
// hold, and the measured costs in their comments assume it.
const MaxInputBytes = 10 << 20

// parseCertChain decodes all CERTIFICATE PEM blocks from pemBytes, returning
// them in order.
func parseCertChain(pemBytes []byte) ([]*x509.Certificate, skippedBlocks, error) {
	declaredCertBlocks := countDeclaredBlocks(pemBytes, certBeginMarker)
	if declaredCertBlocks > maxChainCerts {
		return nil, skippedBlocks{}, fmt.Errorf("certificate PEM chain declares %d CERTIFICATE block(s), more than the %d this app converts",
			declaredCertBlocks, maxChainCerts)
	}
	var scan certScan
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if err := scan.visit(block); err != nil {
			return nil, skippedBlocks{}, err
		}
	}

	if len(scan.certs) != declaredCertBlocks {
		return nil, skippedBlocks{}, fmt.Errorf("certificate PEM chain is malformed: decoded %d of %d declared CERTIFICATE block(s)", len(scan.certs), declaredCertBlocks)
	}

	if len(scan.certs) == 0 {
		// The label named is the one that diagnoses the mistake, not simply the first
		// skipped block: a private-key label when the file holds one, otherwise the first
		// label naming neither a certificate nor a key companion
		// (isExpectedCertFilePassenger owns that set). `openssl ecparam -genkey` writes
		// EC PARAMETERS IMMEDIATELY BEFORE the EC PRIVATE KEY it describes, so a key file
		// supplied as the certificate file named "EC PARAMETERS" — a companion of the
		// key — while the label that actually diagnoses the mistake went unmentioned.
		switch {
		case scan.keyLabels.count > 0:
			return nil, skippedBlocks{}, fmt.Errorf("no certificate PEM block found (skipped %d non-certificate PEM block(s), including a %q block: this looks like the private key file rather than the certificate file)",
				scan.skipped.count, scan.keyLabels.firstTypeForLog())
		case scan.unrelated.count > 0:
			return nil, skippedBlocks{}, fmt.Errorf("no certificate PEM block found (%d of the %d skipped PEM block(s) name neither a certificate nor a key companion, first %q)",
				scan.unrelated.count, scan.skipped.count, scan.unrelated.firstTypeForLog())
		case scan.skipped.count > 0:
			return nil, skippedBlocks{}, fmt.Errorf("no certificate PEM block found (skipped %d non-certificate PEM block(s), first %q)",
				scan.skipped.count, scan.skipped.firstTypeForLog())
		}
		return nil, skippedBlocks{}, errors.New("no certificate PEM block found")
	}
	return scan.certs, scan.unrelated, nil
}

// certScan accumulates what one pass over a certificate file's PEM blocks
// learned: the parsed chain, plus the skipped-block evidence the "no certificate"
// diagnostic and the unrelated-passenger report need.
type certScan struct {
	certs     []*x509.Certificate
	skipped   skippedBlocks
	unrelated skippedBlocks
	// keyLabels are the private-key blocks the certificate file holds.
	keyLabels skippedBlocks
}

// visit classifies one PEM block, applying the parser's per-block rules.
func (s *certScan) visit(block *pem.Block) error {
	if block.Type != pemTypeCertificate {
		s.skipped.add(block.Type)
		if isPrivateKeyLabel(block.Type) {
			s.keyLabels.add(block.Type)
		}
		// Only a label naming neither a certificate nor a key companion is reported;
		// isExpectedCertFilePassenger owns that set.
		if !isExpectedCertFilePassenger(block.Type) {
			s.unrelated.add(block.Type)
		}
		return nil
	}
	if len(block.Bytes) > maxCertDERBytes {
		return fmt.Errorf("certificate PEM block %d: certificate is %d bytes of DER, above the %d this app parses (this app's own ceiling on what one certificate may allocate inside the parser, not an X.509 limit)",
			len(s.certs)+1, len(block.Bytes), maxCertDERBytes)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("certificate PEM block %d: %w", len(s.certs)+1, boundedTextError{err})
	}
	if err := oversizedParsedCertificateError(c); err != nil {
		return fmt.Errorf("certificate PEM block %d: %w", len(s.certs)+1, err)
	}
	s.certs = append(s.certs, c)
	return nil
}

// maxCertDERBytes bounds one CERTIFICATE block's DER before x509.ParseCertificate
// sees it.
const maxCertDERBytes = 256 << 10

// Aggregate ceilings on what ONE parsed certificate may RETAIN for the life of the
// chain, in the two EXTENSION shapes x509.ParseCertificate keeps (a parsed
// distinguished name is a third, counted by none of these and bounded only by
// maxCertDERBytes): the extension
// IDENTIFIERS (one int per identifier arc, held in Certificate.Extensions) and the
// decoded extension CONTENT (one freshly allocated Go value per encoded name,
// identifier or URI, held in the typed fields the parser fills).
const (
	maxCertExtensions        = 64
	maxCertExtensionOIDArcs  = 4096
	maxCertExtensionElements = 4096
)

// oversizedParsedCertificateError refuses a parsed certificate whose extension
// identifiers or decoded extension content exceed the aggregate retention ceilings
// above.
func oversizedParsedCertificateError(c *x509.Certificate) error {
	if len(c.Extensions) > maxCertExtensions {
		return fmt.Errorf("certificate carries %d extensions, above the %d this app accepts (this app's own ceiling on what a parsed chain may retain, not an X.509 limit)",
			len(c.Extensions), maxCertExtensions)
	}
	arcs := 0
	for _, ext := range c.Extensions {
		arcs += len(ext.Id)
	}
	if arcs > maxCertExtensionOIDArcs {
		return fmt.Errorf("certificate's extension identifiers total %d arcs, above the %d this app retains for a parsed chain (this app's own ceiling, not an X.509 limit: the parser keeps one int per identifier arc for as long as the chain)",
			arcs, maxCertExtensionOIDArcs)
	}
	if elements := retainedExtensionElements(c); elements > maxCertExtensionElements {
		return fmt.Errorf("certificate's extensions decode to %d retained elements (names, identifiers and URIs), above the %d this app retains for a parsed chain (this app's own ceiling, not an X.509 limit: the parser keeps one allocated value per element for as long as the chain)",
			elements, maxCertExtensionElements)
	}
	return nil
}

// retainedExtensionElements counts the decoded extension content the parser kept on
// c.
func retainedExtensionElements(c *x509.Certificate) int {
	return len(c.DNSNames) + len(c.EmailAddresses) + len(c.IPAddresses) + len(c.URIs) +
		len(c.UnknownExtKeyUsage) + len(c.ExtKeyUsage) + len(c.PolicyIdentifiers) +
		len(c.Policies) + len(c.CRLDistributionPoints) + len(c.OCSPServer) +
		len(c.IssuingCertificateURL) + len(c.PermittedDNSDomains) +
		len(c.ExcludedDNSDomains) + len(c.PermittedEmailAddresses) +
		len(c.ExcludedEmailAddresses) + len(c.PermittedIPRanges) +
		len(c.ExcludedIPRanges) + len(c.PermittedURIDomains) + len(c.ExcludedURIDomains)
}

// isExpectedCertFilePassenger reports whether a non-certificate PEM label in the
// CERTIFICATE file is an expected companion rather than something the operator meant
// this app to read as a certificate.
func isExpectedCertFilePassenger(blockType string) bool {
	if isPrivateKeyLabel(blockType) {
		return true
	}
	return blockType == pemTypeECParameters
}

// keyLabels are the PEM labels that name a private-key block, the encrypted
// spellings included. It is the one declaration of that set: the predicate below,
// the declaration markers parsePrivateKeys counts, and keyScan's per-block dispatch
// all read it.
var keyLabels = []string{
	pemTypePrivateKey,
	pemTypeRSAPrivateKey,
	pemTypeECPrivateKey,
	pemTypeEncryptedPrivateKey,
}

// isPrivateKeyLabel reports whether a PEM label names a private-key block, the
// encrypted spellings included.
func isPrivateKeyLabel(blockType string) bool {
	return slices.Contains(keyLabels, blockType)
}

// pkcs8Fields returns a PKCS#8 PrivateKeyInfo's AlgorithmIdentifier element and the
// DER that follows it (whose first element is the privateKey OCTET STRING), and false
// for anything that is not that shape.
func pkcs8Fields(der []byte) (algorithm asn1.RawValue, afterAlgorithm []byte, ok bool) {
	outer, _, ok := asn1ElementWithTag(der, asn1.TagSequence)
	if !ok {
		return asn1.RawValue{}, nil, false
	}
	_, afterVersion, ok := asn1ElementWithTag(outer.Bytes, asn1.TagInteger)
	if !ok {
		return asn1.RawValue{}, nil, false
	}
	return asn1ElementWithTag(afterVersion, asn1.TagSequence)
}

// pkcs8AlgorithmOID returns the retained (undecoded) algorithm OID element of
// PKCS#8 PrivateKeyInfo DER, together with the DER that follows it INSIDE the same
// AlgorithmIdentifier (its optional parameters field), and false for anything that is
// not that shape.
func pkcs8AlgorithmOID(der []byte) (oid asn1.RawValue, parameters []byte, ok bool) {
	algorithm, _, ok := pkcs8Fields(der)
	if !ok {
		return asn1.RawValue{}, nil, false
	}
	return asn1ElementWithTag(algorithm.Bytes, asn1.TagOID)
}

// isExpectedKeyFilePassenger reports whether a non-key PEM label in the KEY file is
// an expected companion of the key rather than something the operator meant this app
// to read as one.
func isExpectedKeyFilePassenger(blockType string) bool {
	switch blockType {
	case pemTypeCertificate, pemTypeECParameters:
		return true
	}
	return false
}

// --- PEM declaration counting (shared by both parsers) ---

// pemBeginMarker builds the PEM declaration line that opens a block of the
// given type, exactly as encoding/pem writes it.
func pemBeginMarker(blockType string) []byte {
	return []byte("-----BEGIN " + blockType + "-----")
}

// certBeginMarker is the PEM declaration line that opens a CERTIFICATE block.
var certBeginMarker = pemBeginMarker(pemTypeCertificate)

// keyBeginMarkers are the PEM declaration lines that open the private-key blocks
// keyLabels names, the encrypted forms parsePrivateKeys diagnoses rather than
// decodes included.
var keyBeginMarkers = pemBeginMarkers(keyLabels)

// pemBeginMarkers builds the PEM declaration lines that open blocks of the given
// types.
func pemBeginMarkers(blockTypes []string) [][]byte {
	markers := make([][]byte, 0, len(blockTypes))
	for _, blockType := range blockTypes {
		markers = append(markers, pemBeginMarker(blockType))
	}
	return markers
}

// countDeclaredBlocks counts the declarations in markers the way encoding/pem
// recognises them: a marker declares a block only when it occupies a complete
// line, so the same text embedded in surrounding prose (which pem.Decode
// ignores entirely) is not counted and cannot make a valid chain look
// malformed.
func countDeclaredBlocks(pemBytes []byte, markers ...[]byte) int {
	var n int
	for line := range bytes.Lines(pemBytes) {
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimRight(bytes.TrimSuffix(line, []byte("\r")), " \t")
		for _, marker := range markers {
			if bytes.Equal(line, marker) {
				n++
				break
			}
		}
	}
	return n
}

// skippedBlocks accumulates the PEM blocks a parser passed over: how many, and
// the label of the first one, which is what a diagnostic names so an operator
// learns WHAT the file held rather than only that something was skipped.
type skippedBlocks struct {
	firstType string
	count     int
}

// add records one skipped block, keeping the first label seen.
func (s *skippedBlocks) add(blockType string) {
	s.count++
	if s.count == 1 {
		s.firstType = blockType
	}
}

// firstTypeForLog returns the first skipped label bounded for a log line: the
// PEM type is operator-supplied text capped only by the MaxInputBytes input read
// bound internal/process applies.
func (s *skippedBlocks) firstTypeForLog() string {
	return boundLogText(s.firstType, maxBlockTypeLogLen)
}

// maxBlockTypeLogLen bounds the PEM block label a parse diagnostic names.
const maxBlockTypeLogLen = 64

// boundLogText makes input-derived text safe and bounded for a log-bound
// diagnostic.
func boundLogText(s string, limit int) string {
	text, _ := runesafe.SanitizeSingleLineBudgeted(s, limit, logtext.Marker)
	return text
}

// maxSubjectLogLen bounds the certificate-controlled subject interpolated into a
// diagnostic.
const maxSubjectLogLen = 256

// maxSubjectRenderAttrs bounds how many distinguished-name attributes are handed to
// pkix.RDNSequence.String() when a certificate subject is rendered for a diagnostic.
const maxSubjectRenderAttrs = 256

// subjectForLog renders a certificate's subject for a log-bound diagnostic.
func subjectForLog(c *x509.Certificate) string {
	return boundLogText(boundedDN(dnSequence(&c.Subject)).String(), maxSubjectLogLen)
}

// dnSequence returns the RDNSequence pkix.Name.String() renders for a
// PARSER-PRODUCED name, mirroring that method's own construction so the bounded
// render below is byte-identical to the unbounded one it replaces.
func dnSequence(n *pkix.Name) pkix.RDNSequence {
	var rdns pkix.RDNSequence
	for _, atv := range n.Names {
		t := atv.Type
		if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
			switch t[3] {
			case 3, 5, 6, 7, 8, 9, 10, 11, 17:
				// Already carried by a named field, so ToRDNSequence emits it.
				continue
			}
		}
		rdns = append(rdns, []pkix.AttributeTypeAndValue{atv})
	}
	return append(rdns, n.ToRDNSequence()...)
}

// boundedDN returns the part of seq that pkix.RDNSequence.String() emits FIRST — it
// walks the sequence in REVERSE — carrying at most maxSubjectRenderAttrs attributes.
func boundedDN(seq pkix.RDNSequence) pkix.RDNSequence {
	budget := maxSubjectRenderAttrs
	for i, rdn := range slices.Backward(seq) {
		if len(rdn) >= budget {
			bounded := make(pkix.RDNSequence, 0, len(seq)-i)
			bounded = append(bounded, rdn[:budget])
			return append(bounded, seq[i+1:]...)
		}
		budget -= len(rdn)
	}
	return seq
}

// boundedTextError caps the rendered text of an input-derived error.
type boundedTextError struct{ err error }

func (e boundedTextError) Error() string { return boundLogText(e.err.Error(), maxSubjectLogLen) }
func (e boundedTextError) Unwrap() error { return e.err }

// --- Private key parsing ---

// keyScan accumulates what one pass over a key file's PEM blocks learned: the
// usable keys, plus the evidence noPrivateKeyError needs when there are none.
type keyScan struct {
	keys          []crypto.Signer
	firstParseErr error
	skipped       skippedBlocks
	unrelated     skippedBlocks
	decodedBlocks int
	parseFailures int
	sawEncrypted  bool
}

// visit classifies one PEM block, applying the parser's per-block rules.
func (s *keyScan) visit(block *pem.Block) {
	if !isPrivateKeyLabel(block.Type) {
		s.skipped.add(block.Type)
		// Only a label naming something this app cannot read as a key AT ALL (an
		// OpenSSH-format key, for instance) is reported; the expected companions of a
		// real key file are not.
		if !isExpectedKeyFilePassenger(block.Type) {
			s.unrelated.add(block.Type)
		}
		return
	}
	s.decodedBlocks++
	// A PKCS#8 ENCRYPTED PRIVATE KEY block is ciphertext by its label alone; the
	// traditional spellings declare it in their headers instead.
	if block.Type == pemTypeEncryptedPrivateKey || isEncryptedPEMBlock(block) {
		s.sawEncrypted = true
		return
	}
	key, err := parsePrivateKeyBlock(block)
	if err != nil {
		s.parseFailures++
		if s.firstParseErr == nil {
			s.firstParseErr = err
		}
		return
	}
	s.keys = append(s.keys, key)
}

// parsePrivateKeys extracts EVERY usable private key from PEM data, in file
// order, trying PKCS8 first for each block, then falling back to PKCS1 (RSA)
// and SEC1 (EC).
func parsePrivateKeys(pemBytes []byte) ([]crypto.Signer, keyDefects, error) {
	declaredKeyBlocks := countDeclaredBlocks(pemBytes, keyBeginMarkers...)
	if declaredKeyBlocks > maxKeyBlocks {
		return nil, keyDefects{}, fmt.Errorf("private key PEM file declares %d key block(s), more than the %d this app reads",
			declaredKeyBlocks, maxKeyBlocks)
	}
	var scan keyScan
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		scan.visit(block)
	}
	if len(scan.keys) == 0 {
		return nil, keyDefects{}, noPrivateKeyError(scan.firstParseErr, scan.sawEncrypted, scan.skipped,
			scan.unrelated, declaredKeyBlocks-scan.decodedBlocks)
	}
	return scan.keys, keyDefects{
		firstUnreadable:   scan.unrelated.firstTypeForLog(),
		firstParseFailure: parseFailureForLog(scan.firstParseErr),
		unreadable:        scan.unrelated.count,
		unparseable:       scan.parseFailures,
		undecoded:         declaredKeyBlocks - scan.decodedBlocks,
		encrypted:         scan.sawEncrypted,
	}, nil
}

// noPrivateKeyError explains why parsePrivateKeys decoded no usable key, in
// order of specificity: a DER parse failure from a key-labelled block outranks
// "everything was encrypted", which outranks "there were PEM blocks, none of
// them a key" (which names the first label that names no key format this app
// reads, falling back to the first skipped label when every skipped block is an
// expected companion, bounded, so an ssh-keygen-format or otherwise unsupported
// key file is diagnosable from the message alone), which outranks "no PEM block
// at all".
func noPrivateKeyError(firstParseErr error, sawEncrypted bool, skipped, unrelated skippedBlocks, undecodedKeyBlocks int) error {
	switch {
	case firstParseErr != nil:
		return firstParseErr
	case sawEncrypted:
		return errors.New("private key PEM block is encrypted; decrypt it before use")
	}
	msg := "no private key PEM block found"
	// The label named is the first one that names NO key format this app reads, not
	// simply the first skipped one: a key file may legitimately carry its certificate
	// or the EC PARAMETERS companion of the key beside it, and those come FIRST in
	// every file that has them, so naming the first skipped block pointed the operator
	// at an expected passenger while the ssh-keygen-format block this clause exists to
	// diagnose went unmentioned.
	switch {
	case unrelated.count > 0:
		msg = fmt.Sprintf("%s (%d of the %d skipped PEM block(s) name no key format this app reads, first %q)",
			msg, unrelated.count, skipped.count, unrelated.firstTypeForLog())
	case skipped.count > 0:
		msg = fmt.Sprintf("%s (skipped %d PEM block(s), first %q)", msg, skipped.count,
			skipped.firstTypeForLog())
	}
	if undecodedKeyBlocks > 0 {
		msg = fmt.Sprintf("%s; the file declares %d private-key PEM block(s) that could not be decoded (truncated armour or a corrupt body)", msg, undecodedKeyBlocks)
	}
	return errors.New(msg)
}

// parseFailureForLog renders the first key-block parse failure for a diagnostic,
// or "" when every decoded block parsed.
func parseFailureForLog(err error) string {
	if err == nil {
		return ""
	}
	return boundLogText(err.Error(), maxSubjectLogLen)
}

// keyDefects counts the key blocks that yielded no usable key even though
// another block did.
type keyDefects struct {
	// firstUnreadable is the first key-file PEM label that names neither a key
	// format this app reads nor an expected companion of the key
	// (isExpectedKeyFilePassenger owns that set), already sanitized and bounded
	// for a log by skippedBlocks.firstTypeForLog.
	firstUnreadable string
	// firstParseFailure is WHY the first key-labelled block's DER was rejected,
	// sanitized and bounded like every other file-derived text in this package.
	firstParseFailure string
	// unreadable is how many such blocks the file holds.
	unreadable int
	// unparseable is the number of key-labelled blocks whose DER no parser accepted.
	unparseable int
	// undecoded is the number of private-key declarations encoding/pem could not
	// decode at all (truncated armour, a corrupt body).
	undecoded int
	// encrypted reports that at least one block held ciphertext.
	encrypted bool
}

// suffix names those blocks for a "nothing matches" diagnostic, or returns ""
// when every declared block became a key.
func (d keyDefects) suffix() string {
	details := d.details()
	if details == "" {
		return ""
	}
	return "; the key file also holds block(s) that yielded no key: " + details
}

// details lists the defective blocks as one clause ("2 could not be parsed, at
// least one is encrypted"), or returns "" when every declared block became a key.
func (d keyDefects) details() string {
	var parts []string
	if d.unparseable > 0 {
		clause := fmt.Sprintf("%d could not be parsed", d.unparseable)
		if d.firstParseFailure != "" {
			clause += fmt.Sprintf(" (first: %s)", d.firstParseFailure)
		}
		parts = append(parts, clause)
	}
	if d.encrypted {
		parts = append(parts, "at least one is encrypted")
	}
	if d.undecoded > 0 {
		parts = append(parts, fmt.Sprintf("%d declared block(s) could not be decoded (truncated armour or a corrupt body)", d.undecoded))
	}
	if d.unreadable > 0 {
		parts = append(parts, fmt.Sprintf("%d block(s) carry a label naming no key format this app reads (first %q)", d.unreadable, d.firstUnreadable))
	}
	return strings.Join(parts, ", ")
}

// isEncryptedPEMBlock reports whether a traditional OpenSSL private-key block
// carries encryption headers ("Proc-Type: 4,ENCRYPTED" or "DEK-Info"), whose
// body is ciphertext the DER parsers cannot decode.
func isEncryptedPEMBlock(block *pem.Block) bool {
	for name, value := range block.Headers {
		switch {
		case strings.EqualFold(name, "DEK-Info") && value != "":
			return true
		case strings.EqualFold(name, "Proc-Type"):
			normalized := strings.ToUpper(strings.Join(strings.Fields(value), ""))
			if normalized == "4,ENCRYPTED" {
				return true
			}
		}
	}
	return false
}

// oversizedRSAKeyError refuses a private-key block holding an RSA integer larger
// than maxVerifiableKeyBits or declaring more than maxRSAPrimeFactors prime factors,
// and reports nil for every block that is not an RSA private-key envelope at all.
func oversizedRSAKeyError(block *pem.Block) error {
	scan := scanRSAKeyEnvelope(block.Bytes, 1)
	if !scan.isRSA {
		return nil
	}
	if scan.factors > maxRSAPrimeFactors {
		return fmt.Errorf("private key in a %q block declares more than %d RSA prime factors, above the %d-factor ceiling this app reads a private key at (parsing it would run one modular inverse per additional prime against a growing product and stall the scan)",
			boundLogText(block.Type, maxBlockTypeLogLen), maxRSAPrimeFactors, maxRSAPrimeFactors)
	}
	// The size ceiling is the half that CAN be inapplicable: a block none of whose
	// integers could be sized has no measured size to compare, and the parser's own
	// error is the right answer for it.
	if !scan.sized || scan.maxBits <= maxVerifiableKeyBits {
		return nil
	}
	return fmt.Errorf("private key in a %q block holds a %d-bit RSA integer (modulus, prime or CRT value), above the %d-bit ceiling this app reads a private key at (parsing it would run RSA precomputation on file-supplied integers and stall the scan)",
		boundLogText(block.Type, maxBlockTypeLogLen), scan.maxBits, maxVerifiableKeyBits)
}

// maxRSAPrimeFactors caps how many prime factors a private key may declare before
// the pre-scan refuses it, and it is a SECOND bound with its own reason: the
// per-integer ceiling above bounds one oversized value, while this bounds MANY
// small ones.
const maxRSAPrimeFactors = 64

// maxRSAKeyElements bounds how many top-level elements of a PKCS#1 RSAPrivateKey
// body the pre-scan walks AFTER the modulus it has already folded, and it is a THIRD
// bound whose subject is the walk itself rather than the key. RFC 8017 A.1.2
// declares nine INTEGERs plus the optional otherPrimeInfos SEQUENCE, so eight
// elements follow the modulus; 16 is generous headroom for a structure some other
// tool wrote.
const maxRSAKeyElements = 16

// rsaKeyPreScan is what the DER-only envelope scan learned about a private-key
// block: its SHAPE, the prime-factor count that shape declares, and — optionally —
// the size of the largest integer in it.
type rsaKeyPreScan struct {
	// maxBits is the bit length of the largest RSA integer the structure holds —
	// the modulus, a prime, a CRT value, or any integer inside OtherPrimeInfos.
	maxBits int
	// factors is how many prime factors the structure declares: two, plus one per
	// OtherPrimeInfos entry, SATURATED at maxRSAPrimeFactors+1 — past the ceiling the
	// exact count buys nothing and the counting itself is attacker-controlled work.
	factors int
	// isRSA reports that the block IS an RSA private-key envelope: a PKCS#1
	// RSAPrivateKey, or a PKCS#8 PrivateKeyInfo wrapping one.
	isRSA bool
	// sized reports that at least one integer in the envelope could be measured, so
	// maxBits means something.
	sized bool
}

// scanRSAKeyEnvelope reads a private-key DER envelope, reporting whether it IS an
// RSA private-key envelope, how many prime factors it declares, and the size of the
// largest INTEGER in it when any integer could be sized — one walk, three answers,
// because the two refusals oversizedRSAKeyError applies must be able to fire
// independently.
func scanRSAKeyEnvelope(der []byte, depth int) rsaKeyPreScan {
	outer, _, ok := asn1ElementWithTag(der, asn1.TagSequence)
	if !ok {
		return rsaKeyPreScan{}
	}
	_, afterVersion, ok := asn1ElementWithTag(outer.Bytes, asn1.TagInteger)
	if !ok {
		return rsaKeyPreScan{}
	}
	second, afterSecond, ok := asn1Element(afterVersion)
	if !ok {
		return rsaKeyPreScan{}
	}
	switch {
	case isASN1(second, asn1.TagInteger):
		// PKCS#1 RSAPrivateKey: the modulus follows the version, and the primes,
		// CRT values and the optional OtherPrimeInfos collection follow the
		// modulus.
		return scanRSAPKCS1Body(second, afterSecond)
	case isASN1(second, asn1.TagSequence):
		return scanRSAKeyEnvelopePKCS8(afterSecond, depth)
	}
	return rsaKeyPreScan{}
}

// scanRSAKeyEnvelopePKCS8 scans the PKCS#1 key inside a PKCS#8 PrivateKeyInfo,
// given the DER after its AlgorithmIdentifier: the privateKey OCTET STRING that
// follows holds the PKCS#1 structure.
func scanRSAKeyEnvelopePKCS8(afterAlgorithm []byte, depth int) rsaKeyPreScan {
	if depth <= 0 {
		return rsaKeyPreScan{}
	}
	inner, _, ok := asn1ElementWithTag(afterAlgorithm, asn1.TagOctetString)
	if !ok {
		return rsaKeyPreScan{}
	}
	return scanRSAKeyEnvelope(inner.Bytes, depth-1)
}

// scanRSAPKCS1Body scans a PKCS#1 RSAPrivateKey body, given its modulus element and
// the DER of the elements after it.
func scanRSAPKCS1Body(modulus asn1.RawValue, rest []byte) rsaKeyPreScan {
	scan := rsaKeyPreScan{factors: 2, isRSA: true}
	scan.fold(modulus)
	// The walk is bounded on BOTH axes: maxRSAKeyElements bounds how many elements
	// after the folded modulus it reads at all (the walk's own cost),
	// maxRSAPrimeFactors below bounds what they may declare.
	for range maxRSAKeyElements {
		if len(rest) == 0 {
			break
		}
		elem, remaining, elemOK := asn1Element(rest)
		if !elemOK {
			break
		}
		scan.fold(elem)
		// The factor count SATURATES: once it is one past the ceiling the refusal is
		// already proven, and every further element measured is attacker-controlled
		// work bought for a number no caller reads.
		if scan.factors > maxRSAPrimeFactors {
			break
		}
		rest = remaining
	}
	return scan
}

// fold folds one PKCS#1 element into the scan: an INTEGER can only raise the
// measured size (and prove the envelope sizeable at all), and the OtherPrimeInfos
// SEQUENCE contributes both its integers' sizes and its element count, counted only
// as far as the ceiling the count feeds.
func (s *rsaKeyPreScan) fold(elem asn1.RawValue) {
	switch {
	case isASN1(elem, asn1.TagInteger):
		if elemBits, ok := derIntegerBits(elem.Bytes); ok {
			s.sized = true
			if elemBits > s.maxBits {
				s.maxBits = elemBits
			}
		}
	case isASN1(elem, asn1.TagSequence):
		additional, additionalBits := rsaOtherPrimeInfos(elem.Bytes, maxRSAPrimeFactors-s.factors+1)
		s.factors += additional
		// A positive bit length is itself the proof that some integer in the
		// collection was readable: derIntegerBits reports zero for every value whose
		// size means nothing.
		if additionalBits > 0 {
			s.sized = true
			if additionalBits > s.maxBits {
				s.maxBits = additionalBits
			}
		}
	}
}

// rsaOtherPrimeInfos walks PKCS#1's OtherPrimeInfos (a SEQUENCE OF
// OtherPrimeInfo, each SEQUENCE { INTEGER prime, INTEGER exponent, INTEGER
// coefficient }), reporting how many additional primes it declares and the widest
// integer inside it.
func rsaOtherPrimeInfos(body []byte, limit int) (additional, maxBits int) {
	for len(body) > 0 && additional < limit {
		info, remaining, ok := asn1ElementWithTag(body, asn1.TagSequence)
		if !ok {
			break
		}
		additional++
		if infoBits := otherPrimeInfoBits(info); infoBits > maxBits {
			maxBits = infoBits
		}
		body = remaining
	}
	return additional, maxBits
}

// otherPrimeInfoBits reports the widest of one OtherPrimeInfo's three INTEGERs
// (prime, exponent, coefficient), and zero for a shape it cannot read — which only
// ever LOWERS the measured size, never the factor count the refusal turns on.
func otherPrimeInfoBits(info asn1.RawValue) int {
	var maxBits int
	fields := info.Bytes
	for range 3 {
		field, afterField, ok := asn1ElementWithTag(fields, asn1.TagInteger)
		if !ok {
			break
		}
		if fieldBits, bitsOK := derIntegerBits(field.Bytes); bitsOK && fieldBits > maxBits {
			maxBits = fieldBits
		}
		fields = afterField
	}
	return maxBits
}

// asn1Element reads one tag-length-value header off b, returning the element and
// the bytes after it.
func asn1Element(b []byte) (asn1.RawValue, []byte, bool) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(b, &v)
	if err != nil {
		return asn1.RawValue{}, nil, false
	}
	return v, rest, true
}

// isASN1 reports whether v carries the given universal tag.
func isASN1(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == tag
}

// asn1ElementWithTag reads one DER element and reports it only when it carries the
// expected UNIVERSAL tag, so a schema walk states each step once instead of
// repeating the decode-then-check-the-tag conjunction at every field.
func asn1ElementWithTag(b []byte, tag int) (asn1.RawValue, []byte, bool) {
	v, rest, ok := asn1Element(b)
	if !ok || !isASN1(v, tag) {
		return asn1.RawValue{}, nil, false
	}
	return v, rest, true
}

// derIntegerBits reports the bit length of a DER INTEGER's content bytes, and
// false when the value is not a positive integer whose size means anything: an
// empty content, a negative value (the leading byte of a two's-complement DER
// INTEGER has its high bit set), or zero.
func derIntegerBits(content []byte) (int, bool) {
	if len(content) == 0 || content[0] >= 0x80 {
		return 0, false
	}
	for len(content) > 0 && content[0] == 0x00 {
		content = content[1:]
	}
	if len(content) == 0 {
		return 0, false
	}
	return (len(content)-1)*8 + bits.Len8(content[0]), true
}

// parsePrivateKeyBlock decodes a single unencrypted private-key PEM block,
// trying PKCS8 first, then falling back to PKCS1 (RSA) and SEC1 (EC).
func parsePrivateKeyBlock(block *pem.Block) (crypto.Signer, error) {
	if err := prohibitiveKeyError(block); err != nil {
		return nil, err
	}

	key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if pkcs8Err == nil {
		// An allowlist, not a crypto.Signer type assertion: every arm here is a key
		// go-pkcs12 can also ENCODE, so a key type crypto/x509 learns to parse in some
		// later release is refused at the parse with a diagnostic naming it, rather
		// than accepted and then failing at the write with the library's own message.
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		case *mldsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported private key type in PKCS8 container: %T (supported: RSA, ECDSA, Ed25519, ML-DSA)", key)
		}
	}

	rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if pkcs1Err == nil {
		return rsaKey, nil
	}
	ecKey, sec1Err := x509.ParseECPrivateKey(block.Bytes)
	if sec1Err == nil {
		return ecKey, nil
	}

	// Report the failure of the parser that matches the block's own label: a
	// malformed "RSA PRIVATE KEY" must not be diagnosed with the PKCS8 error,
	// which would point the operator at the wrong encoding.
	parseErr := pkcs8Err
	switch block.Type {
	case pemTypeRSAPrivateKey:
		parseErr = pkcs1Err
	case pemTypeECPrivateKey:
		parseErr = sec1Err
	}
	return nil, fmt.Errorf("failed to parse private key from a %q block (tried PKCS8, PKCS1, SEC1): %w",
		boundLogText(block.Type, maxBlockTypeLogLen), boundedTextError{parseErr})
}

// prohibitiveKeyError is every refusal a private-key block earns from its DER
// alone, before any parser sees it: an RSA integer or prime count whose
// precomputation would stall the scan, and an algorithm identifier whose decode
// would allocate megabytes to reject a key.
func prohibitiveKeyError(block *pem.Block) error {
	if err := oversizedRSAKeyError(block); err != nil {
		return err
	}
	if err := oversizedKeyAlgorithmOIDError(block); err != nil {
		return err
	}
	return oversizedSEC1CurveOIDError(block)
}

// oversizedKeyAlgorithmOIDError refuses a PKCS#8 private-key block whose algorithm
// identifier — or the parameters identifier beside it in the same
// AlgorithmIdentifier — is larger than maxOIDBytes, and reports nil for every block
// that is not that shape.
func oversizedKeyAlgorithmOIDError(block *pem.Block) error {
	oid, parameters, ok := pkcs8AlgorithmOID(block.Bytes)
	if !ok {
		return nil
	}
	if len(oid.Bytes) > maxOIDBytes {
		return fmt.Errorf("private key in a %q block names a %d-byte algorithm identifier, above the %d-byte ceiling this app decodes an identifier at (decoding it would allocate one int per encoded byte before the key could be rejected)",
			boundLogText(block.Type, maxBlockTypeLogLen), len(oid.Bytes), maxOIDBytes)
	}
	// The AlgorithmIdentifier's parameters field is decoded the same way and by the
	// same call: for an EC key x509 unmarshals it into an asn1.ObjectIdentifier (the
	// named curve) before it can reject an unknown curve.
	if params, _, paramsOK := asn1ElementWithTag(parameters, asn1.TagOID); paramsOK &&
		!params.IsCompound && len(params.Bytes) > maxOIDBytes {
		return fmt.Errorf("private key in a %q block names a %d-byte algorithm parameter identifier, above the %d-byte ceiling this app decodes an identifier at (decoding it would allocate one int per encoded byte before the key could be rejected)",
			boundLogText(block.Type, maxBlockTypeLogLen), len(params.Bytes), maxOIDBytes)
	}
	return nil
}

// oversizedSEC1CurveOIDError refuses a SEC1 ECPrivateKey block whose explicit [0]
// named-curve identifier is larger than maxOIDBytes, and reports nil for every block
// that is not that shape.
func oversizedSEC1CurveOIDError(block *pem.Block) error {
	size, found := sec1CurveOIDBytes(block.Bytes)
	if !found || size <= maxOIDBytes {
		// x509 reaches the SAME SEC1 parser through a PKCS#8 EC container: for an
		// id-ecPublicKey key, ParsePKCS8PrivateKey hands the privateKey OCTET STRING's
		// content to parseECPrivateKey, whose ecPrivateKey struct decodes the explicit
		// [0] named-curve identifier into an asn1.ObjectIdentifier exactly as the
		// top-level SEC1 path does — and then DISCARDS it, because the curve named in
		// the AlgorithmIdentifier wins.
		size, found = sec1CurveOIDBytes(pkcs8PrivateKeyDER(block.Bytes))
	}
	if !found || size <= maxOIDBytes {
		return nil
	}
	return fmt.Errorf("private key in a %q block names a %d-byte curve identifier, above the %d-byte ceiling this app decodes an identifier at (decoding it would allocate one int per encoded byte before the key could be rejected)",
		boundLogText(block.Type, maxBlockTypeLogLen), size, maxOIDBytes)
}

// sec1CurveOIDBytes reports the content length of a SEC1 ECPrivateKey's explicit
// [0] named-curve identifier — SEQUENCE { INTEGER version, OCTET STRING privateKey,
// [0] parameters OPTIONAL } — and false for anything that is not that shape.
func sec1CurveOIDBytes(der []byte) (int, bool) {
	outer, _, ok := asn1ElementWithTag(der, asn1.TagSequence)
	if !ok {
		return 0, false
	}
	_, afterVersion, ok := asn1ElementWithTag(outer.Bytes, asn1.TagInteger)
	if !ok {
		return 0, false
	}
	_, afterPriv, ok := asn1ElementWithTag(afterVersion, asn1.TagOctetString)
	if !ok {
		return 0, false
	}
	params, _, ok := asn1Element(afterPriv)
	if !ok || params.Class != asn1.ClassContextSpecific || params.Tag != 0 || !params.IsCompound {
		return 0, false
	}
	oid, _, ok := asn1ElementWithTag(params.Bytes, asn1.TagOID)
	if !ok {
		return 0, false
	}
	return len(oid.Bytes), true
}

// pkcs8PrivateKeyDER returns the content of a PKCS#8 PrivateKeyInfo's privateKey
// OCTET STRING — the inner key structure x509 hands to the algorithm's own parser —
// and nil for anything that is not that shape.
func pkcs8PrivateKeyDER(der []byte) []byte {
	_, afterAlgorithm, ok := pkcs8Fields(der)
	if !ok {
		return nil
	}
	inner, _, ok := asn1ElementWithTag(afterAlgorithm, asn1.TagOctetString)
	if !ok {
		return nil
	}
	return inner.Bytes
}

// Package convert provides PEM parsing and PFX encoding utilities.
package convert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/bits"
	"strings"
	"unicode/utf8"

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

// maxChainCerts bounds how many CERTIFICATE blocks one input file may declare. A
// real chain is a leaf plus a handful of issuers; the bound exists because
// Analyse's graph work is superlinear in the certificate count (all-pairs
// candidate edges, and a path walk that verifies up to n^2/2 signatures), so one
// file inside the reader's MaxInputBytes cap could otherwise hold ~19,000 certificates
// and spend hours of CPU plus gigabytes of adjacency state on the scan's only
// goroutine.
const maxChainCerts = 64

// maxKeyBlocks bounds how many private-key blocks one key file may declare.
// Rotation appends a second key; nothing legitimate appends thousands, and every
// extra key multiplies identity matching.
const maxKeyBlocks = 16

// MaxInputBytes is the largest certificate or key file this package's acceptance
// bounds are calibrated against: maxChainCerts, maxKeyBlocks, maxRSAPrimeFactors
// and the log-text bounds are each sized from the worst case a file this large can
// hold, and the measured costs in their comments assume it. The reader enforces it
// (internal/process reads every input under this cap), so the number lives here
// where the reasoning that depends on it lives: raising the cap has to be a change
// to this constant, which lands in the diff beside the bounds it invalidates.
const MaxInputBytes = 10 << 20

// parseCertChain decodes all CERTIFICATE PEM blocks from pemBytes, returning
// them in order. Blocks of any other type (the private key of a combined
// cert+key file, for instance) are skipped, and the "no certificate" diagnostic
// names the first skipped block's label (bounded) so a swapped cert/key pair is
// diagnosable from the message alone. Blocks that are neither a certificate nor
// a private key are additionally returned as the second result, so Analyse can
// report that they were left out of the bundle instead of dropping them
// silently. Two kinds of label are exempt from that second result: any private-key
// label, including the encrypted one (a combined cert+key file is a supported input),
// and EC PARAMETERS, but only in a file that also holds the EC private key it
// describes (what `openssl ecparam -genkey` writes as one combined bundle). Both are
// expected companions rather than something left out by mistake;
// isExpectedCertFilePassenger owns that set. It returns an error if no CERTIFICATE
// block is present, and also if any CERTIFICATE block holds DER
// that x509 cannot parse: a partially decodable chain is rejected outright
// rather than silently truncated, because a PFX built from a truncated chain
// fails validation obscurely at the consumer instead of here.
//
// It is unexported because Analyse owns the invariants a caller could otherwise
// bypass: the cert/key match and the leaf/chain split. Publishing the
// lower-level parser would offer a second contract around them with no
// production consumer. The package's own tests reach it through export_test.go.
func parseCertChain(pemBytes []byte) ([]*x509.Certificate, skippedBlocks, error) {
	declaredCertBlocks := countDeclaredBlocks(pemBytes, certBeginMarker)
	if declaredCertBlocks > maxChainCerts {
		return nil, skippedBlocks{}, fmt.Errorf("certificate PEM chain declares %d CERTIFICATE block(s), more than the %d this app converts",
			declaredCertBlocks, maxChainCerts)
	}
	var scan certScan
	// EC PARAMETERS is an expected passenger only as the companion of the EC key
	// `openssl ecparam -genkey` writes beside it, so whether this file carries that
	// key is a property of the file as a whole and is settled BEFORE the blocks are
	// classified in order (the parameters block precedes the key it describes, and
	// the report names the FIRST unrelated label, so the answer cannot be deferred
	// to the end of the drain). The pre-scan is gated on the label being declared at
	// all, so an ordinary bundle pays one line scan and no second decode.
	if countDeclaredBlocks(pemBytes, pemBeginMarker(pemTypeECParameters)) > 0 {
		scan.ecKeyPresent = holdsECPrivateKey(pemBytes)
	}

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
		if scan.skipped.count > 0 {
			return nil, skippedBlocks{}, fmt.Errorf("no certificate PEM block found (skipped %d non-certificate PEM block(s), first %q)",
				scan.skipped.count, scan.skipped.firstTypeForLog())
		}
		return nil, skippedBlocks{}, errors.New("no certificate PEM block found")
	}
	return scan.certs, scan.unrelated, nil
}

// certScan accumulates what one pass over a certificate file's PEM blocks
// learned: the parsed chain, plus the skipped-block evidence the "no certificate"
// diagnostic and the unrelated-passenger report need. Hoisting the loop body onto
// it keeps parseCertChain a bounds -> drain -> validate sequence, the same shape
// keyScan gives parsePrivateKeys.
//
// Field order is chosen for pointer-region packing (govet fieldalignment): the
// slice leads, then the two skippedBlocks whose string leads them.
type certScan struct {
	certs     []*x509.Certificate
	skipped   skippedBlocks
	unrelated skippedBlocks
	// ecKeyPresent says whether the file also holds an EC private key, which is what
	// makes an EC PARAMETERS block in it an expected companion rather than a stray.
	// It is a property of the whole file, so parseCertChain settles it before the
	// drain rather than the visit loop discovering it.
	ecKeyPresent bool
}

// visit classifies one PEM block, applying the parser's per-block rules. The
// error it returns is the chain-rejecting one: unparseable certificate DER ends
// the scan rather than truncating the chain.
func (s *certScan) visit(block *pem.Block) error {
	if block.Type != pemTypeCertificate {
		s.skipped.add(block.Type)
		// Only a label naming neither a certificate nor a key companion is reported;
		// isExpectedCertFilePassenger owns that set.
		if !isExpectedCertFilePassenger(block.Type, s.ecKeyPresent) {
			s.unrelated.add(block.Type)
		}
		return nil
	}
	if err := oversizedCertificateOIDError(block); err != nil {
		return fmt.Errorf("certificate PEM block %d: %w", len(s.certs)+1, err)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("certificate PEM block %d: %w", len(s.certs)+1, boundedTextError{err})
	}
	s.certs = append(s.certs, c)
	return nil
}

// isExpectedCertFilePassenger reports whether a non-certificate PEM label in the
// CERTIFICATE file is an expected companion rather than something the operator meant
// this app to read as a certificate. The private-key labels are the combined cert+key
// file (a supported input). EC PARAMETERS is what `openssl ecparam -genkey` writes
// immediately before the EC PRIVATE KEY it describes, so it is expected only when
// ecKeyPresent says this same file carries that key — the mirror of
// isExpectedKeyFilePassenger for the combined bundle, without extending the silence
// to a certificate file whose matching key is separate or is not an EC key at all.
// That narrowing is the difference between "these parameters belong to the key beside
// them" and "the label alone excuses the block": in the latter case the parameters
// really were left out of the bundle, and ObsUnrelatedBlocksSkipped is the only thing
// that says so. It reads the same pemType* constants keyBeginMarkers is built from,
// so the "a key in the certificate file is expected" rule cannot drift from the
// parser's own set.
func isExpectedCertFilePassenger(blockType string, ecKeyPresent bool) bool {
	switch blockType {
	case pemTypePrivateKey, pemTypeRSAPrivateKey, pemTypeECPrivateKey,
		pemTypeEncryptedPrivateKey:
		return true
	case pemTypeECParameters:
		return ecKeyPresent
	}
	return false
}

// holdsECPrivateKey reports whether pemBytes carries an EC private key: a SEC1
// "EC PRIVATE KEY" block, or a PKCS#8 "PRIVATE KEY" block whose
// AlgorithmIdentifier names id-ecPublicKey. Both spellings occur in a combined
// `openssl ecparam -genkey` bundle depending on whether the key was converted to
// PKCS#8 afterwards, and only the second needs to look past the label.
//
// It reads the PKCS#8 algorithm OID rather than parsing the key, for the reason
// oversizedRSAKeyError documents: parsing a file-supplied private key runs RSA
// precomputation inside crypto/x509 before anything can reject it, and this
// question is asked about a CERTIFICATE file whose key blocks are otherwise never
// offered to a parser. Walking the DER header costs bytes, not milliseconds, and an
// encrypted or malformed key answers "no" — unproven rather than disproven, which
// is the safe direction here: an unproven companion is reported, not hidden.
func holdsECPrivateKey(pemBytes []byte) bool {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return false
		}
		switch block.Type {
		case pemTypeECPrivateKey:
			return true
		case pemTypePrivateKey:
			if pkcs8HoldsECKey(block.Bytes) {
				return true
			}
		}
	}
}

// ecPublicKeyOID is id-ecPublicKey (1.2.840.10045.2.1, RFC 5480 2.1.1), the
// algorithm a PKCS#8 container names when it holds an EC private key.
var ecPublicKeyOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// pkcs8HoldsECKey reports whether PKCS#8 PrivateKeyInfo DER declares an EC key,
// reading only the AlgorithmIdentifier's OID: SEQUENCE { INTEGER version, SEQUENCE
// { OBJECT IDENTIFIER algorithm, ... }, OCTET STRING privateKey }. It shares
// scanRSAKeyEnvelope's asn1.RawValue walk, so nothing is decoded beyond the
// tag-length headers and the OID itself, and anything it cannot read is false.
//
// The identifier is decoded through decodeOID, so the package's untrusted-OID bound
// (maxOIDBytes) applies here too: encoding/asn1 allocates one int per encoded byte
// when it decodes into an asn1.ObjectIdentifier, so a near-limit PEM devoting its
// DER to one syntactically valid identifier could otherwise spend tens of megabytes
// of heap merely to answer "no" — on the scan's only goroutine, for a CERTIFICATE
// file's companion-block question. An oversized identifier answers false, which is
// the same safe direction as every other shape this walk cannot read: the block is
// reported rather than silently treated as the EC key's companion.
func pkcs8HoldsECKey(der []byte) bool {
	oid, _, ok := pkcs8AlgorithmOID(der)
	if !ok {
		return false
	}
	parsed, err := decodeOID(oid)
	return err == nil && parsed.Equal(ecPublicKeyOID)
}

// pkcs8AlgorithmOID returns the retained (undecoded) algorithm OID element of
// PKCS#8 PrivateKeyInfo DER, together with the DER that follows it INSIDE the same
// AlgorithmIdentifier (its optional parameters field), and false for anything that is
// not that shape. It is the one reader of that field: every caller needs a length
// before anything decodes it, so each element is handed back undecoded for the same
// reason profile.go retains every untrusted identifier as an asn1.RawValue.
func pkcs8AlgorithmOID(der []byte) (oid asn1.RawValue, parameters []byte, ok bool) {
	outer, _, ok := asn1Element(der)
	if !ok || !isASN1(outer, asn1.TagSequence) {
		return asn1.RawValue{}, nil, false
	}
	version, afterVersion, ok := asn1Element(outer.Bytes)
	if !ok || !isASN1(version, asn1.TagInteger) {
		return asn1.RawValue{}, nil, false
	}
	algorithm, _, ok := asn1Element(afterVersion)
	if !ok || !isASN1(algorithm, asn1.TagSequence) {
		return asn1.RawValue{}, nil, false
	}
	oid, parameters, ok = asn1Element(algorithm.Bytes)
	if !ok || !isASN1(oid, asn1.TagOID) {
		return asn1.RawValue{}, nil, false
	}
	return oid, parameters, true
}

// isExpectedKeyFilePassenger reports whether a non-key PEM label in the KEY file is
// an expected companion of the key rather than something the operator meant this app
// to read as one. Two of them, and both are silent on purpose: a CERTIFICATE block is
// the combined cert+key file (the mirror of parseCertChain's private-key rule), and an
// EC PARAMETERS block is what `openssl ecparam -genkey` writes immediately before the
// EC PRIVATE KEY it describes, so reporting it would WARN about a healthy file on
// every scan.
func isExpectedKeyFilePassenger(blockType string) bool {
	switch blockType {
	case pemTypeCertificate, pemTypeECParameters:
		return true
	}
	return false
}

// --- PEM declaration counting (shared by both parsers) ---

// pemBeginMarker builds the PEM declaration line that opens a block of the
// given type, exactly as encoding/pem writes it. Deriving the markers from the
// pemType* constants keeps them in lockstep with the block types the decode
// loops switch on (and keeps literal PEM key headers out of the source).
func pemBeginMarker(blockType string) []byte {
	return []byte("-----BEGIN " + blockType + "-----")
}

// certBeginMarker is the PEM declaration line that opens a CERTIFICATE block.
var certBeginMarker = pemBeginMarker(pemTypeCertificate)

// keyBeginMarkers are the PEM declaration lines that open a private-key block
// parsePrivateKeys knows about, including the encrypted forms it diagnoses
// rather than decodes.
var keyBeginMarkers = [][]byte{
	pemBeginMarker(pemTypePrivateKey),
	pemBeginMarker(pemTypeRSAPrivateKey),
	pemBeginMarker(pemTypeECPrivateKey),
	pemBeginMarker(pemTypeEncryptedPrivateKey),
}

// countDeclaredBlocks counts the declarations in markers the way encoding/pem
// recognises them: a marker declares a block only when it occupies a complete
// line, so the same text embedded in surrounding prose (which pem.Decode
// ignores entirely) is not counted and cannot make a valid chain look
// malformed. Line endings are normalised the way pem's getLine does — the line
// terminator, then at most ONE trailing carriage return, then trailing spaces
// and tabs — so CRLF input counts identically and a line pem does NOT accept as
// a declaration (a doubled "\r\r", or a "\r" followed by a space) is not
// counted either. One deliberate divergence: getLine strips the carriage return
// only on a newline-terminated line, while this strips it on an unterminated
// final line too, so a file whose last line is "-----BEGIN CERTIFICATE-----\r"
// still counts as a declaration and is reported as a truncated chain instead of
// being silently ignored.
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
// learns WHAT the file held rather than only that something was skipped. Both
// parsers share it, so the "remember the first label" rule lives in one place
// and cannot drift between them.
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

// maxBlockTypeLogLen bounds the PEM block label a parse diagnostic names. A PEM
// type line is arbitrary operator-supplied text bounded only by the caller's
// MaxInputBytes input read bound, so
// it is truncated before it reaches the log.
const maxBlockTypeLogLen = 64

// boundLogText makes input-derived text safe and bounded for a log-bound
// diagnostic. It is the single home for that rule: every diagnostic in this package
// that interpolates text taken from a file the app does not control (a certificate
// subject, a PEM block label) goes through it.
//
// The whole composition is runesafe's: SanitizeSingleLineCapped applies the fleet's
// shared single-line policy (so the text is safe under any slog handler by
// construction rather than by matching one handler's escaping), caps the SANITIZED
// form on a rune boundary — the cap must run after sanitizing, which can GROW the
// text as an invalid byte becomes the three-byte U+FFFD, and a cut inside a rune
// would mint exactly the raw 0x80-0x9F tail bytes the sanitizer just removed — and
// names the cut with the marker this app supplies. Nothing is re-implemented here;
// the app contributes only the marker and the limit.
//
// The bound exists because the source file is capped only by the caller's input read
// bound (MaxInputBytes), so an unbounded
// interpolation would put a multi-megabyte line into the log of every scan that
// retries the pair.
//
// The marker is charged AGAINST limit, so the result never exceeds limit at all —
// where the app's own composition used to append the marker after the cut and run to
// limit plus the marker's length. The bound exists to stop multi-megabyte lines, so
// either placement serves it; taking the library's makes limit mean the total, which
// is the simpler promise to a caller sizing a diagnostic.
//
// The cut FACT is discarded deliberately: no diagnostic in this package reports
// truncation as a separate attribute, and the marker in the text is what an operator
// reads. A caller that ever needs the fact takes the pair directly rather than
// re-deriving it from the marker, which a value legitimately ending in the marker
// would defeat.
func boundLogText(s string, limit int) string {
	text, _ := runesafe.SanitizeSingleLineCapped(s, limit, logtext.Marker)
	return text
}

// truncationMarker names text boundLogText had to cut, so a reader can tell a
// diagnostic that ends mid-subject from one that genuinely ends there. It is
// deliberately more explicit than runesafe's own "..." preset marker, which is why
// boundLogText passes a marker of its own to the library's caller-marker primitive.
// The wording lives in internal/logtext because internal/process bounds its orphan
// path sample with the same marker and the two must not drift; this alias is what
// the package's own assertions read.
const truncationMarker = logtext.Marker

// maxSubjectLogLen bounds the certificate-controlled subject interpolated into a
// diagnostic. The subject is parsed out of a PEM file the app does not control
// and is capped only by the reader's size limit, so an unbounded interpolation
// puts a multi-megabyte line into the logs of every scan that retries the pair.
const maxSubjectLogLen = 256

// boundSubject truncates a certificate subject to maxSubjectLogLen bytes for a
// log-bound diagnostic, dropping the partial rune the cut may leave behind so
// the %q form stays readable. It is a named alias for the package's shared
// boundLogText rule.
func boundSubject(subject string) string {
	return boundLogText(subject, maxSubjectLogLen)
}

// boundedTextError caps the rendered text of an input-derived error. The
// crypto/x509 parser interpolates certificate-controlled fields into several of
// its messages with %q (a SAN URI, a name constraint, an extension OID), and
// x509's PKCS#8 unknown-algorithm message interpolates an OBJECT IDENTIFIER
// decoded from the key file. Either file is capped only by the caller's input
// read bound (MaxInputBytes), so the unbounded text would
// put a multi-megabyte line into the log of every scan that retries the pair.
// It shares the same bound (maxSubjectLogLen) and the same partial-rune handling
// as every other certificate-controlled interpolation in this package. Unwrap is
// kept so errors.Is/As still reach the wrapped error.
type boundedTextError struct{ err error }

func (e boundedTextError) Error() string { return boundLogText(e.err.Error(), maxSubjectLogLen) }
func (e boundedTextError) Unwrap() error { return e.err }

// --- Private key parsing ---

// keyScan accumulates what one pass over a key file's PEM blocks learned: the
// usable keys, plus the evidence noPrivateKeyError needs when there are none.
// Hoisting the loop body onto it keeps parsePrivateKeys a plain drain loop.
//
// Field order is chosen for pointer-region packing (govet fieldalignment), not
// for narrative order: the two pointer-bearing fields lead, then skippedBlocks
// whose string leads it, then the scalars.
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
	switch block.Type {
	case pemTypePrivateKey, pemTypeRSAPrivateKey, pemTypeECPrivateKey:
		s.decodedBlocks++
		if isEncryptedPEMBlock(block) {
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
	case pemTypeEncryptedPrivateKey:
		s.decodedBlocks++
		s.sawEncrypted = true
	default:
		s.skipped.add(block.Type)
		// Only a label naming something this app cannot read as a key AT ALL (an
		// OpenSSH-format key, for instance) is reported; the expected companions of a
		// real key file are not.
		if !isExpectedKeyFilePassenger(block.Type) {
			s.unrelated.add(block.Type)
		}
	}
}

// parsePrivateKeys extracts EVERY usable private key from PEM data, in file
// order, trying PKCS8 first for each block, then falling back to PKCS1 (RSA)
// and SEC1 (EC).
//
// Block selection and DER validation share one loop, so a key file whose first
// key-labelled block is malformed (or holds an unsupported PKCS#8 key type)
// still yields a usable key from a later block; the first parse failure is
// reported only when no block decodes. It distinguishes "no key block at all"
// from "the only key blocks are encrypted" so the caller surfaces actionable
// guidance: both a PKCS#8 ENCRYPTED PRIVATE KEY block and a traditional OpenSSL
// key carrying "Proc-Type: 4,ENCRYPTED" + "DEK-Info" headers hold ciphertext
// none of the parsers can decode. It also counts the private-key declarations
// the file carries (the same line-accurate accounting parseCertChain applies to
// CERTIFICATE blocks) so a key file whose armour encoding/pem silently dropped
// is diagnosed as damaged rather than as holding no key at all. Unlike the
// chain, a partially decodable key file is NOT rejected: a usable later block
// still wins, and the count only enriches the failure message.
//
// Returning all of them is what lets identity selection be key-first: with more
// than one key present, the certificate decides which key is correct, so
// discarding the later blocks would throw away the evidence. The failure
// diagnostics are consulted only when NO block yields a key; when one does, the
// returned keyDefects carries the blocks that did not, so a later identity
// mismatch can still name the half of the file that is damaged.
//
// The result element type is crypto.Signer, not crypto.PrivateKey, because that
// is what the allowlist below actually admits: every accepted key type exposes a
// public half, which is what identity matching compares. Naming the narrower type
// here means no caller has to handle a key that cannot be matched.
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
			declaredKeyBlocks-scan.decodedBlocks)
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
// them a key" (which names the first skipped block's label, bounded, so an
// ssh-keygen-format or otherwise unsupported key file is diagnosable from the
// message alone), which outranks "no PEM block at all". The last two are further
// qualified by undecodedKeyBlocks, the number of private-key declarations the
// file carries that encoding/pem dropped (truncated armour, a corrupt body, or
// a run-together END/BEGIN line), so a damaged key file is not reported with
// the same sentence as a file that genuinely holds no key. The base sentence is
// kept as the prefix so existing log matching is unaffected.
func noPrivateKeyError(firstParseErr error, sawEncrypted bool, skipped skippedBlocks, undecodedKeyBlocks int) error {
	switch {
	case firstParseErr != nil:
		return firstParseErr
	case sawEncrypted:
		return errors.New("private key PEM block is encrypted; decrypt it before use")
	}
	msg := "no private key PEM block found"
	if skipped.count > 0 {
		msg = fmt.Sprintf("%s (skipped %d PEM block(s), first %q)", msg, skipped.count,
			skipped.firstTypeForLog())
	}
	if undecodedKeyBlocks > 0 {
		msg = fmt.Sprintf("%s; the file declares %d private-key PEM block(s) that could not be decoded (truncated armour or a corrupt body)", msg, undecodedKeyBlocks)
	}
	return errors.New(msg)
}

// parseFailureForLog renders the first key-block parse failure for a diagnostic,
// or "" when every decoded block parsed. It goes through boundLogText for the same
// reason every other file-derived interpolation in this package does: the text is
// built from a key file the app does not control, and this is the package's single
// gate for that. parsePrivateKeyBlock bounds the WRAPPED parser error at the same
// limit, but its own sentence is charged against that budget first, so a maximal
// inner error loses its tail here — the reason's opening survives, which is the part
// that names the remedy. Routing through the gate keeps the rule "no file-derived
// text reaches a diagnostic ungated" true by construction rather than by tracing
// every producer.
func parseFailureForLog(err error) string {
	if err == nil {
		return ""
	}
	return boundLogText(err.Error(), maxSubjectLogLen)
}

// keyDefects counts the key blocks that yielded no usable key even though
// another block did. parsePrivateKeys itself succeeds in that case, so without
// carrying this out the evidence is discarded exactly when it is needed: a
// mid-rotation file whose appended key is truncated or of an unsupported type
// still parses its OLD key, and if the certificate has been renewed the failure
// the operator then sees is "the key does not match the certificate".
type keyDefects struct {
	// firstUnreadable is the first key-file PEM label that names neither a key
	// format this app reads nor a certificate, already sanitized and bounded for a
	// log by skippedBlocks.firstTypeForLog.
	firstUnreadable string
	// firstParseFailure is WHY the first key-labelled block's DER was rejected,
	// sanitized and bounded like every other file-derived text in this package. The
	// count alone tells an operator that a block is damaged but not what to do about
	// it; the reason distinguishes truncated armour from an unsupported key type
	// from an oversized RSA modulus, which are three different remedies.
	firstParseFailure string
	// unreadable is how many such blocks the file holds. Counted apart from
	// unparseable because encoding/pem decoded them fine and no parser was ever
	// offered them: only the label rules them out.
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
// when every declared block became a key. It is appended to the existing
// sentence rather than folded into it, so log matching on the base message is
// unaffected.
func (d keyDefects) suffix() string {
	details := d.details()
	if details == "" {
		return ""
	}
	return "; the key file also holds block(s) that yielded no key: " + details
}

// details lists the defective blocks as one clause ("2 could not be parsed, at
// least one is encrypted"), or returns "" when every declared block became a key.
//
// It is the single home of that wording because two diagnostics need it and must
// not drift: noMatchError's suffix on the hard-failure path, and the
// unusable-key-blocks observation analyseAt emits when identity selection
// SUCCEEDED anyway. Every part is a count or a fixed phrase except the unreadable
// clause's PEM label, which skippedBlocks.firstTypeForLog has already sanitized
// and bounded, so the text is safe for a log as it stands.
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
// body is ciphertext the DER parsers cannot decode. Header names are matched
// case-insensitively (encoding/pem preserves the spelling it was given) and the
// Proc-Type value is compared case-insensitively ignoring all interior
// whitespace, so a hand-written "4, ENCRYPTED" or a tab-separated value is
// still recognised.
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
//
// The two ceilings are asked of the SAME envelope scan, and independently: the
// factor ceiling is decided from the envelope's shape alone, so it still refuses a
// key whose integers could not be SIZED. A block whose modulus is zero or negative
// is malformed, but it is unambiguously an RSA envelope, and the collection of extra
// prime factors it declares is read from tag-length headers that do not depend on
// the modulus being readable. Deciding "unmeasurable, therefore nothing to say" —
// which is what a size-only pre-scan did — left the amplification shape the factor
// ceiling exists for reachable behind one malformed integer.
//
// A consequence, accepted deliberately: for such a block this app's own bounded
// refusal is now the error the operator sees, where crypto/x509's malformed-key
// error used to be. The app refuses the file either way; only the wording changes,
// and it changes towards the diagnostic that names the ceiling and the remedy.
//
// It exists because the cost is INSIDE the parser: x509.ParsePKCS8PrivateKey and
// x509.ParsePKCS1PrivateKey run RSA CRT precomputation and consistency validation
// on the integers the FILE supplies before either can reject the key, and that
// work has no context or cancellation path. Measured on go1.26.5, a
// self-consistent key costs 8.8ms to parse at 16384 bits and 369ms at 131072 bits
// from a 73 KB block, and other shapes inside the reader's MaxInputBytes cap are far
// worse; all of it lands on the scan's only goroutine, before convertEntry can
// emit its per-path diagnostic, where shutdown cannot interrupt it. So the guard
// cannot inspect a PARSED key — by then the stall has already happened — and runs
// on the DER instead.
//
// The ceiling is maxVerifiableKeyBits, deliberately the same constant analyse.go's
// signature-verification guard uses rather than a second number: a certificate
// above it is already refused a signature check, so accepting a private key above
// it could only produce a bundle this app would not reason about.
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
// small ones. crypto/x509 decodes PKCS#1's optional OtherPrimeInfos into a slice
// and crypto/rsa's precomputeLegacy then runs one ModInverse per additional prime
// against a product that grows with each, so cost climbs superlinearly in the
// element COUNT at a constant few bytes per element. Measured on go1.26.5 with
// 1024-bit factors: 1,000 entries (12 KB DER) cost 3.0ms and 2.6 MB, 5,000 (61 KB)
// cost 52ms and 70 MB, 10,000 (127 KB) cost 160ms and 292 MB — all far inside the
// reader's MaxInputBytes cap, on the scan's only goroutine, with no cancellation path.
//
// 64 is far above any real key: multi-prime RSA is rare and practical keys use
// three or four factors, so this refuses an amplification shape rather than a
// configuration.
const maxRSAPrimeFactors = 64

// maxRSAKeyElements bounds how many top-level elements of a PKCS#1 RSAPrivateKey
// body the pre-scan walks, and it is a THIRD bound whose subject is the walk
// itself rather than the key. RFC 8017 A.1.2 declares nine INTEGERs plus the
// optional otherPrimeInfos SEQUENCE, so eight elements follow the modulus; 16 is
// generous headroom for a structure some other tool wrote.
//
// It exists because the walk is not free: every element costs one asn1.Unmarshal
// into an asn1.RawValue, so a body of tiny INTEGERs makes the GUARD the expensive
// operation. Measured on go1.26.5, a 7.86 MB body (the largest DER a 10 MB PEM
// file yields) holding 2,621,438 three-byte INTEGERs cost the walk 340 ms and
// 200 MB of transient allocation, while x509.ParsePKCS1PrivateKey rejected the
// same DER in 60 us; at a full 10 MB DER, 855 ms and 267 MB.
//
// Stopping cannot let an expensive shape through: a body with more top-level
// elements than PKCS#1 declares cannot hide an expensive one past the budget.
// encoding/asn1 maps a SEQUENCE onto crypto/x509's pkcs1PrivateKey POSITIONALLY, so
// every integer whose size drives precomputation (N, E, D, P, Q and the three CRT
// values) is among the eight elements after the modulus, and asn1 TOLERATES extra
// bytes at the end of a SEQUENCE (measured on go1.26.5: a real key padded with 12
// trailing INTEGERs still parses) — which means an otherPrimeInfos collection padded
// past this budget is not matched by the optional field either, and is skipped
// without cost. It is the same ceiling profile.go's sequenceElements applies to every
// SEQUENCE OF the preflight walks.
const maxRSAKeyElements = 16

// rsaKeyPreScan is what the DER-only envelope scan learned about a private-key
// block: its SHAPE, the prime-factor count that shape declares, and — optionally —
// the size of the largest integer in it. All three come back from one walk because
// the refusals they feed must not depend on each other: a size that could not be
// measured is a missing MEASUREMENT, not a missing envelope, and it must not silence
// the factor ceiling.
type rsaKeyPreScan struct {
	// maxBits is the bit length of the largest RSA integer the structure holds —
	// the modulus, a prime, a CRT value, or any integer inside OtherPrimeInfos.
	// Meaningless unless sized.
	maxBits int
	// factors is how many prime factors the structure declares: two, plus one per
	// OtherPrimeInfos entry, SATURATED at maxRSAPrimeFactors+1 — past the ceiling the
	// exact count buys nothing and the counting itself is attacker-controlled work.
	// Meaningless unless isRSA.
	factors int
	// isRSA reports that the block IS an RSA private-key envelope: a PKCS#1
	// RSAPrivateKey, or a PKCS#8 PrivateKeyInfo wrapping one. False is the FAIL-OPEN
	// answer for a shape that is not one (a non-RSA key, a truncated or malformed
	// container) and means the pre-scan decides nothing: the block goes to the
	// existing parsers with their existing errors.
	isRSA bool
	// sized reports that at least one integer in the envelope could be measured, so
	// maxBits means something. It is INDEPENDENT of isRSA: a malformed envelope
	// whose every integer is zero, negative or unreadable is still an envelope whose
	// factor count is known, which is why this is a second flag and not the absence
	// of the first.
	sized bool
}

// scanRSAKeyEnvelope reads a private-key DER envelope, reporting whether it IS an
// RSA private-key envelope, how many prime factors it declares, and the size of the
// largest INTEGER in it when any integer could be sized — one walk, three answers,
// because the two refusals oversizedRSAKeyError applies must be able to fire
// independently.
//
// It reads ONLY each element's own tag-length header, through encoding/asn1's
// RawValue (which slices the content rather than decoding it), and never converts a
// file-supplied integer to a big.Int, so it costs sub-microseconds on a 32 KB block
// where the parser costs hundreds of milliseconds.
//
// Two shapes carry those integers, and both are handled: a PKCS#1 RSAPrivateKey,
// whose modulus is the INTEGER after the version INTEGER (with the primes and CRT
// values after it), and a PKCS#8 PrivateKeyInfo, whose privateKey OCTET STRING
// (after the version INTEGER and the AlgorithmIdentifier SEQUENCE) wraps that same
// PKCS#1 structure — hence depth, which admits exactly one level of unwrapping and
// stops a crafted file from nesting containers indefinitely.
//
// It FAILS OPEN on SHAPE by design: an isRSA-false result for anything that is not
// one of those two envelopes, which covers a non-RSA key (a SEC1 EC key's second
// element is an OCTET STRING, a PKCS#8 EC or Ed25519 key's inner OCTET STRING is not
// a PKCS#1 SEQUENCE, and none of them is expensive to parse) and a container it
// cannot read at all. Measurability is a SEPARATE answer: inside a recognised
// envelope, an integer this walk cannot size simply does not contribute a size, and
// the envelope's factor count still stands. The guard's job is to refuse OVERSIZED
// and OVER-FACTORED keys, not to become a second parser: every other verdict is left
// to the existing parsers and their existing errors.
func scanRSAKeyEnvelope(der []byte, depth int) rsaKeyPreScan {
	outer, _, ok := asn1Element(der)
	if !ok || !isASN1(outer, asn1.TagSequence) {
		return rsaKeyPreScan{}
	}
	version, afterVersion, ok := asn1Element(outer.Bytes)
	if !ok || !isASN1(version, asn1.TagInteger) {
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
		// modulus. crypto/rsa builds a bigmod modulus from p and q (Validate ->
		// precompute) before it can reject an inconsistent key, so the LARGEST
		// integer in the structure decides the cost, not the modulus. Measuring
		// only the modulus let a 710 KB block with a 20-bit modulus and 2-Mbit
		// "primes" spend 59.8s inside x509.ParsePKCS1PrivateKey.
		return scanRSAPKCS1Body(second, afterSecond)
	case isASN1(second, asn1.TagSequence):
		return scanRSAKeyEnvelopePKCS8(afterSecond, depth)
	}
	return rsaKeyPreScan{}
}

// scanRSAKeyEnvelopePKCS8 scans the PKCS#1 key inside a PKCS#8 PrivateKeyInfo,
// given the DER after its AlgorithmIdentifier: the privateKey OCTET STRING that
// follows holds the PKCS#1 structure.
//
// depth is the unwrap allowance, and it is a security rule rather than a style
// one: an exhausted allowance fails open here exactly as it did inline, so a
// crafted file cannot nest containers indefinitely and make the walk recurse. It
// fails open on anything else it cannot read, for the reason scanRSAKeyEnvelope
// documents.
func scanRSAKeyEnvelopePKCS8(afterAlgorithm []byte, depth int) rsaKeyPreScan {
	if depth <= 0 {
		return rsaKeyPreScan{}
	}
	inner, _, ok := asn1Element(afterAlgorithm)
	if !ok || !isASN1(inner, asn1.TagOctetString) {
		return rsaKeyPreScan{}
	}
	return scanRSAKeyEnvelope(inner.Bytes, depth-1)
}

// scanRSAPKCS1Body scans a PKCS#1 RSAPrivateKey body, given its modulus element and
// the DER of the elements after it. The envelope is RECOGNISED by the time this is
// called, so isRSA is true and the factor count starts at the two primes PKCS#1
// always declares; only the size is conditional.
//
// The modulus is folded in like any other integer rather than gating the walk. A
// modulus that is absent, zero or negative used to abandon the whole scan, and with
// it the factor count — so a malformed key carrying a huge OtherPrimeInfos
// collection reached crypto/x509 with both ceilings skipped. Every integer here can
// only RAISE the measured size, so a value this walk cannot read can never lower the
// ceiling check.
//
// The trailing SEQUENCE, when present, is PKCS#1's optional OtherPrimeInfos: its
// integers count towards the size and its element count towards the factor total,
// because that collection is the amplification shape maxRSAPrimeFactors bounds. That
// count is the only superlinear cost in reach, and it saturates; everything else
// here is one tag-length header per element.
//
// The element count is bounded too (maxRSAKeyElements), because the walk's own
// per-element cost is what a body of millions of tiny INTEGERs attacks; a body
// longer than PKCS#1 declares is rejected by encoding/asn1's struct decode in
// microseconds, so the budget forfeits no refusal that could have mattered.
func scanRSAPKCS1Body(modulus asn1.RawValue, rest []byte) rsaKeyPreScan {
	scan := rsaKeyPreScan{factors: 2, isRSA: true}
	scan.fold(modulus)
	// The walk is bounded on BOTH axes: maxRSAKeyElements bounds how many elements
	// it reads at all (the walk's own cost), maxRSAPrimeFactors below bounds what
	// they may declare.
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
		// work bought for a number no caller reads. The size ceiling can only be
		// raised by an element this loop would keep walking, and a block that already
		// earns the factor refusal is never reported for its size.
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
// integer inside it. Nothing is decoded here either: each element is measured
// from its own tag-length header.
//
// limit is how many entries are still worth counting — one more than the caller
// needs to prove its refusal — so the walk stops as soon as the ceiling is exceeded
// instead of measuring an attacker-sized collection to the end for an exact count
// nothing reads. A non-positive limit stops immediately.
//
// It counts an entry it cannot fully read, and stops at the first element that is
// not an OtherPrimeInfo, which is the FAIL-CLOSED direction on purpose — the count
// feeds a refusal, so undercounting a malformed collection is the only mistake
// with a cost. Undercounting cannot happen from a short read: the walk stops, and
// the caller refuses on what it already counted.
func rsaOtherPrimeInfos(body []byte, limit int) (additional, maxBits int) {
	for len(body) > 0 && additional < limit {
		info, remaining, ok := asn1Element(body)
		if !ok || !isASN1(info, asn1.TagSequence) {
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
		field, afterField, ok := asn1Element(fields)
		if !ok || !isASN1(field, asn1.TagInteger) {
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
// the bytes after it. The RawValue's content is a slice of b, so nothing is
// decoded and nothing is copied.
func asn1Element(b []byte) (asn1.RawValue, []byte, bool) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(b, &v)
	if err != nil {
		return asn1.RawValue{}, nil, false
	}
	return v, rest, true
}

// isASN1 reports whether v carries the given universal tag. The class check is
// what keeps a context-specific element (PKCS#8's optional attributes, SEC1's
// [0] parameters) from being mistaken for the universal tag of the same number.
func isASN1(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == tag
}

// derIntegerBits reports the bit length of a DER INTEGER's content bytes, and
// false when the value is not a positive integer whose size means anything: an
// empty content, a negative value (the leading byte of a two's-complement DER
// INTEGER has its high bit set), or zero. None of those is a size, so such a value
// contributes nothing to the envelope scan's measurement — the scan still reports
// the envelope's shape and factor count, and only the SIZE half of the pre-scan
// stands down. The sign is read from the FIRST byte, before the
// 0x00 bytes DER prepends to keep a large positive value positive are stripped.
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
// trying PKCS8 first, then falling back to PKCS1 (RSA) and SEC1 (EC). A PKCS8
// container holding a key type cert-converter does not support is rejected with
// a distinct error rather than reported as unparseable.
//
// Every refusal a private-key block earns from its DER alone is applied BEFORE any
// parser sees the block, because the cost is paid inside the parser itself: an
// oversized RSA integer, too many RSA prime factors, and an oversized algorithm,
// parameter or curve identifier; see prohibitiveKeyError.
//
// The return type is crypto.Signer: every accepted type implements it, so the
// caller never has to consider a key whose public half cannot be read.
func parsePrivateKeyBlock(block *pem.Block) (crypto.Signer, error) {
	if err := prohibitiveKeyError(block); err != nil {
		return nil, err
	}

	key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if pkcs8Err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported private key type in PKCS8 container: %T (supported: RSA, ECDSA, Ed25519)", key)
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
// would allocate megabytes to reject a key. They share a home because they share a
// reason — each cost is paid INSIDE crypto/x509, where nothing can interrupt it —
// and because the order they are asked in is not a decision a caller should have to
// make.
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
//
// It is the same allocation bound profile.go's decodeOID applies to bundle bytes,
// applied here because x509.ParsePKCS8PrivateKey decodes that identifier into an
// asn1.ObjectIdentifier before it can reject an unsupported key: encoding/asn1
// allocates one int per encoded byte, roughly eight bytes of heap per input byte, so
// a file inside the reader's MaxInputBytes cap can spend most of its DER on one
// syntactically valid identifier and drive tens of megabytes of transient
// allocation merely to be refused — on the scan's only goroutine, with no
// cancellation path. The refusal is bounded and names the size, like every other
// pre-parse guard here; every identifier a real key names is 9 bytes or fewer.
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
	// named curve) before it can reject an unknown curve. Only a PRIMITIVE OBJECT
	// IDENTIFIER reaches that allocation; a compound tag or a SEQUENCE (explicit EC
	// parameters, RSASSA-PSS parameters) is refused by encoding/asn1 without
	// allocating, so it is left alone.
	if params, _, paramsOK := asn1Element(parameters); paramsOK && isASN1(params, asn1.TagOID) &&
		!params.IsCompound && len(params.Bytes) > maxOIDBytes {
		return fmt.Errorf("private key in a %q block names a %d-byte algorithm parameter identifier, above the %d-byte ceiling this app decodes an identifier at (decoding it would allocate one int per encoded byte before the key could be rejected)",
			boundLogText(block.Type, maxBlockTypeLogLen), len(params.Bytes), maxOIDBytes)
	}
	return nil
}

// oversizedSEC1CurveOIDError refuses a SEC1 ECPrivateKey block whose explicit [0]
// named-curve identifier is larger than maxOIDBytes, and reports nil for every block
// that is not that shape.
//
// It is the third door on the same call chain as oversizedKeyAlgorithmOIDError:
// x509.ParseECPrivateKey decodes that identifier into an asn1.ObjectIdentifier (one
// int per encoded byte) before it can reject an unknown curve, and
// parsePrivateKeyBlock tries that parser on EVERY block that fails PKCS#8 and PKCS#1,
// whatever its label. Every curve a real key names is 9 bytes or fewer, so nothing
// legitimate is newly refused; only the refusal point and its text move.
func oversizedSEC1CurveOIDError(block *pem.Block) error {
	size, found := sec1CurveOIDBytes(block.Bytes)
	if !found || size <= maxOIDBytes {
		// x509 reaches the SAME SEC1 parser through a PKCS#8 EC container: for an
		// id-ecPublicKey key, ParsePKCS8PrivateKey hands the privateKey OCTET STRING's
		// content to parseECPrivateKey, whose ecPrivateKey struct decodes the explicit
		// [0] named-curve identifier into an asn1.ObjectIdentifier exactly as the
		// top-level SEC1 path does — and then DISCARDS it, because the curve named in
		// the AlgorithmIdentifier wins. Neither the RSA pre-scan (the inner structure's
		// second element is an OCTET STRING) nor the PKCS#8 identifier bound (which
		// reads only the AlgorithmIdentifier, whose own identifiers are the ordinary 7
		// and 8 bytes) sees it, so the fourth door needs this unwrap.
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
// [0] parameters OPTIONAL } — and false for anything that is not that shape. Only
// the LENGTH comes back, for the reason decodeOID documents: the whole point is to
// compare it before anything decodes the identifier.
func sec1CurveOIDBytes(der []byte) (int, bool) {
	outer, _, ok := asn1Element(der)
	if !ok || !isASN1(outer, asn1.TagSequence) {
		return 0, false
	}
	version, afterVersion, ok := asn1Element(outer.Bytes)
	if !ok || !isASN1(version, asn1.TagInteger) {
		return 0, false
	}
	priv, afterPriv, ok := asn1Element(afterVersion)
	if !ok || !isASN1(priv, asn1.TagOctetString) {
		return 0, false
	}
	params, _, ok := asn1Element(afterPriv)
	if !ok || params.Class != asn1.ClassContextSpecific || params.Tag != 0 || !params.IsCompound {
		return 0, false
	}
	oid, _, oidOK := asn1Element(params.Bytes)
	if !oidOK || !isASN1(oid, asn1.TagOID) {
		return 0, false
	}
	return len(oid.Bytes), true
}

// pkcs8PrivateKeyDER returns the content of a PKCS#8 PrivateKeyInfo's privateKey
// OCTET STRING — the inner key structure x509 hands to the algorithm's own parser —
// and nil for anything that is not that shape. It is the sibling of
// scanRSAKeyEnvelopePKCS8's unwrap and admits exactly one level for the same
// reason: a crafted file must not be able to make a pre-parse walk recurse.
func pkcs8PrivateKeyDER(der []byte) []byte {
	outer, _, ok := asn1Element(der)
	if !ok || !isASN1(outer, asn1.TagSequence) {
		return nil
	}
	version, afterVersion, ok := asn1Element(outer.Bytes)
	if !ok || !isASN1(version, asn1.TagInteger) {
		return nil
	}
	algorithm, afterAlgorithm, ok := asn1Element(afterVersion)
	if !ok || !isASN1(algorithm, asn1.TagSequence) {
		return nil
	}
	inner, _, ok := asn1Element(afterAlgorithm)
	if !ok || !isASN1(inner, asn1.TagOctetString) {
		return nil
	}
	return inner.Bytes
}

// PasswordEncodingIssues reports the ways a PFX password cannot survive the
// PKCS#12 BMPString (UCS-2) password encoding (RFC 7292 appendix B.1). It is
// the single semantic home for that rule: internal/convert enforces it before
// encoding, and internal/config reuses the same query for its startup
// diagnostic, so the two cannot drift. The zero value means the password
// encodes faithfully.
type PasswordEncodingIssues struct {
	// InvalidUTF8 means the password is not valid UTF-8, so every invalid byte
	// is encoded as U+FFFD and the PFX ends up protected by a different,
	// lower-entropy password than the configured secret.
	InvalidUTF8 bool
	// NonBMP means the password holds a rune above U+FFFF, which UCS-2 cannot
	// represent at all, so every Encode call fails.
	NonBMP bool
	// EmbeddedNUL means the password contains U+0000. PKCS#12 passwords are
	// NUL-terminated BMPStrings (RFC 7292 appendix B.1), and go-pkcs12 encodes
	// an interior NUL verbatim before appending its own terminator, so no
	// consumer that builds the BMPString from a NUL-terminated string
	// (OpenSSL, Windows CryptoAPI) can reproduce the key-derivation input.
	EmbeddedNUL bool
}

// PasswordEncodingIssue names one shape, or none.
type PasswordEncodingIssue string

// The password shapes PasswordEncodingIssues.Primary selects between.
const (
	PasswordEncodesFine PasswordEncodingIssue = ""
	PasswordInvalidUTF8 PasswordEncodingIssue = "invalid-utf8" //nolint:gosec // G101 false positive: a shape NAME for a diagnostic, not a credential value.
	PasswordNonBMP      PasswordEncodingIssue = "non-bmp"
	PasswordEmbeddedNUL PasswordEncodingIssue = "embedded-nul"
)

// Primary reports the shape to name when several hold. The ORDER is the
// contract: internal/config's startup gate and Encode's codec guard must
// name the same shape for the same password, so it lives here once rather
// than as two switches kept aligned by comment.
func (i PasswordEncodingIssues) Primary() PasswordEncodingIssue {
	switch {
	case i.InvalidUTF8:
		return PasswordInvalidUTF8
	case i.NonBMP:
		return PasswordNonBMP
	case i.EmbeddedNUL:
		return PasswordEmbeddedNUL
	}
	return PasswordEncodesFine
}

// Explain says why a shape cannot survive the PKCS#12 UCS-2 password encoding and
// what to do about it, or "" for a password that encodes faithfully. It is the
// single home of that wording: Encode's codec guard and internal/config's startup
// gate both refuse on a non-empty result, so neither re-enumerates the shapes and a
// new shape lands once. Never names the password value; these texts reach the log.
func (s PasswordEncodingIssue) Explain() string {
	switch s {
	case PasswordEncodesFine:
		return ""
	case PasswordInvalidUTF8:
		return "is not valid UTF-8, so the PKCS#12 UCS-2 password encoding would " +
			"replace every invalid byte with U+FFFD and protect the bundle with a " +
			"different, lower-entropy password than the one supplied; supply a text " +
			"secret (for example base64) instead of raw binary bytes"
	case PasswordNonBMP:
		return "contains a character outside the Basic Multilingual Plane, which the " +
			"PKCS#12 UCS-2 password encoding cannot represent, so every encode would " +
			"fail; choose a password made of BMP characters (ASCII is safest)"
	case PasswordEmbeddedNUL:
		return "contains a NUL byte, and PKCS#12 passwords are NUL-terminated, so no " +
			"consumer that builds the terminated BMPString itself could open the bundle " +
			"with the password supplied; strip NUL bytes from the secret (a UTF-16 or " +
			"NUL-padded secret file is the usual cause)"
	}
	// Fail CLOSED for a shape this wording does not cover: a non-empty result is a
	// refusal, so a future recognised shape is refused by both consumers until its
	// text is added here, instead of being accepted by fallthrough at either.
	return fmt.Sprintf("carries encoding shape %q, which this app cannot prove the "+
		"PKCS#12 UCS-2 password encoding carries intact", s)
}

// InspectPasswordEncoding reports how a PFX password fares under the PKCS#12
// UCS-2 password encoding. All shapes are computed in one pass so callers do
// not re-derive the rule: go-pkcs12 rejects a non-BMP password with a message
// that names neither the password nor the constraint's source, it silently
// replaces invalid UTF-8 rune-by-rune, and it encodes an interior NUL verbatim
// into a password format that is itself NUL-terminated. The offending rune or
// byte is deliberately never reported: it is part of a secret, and the
// diagnostics built on this query go to the container log.
func InspectPasswordEncoding(password string) PasswordEncodingIssues {
	issues := PasswordEncodingIssues{
		InvalidUTF8: !utf8.ValidString(password),
		EmbeddedNUL: strings.ContainsRune(password, 0),
	}
	for _, r := range password {
		if r > 0xFFFF {
			issues.NonBMP = true
			break
		}
	}
	return issues
}

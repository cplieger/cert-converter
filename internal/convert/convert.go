// Package convert provides PEM parsing and PFX encoding utilities.
package convert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/cplieger/runesafe"
)

// PEM block type constants.
const (
	pemTypeCertificate         = "CERTIFICATE"
	pemTypePrivateKey          = "PRIVATE KEY"
	pemTypeRSAPrivateKey       = "RSA PRIVATE KEY"
	pemTypeECPrivateKey        = "EC PRIVATE KEY"
	pemTypeEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
)

// --- Certificate chain parsing ---

// maxChainCerts bounds how many CERTIFICATE blocks one input file may declare. A
// real chain is a leaf plus a handful of issuers; the bound exists because
// Analyse's graph work is superlinear in the certificate count (all-pairs
// candidate edges, and a path walk that verifies up to n^2/2 signatures), so one
// file inside the reader's 10 MB cap could otherwise hold ~19,000 certificates
// and spend hours of CPU plus gigabytes of adjacency state on the scan's only
// goroutine.
const maxChainCerts = 64

// maxKeyBlocks bounds how many private-key blocks one key file may declare.
// Rotation appends a second key; nothing legitimate appends thousands, and every
// extra key multiplies identity matching.
const maxKeyBlocks = 16

// parseCertChain decodes all CERTIFICATE PEM blocks from pemBytes, returning
// them in order. Blocks of any other type (the private key of a combined
// cert+key file, for instance) are skipped, and the "no certificate" diagnostic
// names the first skipped block's label (bounded) so a swapped cert/key pair is
// diagnosable from the message alone. It returns an error if no
// CERTIFICATE block is present, and also if any CERTIFICATE block holds DER
// that x509 cannot parse: a partially decodable chain is rejected outright
// rather than silently truncated, because a PFX built from a truncated chain
// fails validation obscurely at the consumer instead of here.
//
// It is unexported because Analyse owns the invariants a caller could otherwise
// bypass: the cert/key match and the leaf/chain split. Publishing the
// lower-level parser would offer a second contract around them with no
// production consumer. The package's own tests reach it through export_test.go.
func parseCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	declaredCertBlocks := countDeclaredBlocks(pemBytes, certBeginMarker)
	if declaredCertBlocks > maxChainCerts {
		return nil, fmt.Errorf("certificate PEM chain declares %d CERTIFICATE block(s), more than the %d this app converts",
			declaredCertBlocks, maxChainCerts)
	}
	var certs []*x509.Certificate
	var skipped skippedBlocks

	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != pemTypeCertificate {
			skipped.add(block.Type)
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate PEM block %d: %w", len(certs)+1, boundedTextError{err})
		}
		certs = append(certs, c)
	}

	if len(certs) != declaredCertBlocks {
		return nil, fmt.Errorf("certificate PEM chain is malformed: decoded %d of %d declared CERTIFICATE block(s)", len(certs), declaredCertBlocks)
	}

	if len(certs) == 0 {
		if skipped.count > 0 {
			return nil, fmt.Errorf("no certificate PEM block found (skipped %d non-certificate PEM block(s), first %q)",
				skipped.count, skipped.firstTypeForLog())
		}
		return nil, errors.New("no certificate PEM block found")
	}
	return certs, nil
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
// PEM type is operator-supplied text capped only by the 10 MB input read bound
// internal/process applies (source.go maxFileSize).
func (s *skippedBlocks) firstTypeForLog() string {
	return boundLogText(s.firstType, maxBlockTypeLogLen)
}

// maxBlockTypeLogLen bounds the PEM block label a parse diagnostic names. A PEM
// type line is arbitrary operator-supplied text bounded only by the caller's 10 MB
// input read bound (internal/process source.go maxFileSize), so
// it is truncated before it reaches the log.
const maxBlockTypeLogLen = 64

// boundLogText makes input-derived text safe and bounded for a log-bound
// diagnostic. It is the single home for that rule: every diagnostic in this package
// that interpolates text taken from a file the app does not control (a certificate
// subject, a PEM block label) goes through it.
//
// Sanitizing is delegated to runesafe.SanitizeSingleLine, the fleet's shared policy
// for untrusted text bound for a single-line sink, so the text is safe under any
// slog handler by construction rather than by matching one handler's escaping.
//
// Bounding stays here: the source file is capped only by the caller's input read
// bound (10 MB, internal/process source.go maxFileSize), so an unbounded
// interpolation would put a multi-megabyte line into the log of every scan that
// retries the pair. The cap runs AFTER sanitizing, on a rune boundary
// (runesafe.CapBytes), because sanitizing can GROW the text — an invalid byte
// becomes the three-byte U+FFFD — and a cut inside a rune would mint exactly the
// raw 0x80-0x9F tail bytes the sanitizer just removed.
//
// This is runesafe.SanitizeSingleLineBounded composed from the library's own
// primitives, which is how runesafe documents keeping a caller's marker: the preset
// marks a cut with "..." and this package marks it with truncationMarker. The marker
// is appended after the cut, so a truncated result exceeds limit by the marker's own
// length; the bound exists to stop multi-megabyte lines, not to hit limit exactly.
func boundLogText(s string, limit int) string {
	s = runesafe.SanitizeSingleLine(s)
	if len(s) <= limit {
		return s
	}
	return runesafe.CapBytes(s, limit) + truncationMarker
}

// truncationMarker is appended to text boundLogText had to cut, so a reader can tell
// a diagnostic that ends mid-subject from one that genuinely ends there. It is
// deliberately more explicit than runesafe's own "..." marker, which is why
// boundLogText composes the library's primitives instead of taking its preset.
const truncationMarker = "...(truncated)"

// boundedTextError caps the rendered text of an input-derived error. The
// crypto/x509 parser interpolates certificate-controlled fields into several of
// its messages with %q (a SAN URI, a name constraint, an extension OID), and
// x509's PKCS#8 unknown-algorithm message interpolates an OBJECT IDENTIFIER
// decoded from the key file. Either file is capped only by the caller's input
// read bound (10 MB), so the unbounded text would
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
	decodedBlocks int
	sawEncrypted  bool
}

// visit classifies one PEM block, applying the same per-block rules the parser
// has always used.
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
// discarding the later blocks would throw away the evidence. The diagnostics are
// unchanged and are consulted only when NO block yields a key, so an input that
// used to produce a key still produces the same first key.
//
// The result element type is crypto.Signer, not crypto.PrivateKey, because that
// is what the allowlist below actually admits: every accepted key type exposes a
// public half, which is what identity matching compares. Naming the narrower type
// here means no caller has to handle a key that cannot be matched.
func parsePrivateKeys(pemBytes []byte) ([]crypto.Signer, error) {
	declaredKeyBlocks := countDeclaredBlocks(pemBytes, keyBeginMarkers...)
	if declaredKeyBlocks > maxKeyBlocks {
		return nil, fmt.Errorf("private key PEM file declares %d key block(s), more than the %d this app reads",
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
		return nil, noPrivateKeyError(scan.firstParseErr, scan.sawEncrypted, scan.skipped,
			declaredKeyBlocks-scan.decodedBlocks)
	}
	return scan.keys, nil
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

// parsePrivateKeyBlock decodes a single unencrypted private-key PEM block,
// trying PKCS8 first, then falling back to PKCS1 (RSA) and SEC1 (EC). A PKCS8
// container holding a key type cert-converter does not support is rejected with
// a distinct error rather than reported as unparseable.
//
// The return type is crypto.Signer: every accepted type implements it, so the
// caller never has to consider a key whose public half cannot be read.
func parsePrivateKeyBlock(block *pem.Block) (crypto.Signer, error) {
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
	return nil, fmt.Errorf("failed to parse private key from %s block (tried PKCS8, PKCS1, SEC1): %w",
		block.Type, boundedTextError{parseErr})
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

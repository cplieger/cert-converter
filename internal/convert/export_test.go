package convert

import (
	"crypto"
	"crypto/x509"
)

// ParseCertChain drops the skipped-unrelated-block evidence the parser returns
// for Analyse's observation.
//
// parseCertChain and parsePrivateKeys stay unexported: Analyse is the package's
// only production conversion edge, owning the cert/key match and the leaf/chain
// split, so no production package outside internal/convert may bypass those
// invariants. This wrapper (and ParsePrivateKey below) keep their coverage
// available to the external convert_test package without widening the API.
func ParseCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	certs, _, err := parseCertChain(pemBytes)
	return certs, err
}

// Test-only handles on the read-back steps CheckCurrency sequences. Same rule as
// the parsers above: publishing inspect, decode or matchesAnalysis would offer a
// second contract that skips CheckCurrency's mandatory preflight-before-derivation
// ordering, and no production consumer needs one.
var (
	Inspect = inspect
	Decode  = decode
)

// Decoded is the decoded-bundle type the external tests build comparison cases
// from. An alias rather than a wrapper, so a test can name the exported fields
// directly.
type Decoded = decoded

// MatchesAnalysis is the unexported method as a function, because a type alias
// cannot re-export a method.
func MatchesAnalysis(d Decoded, a Analysis) bool { return d.matchesAnalysis(a) }

// ParsePrivateKey is the single-key convenience the parser's own tests read
// through. Production uses parsePrivateKeys, since with more than one key
// present the certificate decides which is correct.
func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	keys, _, err := parsePrivateKeys(pemBytes)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// MaxVerifiableKeyBits is the signature-verification key ceiling, exported so the
// external tests can build a key just above it instead of hardcoding a number
// that silently stops testing the refusal if the ceiling ever moves.
const MaxVerifiableKeyBits = maxVerifiableKeyBits

// Analysis's representation, as test-only accessors. Production exports only
// Observations, so keeping the leaf, chain, key and excluded certificates
// unexported is what stops a consumer invalidating Analyse's cert-matches-key
// invariant before handing the value back to Encode. The external tests still
// have to assert on that representation, so they read it here.
func (a *Analysis) Leaf() *x509.Certificate    { return a.leaf }
func (a *Analysis) Chain() []*x509.Certificate { return a.chain }
func (a *Analysis) Key() crypto.PrivateKey     { return a.key }
func (a *Analysis) Extra() []*x509.Certificate { return a.extra }

// The PKCS#12 password-encoding classifier, as test-only handles. Same rule as
// the parsers above: the package publishes only ValidatePasswordEncoding, so
// keeping the recognizer, its precedence and its wording unexported stops a
// consumer coupling to the representation the codec classifies with.
type PasswordEncodingIssues = passwordEncodingIssues

var InspectPasswordEncoding = inspectPasswordEncoding

// Why is the unexported method under an exported name, because an external test
// package cannot call an unexported method through a type alias.
func (i PasswordEncodingIssues) Why() string { return i.why() }

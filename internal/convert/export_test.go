package convert

import (
	"crypto"
	"crypto/x509"
)

// Test-only handles on the package-internal PEM parsers. Analyse is the
// package's only production conversion edge (it owns the cert/key match and the
// leaf/chain split), so parseCertChain and parsePrivateKeys
// stay unexported: no production package outside internal/convert may bypass
// those invariants. Their direct unit, property and fuzz coverage still matters,
// and the standard-library export_test.go idiom keeps that coverage available to
// the external convert_test package without widening the app's API — test
// placement no longer dictates the package surface.
var (
	EncoderFor = encoderFor
)

// ParseCertChain drops the skipped-unrelated-block evidence the parser returns
// for Analyse's observation, so the parser's own tests keep asserting on the
// certificates and the error alone.
func ParseCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	certs, _, err := parseCertChain(pemBytes)
	return certs, err
}

// Test-only handles on the read-back steps CheckCurrency sequences. Same rule as
// the parsers above, for the same reason: publishing inspect, decode or
// matchesAnalysis would offer a second contract that skips the ordering
// CheckCurrency exists to enforce (preflight before derivation), and no
// production consumer needs one. Their individual coverage is worth keeping, so
// the external tests reach them here.
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
func MatchesAnalysis(d Decoded, a *Analysis) bool { return d.matchesAnalysis(a) }

// ParsePrivateKey is the single-key convenience the parser's own tests read
// through. Production uses parsePrivateKeys: identity selection needs every key
// in the file, because with more than one present the certificate decides which
// is correct. The wrapper lives here rather than in production so no production
// function exists solely for tests.
func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	keys, _, err := parsePrivateKeys(pemBytes)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// MaxVerifiableKeyBits is the signature-verification key ceiling, exported so the
// external tests can build a key just above it instead of hardcoding a number that
// silently stops testing the refusal if the ceiling ever moves up.
const MaxVerifiableKeyBits = maxVerifiableKeyBits

// Analysis's representation, as test-only accessors. Production exports only
// Observations, because reporting what was noticed is all internal/process does
// with an Analysis; the leaf, chain, key and excluded certificates are codec
// material, and keeping them unexported is what stops a consumer invalidating
// Analyse's cert-matches-key invariant before handing the value back to Encode.
// The external tests still have to assert on that representation — it IS the
// result Analyse computes — so they read it here, the same way they reach inspect
// and decode above. Test placement does not dictate the package surface.
func (a *Analysis) Leaf() *x509.Certificate    { return a.leaf }
func (a *Analysis) Chain() []*x509.Certificate { return a.chain }
func (a *Analysis) Key() crypto.PrivateKey     { return a.key }
func (a *Analysis) Extra() []*x509.Certificate { return a.extra }

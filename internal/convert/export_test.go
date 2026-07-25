package convert

import "crypto"

// Test-only handles on the package-internal PEM parsers. PairInRoot is the
// package's only production conversion edge (it owns the cert/key match, the
// leaf/chain split and the PFX write), so parseCertChain and parsePrivateKey
// stay unexported: no production package outside internal/convert may bypass
// those invariants. Their direct unit, property and fuzz coverage still matters,
// and the standard-library export_test.go idiom keeps that coverage available to
// the external convert_test package without widening the app's API — test
// placement no longer dictates the package surface.
var (
	ParseCertChain = parseCertChain
	EncoderFor     = encoderFor
)

// ParsePrivateKey is the single-key convenience the parser's own tests read
// through. Production uses parsePrivateKeys: identity selection needs every key
// in the file, because with more than one present the certificate decides which
// is correct. The wrapper lives here rather than in production so no production
// function exists solely for tests.
func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	keys, err := parsePrivateKeys(pemBytes)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

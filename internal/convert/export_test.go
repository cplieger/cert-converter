package convert

// Test-only handles on the package-internal PEM parsers. PairInRoot is the
// package's only production conversion edge (it owns the cert/key match, the
// leaf/chain split and the PFX write), so parseCertChain and parsePrivateKey
// stay unexported: no production package outside internal/convert may bypass
// those invariants. Their direct unit, property and fuzz coverage still matters,
// and the standard-library export_test.go idiom keeps that coverage available to
// the external convert_test package without widening the app's API — test
// placement no longer dictates the package surface.
var (
	ParseCertChain  = parseCertChain
	ParsePrivateKey = parsePrivateKey
)

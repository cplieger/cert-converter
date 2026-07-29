package convert_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// FuzzAnalyse_keeps_the_bundle_internally_consistent fuzzes the two INDEPENDENT
// files production actually reads: /input holds a certificate file and a separate
// key file, and the existing FuzzToPFXRoundTrip passes one blob as both, so no
// fuzz target reaches a bundle whose certificate file and key file differ. That is
// the whole input space identity selection exists for (a chain beside a key file
// carrying decoys, a rotation, an unrelated key).
//
// The invariants are the two Analyse documents and that nothing else checks over
// arbitrary input. Internal consistency: the returned key is provably the private
// half of the returned leaf, which is what makes the emitted PFX usable at all.
// Conservation: every certificate Analyse emits came from the certificate file,
// each appears exactly once across the leaf, the chain and the excluded set, and
// every distinct input certificate is accounted for in one of the three. A chain
// assembly or path walk that dropped a link, repeated the leaf as its own CA bag or
// invented a certificate would satisfy every fixture-based test in the package.
func FuzzAnalyse_keeps_the_bundle_internally_consistent(f *testing.F) {
	m := testcerts.GenerateChainMaterial(f)
	_, unrelatedKeyPEM := testcerts.GenerateSelfSignedCert(f, "fuzz-unrelated.example.com", "ecdsa")
	unrelatedCertPEM, _ := testcerts.GenerateSelfSignedCert(f, "fuzz-stranger.example.com", "ecdsa")
	spareCAPEM := fuzzSpareCA(f)

	// The committed seeds ARE the durable fuzz coverage (the weekly run's generated
	// corpus is discarded), so they cover every resolvable shape the package
	// documents: leaf-first, leaf-last, a renewal tie, a stranger to exclude, decoy
	// keys, a key that matches nothing, and a CA as the identity.
	//
	// The last three end on a terminus that is NOT proven self-signed, which is the
	// app's canonical ACME/Caddy input (the root lives in the consumer's trust store,
	// never in the file) and the only branch that MOVES a certificate between the
	// emitted chain and the excluded set. Without them the conservation invariant
	// below never runs on that branch at all, so a fallback that emitted a kept
	// certificate twice, or dropped one, satisfied every seed.
	for _, seed := range []struct{ certPEM, keyPEM []byte }{
		{concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM},
		{concatPEM(m.CAPEM, m.LeafPEM), m.LeafKeyPEM},
		{concatPEM(m.LeafPEM, m.RenewedPEM, m.CAPEM), m.LeafKeyPEM},
		{concatPEM(m.LeafPEM, m.CAPEM, unrelatedCertPEM), m.LeafKeyPEM},
		{concatPEM(m.LeafPEM, m.CAPEM), concatPEM(unrelatedKeyPEM, m.LeafKeyPEM)},
		{concatPEM(m.LeafPEM, m.CAPEM), unrelatedKeyPEM},
		{m.CAPEM, m.CAKeyPEM},
		{m.LeafPEM, m.LeafKeyPEM},
		{concatPEM(m.LeafPEM, unrelatedCertPEM), m.LeafKeyPEM},
		{concatPEM(m.LeafPEM, spareCAPEM), m.LeafKeyPEM},
	} {
		f.Add(seed.certPEM, seed.keyPEM)
	}

	f.Fuzz(func(t *testing.T, certPEM, keyPEM []byte) {
		got, err := convert.Analyse(certPEM, keyPEM)
		if err != nil {
			// An unresolvable pair is a documented outcome (no key matches, several
			// identities, the key belongs to an issuer), not a broken invariant.
			return
		}

		assertKeyMatchesLeaf(t, got)

		inputCerts, parseErr := convert.ParseCertChain(certPEM)
		if parseErr != nil {
			t.Fatalf("Analyse resolved a certificate file ParseCertChain rejects: %v", parseErr)
		}
		fromInput := make(map[string]bool, len(inputCerts))
		for _, c := range inputCerts {
			fromInput[string(c.Raw)] = true
		}

		emitted := make(map[string]int, len(fromInput))
		emitted[string(got.Leaf().Raw)]++
		for _, c := range got.Chain() {
			emitted[string(c.Raw)]++
		}
		for _, c := range got.Extra() {
			emitted[string(c.Raw)]++
		}
		for raw, n := range emitted {
			if !fromInput[raw] {
				t.Fatal("Analyse emitted a certificate the certificate file does not hold")
			}
			if n != 1 {
				t.Fatalf("Analyse emitted one certificate %d times across the leaf, the chain and the excluded set", n)
			}
		}
		if len(emitted) != len(fromInput) {
			t.Fatalf("Analyse accounted for %d of the %d distinct certificates in the file; each one is the leaf, chain material or excluded",
				len(emitted), len(fromInput))
		}
	})
}

// fuzzSpareCA mints a self-signed CA with a subject no other fixture uses. It is
// what gives the unfinished-chain seed something the additive fallback can KEEP:
// GenerateSelfSignedCert produces a certificate with no CA extensions (which
// partitionIssuerEligible disqualifies), and a second GenerateChainMaterial CA
// shares "Material Test CA" as its subject, so the path walk adopts it as an
// unproven parent instead of leaving it over.
func fuzzSpareCA(f *testing.F) []byte {
	key := testcerts.NewECDSAKey(f)
	now := time.Now()
	_, caPEM, _ := testcerts.Mint(f, &x509.Certificate{
		SerialNumber:          big.NewInt(9001),
		Subject:               pkix.Name{CommonName: "fuzz-spare-ca.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &key.PublicKey, nil, key)
	return caPEM
}

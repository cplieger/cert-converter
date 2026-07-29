package convert_test

import (
	"crypto"
	"testing"

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

	// The committed seeds ARE the durable fuzz coverage (the weekly run's generated
	// corpus is discarded), so they cover every resolvable shape the package
	// documents: leaf-first, leaf-last, a renewal tie, a stranger to exclude, decoy
	// keys, a key that matches nothing, and a CA as the identity.
	for _, seed := range []struct{ certPEM, keyPEM []byte }{
		{concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM},
		{concatPEM(m.CAPEM, m.LeafPEM), m.LeafKeyPEM},
		{concatPEM(m.LeafPEM, m.RenewedPEM, m.CAPEM), m.LeafKeyPEM},
		{concatPEM(m.LeafPEM, m.CAPEM, unrelatedCertPEM), m.LeafKeyPEM},
		{concatPEM(m.LeafPEM, m.CAPEM), concatPEM(unrelatedKeyPEM, m.LeafKeyPEM)},
		{concatPEM(m.LeafPEM, m.CAPEM), unrelatedKeyPEM},
		{m.CAPEM, m.CAKeyPEM},
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

		signer, ok := got.Key().(crypto.Signer)
		if !ok {
			t.Fatalf("Analyse returned a key of type %T that is not a crypto.Signer", got.Key())
		}
		matcher, ok := got.Leaf().PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok {
			t.Fatalf("selected leaf carries a public key of type %T with no Equal method", got.Leaf().PublicKey)
		}
		if !matcher.Equal(signer.Public()) {
			t.Fatal("Analyse resolved a bundle whose key is not the private half of the selected leaf")
		}

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

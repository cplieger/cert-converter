package process

import (
	"testing"

	"pgregory.net/rapid"
)

// TestPairFingerprint_properties pins the two properties pairFingerprint's godoc
// promises, neither of which any other test can fail on.
//
// Determinism is what makes the one-shot input diagnostic quiet: convertEntry
// re-emits an observation only when the fingerprint changed, so an unstable hash
// would WARN on every scan for the life of the deployment. The second call is fed
// copies of the same bytes rather than the same slices, so the property is about the
// content and not about one backing array.
//
// Boundary unambiguity is the other half, and it is the one a plausible
// simplification breaks: sha256(certPEM || keyPEM) would satisfy every existing test
// while making a byte moved from the certificate into the key invisible, so the pair
// the operator just broke would read as the one already reported. The property moves
// the last certificate byte to the front of the key -- identical concatenation,
// different split -- rather than re-deriving the hash, so it cannot be satisfied by
// re-implementing the function under test.
func TestPairFingerprint_properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		certPEM := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(rt, "certPEM")
		keyPEM := rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "keyPEM")

		if pairFingerprint(certPEM, keyPEM) != pairFingerprint(append([]byte{}, certPEM...), append([]byte{}, keyPEM...)) {
			rt.Fatalf("pairFingerprint(%q, %q) is not deterministic", certPEM, keyPEM)
		}

		shiftedCert := certPEM[:len(certPEM)-1]
		shiftedKey := append(append([]byte{}, certPEM[len(certPEM)-1:]...), keyPEM...)
		if pairFingerprint(certPEM, keyPEM) == pairFingerprint(shiftedCert, shiftedKey) {
			rt.Fatalf("pairFingerprint(%q, %q) == pairFingerprint(%q, %q): the cert/key boundary is not part of the hash",
				certPEM, keyPEM, shiftedCert, shiftedKey)
		}
	})
}

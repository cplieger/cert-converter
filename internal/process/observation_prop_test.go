package process

import (
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"pgregory.net/rapid"
)

// TestObservationSignature_properties pins the two properties observationSignature's
// godoc promises, neither of which any other test can fail on.
//
// Determinism is what keeps the one-shot input diagnostic quiet: observationLog.note
// re-emits a pair's observations only when the signature changed, so an unstable
// signature would WARN on every fsnotify event and every fallback tick for the life of
// the deployment.
//
// Boundary unambiguity is the half a plausible simplification breaks: appending the
// raw Kind and Detail bytes instead of hashing each separately satisfies every existing
// test while making a character moved from the kind into the detail invisible, so a
// newly introduced observation reads as the one already reported and the operator is
// never told. Detail is certificate-derived text, so the colliding pair is reachable
// from a crafted input. The property moves the last kind byte to the front of the
// detail -- identical concatenation, different split -- rather than re-deriving the
// signature, so it cannot be satisfied by re-implementing the function under test.
func TestObservationSignature_properties(t *testing.T) {
	t.Parallel()
	kinds := []string{
		string(convert.ObsLeafNotFirst),
		string(convert.ObsMultipleKeys),
		string(convert.ObsIdentityExpired),
		string(convert.ObsChainUnverified),
		string(convert.ObsDuplicateCerts),
	}
	rapid.Check(t, func(rt *rapid.T) {
		input := [32]byte(rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(rt, "input"))
		kind := rapid.SampledFrom(kinds).Draw(rt, "kind")
		detail := rapid.String().Draw(rt, "detail")
		obs := []convert.Observation{{Kind: convert.ObservationKind(kind), Detail: detail}}

		same := []convert.Observation{{Kind: convert.ObservationKind(kind), Detail: detail}}
		if observationSignature(input, obs) != observationSignature(input, same) {
			rt.Fatalf("observationSignature(%q, %q) is not deterministic", kind, detail)
		}

		shifted := []convert.Observation{{
			Kind:   convert.ObservationKind(kind[:len(kind)-1]),
			Detail: kind[len(kind)-1:] + detail,
		}}
		if observationSignature(input, obs) == observationSignature(input, shifted) {
			rt.Fatalf("observationSignature(%q|%q) == observationSignature(%q|%q): the kind/detail boundary is not part of the signature",
				kind, detail, shifted[0].Kind, shifted[0].Detail)
		}
	})
}

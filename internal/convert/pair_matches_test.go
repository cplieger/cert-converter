package convert_test

import (
	"crypto/x509"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestDecodedMatchesAnalysis_leaf_guard pins the guard that decides whether an
// existing .pfx is still current. It is the gate in front of every other
// comparison, so getting it wrong is expensive in both directions: a false MATCH
// leaves a stale bundle on disk after a renewal (the app silently stops doing its
// job), and a false MISMATCH rewrites a correct bundle on every scan, churning its
// mtime and re-replicating it downstream forever.
//
// Lives here rather than in main's test file — this is
// the decoded bundle's own contract. It is reached through export_test.go, like
// parseCertChain: the comparison is a step of convert.CheckCurrency and is not
// exported, so no production caller can compare a bundle without the preflight
// having run first.
func TestDecodedMatchesAnalysis_leaf_guard(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "leaf.example.com", "ecdsa")
	analysis, err := convert.Analyse(t.Context(), certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, otherKeyPEM := testcerts.GenerateSelfSignedCert(t, "other.example.com", "ecdsa")
	other, err := convert.Analyse(t.Context(), otherPEM, otherKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		decoded convert.Decoded
		want    bool
	}{
		"the same leaf and key match": {
			convert.Decoded{Leaf: analysis.Leaf(), Key: analysis.Key(), CACerts: analysis.Chain()}, true,
		},
		"a different leaf does not match": {
			convert.Decoded{Leaf: other.Leaf(), Key: other.Key(), CACerts: other.Chain()}, false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := convert.MatchesAnalysis(tt.decoded, analysis); got != tt.want {
				t.Errorf("MatchesAnalysis = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDecode_round_trips_an_encoded_bundle_into_a_currency_match pins the pair of
// operations the scan's "is the file on disk still right?" decision rests on:
// Encode's bytes must decode back into a decoded bundle the comparison accepts. If
// the decode dropped the CA bags, or returned them in the wrong order, every scan
// would rewrite a correct bundle forever; the two steps are only meaningful
// together, so they are asserted together.
//
// Both are reached through export_test.go now that convert.CheckCurrency is the
// only exported door; their combined behaviour through that door is asserted in
// currency_test.go, while this test keeps the step-level coverage.
//
// The failure paths are asserted too, because they are the caller's cue to treat
// the output as stale: a rotated password and a truncated file must both be
// reported as errors rather than as an empty-but-successful decode.
func TestDecode_round_trips_an_encoded_bundle_into_a_currency_match(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	decoded, err := convert.Decode(pfx, "pw")
	if err != nil {
		t.Fatalf("Decode(a bundle Encode just produced) = error %v, want nil", err)
	}
	if len(decoded.CACerts) != len(analysis.Chain()) {
		t.Fatalf("Decode returned %d CA cert(s), want %d: the chain must survive the round trip",
			len(decoded.CACerts), len(analysis.Chain()))
	}
	if !convert.MatchesAnalysis(decoded, analysis) {
		t.Error("MatchesAnalysis(the bundle just written from this analysis) = false, want true: a correct bundle would be rewritten on every scan")
	}

	if _, err := convert.Decode(pfx, "rotated"); err == nil {
		t.Error("Decode(bundle, wrong password) = nil error, want a decode failure so the caller rewrites the output")
	}
	if _, err := convert.Decode(pfx[:len(pfx)/2], "pw"); err == nil {
		t.Error("Decode(truncated bundle) = nil error, want a decode failure")
	}
}

// TestDecodedMatchesAnalysis_rejects_a_bundle_whose_chain_or_key_differs pins the
// comparisons past the leaf guard. They are what makes a renewed INTERMEDIATE, a
// corrected chain or a replaced cross-sign trigger a rewrite: with only the leaf
// compared, a bundle whose chain no longer matches its inputs would be reported as
// current and left on disk indefinitely.
func TestDecodedMatchesAnalysis_rejects_a_bundle_whose_chain_or_key_differs(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	if len(analysis.Chain()) != 1 {
		t.Fatalf("setup: analysis chain length = %d, want 1", len(analysis.Chain()))
	}
	strangerPEM, strangerKeyPEM := testcerts.GenerateSelfSignedCert(t, "stranger.example.com", "ecdsa")
	stranger, err := convert.Analyse(t.Context(), strangerPEM, strangerKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse(stranger): %v", err)
	}

	tests := map[string]convert.Decoded{
		"a missing CA certificate": {
			Leaf: analysis.Leaf(), Key: analysis.Key(), CACerts: nil,
		},
		"an extra CA certificate": {
			Leaf: analysis.Leaf(), Key: analysis.Key(),
			CACerts: []*x509.Certificate{analysis.Chain()[0], stranger.Leaf()},
		},
		"a different CA certificate": {
			Leaf: analysis.Leaf(), Key: analysis.Key(),
			CACerts: []*x509.Certificate{stranger.Leaf()},
		},
		"a different private key": {
			Leaf: analysis.Leaf(), Key: stranger.Key(), CACerts: analysis.Chain(),
		},
		"no private key at all": {
			Leaf: analysis.Leaf(), Key: nil, CACerts: analysis.Chain(),
		},
	}

	for name, decoded := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if convert.MatchesAnalysis(decoded, analysis) {
				t.Errorf("MatchesAnalysis(%s) = true, want false: the bundle on disk is not the one these inputs produce", name)
			}
		})
	}
}

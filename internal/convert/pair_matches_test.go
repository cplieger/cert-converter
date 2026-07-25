package convert_test

import (
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
// The nil cases are not defensive padding: a decode that yielded no leaf, or an
// analysis that produced none, must report "not current" rather than dereference.
//
// Lives here rather than in main's test file (deferred finding l-f13) — this is
// convert.Decoded's contract.
func TestDecodedMatchesAnalysis_leaf_guard(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "leaf.example.com", "ecdsa")
	analysis, err := convert.Analyse(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, otherKeyPEM := testcerts.GenerateSelfSignedCert(t, "other.example.com", "ecdsa")
	other, err := convert.Analyse(otherPEM, otherKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		decoded convert.Decoded
		want    bool
	}{
		"the same leaf and key match": {
			convert.Decoded{Leaf: analysis.Leaf, Key: analysis.Key, CACerts: analysis.Chain}, true,
		},
		"a different leaf does not match": {
			convert.Decoded{Leaf: other.Leaf, Key: other.Key, CACerts: other.Chain}, false,
		},
		"a decoded bundle with no leaf does not match": {
			convert.Decoded{Leaf: nil, Key: analysis.Key}, false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tt.decoded.MatchesAnalysis(&analysis); got != tt.want {
				t.Errorf("MatchesAnalysis = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDecodedMatchesAnalysis_nil_analysis_leaf pins the other half of the same
// guard: an analysis that produced no leaf must report "not current" rather than
// panic. Separate from the table above because it varies the ANALYSIS, not the
// decoded bundle.
func TestDecodedMatchesAnalysis_nil_analysis_leaf(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "leaf.example.com", "ecdsa")
	analysis, err := convert.Analyse(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	decoded := convert.Decoded{Leaf: analysis.Leaf, Key: analysis.Key, CACerts: analysis.Chain}

	if decoded.MatchesAnalysis(&convert.Analysis{}) {
		t.Error("MatchesAnalysis(empty analysis) = true, want false")
	}
}

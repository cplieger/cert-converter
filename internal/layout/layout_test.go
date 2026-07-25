package layout_test

import (
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/layout"
	"pgregory.net/rapid"
)

// TestNamingContract exercises the contract as a whole rather than each function
// separately: for one input name it asserts every predicate and every derived
// name together. A per-function test can pass while the set is inconsistent (a
// name IsCert says yes to but KeyFor derives nonsense from), and that
// inconsistency is the defect this package exists to prevent.
func TestNamingContract(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		input      string
		isCert     bool
		isRelevant bool
		wantKey    string
		wantOutput string
	}{
		{
			name:       "flat certificate",
			input:      "example.com.crt",
			isCert:     true,
			isRelevant: true,
			wantKey:    "example.com.key",
			wantOutput: "example.com.pfx",
		},
		{
			name:       "certificate in a domain directory keeps its prefix",
			input:      "example.com/cert.crt",
			isCert:     true,
			isRelevant: true,
			wantKey:    "example.com/cert.key",
			wantOutput: "example.com/cert.pfx",
		},
		{
			name:       "nested directories are preserved, not flattened",
			input:      "a/b/c/leaf.crt",
			isCert:     true,
			isRelevant: true,
			wantKey:    "a/b/c/leaf.key",
			wantOutput: "a/b/c/leaf.pfx",
		},
		{
			name:       "private key is relevant but is not a conversion trigger",
			input:      "example.com.key",
			isCert:     false,
			isRelevant: true,
			wantKey:    "example.com.key.key",
			wantOutput: "example.com.key.pfx",
		},
		{
			name:       "an unrelated file is neither",
			input:      "README.md",
			isCert:     false,
			isRelevant: false,
			wantKey:    "README.md.key",
			wantOutput: "README.md.pfx",
		},
		{
			name:       "an already-converted bundle is not an input",
			input:      "example.com.pfx",
			isCert:     false,
			isRelevant: false,
			wantKey:    "example.com.pfx.key",
			wantOutput: "example.com.pfx.pfx",
		},
		{
			name:       "the extension alone is treated as a certificate named empty",
			input:      ".crt",
			isCert:     true,
			isRelevant: true,
			wantKey:    ".key",
			wantOutput: ".pfx",
		},
		{
			name:       "a name merely containing the extension is not a certificate",
			input:      "cert.crt.bak",
			isCert:     false,
			isRelevant: false,
			wantKey:    "cert.crt.bak.key",
			wantOutput: "cert.crt.bak.pfx",
		},
		{
			name:       "extension matching is case sensitive",
			input:      "example.com.CRT",
			isCert:     false,
			isRelevant: false,
			wantKey:    "example.com.CRT.key",
			wantOutput: "example.com.CRT.pfx",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := layout.IsCert(tc.input); got != tc.isCert {
				t.Errorf("IsCert(%q) = %v, want %v", tc.input, got, tc.isCert)
			}
			if got := layout.IsRelevant(tc.input); got != tc.isRelevant {
				t.Errorf("IsRelevant(%q) = %v, want %v", tc.input, got, tc.isRelevant)
			}
			if got := layout.KeyFor(tc.input); got != tc.wantKey {
				t.Errorf("KeyFor(%q) = %q, want %q", tc.input, got, tc.wantKey)
			}
			if got := layout.OutputFor(tc.input); got != tc.wantOutput {
				t.Errorf("OutputFor(%q) = %q, want %q", tc.input, got, tc.wantOutput)
			}
		})
	}
}

// TestCertImpliesRelevant pins the containment the two predicates must satisfy:
// every certificate is relevant. watch gates rescans on IsRelevant while process
// gates conversion on IsCert, so a certificate that were relevant-false would be
// converted by a full scan yet never trigger one.
func TestCertImpliesRelevant(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		name := rapid.String().Draw(t, "name")
		if layout.IsCert(name) && !layout.IsRelevant(name) {
			t.Fatalf("IsCert(%q) is true but IsRelevant is false", name)
		}
	})
}

// TestDerivedNamesShareOneStem is the property the whole package exists for: for
// any certificate name, the key and the output are the same path with different
// extensions. A future change that derived one of them differently — resolving
// the output against a separate root, say — would break this.
func TestDerivedNamesShareOneStem(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		stem := rapid.String().Draw(t, "stem")
		certPath := stem + layout.CertExt

		if !layout.IsCert(certPath) {
			t.Fatalf("IsCert(%q) is false for a name built with CertExt", certPath)
		}

		gotKey := layout.KeyFor(certPath)
		gotOutput := layout.OutputFor(certPath)

		if want := stem + layout.KeyExt; gotKey != want {
			t.Errorf("KeyFor(%q) = %q, want %q", certPath, gotKey, want)
		}
		if want := stem + layout.PFXExt; gotOutput != want {
			t.Errorf("OutputFor(%q) = %q, want %q", certPath, gotOutput, want)
		}

		// Both siblings must be reachable from the same stem, which is what lets
		// a scan pair them without a second lookup rule.
		if strings.TrimSuffix(gotKey, layout.KeyExt) != strings.TrimSuffix(gotOutput, layout.PFXExt) {
			t.Errorf("KeyFor(%q) and OutputFor(%q) do not share a stem: %q vs %q",
				certPath, certPath, gotKey, gotOutput)
		}

		// The key half of a pair must itself be relevant, or a key-only write
		// during a rotation would not trigger the rescan that converts the pair.
		if !layout.IsRelevant(gotKey) {
			t.Errorf("IsRelevant(%q) is false for a derived key name", gotKey)
		}
	})
}

package layout_test

import (
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/layout"
	"pgregory.net/rapid"
)

// TestNamingPredicates pins the two classification predicates on concrete names.
// It asserts only what the predicates promise, for any input at all: they are the
// package's only functions whose contract admits arbitrary file names, because
// they are what a scan applies to every entry it finds.
func TestNamingPredicates(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		input      string
		isCert     bool
		isRelevant bool
	}{
		{"flat certificate", "example.com.crt", true, true},
		{"certificate in a domain directory", "example.com/cert.crt", true, true},
		{"private key is relevant but is not a conversion trigger", "example.com.key", false, true},
		{"an unrelated file is neither", "README.md", false, false},
		{"an already-converted bundle is not an input", "example.com.pfx", false, false},
		{"the extension alone is treated as a certificate named empty", ".crt", true, true},
		{"a name merely containing the extension is not a certificate", "cert.crt.bak", false, false},
		{"extension matching is case sensitive", "example.com.CRT", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := layout.IsCert(tc.input); got != tc.isCert {
				t.Errorf("IsCert(%q) = %v, want %v", tc.input, got, tc.isCert)
			}
			if got := layout.IsRelevant(tc.input); got != tc.isRelevant {
				t.Errorf("IsRelevant(%q) = %v, want %v", tc.input, got, tc.isRelevant)
			}
		})
	}
}

// TestCertificateDerivedNames pins both derived names together on inputs that
// satisfy the documented precondition of KeyFor and OutputFor: the argument must
// be a certificate name. Asserting the two together is the point — a per-function
// test can pass while the pair is inconsistent, and that inconsistency is the
// defect this package exists to prevent.
//
// Non-certificate inputs are deliberately absent. Both functions document IsCert
// as their precondition, so today's TrimSuffix behaviour on a README or a .pfx is
// unspecified; pinning it would fail a future implementation that enforced the
// precondition instead, without any production behaviour having changed.
func TestCertificateDerivedNames(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		input      string
		wantKey    string
		wantOutput string
	}{
		{"flat certificate", "example.com.crt", "example.com.key", "example.com.pfx"},
		{"certificate in a domain directory keeps its prefix", "example.com/cert.crt", "example.com/cert.key", "example.com/cert.pfx"},
		{"nested directories are preserved, not flattened", "a/b/c/leaf.crt", "a/b/c/leaf.key", "a/b/c/leaf.pfx"},
		{"the extension alone", ".crt", ".key", ".pfx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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
		// The generator must be able to REACH a certificate name: a plain
		// rapid.String() ends in ".crt" with vanishing probability, which leaves the
		// implication vacuously true and lets an IsRelevant that no longer consults
		// IsCert pass every run. The suffixes are the naming contract's own
		// spellings, written out here because they are layout's implementation
		// detail rather than part of its exported surface.
		name := rapid.String().Draw(t, "stem") +
			rapid.SampledFrom([]string{".crt", ".key", ".pfx", "", ".bak"}).Draw(t, "suffix")
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
		certPath := stem + ".crt"

		if !layout.IsCert(certPath) {
			t.Fatalf("IsCert(%q) is false for a name built with the certificate extension", certPath)
		}

		gotKey := layout.KeyFor(certPath)
		gotOutput := layout.OutputFor(certPath)

		if want := stem + ".key"; gotKey != want {
			t.Errorf("KeyFor(%q) = %q, want %q", certPath, gotKey, want)
		}
		if want := stem + ".pfx"; gotOutput != want {
			t.Errorf("OutputFor(%q) = %q, want %q", certPath, gotOutput, want)
		}

		// Both siblings must be reachable from the same stem, which is what lets
		// a scan pair them without a second lookup rule.
		if strings.TrimSuffix(gotKey, ".key") != strings.TrimSuffix(gotOutput, ".pfx") {
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

// TestOutputAndCertNamesAreInverses pins the forward and reverse halves of the
// naming contract against each other. The output tree's reconciliation asks
// CertForOutput which certificate would have produced a bundle and reaps the
// bundle when that certificate is absent, so a drift between the two rules — one
// gaining a directory prefix, an extension changing on one side only — makes a
// LIVE bundle read as an orphan and be deleted.
func TestOutputAndCertNamesAreInverses(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		stem := rapid.String().Draw(t, "stem")
		certPath := stem + ".crt"

		out := layout.OutputFor(certPath)
		if !layout.IsOutput(out) {
			t.Fatalf("IsOutput(%q) is false for a name OutputFor produced", out)
		}
		if got := layout.CertForOutput(out); got != certPath {
			t.Errorf("CertForOutput(OutputFor(%q)) = %q, want the original certificate path", certPath, got)
		}
	})
}

// TestIsOutput pins the output predicate on concrete paths, including the
// negatives the reconciliation walk depends on: an input certificate, its key and
// a differently-cased extension are NOT bundles, so the walk must not consider
// them reapable output.
func TestIsOutput(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		want  bool
	}{
		{"a flat bundle", "example.com.pfx", true},
		{"a nested bundle keeps its prefix", "example.com/cert.pfx", true},
		{"the extension alone", ".pfx", true},
		{"an input certificate is not an output", "example.com.crt", false},
		{"a private key is not an output", "example.com.key", false},
		{"extension matching is case sensitive", "example.com.PFX", false},
		{"a name merely containing the extension", "bundle.pfx.bak", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := layout.IsOutput(tc.input); got != tc.want {
				t.Errorf("IsOutput(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestCertForOutput pins the reverse mapping on inputs that satisfy its
// documented precondition — IsOutput must hold — because that is the only case
// the reconciliation walk ever asks about: it calls CertForOutput on names it has
// already classified as bundles.
func TestCertForOutput(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"a flat bundle", "example.com.pfx", "example.com.crt"},
		{"a nested bundle keeps its prefix", "example.com/cert.pfx", "example.com/cert.crt"},
		{"deeply nested is preserved, not flattened", "a/b/c/leaf.pfx", "a/b/c/leaf.crt"},
		{"the extension alone", ".pfx", ".crt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := layout.CertForOutput(tc.input); got != tc.want {
				t.Errorf("CertForOutput(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

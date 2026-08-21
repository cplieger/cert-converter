package convert_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestInspect_identifies_every_profile_we_emit is the load-bearing test for
// encoder-profile currency: each of the four profiles must be recognised from the
// bytes alone, because decoding cannot reveal which one wrote a bundle and a
// PFX_ENCODER change would otherwise rewrite nothing.
//
// Both fields are needed and this proves it: modern2023 and modern2026 differ only
// in their MAC, while legacydes and legacyrc2 share a SHA-1 MAC and differ only in
// their encryption. Either field alone leaves two profiles indistinguishable.
//
// The preflight is reached through export_test.go: it is the first step of
// convert.CheckCurrency and is not exported, because running it after a decode
// would bound nothing.
func TestInspect_identifies_every_profile_we_emit(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}

	for _, want := range []convert.EncoderType{
		convert.EncNameModern2023,
		convert.EncNameModern2026,
		convert.EncNameLegacyDES,
		convert.EncNameLegacyRC2,
	} {
		t.Run(string(want), func(t *testing.T) {
			t.Parallel()
			pfx, err := analysis.Encode(want, "pw")
			if err != nil {
				t.Fatalf("Encode(%s) = %v, want nil", want, err)
			}
			got, err := convert.Inspect(pfx)
			if err != nil {
				t.Fatalf("Inspect(a %s bundle) = error %v, want nil", want, err)
			}
			if got != want {
				t.Errorf("Inspect identified %q, want %q", got, want)
			}
		})
	}
}

// TestInspect_refuses_a_bundle_with_appended_bytes pins inspect's outermost refusal
// (unmarshalExact over "the bundle"): a valid bundle with anything appended must be
// rejected, because accepting it would identify a profile from a PREFIX while
// go-pkcs12 then decodes the whole file.
//
// FuzzInspect_boundedProfile seeds this exact mutation but cannot catch its
// regression: with the refusal gone the bundle is ACCEPTED as one of the four known
// profiles, which satisfies that target's invariants -- the same limitation
// TestInspect_rejects_malformed_sequence_framing records for the inner case.
func TestInspect_refuses_a_bundle_with_appended_bytes(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	good, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	got, err := convert.Inspect(append(bytes.Clone(good), 0xff, 0xff))
	if err == nil {
		t.Fatalf("Inspect(a valid bundle plus two appended bytes) = %q with nil error, want a rejection", got)
	}
	if !errors.Is(err, convert.ErrProfileUnknown) {
		t.Fatalf("Inspect(bundle + trailing bytes) = %v, want ErrProfileUnknown", err)
	}
	if want := "trailing byte(s) after the bundle"; !strings.Contains(err.Error(), want) {
		t.Errorf("Inspect(bundle + trailing bytes) = %v, want the refusal to name %q", err, want)
	}
}

// TestInputAndBundleBounds_are_the_documented_sizes pins the two acceptance ceilings
// against literals rather than against each other. Every other assertion in this repo
// compares against the constants themselves — internal/process derives its prior-bundle
// bound from MaxBundleBytes, and the codec's own comments size their costs from
// MaxInputBytes — so an arithmetic slip in either declaration moves every check that
// reads it and only the README's published "10 MB cap" becomes wrong. The same reason
// internal/scancadence pins its reconciliation floor to a literal.
func TestInputAndBundleBounds_are_the_documented_sizes(t *testing.T) {
	t.Parallel()
	if convert.MaxInputBytes != 10485760 {
		t.Errorf("MaxInputBytes = %d, want 10485760 (10 MiB): README.md's Security section publishes a 10 MB cap on every input read",
			convert.MaxInputBytes)
	}
	// Two input files plus PKCS#12 envelope headroom: the largest prior bundle the app
	// admits to the codec, and the bound internal/process reads a prior output under.
	if convert.MaxBundleBytes != 21037056 {
		t.Errorf("MaxBundleBytes = %d, want 21037056 (two 10 MiB inputs plus 64 KiB): a bundle bound below the input it can be built from rejects output this app wrote itself",
			convert.MaxBundleBytes)
	}
}

package convert_test

import (
	"bytes"
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
			pfx, err := convert.Encode(analysis, want, "pw")
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

// TestInspect_rejects_what_we_would_not_have_written pins the failure paths. Every
// one of them means the same thing to the caller — this is not a bundle we wrote, so
// replace it — which is what makes a parse failure safe rather than fatal.
func TestInspect_rejects_what_we_would_not_have_written(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	good, err := convert.Encode(analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	for _, tc := range []struct {
		name string
		pfx  []byte
	}{
		{"empty input", nil},
		{"not DER at all", []byte("this is not a pkcs12 bundle")},
		{"truncated bundle", good[:len(good)/2]},
		{"trailing garbage after a valid bundle", append(bytes.Clone(good), 0xff, 0xff)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := convert.Inspect(tc.pfx); err == nil {
				t.Error("Inspect = nil error, want a rejection")
			}
		})
	}
}

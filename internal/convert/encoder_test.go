package convert_test

import (
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
)

// TestEncoderName pins both halves of the normalization contract: the name a
// raw PFX_ENCODER value resolves to AND the known flag that decides whether the
// caller warns. internal/config owns the warning, so the flag itself is only
// asserted here; without it a spelling that silently stopped being recognized
// would still return the right default name and go unnoticed.
//
// Which pkcs12.Encoder each name selects is deliberately NOT asserted by pointer
// identity here: that is an implementation detail an equivalent encoder value would
// fail while emitting the same algorithms. The behaviour is pinned end-to-end by
// TestInspect_identifies_every_profile_we_emit (Encode then Inspect, all four
// profiles) and TestCheckCurrency_resolves_an_unknown_encoder_name_the_way_Encode_does
// (the unknown-name fallback).
func TestEncoderName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw       string
		wantName  convert.EncoderType
		wantKnown bool
	}{
		{"", convert.EncNameModern2023, true},
		{"modern", convert.EncNameModern2023, true},
		{"modern2023", convert.EncNameModern2023, true},
		{"MODERN2023", convert.EncNameModern2023, true},
		{"  modern2023\t", convert.EncNameModern2023, true},
		{"modern2026", convert.EncNameModern2026, true},
		{"Modern2026", convert.EncNameModern2026, true},
		{"legacy", convert.EncNameLegacyDES, true},
		{"legacydes", convert.EncNameLegacyDES, true},
		{"LegacyDES", convert.EncNameLegacyDES, true},
		{"legacyrc2", convert.EncNameLegacyRC2, true},
		{"LEGACYRC2", convert.EncNameLegacyRC2, true},
		{"   ", convert.EncNameModern2023, true},
		{"modern2029", convert.EncNameModern2023, false},
		{"legcy", convert.EncNameModern2023, false},
		{"legacy des", convert.EncNameModern2023, false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			name, known := convert.EncoderName(tc.raw)
			if name != tc.wantName {
				t.Errorf("convert.EncoderName(%q) name = %q, want %q", tc.raw, name, tc.wantName)
			}
			if known != tc.wantKnown {
				t.Errorf("convert.EncoderName(%q) known = %v, want %v", tc.raw, known, tc.wantKnown)
			}
		})
	}
}

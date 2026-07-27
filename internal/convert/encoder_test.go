package convert_test

import (
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"software.sslmate.com/src/go-pkcs12"
)

func TestEncoderFor(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		in   convert.EncoderType
		want *pkcs12.Encoder
	}{
		"modern2023":                             {convert.EncNameModern2023, pkcs12.Modern2023},
		"modern2026":                             {convert.EncNameModern2026, pkcs12.Modern2026},
		"legacydes":                              {convert.EncNameLegacyDES, pkcs12.LegacyDES},
		"legacyrc2":                              {convert.EncNameLegacyRC2, pkcs12.LegacyRC2},
		"unknown name falls back to modern2023":  {convert.EncoderType("modern2029"), pkcs12.Modern2023},
		"empty name falls back to modern2023":    {convert.EncoderType(""), pkcs12.Modern2023},
		"raw env alias is not a normalized name": {convert.EncoderType("legacy"), pkcs12.Modern2023},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := convert.EncoderFor(tc.in)
			if got == nil {
				t.Fatalf("convert.EncoderFor(%q) = nil, want a non-nil encoder", tc.in)
			}
			if got != tc.want {
				t.Errorf("convert.EncoderFor(%q) = %p, want %p", tc.in, got, tc.want)
			}
		})
	}
}

// TestEncoderName pins both halves of the normalization contract: the name a
// raw PFX_ENCODER value resolves to AND the known flag that decides whether the
// caller warns. internal/config owns the warning, so the flag itself is only
// asserted here; without it a spelling that silently stopped being recognized
// would still return the right default name and go unnoticed.
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

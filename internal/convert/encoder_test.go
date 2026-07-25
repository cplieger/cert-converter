package convert_test

import (
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"pgregory.net/rapid"
	"software.sslmate.com/src/go-pkcs12"
)

func TestPickEncoder(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		env         string
		wantName    convert.EncoderType
		wantEncoder *pkcs12.Encoder
	}{
		{"", convert.EncNameModern2023, pkcs12.Modern2023},
		{"modern2023", convert.EncNameModern2023, pkcs12.Modern2023},
		{"Modern", convert.EncNameModern2023, pkcs12.Modern2023},
		{"modern2026", convert.EncNameModern2026, pkcs12.Modern2026},
		{"Modern2026", convert.EncNameModern2026, pkcs12.Modern2026},
		{"legacy", convert.EncNameLegacyDES, pkcs12.LegacyDES},
		{"legacyrc2", convert.EncNameLegacyRC2, pkcs12.LegacyRC2},
		{"LegacyDES", convert.EncNameLegacyDES, pkcs12.LegacyDES},
		{"unknown", convert.EncNameModern2023, pkcs12.Modern2023},
	} {
		t.Run(tc.env, func(t *testing.T) {
			enc, name := convert.PickEncoder(tc.env)
			if name != tc.wantName {
				t.Errorf("PickEncoder(%q) name = %q, want %q", tc.env, name, tc.wantName)
			}
			if enc != tc.wantEncoder {
				t.Errorf("PickEncoder(%q) encoder = %p, want %p", tc.env, enc, tc.wantEncoder)
			}
		})
	}
}

func TestPickEncoder_trims_surrounding_whitespace(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		wantName convert.EncoderType
	}{
		{"padded legacy", "  legacy  ", convert.EncNameLegacyDES},
		{"padded modern2026", "  modern2026  ", convert.EncNameModern2026},
		{"padded legacyrc2", " legacyrc2 ", convert.EncNameLegacyRC2},
		{"whitespace only is default", "  ", convert.EncNameModern2023},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc, name := convert.PickEncoder(tc.raw)
			if enc == nil {
				t.Fatalf("PickEncoder(%q) returned nil encoder", tc.raw)
			}
			if name != tc.wantName {
				t.Errorf("PickEncoder(%q) name = %q, want %q", tc.raw, name, tc.wantName)
			}
		})
	}
}

func TestPickEncoder_never_returns_nil(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.String().Draw(t, "env_value")
		enc, name := convert.PickEncoder(v)
		if enc == nil {
			t.Errorf("PickEncoder(%q) returned nil encoder", v)
		}
		if name == "" {
			t.Errorf("PickEncoder(%q) returned empty name", v)
		}
		switch name {
		case convert.EncNameModern2023, convert.EncNameModern2026,
			convert.EncNameLegacyDES, convert.EncNameLegacyRC2:
		default:
			t.Errorf("PickEncoder(%q) returned unknown name %q", v, name)
		}
	})
}

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

// TestEncoderFor_unknown_names_fall_back_to_modern2023 generalises the table:
// for an arbitrary name, EncoderFor must return one of the four vendor encoders
// and exactly pkcs12.Modern2023 for anything outside the known set, so a caller
// can never hand a nil encoder to pkcs12.Encode.
func TestEncoderFor_unknown_names_fall_back_to_modern2023(t *testing.T) {
	t.Parallel()
	known := map[convert.EncoderType]*pkcs12.Encoder{
		convert.EncNameModern2023: pkcs12.Modern2023,
		convert.EncNameModern2026: pkcs12.Modern2026,
		convert.EncNameLegacyDES:  pkcs12.LegacyDES,
		convert.EncNameLegacyRC2:  pkcs12.LegacyRC2,
	}
	rapid.Check(t, func(t *rapid.T) {
		name := convert.EncoderType(rapid.String().Draw(t, "name"))
		got := convert.EncoderFor(name)
		if got == nil {
			t.Fatalf("convert.EncoderFor(%q) = nil; the documented contract is that it never returns nil", name)
		}
		want, isKnown := known[name]
		if !isKnown {
			want = pkcs12.Modern2023
		}
		if got != want {
			t.Errorf("convert.EncoderFor(%q) = %p, want %p", name, got, want)
		}
	})
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

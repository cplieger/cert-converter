package convert_test

import (
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"pgregory.net/rapid"
)

func TestPickEncoder(t *testing.T) {
	for _, tc := range []struct {
		env      string
		wantName convert.EncoderType
	}{
		{"", convert.EncNameModern2023},
		{"modern2023", convert.EncNameModern2023},
		{"Modern", convert.EncNameModern2023},
		{"modern2026", convert.EncNameModern2026},
		{"Modern2026", convert.EncNameModern2026},
		{"legacy", convert.EncNameLegacyDES},
		{"legacyrc2", convert.EncNameLegacyRC2},
		{"LegacyDES", convert.EncNameLegacyDES},
		{"unknown", convert.EncNameModern2023},
	} {
		t.Run(tc.env, func(t *testing.T) {
			enc, name := convert.PickEncoder(tc.env)
			if enc == nil {
				t.Fatal("PickEncoder returned nil encoder")
			}
			if name != tc.wantName {
				t.Errorf("PickEncoder name = %q, want %q", name, tc.wantName)
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

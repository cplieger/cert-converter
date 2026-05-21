package config

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestPickEncoder(t *testing.T) {
	for _, tc := range []struct {
		env      string
		wantName EncoderType
	}{
		{"", EncNameModern2023},
		{"modern2023", EncNameModern2023},
		{"Modern", EncNameModern2023},
		{"modern2026", EncNameModern2026},
		{"Modern2026", EncNameModern2026},
		{"legacy", EncNameLegacyDES},
		{"legacyrc2", EncNameLegacyRC2},
		{"LegacyDES", EncNameLegacyDES},
		{"unknown", EncNameModern2023},
	} {
		t.Run(tc.env, func(t *testing.T) {
			enc, name := PickEncoder(tc.env)
			if enc == nil {
				t.Fatal("PickEncoder returned nil encoder")
			}
			if name != tc.wantName {
				t.Errorf("PickEncoder name = %q, want %q", name, tc.wantName)
			}
		})
	}
}

func TestParseFallbackInterval(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  string
		want time.Duration
	}{
		{"empty", "", 0},
		{"zero", "0", 0},
		{"false", "false", 0},
		{"FALSE", "FALSE", 0},
		{"valid", "12", 12 * time.Hour},
		{"one", "1", 1 * time.Hour},
		{"negative", "-1", 6 * time.Hour},
		{"non-numeric", "abc", 6 * time.Hour},
		{"leading spaces", "  12", 12 * time.Hour},
		{"trailing spaces", "12  ", 12 * time.Hour},
		{"padded zero", " 0 ", 0},
		{"padded false", " false ", 0},
		{"padded empty", "   ", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseFallbackInterval(tc.val); got != tc.want {
				t.Errorf("ParseFallbackInterval(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestParseFallbackInterval_never_panics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.String().Draw(t, "env_value")
		got := ParseFallbackInterval(v)
		if got < 0 {
			t.Errorf("ParseFallbackInterval(%q) = %v, want non-negative", v, got)
		}
	})
}

func TestPickEncoder_never_returns_nil(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.String().Draw(t, "env_value")
		enc, name := PickEncoder(v)
		if enc == nil {
			t.Errorf("PickEncoder(%q) returned nil encoder", v)
		}
		if name == "" {
			t.Errorf("PickEncoder(%q) returned empty name", v)
		}
		switch name {
		case EncNameModern2023, EncNameModern2026, EncNameLegacyDES, EncNameLegacyRC2:
		default:
			t.Errorf("PickEncoder(%q) returned unknown name %q", v, name)
		}
	})
}

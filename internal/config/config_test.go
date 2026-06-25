package config

import (
	"errors"
	"os"
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
			enc, name := pickEncoder(tc.env)
			if enc == nil {
				t.Fatal("pickEncoder returned nil encoder")
			}
			if name != tc.wantName {
				t.Errorf("pickEncoder name = %q, want %q", name, tc.wantName)
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
		{"empty uses default", "", 6 * time.Hour},
		{"zero", "0", 0},
		{"false", "false", 0},
		{"FALSE", "FALSE", 0},
		{"valid", "12", 12 * time.Hour},
		{"one", "1", 1 * time.Hour},
		{"negative", "-1", 6 * time.Hour},
		// Non-canonical zeros reach the numeric branch (the "0" switch case
		// only matches the literal string "0"), so they exercise the n > 0
		// boundary: Atoi yields 0, which must NOT be treated as a positive
		// interval. Pins n > 0 against the n >= 0 mutant.
		{"non-canonical zero", "00", 6 * time.Hour},
		{"signed zero", "+0", 6 * time.Hour},
		{"non-numeric", "abc", 6 * time.Hour},
		{"leading spaces", "  12", 12 * time.Hour},
		{"trailing spaces", "12  ", 12 * time.Hour},
		{"padded zero", " 0 ", 0},
		{"padded false", " false ", 0},
		{"padded empty uses default", "   ", 6 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseFallbackInterval(tc.val); got != tc.want {
				t.Errorf("parseFallbackInterval(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestParseFallbackInterval_clamps_excessive_values(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  string
		want time.Duration
	}{
		// 87600h (10 years) is the clamp ceiling: at the ceiling the value
		// passes through unchanged; above it the value is clamped down to it.
		{"at ceiling unclamped", "87600", 87600 * time.Hour},
		{"one above ceiling clamped", "87601", 87600 * time.Hour},
		{"far above ceiling clamped", "1000000", 87600 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseFallbackInterval(tc.val); got != tc.want {
				t.Errorf("parseFallbackInterval(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestParseFallbackInterval_never_panics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.String().Draw(t, "env_value")
		got := parseFallbackInterval(v)
		if got < 0 {
			t.Errorf("parseFallbackInterval(%q) = %v, want non-negative", v, got)
		}
	})
}

func TestPickEncoder_never_returns_nil(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.String().Draw(t, "env_value")
		enc, name := pickEncoder(v)
		if enc == nil {
			t.Errorf("pickEncoder(%q) returned nil encoder", v)
		}
		if name == "" {
			t.Errorf("pickEncoder(%q) returned empty name", v)
		}
		switch name {
		case EncNameModern2023, EncNameModern2026, EncNameLegacyDES, EncNameLegacyRC2:
		default:
			t.Errorf("pickEncoder(%q) returned unknown name %q", v, name)
		}
	})
}

func TestLoad_unset_fallback_uses_six_hour_default(t *testing.T) {
	t.Setenv("PFX_PASSWORD", "s3cret")
	t.Setenv("FALLBACK_SCAN_HOURS", "placeholder")
	os.Unsetenv("FALLBACK_SCAN_HOURS")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.FallbackInterval != 6*time.Hour {
		t.Errorf("Load() FallbackInterval = %v, want %v", cfg.FallbackInterval, 6*time.Hour)
	}
}

func TestLoad_explicit_fallback_overrides_default(t *testing.T) {
	t.Setenv("PFX_PASSWORD", "s3cret")
	t.Setenv("FALLBACK_SCAN_HOURS", "12")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.FallbackInterval != 12*time.Hour {
		t.Errorf("Load() FallbackInterval = %v, want %v", cfg.FallbackInterval, 12*time.Hour)
	}
}

func TestLoad_empty_fallback_uses_default(t *testing.T) {
	t.Setenv("PFX_PASSWORD", "s3cret")
	t.Setenv("FALLBACK_SCAN_HOURS", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// A set-but-empty value must use the default, NOT silently disable the
	// safety-net rescan. Only an explicit "0"/"false" disables it.
	if cfg.FallbackInterval != 6*time.Hour {
		t.Errorf("Load() FallbackInterval = %v, want %v (empty must use default)", cfg.FallbackInterval, 6*time.Hour)
	}
}

func TestLoad_explicit_zero_disables_polling(t *testing.T) {
	t.Setenv("PFX_PASSWORD", "s3cret")
	t.Setenv("FALLBACK_SCAN_HOURS", "0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.FallbackInterval != 0 {
		t.Errorf("Load() FallbackInterval = %v, want 0 (explicit 0 disables)", cfg.FallbackInterval)
	}
}

func TestLoad_reads_password_and_encoder(t *testing.T) {
	t.Setenv("PFX_PASSWORD", "s3cret")
	t.Setenv("PFX_ENCODER", "legacy")
	t.Setenv("FALLBACK_SCAN_HOURS", "0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Password != "s3cret" {
		t.Errorf("Load() Password = %q, want %q", cfg.Password, "s3cret")
	}
	if cfg.EncoderName != EncNameLegacyDES {
		t.Errorf("Load() EncoderName = %q, want %q", cfg.EncoderName, EncNameLegacyDES)
	}
}

func TestLoad_empty_password_returns_error(t *testing.T) {
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")
	if _, err := Load(); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("Load() error = %v, want ErrEmptyPassword", err)
	}
}

func TestLoad_empty_password_allowed_by_optout(t *testing.T) {
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Password != "" {
		t.Errorf("Load() Password = %q, want empty", cfg.Password)
	}
}

func TestPickEncoder_trims_surrounding_whitespace(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		wantName EncoderType
	}{
		{"padded legacy", "  legacy  ", EncNameLegacyDES},
		{"padded modern2026", "  modern2026  ", EncNameModern2026},
		{"padded legacyrc2", " legacyrc2 ", EncNameLegacyRC2},
		{"whitespace only is default", "  ", EncNameModern2023},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc, name := pickEncoder(tc.raw)
			if enc == nil {
				t.Fatalf("pickEncoder(%q) returned nil encoder", tc.raw)
			}
			if name != tc.wantName {
				t.Errorf("pickEncoder(%q) name = %q, want %q", tc.raw, name, tc.wantName)
			}
		})
	}
}

func TestLoad_empty_password_optout_requires_literal_true(t *testing.T) {
	for _, tc := range []struct {
		name      string
		optout    string
		wantAllow bool
	}{
		{"lowercase true allows", "true", true},
		{"uppercase TRUE allows", "TRUE", true},
		{"mixed-case True allows", "True", true},
		{"padded true allows", "  true  ", true},
		{"padded uppercase allows", " TRUE ", true},
		{"1 does not allow", "1", false},
		{"yes does not allow", "yes", false},
		{"on does not allow", "on", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PFX_PASSWORD", "")
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", tc.optout)

			_, err := Load()

			if tc.wantAllow && err != nil {
				t.Errorf("Load() with PFX_ALLOW_EMPTY_PASSWORD=%q got err %v, want nil (trimmed, case-insensitive true opts out)", tc.optout, err)
			}
			if !tc.wantAllow && !errors.Is(err, ErrEmptyPassword) {
				t.Errorf("Load() with PFX_ALLOW_EMPTY_PASSWORD=%q got err %v, want ErrEmptyPassword (only literal true opts out)", tc.optout, err)
			}
		})
	}
}

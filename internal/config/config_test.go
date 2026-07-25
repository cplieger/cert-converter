package config

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"pgregory.net/rapid"
)

func TestLoad_empty_password_optout_warns_only_on_unrecognized_values(t *testing.T) {
	// slog.Default is process-global: this test swaps it, so it must not run
	// in parallel with anything that logs.
	for _, tc := range []struct {
		name     string
		optout   string
		wantWarn bool
	}{
		{"explicit false is silent", "false", false},
		{"uppercase FALSE is silent", "FALSE", false},
		{"padded false is silent", "  false  ", false},
		{"unset is silent", "", false},
		{"true is silent", "true", false},
		{"1 warns", "1", true},
		{"yes warns", "yes", true},
		{"on warns", "on", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", tc.optout)

			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			warned := strings.Contains(buf.String(), "unrecognized PFX_ALLOW_EMPTY_PASSWORD")
			if warned != tc.wantWarn {
				t.Errorf("Load() with PFX_ALLOW_EMPTY_PASSWORD=%q warned = %v, want %v (log: %q)",
					tc.optout, warned, tc.wantWarn, buf.String())
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
		// interval. Pins the n > 0 guard: a parsed zero falls through to the
		// default, never accepted as a (disabling) zero interval.
		{"non-canonical zero", "00", 6 * time.Hour},
		{"signed zero", "+0", 6 * time.Hour},
		{"non-numeric", "abc", 6 * time.Hour},
		// strconv reports ErrRange (not ErrSyntax) once the digit prefix
		// overflows, even when junk follows, so a malformed value must stay
		// malformed instead of being mistaken for an above-ceiling number.
		{"overflowing prefix with junk", "999999999999999999999999999999x", 6 * time.Hour},
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
		// Beyond int64: a valid decimal that overflows is still a positive
		// above-ceiling value, so it clamps rather than falling through to the
		// 6h default. An optional leading "+" is still a valid decimal.
		{"beyond int64 clamped", "999999999999999999999999999999", 87600 * time.Hour},
		{"signed beyond int64 clamped", "+999999999999999999999999999999", 87600 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseFallbackInterval(tc.val); got != tc.want {
				t.Errorf("parseFallbackInterval(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestParseFallbackInterval_permitted_cadence_and_padding_invariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// A plain rapid.String() generator almost never produces the values that
		// decide this parser ("0", "false", a numeric string), so the interesting
		// inputs are drawn explicitly alongside arbitrary text.
		v := rapid.OneOf(
			rapid.SampledFrom([]string{"", " ", "0", "00", "+0", "false", "FALSE", "-1", "1", "6", "12", "87600", "87601"}),
			rapid.StringMatching(`[ \t]*[-+]?[0-9]{0,7}[ \t]*`),
			rapid.String(),
		).Draw(t, "env_value")
		got := parseFallbackInterval(v)

		// Surrounding whitespace is trimmed, so padding can never change the
		// decision: a padded "0" still disables, a padded number still parses,
		// and a padded blank still takes the default.
		if padded := parseFallbackInterval(" \t" + v + "\n "); padded != got {
			t.Errorf("parseFallbackInterval(%q) = %v but padded variant = %v, want padding-invariant", v, got, padded)
		}

		// Every accepted value is either "disabled", the default, or a whole
		// number of hours no greater than the 10-year overflow ceiling.
		switch {
		case got == 0 || got == defaultFallbackInterval:
		case got > 0 && got <= 87600*time.Hour && got%time.Hour == 0:
		default:
			t.Errorf("parseFallbackInterval(%q) = %v, want 0, %v, or whole hours in (0, 87600h]", v, got, defaultFallbackInterval)
		}
	})
}

// isolatePasswordFile clears PFX_PASSWORD_FILE so an ambient value inherited
// from the host cannot take precedence over the PFX_PASSWORD the test sets:
// envx.Secret prefers the <KEY>_FILE indirection whenever it is non-empty.
func isolatePasswordFile(t *testing.T) {
	t.Helper()
	t.Setenv("PFX_PASSWORD_FILE", "")
}

func TestLoad_unset_fallback_uses_six_hour_default(t *testing.T) {
	isolatePasswordFile(t)
	t.Setenv("PFX_PASSWORD", "s3cret")
	// t.Setenv first so its registered Cleanup restores whatever the host had,
	// then Unsetenv to reach the genuinely-unset case: t.Setenv cannot express
	// "absent", and a bare os.Unsetenv would leak into every later test.
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
	isolatePasswordFile(t)
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
	isolatePasswordFile(t)
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
	isolatePasswordFile(t)
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
	isolatePasswordFile(t)
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
	if cfg.EncoderName != convert.EncNameLegacyDES {
		t.Errorf("Load() EncoderName = %q, want %q", cfg.EncoderName, convert.EncNameLegacyDES)
	}
}

func TestLoad_empty_password_returns_error(t *testing.T) {
	isolatePasswordFile(t)
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")
	if _, err := Load(); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("Load() error = %v, want ErrEmptyPassword", err)
	}
}

func TestLoad_empty_password_allowed_by_optout(t *testing.T) {
	isolatePasswordFile(t)
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

func TestLoad_password_file_takes_precedence_over_env(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pfx-password")
	if err := os.WriteFile(path, []byte("  from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_PASSWORD", "from-env")
	t.Setenv("PFX_PASSWORD_FILE", path)
	t.Setenv("PFX_ENCODER", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with PFX_PASSWORD_FILE = %v, want nil", err)
	}
	if cfg.Password != "from-file" {
		t.Errorf("Load() Password = %q, want %q (file wins over env, whitespace trimmed)",
			cfg.Password, "from-file")
	}
}

func TestLoad_unreadable_password_file_fails_loudly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"missing file", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "absent")
		}},
		{"empty file", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "empty")
			if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		// A readable file the operator could reach by hand: envx still refuses
		// the path, and the refusal must not degrade to PFX_PASSWORD.
		{"uncleaned path with .. is rejected", func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "pfx"), []byte("from-file"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			// Built by concatenation: filepath.Join would clean the ".." away.
			return dir + "/sub/../pfx"
		}},
		{"filename holding two consecutive dots is rejected", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "pfx..v2")
			if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PFX_PASSWORD", "from-env")
			t.Setenv("PFX_PASSWORD_FILE", tc.setup(t))
			// The opt-out must not rescue a broken secret file.
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

			if _, err := Load(); err == nil {
				t.Fatal("Load() = nil error, want a startup failure for an unusable PFX_PASSWORD_FILE")
			} else if errors.Is(err, ErrEmptyPassword) {
				t.Errorf("Load() = %v, want the underlying secret-file error, not ErrEmptyPassword", err)
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
			isolatePasswordFile(t)
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

func TestLogLevel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    string
		want   slog.Level
		wantOK bool
	}{
		{"unset uses info default", "", slog.LevelInfo, true},
		{"debug", "debug", slog.LevelDebug, true},
		{"uppercase INFO", "INFO", slog.LevelInfo, true},
		{"padded warn", "  warn  ", slog.LevelWarn, true},
		{"warning alias", "warning", slog.LevelWarn, true},
		{"error", "error", slog.LevelError, true},
		{"slog offset", "info+2", slog.LevelInfo + 2, true},
		{"unparseable reports not ok and keeps info", "loud", slog.LevelInfo, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LOG_LEVEL", tc.raw)

			lvl, raw, ok := LogLevel()

			if lvl != tc.want || ok != tc.wantOK {
				t.Errorf("LogLevel() with LOG_LEVEL=%q = (%v, %v), want (%v, %v)",
					tc.raw, lvl, ok, tc.want, tc.wantOK)
			}
			if raw != tc.raw {
				t.Errorf("LogLevel() with LOG_LEVEL=%q raw = %q, want %q (reported verbatim for the WARN)",
					tc.raw, raw, tc.raw)
			}
		})
	}
}

func TestLoad_password_file_log_records_source_without_secret_or_path(t *testing.T) {
	const secret = "sup3r-s3cret-pfx-value"
	path := filepath.Join(t.TempDir(), "pfx-password")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_PASSWORD_FILE", path)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with PFX_PASSWORD_FILE = %v, want nil", err)
	}
	if cfg.Password != secret {
		t.Fatalf("Load() Password = %q, want the file's contents", cfg.Password)
	}

	out := buf.String()
	if !strings.Contains(out, "source=PFX_PASSWORD_FILE") {
		t.Errorf("Load() logged %q, want a record naming PFX_PASSWORD_FILE as the secret source", out)
	}
	if strings.Contains(out, secret) {
		t.Errorf("Load() leaked the PFX password into the log: %q", out)
	}
	if strings.Contains(out, path) {
		t.Errorf("Load() leaked the secret-mount path into the log: %q", out)
	}
}

func TestLoad_env_password_logs_no_secret_source(t *testing.T) {
	t.Setenv("PFX_PASSWORD_FILE", "")
	t.Setenv("PFX_PASSWORD", "from-env")

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if _, err := Load(); err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}

	if out := buf.String(); strings.Contains(out, "PFX_PASSWORD_FILE") {
		t.Errorf("Load() logged %q, want no secret-source record when PFX_PASSWORD_FILE is unset", out)
	}
}

func TestLoad_unknown_encoder_warns_and_falls_back_to_modern2023(t *testing.T) {
	// slog.Default is process-global: this test swaps it, so it must not run
	// in parallel with anything that logs.
	for _, tc := range []struct {
		name     string
		raw      string
		wantName convert.EncoderType
		wantWarn bool
	}{
		{"unrecognized value warns and falls back", "modern2029", convert.EncNameModern2023, true},
		{"typo in a known name warns", "legcy", convert.EncNameModern2023, true},
		{"unset is silent and defaults", "", convert.EncNameModern2023, false},
		{"recognized alias is silent", "modern", convert.EncNameModern2023, false},
		{"recognized legacy is silent", "legacy", convert.EncNameLegacyDES, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("PFX_ENCODER", tc.raw)

			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() with PFX_ENCODER=%q = %v, want nil (an unknown value must not fail startup)", tc.raw, err)
			}
			if cfg.EncoderName != tc.wantName {
				t.Errorf("Load() with PFX_ENCODER=%q EncoderName = %q, want %q", tc.raw, cfg.EncoderName, tc.wantName)
			}
			warned := strings.Contains(buf.String(), "unknown PFX_ENCODER")
			if warned != tc.wantWarn {
				t.Errorf("Load() with PFX_ENCODER=%q warned = %v, want %v (log: %q)", tc.raw, warned, tc.wantWarn, buf.String())
			}
			if tc.wantWarn && !strings.Contains(buf.String(), tc.raw) {
				t.Errorf("Load() with PFX_ENCODER=%q logged %q, want the rejected value named so an operator can spot the typo", tc.raw, buf.String())
			}
		})
	}
}

// TestWarnUnencodablePassword_reports_the_unrepresentable_shape pins both
// diagnostic branches of the startup warning: the shape must be named with its
// remediation, and the secret value must never reach the log. slog.Default is
// process-global, so this test must not run in parallel.
func TestWarnUnencodablePassword_reports_the_unrepresentable_shape(t *testing.T) {
	for _, tc := range []struct {
		name            string
		password        string
		wantMessage     string
		wantRemediation string
		secretNeedle    string
	}{
		{
			name:            "invalid UTF-8",
			password:        string([]byte{0xff}) + "sentinel-secret",
			wantMessage:     "not valid UTF-8",
			wantRemediation: "supply a text secret",
			secretNeedle:    "sentinel-secret",
		},
		{
			name:            "non-BMP character",
			password:        "password-\U0001F600",
			wantMessage:     "outside the Basic Multilingual Plane",
			wantRemediation: "use a PFX password made only of BMP characters",
			secretNeedle:    "password-\U0001F600",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			warnUnencodablePassword(tc.password)

			out := buf.String()
			if !strings.Contains(out, tc.wantMessage) || !strings.Contains(out, tc.wantRemediation) {
				t.Errorf("warnUnencodablePassword(%q) logged %q, want message %q and remediation %q",
					tc.password, out, tc.wantMessage, tc.wantRemediation)
			}
			if strings.Contains(out, tc.secretNeedle) {
				t.Errorf("warnUnencodablePassword(%q) leaked the password in %q", tc.password, out)
			}
		})
	}
}

// TestWarnUnencodablePassword_invalid_utf8_wins_over_non_bmp pins the branch
// precedence the pre-refactor early return provided: a password that is both
// invalid UTF-8 and carries a non-BMP rune reports only the UTF-8 shape.
// slog.Default is process-global, so this test must not run in parallel.
func TestWarnUnencodablePassword_invalid_utf8_wins_over_non_bmp(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	warnUnencodablePassword(string([]byte{0xff}) + "pw-\U0001F600")

	out := buf.String()
	if !strings.Contains(out, "not valid UTF-8") {
		t.Errorf("warnUnencodablePassword logged %q, want the invalid-UTF-8 diagnostic", out)
	}
	if strings.Contains(out, "Basic Multilingual Plane") {
		t.Errorf("warnUnencodablePassword logged %q, want only the invalid-UTF-8 diagnostic", out)
	}
}

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
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/slogx/capture"
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

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			warned := logs.CountLevel(slog.LevelWarn, "unrecognized PFX_ALLOW_EMPTY_PASSWORD") > 0
			if warned != tc.wantWarn {
				t.Errorf("Load() with PFX_ALLOW_EMPTY_PASSWORD=%q warned = %v, want %v (log: %v)",
					tc.optout, warned, tc.wantWarn, logs.Messages())
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

// TestParseFallbackInterval_warns_when_input_is_repaired pins the two repair
// diagnostics: an invalid value and an above-ceiling value are both silently
// repaired, so the WARN naming the rejected value is the operator's only way to
// tell an intended cadence from a default or a clamp.
func TestParseFallbackInterval_warns_when_input_is_repaired(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		want    time.Duration
		message string
	}{
		{"invalid value uses default", "abc", 6 * time.Hour, "invalid FALLBACK_SCAN_HOURS, using default"},
		{"excessive value is clamped", "87601", 87600 * time.Hour, "FALLBACK_SCAN_HOURS too large, clamping"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			if got := parseFallbackInterval(tc.raw); got != tc.want {
				t.Errorf("parseFallbackInterval(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			if n := logs.CountLevel(slog.LevelWarn, tc.message); n != 1 {
				t.Errorf("parseFallbackInterval(%q) logged %d WARN records matching %q, want 1 (logs %v)",
					tc.raw, n, tc.message, logs.Messages())
			}
			if !logs.AttrContains(tc.message, "value", tc.raw) {
				t.Errorf("parseFallbackInterval(%q) WARN does not name the rejected value (logs %v)", tc.raw, logs.Messages())
			}
		})
	}
}

// isolatePasswordFile clears PFX_PASSWORD_FILE so an ambient value inherited
// from the host cannot take precedence over the PFX_PASSWORD the test sets:
// envx.Secret prefers the <KEY>_FILE indirection whenever it is non-empty.
func isolatePasswordFile(t *testing.T) {
	t.Helper()
	t.Setenv("PFX_PASSWORD_FILE", "")
}

// TestLoad_warns_when_the_fallback_rescan_is_disabled pins the startup WARN for
// the FALLBACK_SCAN_HOURS opt-out, the only configuration in which the app
// cannot notice that it has stopped working: no periodic re-scan, no
// health-marker freshness deadline, and a watch dropped by an unmount that
// fsnotify never reports. The warning is the whole detector, so its firing rule
// matters as much as its text.
//
// It must fire ONLY for the explicit opt-out. An empty, whitespace-only, or
// invalid value falls back to the 6h default, which is supervised and must stay
// silent: warning there would train an operator to ignore the line that matters.
// The interval is asserted alongside the warning so the two cannot drift apart.
// slog.Default is process-global, so this test must not run in parallel with
// anything that logs.
func TestLoad_warns_when_the_fallback_rescan_is_disabled(t *testing.T) {
	// Matches only the opt-out WARN: the repair diagnostics read "invalid
	// FALLBACK_SCAN_HOURS, ..." and "FALLBACK_SCAN_HOURS too large, ...".
	const optOutWarn = "FALLBACK_SCAN_HOURS is 0/false"

	for _, tc := range []struct {
		name         string
		raw          string
		wantInterval time.Duration
		wantWarn     bool
	}{
		{"zero opts out and warns", "0", 0, true},
		{"false opts out and warns", "false", 0, true},
		{"uppercase FALSE opts out and warns", "FALSE", 0, true},
		{"padded zero opts out and warns", " 0 ", 0, true},
		{"unset default is silent", "", 6 * time.Hour, false},
		{"whitespace-only value is silent", "   ", 6 * time.Hour, false},
		{"invalid value is silent", "abc", 6 * time.Hour, false},
		{"non-canonical zero is silent", "00", 6 * time.Hour, false},
		{"explicit interval is silent", "12", 12 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("FALLBACK_SCAN_HOURS", tc.raw)

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if cfg.FallbackInterval != tc.wantInterval {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q FallbackInterval = %v, want %v",
					tc.raw, cfg.FallbackInterval, tc.wantInterval)
			}

			warnings := logs.CountLevel(slog.LevelWarn, optOutWarn)
			if (warnings > 0) != tc.wantWarn {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q logged %d WARN records matching %q, want warn = %v (logs %v)",
					tc.raw, warnings, optOutWarn, tc.wantWarn, logs.Messages())
			}
			if !tc.wantWarn {
				return
			}
			if warnings != 1 {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q logged %d opt-out WARN records, want exactly 1 (logs %v)",
					tc.raw, warnings, logs.Messages())
			}
			// The three losses an operator has to weigh, plus the way back.
			for _, want := range []string{"no periodic re-scan", "freshness deadline", "reporting healthy"} {
				if !logs.Contains(want) {
					t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q WARN does not name %q (logs %v)",
						tc.raw, want, logs.Messages())
				}
			}
			if !logs.AttrContains(optOutWarn, "remediation", "FALLBACK_SCAN_HOURS") {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q WARN carries no remediation naming the variable (logs %v)",
					tc.raw, logs.Messages())
			}
		})
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

// TestClassifyPassword pins the blank-password predicate directly in
// its owning package, covering every classification without going through
// Load's guards (TestLoad_password_status_agrees_with_its_warning covers the
// same statuses end to end). No t.Parallel: every test in this file mutates
// process state (env / slog default) and the file is deliberately serial.
func TestClassifyPassword(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		want     PasswordStatus
	}{
		{"empty is empty", "", PasswordEmpty},
		{"single space is whitespace-only", " ", PasswordWhitespaceOnly},
		{"tab newline and space are whitespace-only", "\t\n ", PasswordWhitespaceOnly},
		// unicode.IsSpace covers U+00A0, so a non-breaking space pasted from a
		// document is whitespace-only, not a real password.
		{"non-breaking space is whitespace-only", "\u00a0", PasswordWhitespaceOnly},
		{"real value is configured", "s3cret", PasswordConfigured},
		{"padded real value is configured", "  s3cret  ", PasswordConfigured},
		{"single printable char is configured", "x", PasswordConfigured},
		// TrimSpace does not trim NUL, so a binary secret is a real password.
		{"NUL byte is configured", "\x00", PasswordConfigured},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyPassword(tc.password); got != tc.want {
				t.Errorf("classifyPassword(%q) = %q, want %q", tc.password, got, tc.want)
			}
		})
	}
}

// TestLoad_password_status_agrees_with_its_warning pins the startup
// password-status decision where it now lives: the Config.PasswordStatus main
// reports and the WARN branch must agree, and a real password must produce no
// password-quality warning (the value is a secret, so nothing about it is
// logged beyond the non-secret status). Load emits other startup records --
// including the padded-value whitespace WARN -- so the assertion is scoped to
// the "PFX_PASSWORD is ..." family rather than to total silence. Moved here
// from main_test.go with Load as the entry point, so the warning and the status
// stay pinned in the package that owns both. No t.Parallel: it mutates env and
// slog.Default.
func TestLoad_password_status_agrees_with_its_warning(t *testing.T) {
	for _, tc := range []struct {
		name        string
		password    string
		wantStatus  PasswordStatus
		wantWarnSub string
	}{
		{"empty reports empty", "", PasswordEmpty, "PFX_PASSWORD is empty"},
		{"single space is whitespace-only", " ", PasswordWhitespaceOnly, "PFX_PASSWORD is whitespace-only"},
		{"tab and newline are whitespace-only", "\t\n ", PasswordWhitespaceOnly, "PFX_PASSWORD is whitespace-only"},
		{"real value is configured", "s3cret", PasswordConfigured, ""},
		{"padded value is configured", "  s3cret  ", PasswordConfigured, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", tc.password)
			// A blank password only reaches the warning with the opt-out set;
			// without it Load refuses to start (ErrEmptyPassword).
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			if cfg.PasswordStatus != tc.wantStatus {
				t.Errorf("Load() with PFX_PASSWORD=%q status = %q, want %q", tc.password, cfg.PasswordStatus, tc.wantStatus)
			}
			if tc.wantWarnSub == "" {
				if logs.Contains("PFX_PASSWORD is ") {
					t.Errorf("Load() with PFX_PASSWORD=%q logged %v, want no password warning for a real password",
						tc.password, logs.Messages())
				}
				return
			}
			if n := logs.CountLevel(slog.LevelWarn, tc.wantWarnSub); n != 1 {
				t.Errorf("Load() with PFX_PASSWORD=%q logged %d WARN records matching %q, want 1 (logs %v)",
					tc.password, n, tc.wantWarnSub, logs.Messages())
			}
			if !logs.AttrContains(tc.wantWarnSub, "remediation", "PFX_PASSWORD") {
				t.Errorf("Load() with PFX_PASSWORD=%q WARN is missing an actionable remediation attr (logs %v)",
					tc.password, logs.Messages())
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
	const (
		secret       = "sentinel-env-pfx-password"
		secretSource = "PFX_PASSWORD_FILE"
	)
	t.Setenv(secretSource, "")
	t.Setenv("PFX_PASSWORD", secret)
	t.Setenv("PFX_ENCODER", "")

	logs := capture.Default(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if cfg.Password != secret {
		t.Fatalf("Load() Password = %q, want the configured environment value", cfg.Password)
	}

	if n := logs.Count("PFX password configured"); n != 0 {
		t.Errorf("Load() logged %v, want no secret-source record when PFX_PASSWORD_FILE is unset", logs.Messages())
	}
	// The pre-capture form scanned the whole rendered line, so it also caught the
	// env var leaking as an ATTR (key or value) under ANY message, not just the
	// one that happens to carry it today; Count sees messages only. Walk every
	// captured record end to end to keep that strictly stronger guard, and check
	// the password VALUE alongside the channel name: the sibling
	// PFX_PASSWORD_FILE test guards its secret value, and a future diagnostic
	// that logged the env-sourced password would otherwise keep this test green.
	for _, r := range logs.Records() {
		if strings.Contains(r.Message, secret) {
			t.Errorf("Load() leaked the environment-sourced PFX password in message %q", r.Message)
		}
		if strings.Contains(r.Message, secretSource) {
			t.Errorf("Load() logged message %q, want no %s record when the file channel is unused", r.Message, secretSource)
		}
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Key, secret) || strings.Contains(a.Value.String(), secret) {
				t.Errorf("Load() leaked the environment-sourced PFX password in attr %s=%v on %q", a.Key, a.Value, r.Message)
			}
			if strings.Contains(a.Key, secretSource) || strings.Contains(a.Value.String(), secretSource) {
				t.Errorf("Load() logged attr %s=%v on %q, want no %s record when the file channel is unused",
					a.Key, a.Value, r.Message, secretSource)
			}
			return true
		})
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

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() with PFX_ENCODER=%q = %v, want nil (an unknown value must not fail startup)", tc.raw, err)
			}
			if cfg.EncoderName != tc.wantName {
				t.Errorf("Load() with PFX_ENCODER=%q EncoderName = %q, want %q", tc.raw, cfg.EncoderName, tc.wantName)
			}
			warned := logs.CountLevel(slog.LevelWarn, "unknown PFX_ENCODER") > 0
			if warned != tc.wantWarn {
				t.Errorf("Load() with PFX_ENCODER=%q warned = %v, want %v (log: %v)", tc.raw, warned, tc.wantWarn, logs.Messages())
			}
			if tc.wantWarn && !logs.AttrContains("unknown PFX_ENCODER", "value", tc.raw) {
				t.Errorf("Load() with PFX_ENCODER=%q logged %v, want the rejected value named so an operator can spot the typo", tc.raw, logs.Messages())
			}
		})
	}
}

// TestCheckPasswordEncodable_refuses_every_unrepresentable_shape pins a DELIBERATE
// reversal: all three shapes are now a startup REFUSAL rather than a warning that let
// the container start.
//
// Each must be rejected, must name its shape and remediation so an operator can act,
// and must never put the secret value in the error — the error text reaches the startup
// log, which every aggregator retains.
func TestCheckPasswordEncodable_refuses_every_unrepresentable_shape(t *testing.T) {
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
			wantRemediation: "use a password made only of BMP characters",
			secretNeedle:    "password-\U0001F600",
		},
		{
			name:            "embedded NUL",
			password:        "sentinel-secret\x00",
			wantMessage:     "contains a NUL byte",
			wantRemediation: "strip NUL bytes from the secret file",
			secretNeedle:    "sentinel-secret",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkPasswordEncodable(tc.password)
			if !errors.Is(err, ErrUnencodablePassword) {
				t.Fatalf("checkPasswordEncodable(%q) = %v, want ErrUnencodablePassword: the container must refuse to start", tc.password, err)
			}
			got := err.Error()
			if !strings.Contains(got, tc.wantMessage) || !strings.Contains(got, tc.wantRemediation) {
				t.Errorf("checkPasswordEncodable(%q) = %q, want shape %q and remediation %q",
					tc.password, got, tc.wantMessage, tc.wantRemediation)
			}
			if strings.Contains(got, tc.secretNeedle) {
				t.Errorf("checkPasswordEncodable(%q) leaked the password in %q", tc.password, got)
			}
		})
	}
}

// TestCheckPasswordEncodable_invalid_utf8_wins_over_non_bmp pins the branch precedence:
// a password that is both invalid UTF-8 and carries a non-BMP rune reports only the
// UTF-8 shape, so the operator gets one actionable reason rather than two.
func TestCheckPasswordEncodable_invalid_utf8_wins_over_non_bmp(t *testing.T) {
	t.Parallel()
	err := checkPasswordEncodable(string([]byte{0xff}) + "pw-\U0001F600")
	if err == nil {
		t.Fatal("checkPasswordEncodable = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Errorf("checkPasswordEncodable = %v, want the invalid-UTF-8 reason", err)
	}
	if strings.Contains(err.Error(), "Basic Multilingual Plane") {
		t.Errorf("checkPasswordEncodable = %v, want only the invalid-UTF-8 reason", err)
	}
}

// TestCheckPasswordEncodable_accepts_a_usable_password pins that the gate does not
// reject what PKCS#12 can carry: an ordinary ASCII password, a BMP non-ASCII one, and
// the empty password (whose acceptability is the PFX_ALLOW_EMPTY_PASSWORD opt-out's
// business, not this gate's).
func TestCheckPasswordEncodable_accepts_a_usable_password(t *testing.T) {
	t.Parallel()
	for _, pw := range []string{"", "hunter2", "pässwörd-Ünicode", "日本語パスワード"} {
		if err := checkPasswordEncodable(pw); err != nil {
			t.Errorf("checkPasswordEncodable(%q) = %v, want nil", pw, err)
		}
	}
}

// TestLoad_rejects_a_whitespace_only_password pins the other half of the unification:
// the blank guard now trims, so PFX_PASSWORD=" " — a quoting
// slip in a compose file or .env — is REFUSED where it previously started and embedded a
// single space into every generated bundle as the only protection on the private key.
//
// The opt-out still works, and it now means the same thing for a blank value as for an
// absent one.
func TestLoad_rejects_a_whitespace_only_password(t *testing.T) {
	for _, tc := range []struct {
		name, password, allowEmpty string
		wantErr                    bool
	}{
		{"a single space is blank", " ", "", true},
		{"tabs and newlines are blank", "\t\n ", "", true},
		{"exactly empty is blank", "", "", true},
		{"the opt-out accepts a blank value", " ", "true", false},
		{"a real password is accepted", "hunter2", "", false},
		{"a password with inner spaces is not blank", "two words", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PFX_PASSWORD", tc.password)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", tc.allowEmpty)
			t.Setenv("PFX_PASSWORD_FILE", "")

			_, err := Load()
			if tc.wantErr {
				if !errors.Is(err, ErrEmptyPassword) {
					t.Errorf("Load(PFX_PASSWORD=%q) = %v, want ErrEmptyPassword", tc.password, err)
				}
				return
			}
			if err != nil {
				t.Errorf("Load(PFX_PASSWORD=%q, allow=%q) = %v, want nil", tc.password, tc.allowEmpty, err)
			}
		})
	}
}

// TestLoad_refuses_an_unencodable_password pins that the encoding gate is reached from
// Load, not just callable in isolation: the container must not start.
func TestLoad_refuses_an_unencodable_password(t *testing.T) {
	t.Setenv("PFX_PASSWORD", "pw-\U0001F600")
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")
	t.Setenv("PFX_PASSWORD_FILE", "")

	_, err := Load()
	if !errors.Is(err, ErrUnencodablePassword) {
		t.Fatalf("Load(non-BMP password) = %v, want ErrUnencodablePassword", err)
	}
	if !strings.Contains(err.Error(), "supplied via PFX_PASSWORD") {
		t.Errorf("Load(non-BMP env password) = %v, want the refusal to name the channel that supplied the secret", err)
	}
}

// TestLoad_blank_secret_file_obeys_the_same_optout pins the unification:
// PFX_ALLOW_EMPTY_PASSWORD now means ONE thing regardless of how the secret was
// delivered.
//
// Before, the same question had three answers: a blank PFX_PASSWORD was accepted with a
// warning, a blank PFX_PASSWORD_FILE aborted startup inside envx before the opt-out was
// ever consulted, and the opt-out governed only the environment channel. An operator who
// set PFX_ALLOW_EMPTY_PASSWORD=true and mounted an empty secret file got a container that
// refused to start, for the exact configuration they had just asked for.
//
// This is a deliberate behaviour change in BOTH directions: a blank file now starts WITH
// the opt-out where it previously failed, and fails with ErrEmptyPassword WITHOUT it
// where it previously failed with envx's error. An unusable file — unreadable, oversized,
// rejected path — is still never rescued; that is TestLoad_unreadable_password_file_fails_loudly.
func TestLoad_blank_secret_file_obeys_the_same_optout(t *testing.T) {
	blankFile := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "blank")
		if err := os.WriteFile(path, []byte("   \n\t"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("blank file without the opt-out is ErrEmptyPassword", func(t *testing.T) {
		t.Setenv("PFX_PASSWORD", "")
		t.Setenv("PFX_PASSWORD_FILE", blankFile(t))
		t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

		if _, err := Load(); !errors.Is(err, ErrEmptyPassword) {
			t.Errorf("Load(blank file, no opt-out) = %v, want ErrEmptyPassword", err)
		}
	})

	t.Run("blank file with the opt-out starts", func(t *testing.T) {
		t.Setenv("PFX_PASSWORD", "")
		t.Setenv("PFX_PASSWORD_FILE", blankFile(t))
		t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

		logs := capture.Default(t)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load(blank file, opt-out) = %v, want nil: the opt-out must mean the same thing for both channels", err)
		}
		if cfg.Password != "" {
			t.Errorf("Password = %q, want empty: a blank file must never silently fall back to PFX_PASSWORD", cfg.Password)
		}
		// The blank FILE must say so: an INFO "PFX password configured" here
		// reported a secret that was never configured.
		if n := logs.CountLevel(slog.LevelWarn, "PFX_PASSWORD_FILE is blank"); n != 1 {
			t.Errorf("Load(blank file, opt-out) logged %d WARN records naming the blank secret file, want 1 (logs %v)",
				n, logs.Messages())
		}
		if logs.Contains("PFX password configured") {
			t.Errorf("Load(blank file, opt-out) logged the configured-secret INFO for a blank file (logs %v)", logs.Messages())
		}
	})

	t.Run("a blank file never falls back to PFX_PASSWORD", func(t *testing.T) {
		t.Setenv("PFX_PASSWORD", "from-env")
		t.Setenv("PFX_PASSWORD_FILE", blankFile(t))
		t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load = %v, want nil", err)
		}
		if cfg.Password == "from-env" {
			t.Error("a blank secret file fell back to PFX_PASSWORD; the file channel exists to be authoritative")
		}
	})
}

// TestLoad_blank_secret_file_error_names_configured_path pins the startup
// diagnostic: a blank secret file must fail as ErrEmptyPassword AND name the
// configured path, which is the only way an operator can tell which mounted
// secret to repair. Classifying the error alone stays green if Load stops
// wrapping envx's path-bearing ErrBlankSecretFile.
func TestLoad_blank_secret_file_error_names_configured_path(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blank-pfx-password")
	if err := os.WriteFile(path, []byte("  \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_PASSWORD_FILE", path)
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

	_, err := Load()
	if !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Load(blank password file) = %v, want ErrEmptyPassword", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("Load(blank password file) error = %q, want configured path %q", err, path)
	}
}

// TestLoad_warns_when_the_env_password_is_padded pins the whitespace diagnostic:
// envx trims a PFX_PASSWORD_FILE secret but PFX_PASSWORD is used verbatim, so a
// padded env value silently yields a different password than the same secret
// delivered as a file. The WARN is the only signal an operator gets. Serial: it
// swaps slog.Default().
func TestLoad_warns_when_the_env_password_is_padded(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		wantWarn bool
	}{
		{"padded value warns", "  s3cret  ", true},
		{"clean value is quiet", "s3cret", false},
		{"inner spaces are not padding", "two words", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", tc.password)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() with PFX_PASSWORD=%q = %v, want nil", tc.password, err)
			}
			const msg = "PFX_PASSWORD has leading or trailing whitespace"
			if warned := logs.CountLevel(slog.LevelWarn, msg) > 0; warned != tc.wantWarn {
				t.Errorf("Load() with PFX_PASSWORD=%q warned = %v, want %v (logs %v)",
					tc.password, warned, tc.wantWarn, logs.Messages())
			}
		})
	}
}

// TestLoad_warns_when_both_password_channels_are_set pins the ambiguity warning.
// PFX_PASSWORD_FILE wins by design, so a PFX_PASSWORD set
// beside it is silently ignored — an operator who edits the wrong one gets a successful
// startup and bundles carrying the other password, and only finds out when a consumer
// cannot open a .pfx. Runs serially: it swaps slog.Default().
func TestLoad_warns_when_both_password_channels_are_set(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pfx")
	if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, env, file string
		wantWarn        bool
	}{
		{"both set warns", "from-env", path, true},
		{"file only is quiet", "", path, false},
		{"env only is quiet", "from-env", "", false},
		{"whitespace-only env is not a real conflict", "   ", path, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			t.Setenv("PFX_PASSWORD", tc.env)
			t.Setenv("PFX_PASSWORD_FILE", tc.file)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			if _, err := Load(); err != nil {
				t.Fatalf("Load = %v, want nil", err)
			}

			out := buf.String()
			got := strings.Contains(out, "both PFX_PASSWORD and PFX_PASSWORD_FILE are set")
			if got != tc.wantWarn {
				t.Errorf("Load(env=%q file=%q) warned = %v, want %v; log = %q", tc.env, tc.file, got, tc.wantWarn, out)
			}
			if strings.Contains(out, "from-env") || strings.Contains(out, "from-file") {
				t.Errorf("the log leaked a password value: %q", out)
			}
		})
	}
}

// TestLoad_wires_output_lifecycle pins the OUTPUT_LIFECYCLE knob end to end:
// Load must carry the parsed mode into Config.Lifecycle (nothing else reads the
// env var, so a dropped assignment would silently revert every deployment to
// warn and leave orphaned .pfx files behind forever), and an unrecognised value
// must warn while still starting. Serial: it swaps slog.Default().
func TestLoad_wires_output_lifecycle(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		want     outputpolicy.Lifecycle
		wantWarn bool
	}{
		{"unset defaults to warn", "", outputpolicy.LifecycleWarn, false},
		{"explicit warn", "warn", outputpolicy.LifecycleWarn, false},
		{"sync is wired through", "sync", outputpolicy.LifecycleSync, false},
		{"keep is wired through", "keep", outputpolicy.LifecycleKeep, false},
		{"padded mixed case is normalised", "  SyNc  ", outputpolicy.LifecycleSync, false},
		{"unknown value warns and falls back to warn", "delete", outputpolicy.LifecycleWarn, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("OUTPUT_LIFECYCLE", tc.raw)

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() with OUTPUT_LIFECYCLE=%q = %v, want nil (an unknown value must not fail startup)", tc.raw, err)
			}
			if cfg.Lifecycle != tc.want {
				t.Errorf("Load() with OUTPUT_LIFECYCLE=%q Lifecycle = %q, want %q", tc.raw, cfg.Lifecycle, tc.want)
			}
			warned := logs.CountLevel(slog.LevelWarn, "unknown OUTPUT_LIFECYCLE") > 0
			if warned != tc.wantWarn {
				t.Errorf("Load() with OUTPUT_LIFECYCLE=%q warned = %v, want %v (log: %v)", tc.raw, warned, tc.wantWarn, logs.Messages())
			}
			if tc.wantWarn && !logs.AttrContains("unknown OUTPUT_LIFECYCLE", "value", tc.raw) {
				t.Errorf("Load() with OUTPUT_LIFECYCLE=%q logged %v, want the rejected value named so an operator can spot the typo", tc.raw, logs.Messages())
			}
		})
	}
}

// TestLoad_warns_when_the_password_contains_a_control_character pins the
// interior-control-character diagnostic, the one shape both existing guards
// miss: envx trims only surrounding whitespace and PKCS#12 encodes a newline or
// tab verbatim, so the bundle is written, health stays green, and the password
// cannot be typed into the consumers that need it. The clean case is what keeps
// the WARN from firing on every healthy startup. Serial: it swaps slog.Default().
func TestLoad_warns_when_the_password_contains_a_control_character(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		wantWarn bool
	}{
		{"an interior newline warns", "line1\nline2", true},
		{"an interior tab warns", "pw\tsecret", true},
		{"a clean password is silent", "hunter2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", tc.password)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil: a control character is a WARN, not a startup refusal", err)
			}
			const msg = "contains a control character"
			warned := logs.CountLevel(slog.LevelWarn, msg) > 0
			if warned != tc.wantWarn {
				t.Errorf("Load(%s) control-character WARN = %v, want %v (logs %v)", tc.name, warned, tc.wantWarn, logs.Messages())
			}
			if tc.wantWarn && !logs.AttrContains(msg, "source", "env") {
				t.Errorf("control-character WARN does not name the delivery channel (logs %v)", logs.Messages())
			}
		})
	}
}

// TestLoad_unencodable_secret_file_names_the_file_channel pins the half of the
// refusal that actually redirects the operator: when the rejected secret came
// from the mounted file, the error must name PFX_PASSWORD_FILE, because the
// file-wins rule means editing PFX_PASSWORD would change nothing. The secret
// value itself must stay out of the startup log.
func TestLoad_unencodable_secret_file_names_the_file_channel(t *testing.T) {
	const secret = "pw-\U0001F600"
	path := filepath.Join(t.TempDir(), "pfx-password")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_PASSWORD_FILE", path)
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

	_, err := Load()
	if !errors.Is(err, ErrUnencodablePassword) {
		t.Fatalf("Load(unencodable secret file) = %v, want ErrUnencodablePassword", err)
	}
	if !strings.Contains(err.Error(), "supplied via PFX_PASSWORD_FILE") {
		t.Errorf("Load(unencodable secret file) = %v, want it to name PFX_PASSWORD_FILE, not the ignored env variable", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("Load(unencodable secret file) leaked the secret into %q", err.Error())
	}
}

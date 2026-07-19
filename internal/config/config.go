// Package config provides environment-based configuration for cert-converter.
package config

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// EncoderType is a typed string for PFX encoding selection.
type EncoderType string

// Encoder name constants for PFX encoding selection.
const (
	EncNameModern2023 EncoderType = "modern2023"
	EncNameModern2026 EncoderType = "modern2026"
	EncNameLegacyDES  EncoderType = "legacydes"
	EncNameLegacyRC2  EncoderType = "legacyrc2"
)

// envFalseValue is the lexical "disabled" marker for env-var parsers.
const envFalseValue = "false"

// defaultFallbackInterval is the full-rescan cadence used when
// FALLBACK_SCAN_HOURS is unset, empty, or unparseable. Only an explicit "0" or
// "false" disables the fallback rescan.
const defaultFallbackInterval = 6 * time.Hour

// Config holds the runtime configuration for cert-converter.
type Config struct {
	Password         string
	Encoder          *pkcs12.Encoder
	EncoderName      EncoderType
	FallbackInterval time.Duration
}

// ErrEmptyPassword indicates PFX_PASSWORD is empty and the empty-password
// opt-out (PFX_ALLOW_EMPTY_PASSWORD=true) is not set. A PFX generated with an
// empty password protects the embedded private key with no password at all.
var ErrEmptyPassword = errors.New(
	"PFX_PASSWORD is empty; set it or set PFX_ALLOW_EMPTY_PASSWORD=true")

// Load reads environment variables and returns a populated Config. It returns
// ErrEmptyPassword when PFX_PASSWORD is empty unless PFX_ALLOW_EMPTY_PASSWORD
// is set to true.
func Load() (Config, error) {
	password := os.Getenv("PFX_PASSWORD")
	allowEmpty := strings.EqualFold(
		strings.TrimSpace(os.Getenv("PFX_ALLOW_EMPTY_PASSWORD")), "true")
	if password == "" && !allowEmpty {
		return Config{}, ErrEmptyPassword
	}

	enc, encName := pickEncoder(os.Getenv("PFX_ENCODER"))

	return Config{
		Password:         password,
		Encoder:          enc,
		EncoderName:      encName,
		FallbackInterval: FallbackInterval(),
	}, nil
}

// FallbackInterval returns the effective FALLBACK_SCAN_HOURS as a
// duration (0 = fallback rescan disabled), parsed with the same rules
// Load applies. Exported separately so the health subcommand can derive
// its probe max-age from the same source of truth without a full config
// load, which would fail on a missing PFX_PASSWORD the probe does not
// need.
func FallbackInterval() time.Duration {
	if v, ok := os.LookupEnv("FALLBACK_SCAN_HOURS"); ok {
		return parseFallbackInterval(v)
	}
	return defaultFallbackInterval
}

// parseFallbackInterval parses a FALLBACK_SCAN_HOURS value into a re-scan
// cadence. Only an explicit "0" or "false" disables the fallback (returns 0).
// An empty or whitespace-only value — or any unparseable value — yields
// defaultFallbackInterval, matching an unset variable, so a blank
// FALLBACK_SCAN_HOURS never silently disables the safety-net rescan. A value
// above maxFallbackHours is clamped to it.
func parseFallbackInterval(v string) time.Duration {
	// maxFallbackHours keeps time.Duration(n)*time.Hour from overflowing int64;
	// 10y is far beyond any real re-scan cadence.
	const maxFallbackHours = 87600

	trimmed := strings.TrimSpace(v)
	switch strings.ToLower(trimmed) {
	case "0", envFalseValue:
		return 0
	case "":
		return defaultFallbackInterval
	default:
		if n, err := strconv.Atoi(trimmed); err == nil && n > 0 {
			if n > maxFallbackHours {
				slog.Warn("FALLBACK_SCAN_HOURS too large, clamping",
					"value", v, "max_hours", maxFallbackHours)
				n = maxFallbackHours
			}
			return time.Duration(n) * time.Hour
		}
		slog.Warn("invalid FALLBACK_SCAN_HOURS, using default",
			"value", v, "default", defaultFallbackInterval.String())
		return defaultFallbackInterval
	}
}

// pickEncoder returns the PFX encoder and its name based on the raw env value.
func pickEncoder(raw string) (enc *pkcs12.Encoder, name EncoderType) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(EncNameLegacyRC2):
		return pkcs12.LegacyRC2, EncNameLegacyRC2
	case "legacy", string(EncNameLegacyDES):
		return pkcs12.LegacyDES, EncNameLegacyDES
	case string(EncNameModern2026):
		return pkcs12.Modern2026, EncNameModern2026
	case "", "modern", string(EncNameModern2023):
		return pkcs12.Modern2023, EncNameModern2023
	default:
		slog.Warn("unknown PFX_ENCODER, using modern2023", "value", raw)
		return pkcs12.Modern2023, EncNameModern2023
	}
}

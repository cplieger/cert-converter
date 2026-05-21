// Package config provides environment-based configuration for cert-convert.
package config

import (
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

// Config holds the runtime configuration for cert-convert.
type Config struct {
	Password         string
	Encoder          *pkcs12.Encoder
	EncoderName      EncoderType
	FallbackInterval time.Duration
}

// Load reads environment variables and returns a populated Config.
func Load() Config {
	enc, encName := PickEncoder(os.Getenv("PFX_ENCODER"))

	var interval time.Duration
	if v, ok := os.LookupEnv("FALLBACK_SCAN_HOURS"); ok {
		interval = ParseFallbackInterval(v)
	} else {
		interval = 6 * time.Hour
	}

	return Config{
		Password:         os.Getenv("PFX_PASSWORD"),
		Encoder:          enc,
		EncoderName:      encName,
		FallbackInterval: interval,
	}
}

// ParseFallbackInterval parses a FALLBACK_SCAN_HOURS value string.
// Returns 0 to disable polling, or the parsed duration.
// An empty string disables polling (caller should use default when env is unset).
func ParseFallbackInterval(v string) time.Duration {
	trimmed := strings.TrimSpace(v)
	switch strings.ToLower(trimmed) {
	case "", "0", envFalseValue:
		return 0
	default:
		if n, err := strconv.Atoi(trimmed); err == nil && n > 0 {
			return time.Duration(n) * time.Hour
		}
		slog.Warn("invalid FALLBACK_SCAN_HOURS, using default",
			"value", v, "default", "6h")
		return 6 * time.Hour
	}
}

// PickEncoder returns the PFX encoder and its name based on the raw env value.
func PickEncoder(raw string) (enc *pkcs12.Encoder, name EncoderType) {
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

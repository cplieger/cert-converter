// Package config provides environment-based configuration for cert-converter.
package config

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/envx"
)

// envFalseValue is the lexical "disabled" marker for env-var parsers.
const envFalseValue = "false"

// defaultFallbackInterval is the full-rescan cadence used when
// FALLBACK_SCAN_HOURS is unset, empty, or unparseable. Only an explicit "0" or
// "false" disables the fallback rescan.
const defaultFallbackInterval = 6 * time.Hour

// Config holds the runtime configuration for cert-converter. The PFX encoder is
// carried as the app-owned convert.EncoderType name, not as a go-pkcs12 value:
// the vendor type stays confined to internal/convert, which resolves the name
// with EncoderFor inside PairInRoot; main and process only carry the name.
type Config struct {
	Password         string
	EncoderName      convert.EncoderType
	FallbackInterval time.Duration
}

// ErrEmptyPassword indicates PFX_PASSWORD is empty and the empty-password
// opt-out (PFX_ALLOW_EMPTY_PASSWORD=true) is not set. A PFX generated with an
// empty password protects the embedded private key with no password at all.
var ErrEmptyPassword = errors.New(
	"PFX_PASSWORD is empty; set it or set PFX_ALLOW_EMPTY_PASSWORD=true")

// Load reads environment variables and returns a populated Config. The PFX
// password follows the Docker-secrets convention: when PFX_PASSWORD_FILE is
// set the secret is read from that file (bounded, whitespace-trimmed) so it
// never appears in the process environment; otherwise PFX_PASSWORD is used. It
// returns ErrEmptyPassword when neither supplies a value unless
// PFX_ALLOW_EMPTY_PASSWORD is set to true, and it fails loudly when a
// configured PFX_PASSWORD_FILE cannot be read.
func Load() (Config, error) {
	password, secretErr := envx.Secret("PFX_PASSWORD")
	if secretErr != nil {
		var missing *envx.MissingError
		if !errors.As(secretErr, &missing) {
			// An unreadable, oversized, or empty PFX_PASSWORD_FILE must fail
			// loudly rather than silently degrade to an empty password.
			return Config{}, secretErr
		}
		password = "" // fall through to the empty-password guard below
	}
	rawAllowEmpty := strings.TrimSpace(os.Getenv("PFX_ALLOW_EMPTY_PASSWORD"))
	allowEmpty := strings.EqualFold(rawAllowEmpty, "true")
	// Only literal true opts out, but literal false is the documented (and
	// default-safe) disabled spelling: warning on it would fire on every
	// startup of a correctly configured deployment. Warn only on values that
	// are genuinely unrecognized (1/yes/on), which the literal-true contract
	// deliberately rejects.
	explicitFalse := strings.EqualFold(rawAllowEmpty, envFalseValue)
	if rawAllowEmpty != "" && !allowEmpty && !explicitFalse {
		slog.Warn("unrecognized PFX_ALLOW_EMPTY_PASSWORD, treating as false",
			"value", rawAllowEmpty, "expected", "true or false")
	}
	if password == "" && !allowEmpty {
		return Config{}, ErrEmptyPassword
	}

	encName := convert.EncoderName(os.Getenv("PFX_ENCODER"))

	return Config{
		Password:         password,
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
	return parseFallbackInterval(os.Getenv("FALLBACK_SCAN_HOURS"))
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

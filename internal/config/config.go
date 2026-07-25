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
	"github.com/cplieger/slogx"
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
// with encoderFor inside PairInRoot; main and process only carry the name.
type Config struct {
	Password         string
	EncoderName      convert.EncoderType
	FallbackInterval time.Duration
}

// ErrEmptyPassword indicates PFX_PASSWORD is empty and the empty-password
// opt-out (PFX_ALLOW_EMPTY_PASSWORD=true) is not set. A PFX generated with an
// empty password protects the embedded private key with no password at all.
var ErrEmptyPassword = errors.New(
	"PFX_PASSWORD is empty; set it, point PFX_PASSWORD_FILE at a secret file, " +
		"or set PFX_ALLOW_EMPTY_PASSWORD=true")

// PasswordStatus is a non-secret classification of how well PFX_PASSWORD
// protects the private key inside every generated PFX file.
type PasswordStatus string

// The PFX password classifications reported by ClassifyPassword.
const (
	// PasswordEmpty means no password at all was supplied.
	PasswordEmpty PasswordStatus = "empty"
	// PasswordWhitespaceOnly means the password consists only of whitespace,
	// which is effectively no protection.
	PasswordWhitespaceOnly PasswordStatus = "whitespace-only"
	// PasswordConfigured means a real password was supplied.
	PasswordConfigured PasswordStatus = "configured"
)

// ClassifyPassword classifies a PFX password. It is the single home for the
// blank-password predicate: Load's empty-password guard and the caller's
// startup log both derive their decision from it, so the two cannot drift.
func ClassifyPassword(password string) PasswordStatus {
	switch {
	case password == "":
		return PasswordEmpty
	case strings.TrimSpace(password) == "":
		return PasswordWhitespaceOnly
	default:
		return PasswordConfigured
	}
}

// Load reads environment variables and returns a populated Config. The PFX
// password follows the Docker-secrets convention: when PFX_PASSWORD_FILE is
// set the secret is read from that file (bounded, whitespace-trimmed) so it
// never appears in the process environment; otherwise PFX_PASSWORD is used. It
// returns ErrEmptyPassword when neither supplies a value unless
// PFX_ALLOW_EMPTY_PASSWORD is set to true, and it fails loudly when a
// configured PFX_PASSWORD_FILE cannot be used — including a path envx
// rejects (it must already be cleaned and contain no ".." anywhere, so even
// a "pfx..v2" filename is refused), an oversized file, and a file whose
// trimmed content is empty.
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
	allowEmpty := allowEmptyPassword(os.Getenv("PFX_ALLOW_EMPTY_PASSWORD"))
	if ClassifyPassword(password) == PasswordEmpty && !allowEmpty {
		return Config{}, ErrEmptyPassword
	}
	warnUnencodablePassword(password)
	if os.Getenv("PFX_PASSWORD_FILE") != "" {
		// Record the secret's SOURCE (never its value) so an operator can confirm
		// a mounted secret was actually consumed instead of silently falling back
		// to PFX_PASSWORD. The configured path is deliberately omitted from this
		// steady-state line, which every log aggregator retains: it would publish
		// the secret-mount topology on every healthy startup for no diagnostic
		// gain. A startup FAILURE is the deliberate exception — the envx error
		// returned above names the path, and main logs it, because an unusable
		// secret file cannot be diagnosed without it.
		slog.Info("PFX password configured", "source", "PFX_PASSWORD_FILE")
	}

	rawEncoder := os.Getenv("PFX_ENCODER")
	encName, known := convert.EncoderName(rawEncoder)
	if !known {
		slog.Warn("unknown PFX_ENCODER, using modern2023", "value", rawEncoder)
	}

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

// LogLevel returns the effective LOG_LEVEL as a slog level, the raw value as
// configured, and whether it parsed. Exported separately from Load so the
// logger can be installed before Load runs (Load emits WARN lines that must
// honour the configured level), while the LOG_LEVEL name and its info default
// stay in the config layer — the same reason FallbackInterval is exported.
func LogLevel() (lvl slog.Level, raw string, ok bool) {
	raw = os.Getenv("LOG_LEVEL")
	lvl, ok = slogx.ParseLevel(raw, slog.LevelInfo)
	return lvl, raw, ok
}

// allowEmptyPassword reports whether PFX_ALLOW_EMPTY_PASSWORD opts out of the
// empty-password guard. Only a literal "true" (trimmed, case-insensitive) opts
// out. Literal "false" is the documented, default-safe spelling and is accepted
// silently — warning on it would fire on every startup of a correctly
// configured deployment — while any other non-empty value warns and is treated
// as false, because the literal-true contract deliberately rejects 1/yes/on.
func allowEmptyPassword(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if strings.EqualFold(trimmed, "true") {
		return true
	}
	if trimmed != "" && !strings.EqualFold(trimmed, envFalseValue) {
		slog.Warn("unrecognized PFX_ALLOW_EMPTY_PASSWORD, treating as false",
			"value", trimmed, "expected", "true or false")
	}
	return false
}

// warnUnencodablePassword warns when the PFX password cannot survive the
// PKCS#12 BMPString (UCS-2) encoding go-pkcs12 applies to it. Three shapes are
// diagnosed, and none is rejected here because the value is the operator's
// choice: a rune outside the Basic Multilingual Plane makes every Encode call
// fail, a byte sequence that is not valid UTF-8 is replaced rune-by-rune
// with U+FFFD, so the PFX ends up protected by a different, lower-entropy
// password than the configured secret, and a NUL byte (reachable only through
// PFX_PASSWORD_FILE, since an environment string cannot carry one) is encoded
// verbatim into a NUL-terminated password format, so no consumer can reproduce
// the password the PFX was built with. Only the shape is reported, never the
// value. The recognition itself is convert.InspectPasswordEncoding's — the
// package that enforces the same invariant before encoding — so this startup
// diagnostic cannot drift from the conversion gate.
func warnUnencodablePassword(password string) {
	if password == "" {
		return
	}
	issues := convert.InspectPasswordEncoding(password)
	switch {
	case issues.InvalidUTF8:
		slog.Warn("PFX_PASSWORD is not valid UTF-8; every invalid byte is encoded as U+FFFD, so generated PFX files are protected by a different, lower-entropy password than the configured secret",
			"remediation", "supply a text secret (for example base64) instead of raw binary bytes")
	case issues.NonBMP:
		slog.Warn("PFX_PASSWORD contains a character outside the Basic Multilingual Plane; PKCS#12 cannot encode it, so every conversion will fail",
			"remediation", "use a PFX password made only of BMP characters (ASCII is safest)")
	case issues.EmbeddedNUL:
		slog.Warn("PFX_PASSWORD contains a NUL byte; PKCS#12 passwords are NUL-terminated, so generated PFX files cannot be opened with any password a consumer can supply",
			"remediation", "strip NUL bytes from the secret file (a UTF-16 or NUL-padded file is the usual cause); use a plain UTF-8 text secret")
	}
}

// parseFallbackInterval parses a FALLBACK_SCAN_HOURS value into a re-scan
// cadence. Surrounding whitespace is trimmed first, so " 12 " parses as 12
// hours. Only an explicit "0" or "false" disables the fallback (returns 0),
// matched case-insensitively, so "FALSE" and " 0 " disable it too.
// An empty or whitespace-only value — or any unparseable value — yields
// defaultFallbackInterval, matching an unset variable, so a blank
// FALLBACK_SCAN_HOURS never silently disables the safety-net rescan. A value
// above maxFallbackHours is clamped to it, including a valid decimal too large
// for int64: a positive out-of-range number counts as above-ceiling, not as
// malformed input.
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
		n, err := strconv.ParseInt(trimmed, 10, 64)
		// A valid decimal too large for int64 is still a positive
		// above-ceiling value: clamp it like 87601 instead of misreading
		// overflow as malformed input. strconv reports ErrRange (not
		// ErrSyntax) for an overflowing digit prefix followed by junk too, so
		// the digits-only check keeps "1e40x" malformed rather than clamping
		// it; an optional leading "+" is still a valid decimal.
		digits := strings.TrimPrefix(trimmed, "+")
		positiveOverflow := errors.Is(err, strconv.ErrRange) &&
			digits != "" && strings.Trim(digits, "0123456789") == ""
		if positiveOverflow || (err == nil && n > maxFallbackHours) {
			slog.Warn("FALLBACK_SCAN_HOURS too large, clamping",
				"value", v, "max_hours", maxFallbackHours)
			return time.Duration(maxFallbackHours) * time.Hour
		}
		if err == nil && n > 0 {
			return time.Duration(n) * time.Hour
		}
		slog.Warn("invalid FALLBACK_SCAN_HOURS, using default",
			"value", v, "default", defaultFallbackInterval.String())
		return defaultFallbackInterval
	}
}

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
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/scanbudget"
	"github.com/cplieger/cert-converter/internal/scancadence"
	"github.com/cplieger/slogx"
)

// envFalseValue is the lexical "disabled" marker for env-var parsers.
const envFalseValue = "false"

// defaultFallbackInterval is the full-rescan cadence used when
// FALLBACK_SCAN_HOURS is unset, empty, or unparseable.
const defaultFallbackInterval = 6 * time.Hour

// maxFallbackHours keeps time.Duration(n)*time.Hour from overflowing int64;
// 10y is far beyond any real re-scan cadence.
const maxFallbackHours = 87600

// MAX_SCAN_ENTRIES' value domain — the default and the ceiling — lives in
// internal/scanbudget, because internal/process and internal/watch enforce the same two
// numbers for their own walks and neither of them may import this package.

// scanEntriesRepair reports whether parsing accepted, defaulted, or clamped the
// configured MAX_SCAN_ENTRIES.
type scanEntriesRepair int

const (
	// scanEntriesAccepted means the derived budget is the configured one: an
	// explicit in-range count, or an unset/blank value taking the documented
	// default.
	scanEntriesAccepted scanEntriesRepair = iota
	// scanEntriesInvalid means the value was unparseable or non-positive and
	// scanbudget.Default was substituted.
	scanEntriesInvalid
	// scanEntriesClamped means the value was above scanbudget.Ceiling and was
	// clamped down to it.
	scanEntriesClamped
)

// fallbackRepair reports whether parsing accepted, defaulted, or clamped the
// configured value.
type fallbackRepair int

const (
	// fallbackAccepted means the derived cadence is the configured one: an
	// explicit interval, the explicit "0"/"false" opt-out (reported by
	// warnFallbackDisabled), or an unset/blank value taking the documented
	// default.
	fallbackAccepted fallbackRepair = iota
	// fallbackInvalid means the value was unparseable or non-positive and
	// defaultFallbackInterval was substituted.
	fallbackInvalid
	// fallbackClamped means the value was above maxFallbackHours and was
	// clamped down to it.
	fallbackClamped
)

// Config holds the runtime configuration for cert-converter.
type Config struct {
	Password         string
	EncoderName      convert.EncoderType
	Lifecycle        outputpolicy.Lifecycle
	PasswordStatus   PasswordStatus
	FallbackInterval time.Duration
	// MaxScanEntries is how many /input paths one scan may enumerate; the
	// composition root injects it into process.Options and reports it on the
	// startup line, so an accepted explicit value is not silent.
	MaxScanEntries int
}

// Load reads environment variables and returns a populated Config.
func Load() (Config, error) {
	pw, err := resolvePassword()
	if err != nil {
		return Config{}, err
	}

	rawLifecycle := os.Getenv("OUTPUT_LIFECYCLE")
	lifecycle, lifecycleKnown := outputpolicy.ParseLifecycle(rawLifecycle)
	if !lifecycleKnown {
		slog.Warn("unknown OUTPUT_LIFECYCLE, using the default",
			"value", rawLifecycle, "using", string(lifecycle), "expected", outputpolicy.LifecycleModes())
	}

	rawEncoder := os.Getenv("PFX_ENCODER")
	encName, known := convert.EncoderName(rawEncoder)
	if !known {
		slog.Warn("unknown PFX_ENCODER, using the default profile",
			"value", rawEncoder, "using", string(encName), "expected", convert.EncoderNames())
	}
	warnLegacyEncoderProtection(encName)

	fallbackInterval, rawFallback, repair := fallbackIntervalFromEnv()
	warnFallbackRepaired(rawFallback, repair)
	warnFallbackDisabled(fallbackInterval)
	maxScanEntries, rawScanEntries, scanRepair := maxScanEntriesFromEnv()
	warnMaxScanEntriesRepaired(rawScanEntries, scanRepair)
	// Warned last (see warnPasswordStrength), so the weak-password WARN lands after
	// the delivery, lifecycle, encoder, fallback and scan-ceiling diagnostics rather
	// than ahead of them.
	warnPasswordStrength(pw.Status, pw.Channel, pw.BlankFile)

	return Config{
		Password:         pw.Value,
		EncoderName:      encName,
		Lifecycle:        lifecycle,
		FallbackInterval: fallbackInterval,
		MaxScanEntries:   maxScanEntries,
		PasswordStatus:   pw.Status,
	}, nil
}

// FallbackInterval returns the effective FALLBACK_SCAN_HOURS as a
// duration (0 = fallback rescan disabled), parsed with the same rules
// Load applies.
func FallbackInterval() time.Duration {
	interval, _, _ := fallbackIntervalFromEnv()
	return interval
}

// fallbackIntervalFromEnv reads FALLBACK_SCAN_HOURS and returns the effective
// interval, the raw configured value (what a diagnostic must quote), and how the
// parse had to repair it.
func fallbackIntervalFromEnv() (interval time.Duration, raw string, repair fallbackRepair) {
	raw = os.Getenv("FALLBACK_SCAN_HOURS")
	interval, repair = parseFallbackInterval(raw)
	return interval, raw, repair
}

// maxScanEntriesFromEnv reads MAX_SCAN_ENTRIES and returns the effective budget, the
// raw configured value (what a diagnostic must quote), and how the parse had to
// repair it.
func maxScanEntriesFromEnv() (limit int, raw string, repair scanEntriesRepair) {
	raw = os.Getenv("MAX_SCAN_ENTRIES")
	limit, repair = parseMaxScanEntries(raw)
	return limit, raw, repair
}

// LogLevel returns the effective LOG_LEVEL as a slog level.
func LogLevel() slog.Level {
	lvl, _, _ := logLevelFromEnv()
	return lvl
}

// logLevelFromEnv is the single home for the LOG_LEVEL name and its info
// default, shared by the silent LogLevel reader and by WarnInvalidLogLevel.
func logLevelFromEnv() (lvl slog.Level, raw string, ok bool) {
	raw = os.Getenv("LOG_LEVEL")
	lvl, ok = slogx.ParseLevel(raw, slog.LevelInfo)
	return lvl, raw, ok
}

// WarnInvalidLogLevel emits the operator-facing diagnostic for an unparseable
// LOG_LEVEL.
func WarnInvalidLogLevel() {
	lvl, raw, ok := logLevelFromEnv()
	if ok {
		return
	}
	slog.Warn("invalid LOG_LEVEL, using default",
		"value", raw, "default", strings.ToLower(lvl.String()))
}

// parseFallbackInterval parses a FALLBACK_SCAN_HOURS value into a re-scan
// cadence and reports how the value had to be repaired to get there.
func parseFallbackInterval(v string) (time.Duration, fallbackRepair) {
	trimmed := strings.TrimSpace(v)
	switch strings.ToLower(trimmed) {
	case "0", envFalseValue:
		return 0, fallbackAccepted
	case "":
		return defaultFallbackInterval, fallbackAccepted
	default:
		n, err := strconv.ParseInt(trimmed, 10, 64)
		// A valid decimal too large for int64 is still a positive above-ceiling
		// value: clamp it like 87601 instead of misreading overflow as malformed
		// input. isPositiveOverflow owns that rule for both numeric parsers.
		if isPositiveOverflow(trimmed, err) || (err == nil && n > maxFallbackHours) {
			return time.Duration(maxFallbackHours) * time.Hour, fallbackClamped
		}
		if err == nil && n > 0 {
			return time.Duration(n) * time.Hour, fallbackAccepted
		}
		return defaultFallbackInterval, fallbackInvalid
	}
}

// isPositiveOverflow reports whether a trimmed value is a valid decimal too large
// for int64, and therefore an above-ceiling number rather than malformed input.
func isPositiveOverflow(trimmed string, err error) bool {
	digits := strings.TrimPrefix(trimmed, "+")
	return errors.Is(err, strconv.ErrRange) &&
		strings.Trim(digits, "0123456789") == ""
}

// parseMaxScanEntries parses a MAX_SCAN_ENTRIES value into the number of /input
// paths one scan may enumerate, and reports how the value had to be repaired to get
// there.
func parseMaxScanEntries(v string) (int, scanEntriesRepair) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return scanbudget.Default, scanEntriesAccepted
	}
	// Atoi rather than ParseInt: the budget is an int, so parsing at the target
	// width keeps the clamp from needing a narrowing conversion, and an
	// int-overflowing value still arrives as ErrRange.
	n, err := strconv.Atoi(trimmed)
	if isPositiveOverflow(trimmed, err) || (err == nil && n > scanbudget.Ceiling) {
		return scanbudget.Ceiling, scanEntriesClamped
	}
	if err == nil && n > 0 {
		return n, scanEntriesAccepted
	}
	return scanbudget.Default, scanEntriesInvalid
}

// warnFallbackRepaired emits the operator-facing diagnostic for a
// FALLBACK_SCAN_HOURS value the parser could not use as configured.
func warnFallbackRepaired(raw string, repair fallbackRepair) {
	switch repair {
	case fallbackClamped:
		slog.Warn("FALLBACK_SCAN_HOURS too large, clamping",
			"value", raw, "max_hours", maxFallbackHours)
	case fallbackInvalid:
		slog.Warn("invalid FALLBACK_SCAN_HOURS, using default",
			"value", raw, "default", defaultFallbackInterval.String(),
			"expected", "a whole number of hours, or 0/false to disable the periodic rescan")
	case fallbackAccepted:
		// The configured cadence was used as-is.
	}
}

// warnMaxScanEntriesRepaired emits the operator-facing diagnostic for a
// MAX_SCAN_ENTRIES value the parser could not use as configured.
func warnMaxScanEntriesRepaired(raw string, repair scanEntriesRepair) {
	switch repair {
	case scanEntriesClamped:
		slog.Warn("MAX_SCAN_ENTRIES too large, clamping",
			"value", raw, "max_entries", scanbudget.Ceiling)
	case scanEntriesInvalid:
		slog.Warn("invalid MAX_SCAN_ENTRIES, using default",
			"value", raw, "default", scanbudget.Default,
			"expected", "a whole number of entries between 1 and "+strconv.Itoa(scanbudget.Ceiling)+" (there is no value that disables the budget)")
	case scanEntriesAccepted:
		// The configured budget was used as-is; nothing to report.
	}
}

// warnFallbackDisabled warns when the operator's own periodic rescan never runs,
// because nothing else in the process reports it: the explicit 0/false opt-out
// removed it, or the cadence is above the watcher's reconciliation floor, which
// overrides it — a value at or clamped to maxFallbackHours included, since the
// ceiling is far above the floor.
func warnFallbackDisabled(interval time.Duration) {
	if floor := scancadence.Effective(interval); interval > floor {
		// One record for every cadence the floor overrides, the clamped ceiling
		// included: parseFallbackInterval clamps every larger value to exactly
		// maxFallbackHours and the floor is well below that, so an at-ceiling interval
		// satisfies this guard too and needs no arm of its own.
		attrs := append(scancadence.CoverageAttrs(interval),
			"remediation", "set FALLBACK_SCAN_HOURS at or below the floor's hours if the cadence should be yours, or leave it as is: coverage is unaffected")
		slog.Warn("FALLBACK_SCAN_HOURS is above the watcher's reconciliation floor, so no re-scan will ever run on your configured cadence; "+
			"the floor's full-tree reconciliation runs instead, more often than the cadence you set",
			attrs...)
		return
	}
	if interval > 0 {
		return
	}
	slog.Warn("FALLBACK_SCAN_HOURS is 0/false: no routine periodic re-scan on your own cadence; "+
		"a renewal whose fsnotify event never arrived, and an /input watch silently dropped by an unmount or remount, "+
		"wait for the watcher's slower full-tree reconciliation instead (this record's scan_floor names it, and the health-marker "+
		"freshness deadline is derived from it, so a wedged watch loop is still reported unhealthy)",
		append(scancadence.CoverageAttrs(interval),
			"remediation", "unset FALLBACK_SCAN_HOURS (or set it above 0) if a missed renewal should be recovered on your own cadence rather than on the reconciliation floor")...)
}

// warnLegacyEncoderProtection warns when the selected profile is one of the two
// legacy ones, whose bundles are only nominally protected however strong
// PFX_PASSWORD is.
func warnLegacyEncoderProtection(name convert.EncoderType) {
	// Which profiles are weak, and by how much, is internal/convert's profile
	// table to answer: it owns the (MAC, cert, key) algorithm triple, so a profile
	// added there arrives here already classified instead of needing a second
	// enumeration that would silently omit it.
	prot := convert.ProtectionOf(name)
	if !prot.NominalOnly {
		return
	}
	remediation := "use PFX_ENCODER=modern2023 unless the consuming device accepts nothing else; " +
		"if it does not, keep /output and every copy of it as sensitive as the private keys themselves"
	if prot.WeakCertCipher {
		remediation = "use PFX_ENCODER=modern2023, or legacydes if the device needs SHA-1 but not RC2; " +
			"if it accepts nothing else, keep /output and every copy of it as sensitive as the private keys themselves"
	}
	slog.Warn("PFX_ENCODER selects a legacy PKCS#12 profile: its bundles carry a single-iteration "+
		"HMAC-SHA-1 MAC, so the password embedded in every generated PFX file can be searched "+
		"offline at about one hash per guess and the private key follows from it",
		"encoder", string(name),
		"mac_iterations", prot.MACIterations, "modern_mac_iterations", convert.ModernMACIterations,
		"remediation", remediation)
}

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
// FALLBACK_SCAN_HOURS is unset, empty, or unparseable. Only an explicit "0" or
// "false" disables the fallback rescan.
const defaultFallbackInterval = 6 * time.Hour

// maxFallbackHours keeps time.Duration(n)*time.Hour from overflowing int64;
// 10y is far beyond any real re-scan cadence. Package-level rather than local
// to parseFallbackInterval because warnFallbackRepaired names it in the
// clamp WARN, and the two must report the same ceiling.
const maxFallbackHours = 87600

// MAX_SCAN_ENTRIES' value domain — the default and the ceiling — lives in
// internal/scanbudget, because internal/process and internal/watch enforce the same two
// numbers for their own walks and neither of them may import this package. What stays
// here is what config DOES with them: parsing the operator's raw value, clamping it, and
// naming a repaired one in a warning.

// scanEntriesRepair reports whether parsing accepted, defaulted, or clamped the
// configured MAX_SCAN_ENTRIES. Parsing stays silent because maxScanEntriesFromEnv is
// a plain reader; Load owns the one-time diagnostics, exactly as it does for
// FALLBACK_SCAN_HOURS.
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
// configured value. Parsing stays silent because FallbackInterval is called by
// health probes; Load owns the one-time diagnostics.
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

// Config holds the runtime configuration for cert-converter. The PFX encoder is
// carried as the app-owned convert.EncoderType name, not as a go-pkcs12 value:
// the vendor type stays confined to internal/convert, which resolves the name
// with resolvedProfile inside convert.Encode; main and process only carry the name.
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

// Load reads environment variables and returns a populated Config. The PFX
// password follows the Docker-secrets convention: when PFX_PASSWORD_FILE is
// set the secret is read from that file (bounded, and delivered verbatim apart
// from at most one trailing line ending, so whitespace an operator put in the
// password is part of it on both channels) so it never appears in the process
// environment; otherwise PFX_PASSWORD is used. It
// returns ErrEmptyPassword when neither supplies a value, or when the value is
// blank (empty, whitespace-only, or invisible formatting runes only) — a
// whitespace-only or BOM-only PFX_PASSWORD_FILE included, because a blank file
// routes through the same guard as a blank
// PFX_PASSWORD — unless PFX_ALLOW_EMPTY_PASSWORD is set to true; it returns
// ErrUnencodablePassword when the configured password is a shape PKCS#12 cannot
// carry (invalid UTF-8, a non-BMP rune, or an embedded NUL); and it fails
// loudly, with no opt-out, when a configured PFX_PASSWORD_FILE cannot be used
// at all — a path envx rejects (it must already be cleaned and must not
// traverse), or an oversized or unreadable file. The sequence that resolves the two
// password channels, classifies the value and applies those refusals is
// resolvePassword's, in password.go, which is also where both deliberate orderings live.
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
// Load applies. Exported separately so the health subcommand can derive
// its probe max-age from the same source of truth without a full config
// load, which would fail on a missing PFX_PASSWORD the probe does not
// need.
//
// Deliberately SILENT: it emits no log records, because the health subcommand
// calls it on every probe. Every diagnostic for this setting is emitted once per
// process start, by Load.
func FallbackInterval() time.Duration {
	interval, _, _ := fallbackIntervalFromEnv()
	return interval
}

// fallbackIntervalFromEnv reads FALLBACK_SCAN_HOURS and returns the effective
// interval, the raw configured value (what a diagnostic must quote), and how the
// parse had to repair it. The single home for the variable's name, shared by the
// silent FallbackInterval reader and by Load, which is the only caller that
// warns.
func fallbackIntervalFromEnv() (interval time.Duration, raw string, repair fallbackRepair) {
	raw = os.Getenv("FALLBACK_SCAN_HOURS")
	interval, repair = parseFallbackInterval(raw)
	return interval, raw, repair
}

// maxScanEntriesFromEnv reads MAX_SCAN_ENTRIES and returns the effective budget, the
// raw configured value (what a diagnostic must quote), and how the parse had to
// repair it. The single home for the variable's name. Unlike FALLBACK_SCAN_HOURS and
// LOG_LEVEL there is no exported reader beside it: no caller needs the budget before
// or without Load, so the value travels to the composition root on Config and the
// budget WARNed about is the same parse the scanner receives.
func maxScanEntriesFromEnv() (limit int, raw string, repair scanEntriesRepair) {
	raw = os.Getenv("MAX_SCAN_ENTRIES")
	limit, repair = parseMaxScanEntries(raw)
	return limit, raw, repair
}

// LogLevel returns the effective LOG_LEVEL as a slog level. Exported separately
// from Load so the logger can be installed before Load runs (Load emits WARN
// lines that must honour the configured level).
//
// Deliberately SILENT, like FallbackInterval: WarnInvalidLogLevel owns the
// diagnostic, so the LOG_LEVEL name, its info default and the wording all stay
// in this package.
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
// LOG_LEVEL. Called by the composition root AFTER the logger is installed and
// below the argv dispatch, so it fires once per process start and never from the
// `health` subcommand, which re-reads LOG_LEVEL on every probe.
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
// Surrounding whitespace is trimmed first, so " 12 " parses as 12
// hours. Only an explicit "0" or "false" disables the fallback (returns 0),
// matched case-insensitively, so "FALSE" and " 0 " disable it too.
// An empty or whitespace-only value — or any unparseable value — yields
// defaultFallbackInterval, matching an unset variable, so a blank
// FALLBACK_SCAN_HOURS never silently disables the safety-net rescan. A value
// above maxFallbackHours is clamped to it, including a valid decimal too large
// for int64: a positive out-of-range number counts as above-ceiling, not as
// malformed input.
//
// A pure parse: it emits no log records, because FallbackInterval() is also called
// by the `health` subcommand. The repaired-input diagnostics are
// warnFallbackRepaired's, emitted once per process start from Load.
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
// for int64, and therefore an above-ceiling number rather than malformed input. The
// shared rule behind both numeric parsers, so MAX_SCAN_ENTRIES and
// FALLBACK_SCAN_HOURS cannot disagree about what an overflowing value means.
//
// strconv reports ErrRange (not ErrSyntax) for an overflowing digit prefix followed
// by junk too, so the digits-only check keeps "1e40x" malformed rather than clamping
// it; an optional leading "+" is still a valid decimal.
func isPositiveOverflow(trimmed string, err error) bool {
	digits := strings.TrimPrefix(trimmed, "+")
	return errors.Is(err, strconv.ErrRange) &&
		strings.Trim(digits, "0123456789") == ""
}

// parseMaxScanEntries parses a MAX_SCAN_ENTRIES value into the number of /input
// paths one scan may enumerate, and reports how the value had to be repaired to get
// there. Surrounding whitespace is trimmed first, so " 5000 " parses as 5000.
// An empty or whitespace-only value — or any unparseable, zero, or negative value —
// yields scanbudget.Default, matching an unset variable, so a misconfigured
// budget never becomes an unbounded walk. A value above scanbudget.Ceiling is
// clamped to it, including a valid decimal too large for int64: a positive
// out-of-range number counts as above-ceiling, not as malformed input.
//
// There is deliberately no disable spelling (see scanbudget.Ceiling): "0" and
// "false" are unusable input here, not an opt-out, because a scan with no entry
// budget is the exhaustion path the ceiling exists to close.
//
// A pure parse: it emits no log records, so maxScanEntriesFromEnv stays silent for
// any caller. The repaired-input diagnostics are warnMaxScanEntriesRepaired's, emitted
// once per process start from Load.
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
// FALLBACK_SCAN_HOURS value the parser could not use as configured. Both cases are
// silently repaired, so the WARN naming the rejected value is the operator's only
// way to tell an intended cadence from a default or a clamp.
//
// Called only from Load, so each line is emitted exactly once per process start and
// never from the `health` subcommand. raw is the value as configured, untrimmed, so
// the log shows what the operator actually set.
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
		// The configured cadence was used as-is. The explicit "0"/"false"
		// opt-out lands here too and is reported by warnFallbackDisabled, which
		// keys on the interval rather than on the repair.
	}
}

// warnMaxScanEntriesRepaired emits the operator-facing diagnostic for a
// MAX_SCAN_ENTRIES value the parser could not use as configured. Both cases are
// silently repaired, so the WARN naming the rejected value is the operator's only
// way to tell an intended budget from a default or a clamp — and a deployment that
// meant to raise the ceiling would otherwise keep failing its scan at the default
// with nothing to explain why.
//
// Called only from Load, so each line is emitted exactly once per process start and
// never from the `health` subcommand. raw is the value as configured, untrimmed, so
// the log shows what the operator actually set.
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
// ceiling is far above the floor. In both the cadence the operator chose never
// fires, so each earns its own record naming what stands in for it.
//
// What goes away is the operator's CADENCE, not the app's convergence: the watcher
// keeps a reconciliation floor in every configuration (internal/scancadence's
// Floor), the health marker's freshness deadline is derived from that floor rather
// than from this value, and BOTH records below carry it as scan_floor
// (scancadence.CoverageAttrs) rather than leaving it to the INFO startup line a
// LOG_LEVEL=warn deployment never sees.
// Which way that cuts differs by arm. For the 0/false opt-out the tradeoff is
// LATENCY — a renewal whose fsnotify event never arrived, and an /input watch the
// kernel dropped silently on an unmount or remount (IN_UNMOUNT/IN_IGNORED, which
// fsnotify neither reports as an event nor as a closed channel), both wait for that
// slower reconciliation instead of for the cadence the operator would otherwise have
// chosen. For a cadence ABOVE the floor, the maxFallbackHours ceiling included, there
// is no added latency at all: the watcher arms the timer with the smaller of the two
// (scancadence.Effective), so the floor's walk runs MORE often than the cadence that
// was configured, which is why that arm's record reports the override and says
// coverage is unaffected.
//
// Deliberately a warning rather than a detector: whether a day of extra latency on a
// missed renewal is acceptable is the operator's judgment, and the app cannot infer
// it. A wedged loop IS now detected, by the marker deadline.
//
// It keys on the parsed interval: above scancadence.Floor for a cadence the floor
// overrides, which is where a value at or clamped to maxFallbackHours lands too, and
// zero for the explicit "0"/"false" opt-out. A repaired blank or invalid value lands
// on the 6h default, which is below the floor, so it remains enabled and silent here
// (warnFallbackRepaired reports those).
func warnFallbackDisabled(interval time.Duration) {
	if floor := scancadence.Effective(interval); interval > floor {
		// One record for every cadence the floor overrides, the clamped ceiling
		// included: parseFallbackInterval clamps every larger value to exactly
		// maxFallbackHours and the floor is well below that, so an at-ceiling interval
		// satisfies this guard too and needs no arm of its own. At the ceiling the
		// floor's walk runs far MORE often than the cadence that was configured, which
		// is what this record says — do not reword it as waiting for a slower
		// reconciliation, which is the 0/false arm's case, not this one.
		//
		// The safety-net timer always arms with the smaller of the configured cadence
		// and the floor (scancadence.Effective), so this cadence never fires.
		// The pair is rendered by scancadence.CoverageAttrs, the one home for its keys and
		// both renderings; this arm's guard makes the interval positive (so the label
		// renders interval.String()) and floor is already
		// scancadence.Effective(interval).
		//
		// A value clamped TO the ceiling still gets its own "too large, clamping"
		// record from warnFallbackRepaired naming max_hours, so that fact is reported
		// where it belongs and is not this arm's to carry.
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
// PFX_PASSWORD is. go-pkcs12's LegacyDES and LegacyRC2 both derive the bundle's
// MAC key with a SINGLE HMAC-SHA-1 iteration (the modern profiles use 2048), and
// the MAC is what verifies a password guess, so an offline search over a leaked
// .pfx costs about one hash per candidate and the 3DES-wrapped private key opens
// once the password is recovered; legacyrc2 additionally encrypts the certificate
// bag with a 40-bit RC2 key. Upstream says the same of both encoders: use a
// throwaway password and protect the file by other means.
//
// Emitted even though the operator chose the profile explicitly, for the reason
// PFX_ALLOW_EMPTY_PASSWORD=true is warned about on every start: the record reports
// a degraded STATE of what this app writes, not a mistake in the spelling, and it
// is the only statement of that state — the startup line carries the profile name
// at INFO, which a LOG_LEVEL=warn deployment (the level the README's alerting
// section is written for) never sees. It stays out of EncoderName's `known` flag
// deliberately: that flag reports the parse, this reports the outcome.
func warnLegacyEncoderProtection(name convert.EncoderType) {
	// Which profiles are weak, and by how much, is internal/convert's profile
	// table to answer: it owns the (MAC, cert, key) algorithm triple, so a profile
	// added there arrives here already classified instead of needing a second
	// enumeration that would silently omit it. What stays here is the operator
	// wording and the decision to warn on every start.
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

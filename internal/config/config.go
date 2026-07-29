// Package config provides environment-based configuration for cert-converter.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/envx"
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

// defaultMaxScanEntries is the number of /input paths ONE scan will enumerate when
// MAX_SCAN_ENTRIES is unset, empty, or unusable. A Caddy certificate directory holds
// a handful of entries per domain, so ten thousand is already orders of magnitude
// above any real deployment while keeping the walk's worst case small.
const defaultMaxScanEntries = 10000

// maxScanEntriesCeiling is the largest ceiling MAX_SCAN_ENTRIES may raise the budget
// to; a higher configured value is clamped to it. It is the historical hardcoded
// bound, kept as the upper limit so raising the setting cannot restore an
// effectively unbounded walk.
//
// There is deliberately NO disable value (no "0"/"false" spelling, unlike
// FALLBACK_SCAN_HOURS): disabling the budget would reopen the single-scan
// memory/CPU exhaustion path the ceiling exists to close, so a zero or negative
// value is treated as unusable input and falls back to the default.
const maxScanEntriesCeiling = 200000

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
	// defaultMaxScanEntries was substituted.
	scanEntriesInvalid
	// scanEntriesClamped means the value was above maxScanEntriesCeiling and was
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
// with encoderFor inside convert.Encode; main and process only carry the name.
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

// Load is the only entry point that reads the environment; the PFX-password classification and its diagnostics live in password.go.
//
// Load reads environment variables and returns a populated Config. The PFX
// password follows the Docker-secrets convention: when PFX_PASSWORD_FILE is
// set the secret is read from that file (bounded, whitespace-trimmed) so it
// never appears in the process environment; otherwise PFX_PASSWORD is used. It
// returns ErrEmptyPassword when neither supplies a value, or when the value is
// blank (empty, whitespace-only, or invisible formatting runes only) — a
// whitespace-only or BOM-only PFX_PASSWORD_FILE included, because a blank file
// routes through the same guard as a blank
// PFX_PASSWORD — unless PFX_ALLOW_EMPTY_PASSWORD is set to true; it returns
// ErrUnencodablePassword when the configured password is a shape PKCS#12 cannot
// carry (invalid UTF-8, a non-BMP rune, or an embedded NUL); and it fails
// loudly, with no opt-out, when a configured PFX_PASSWORD_FILE cannot be used
// at all — a path envx rejects (it must already be cleaned and contain no ".."
// anywhere, so even a "pfx..v2" filename is refused), or an oversized or
// unreadable file.
func Load() (Config, error) {
	var blankSecretFile error
	// Emitted before resolution: a blank pointer is not the file channel at all, so
	// neither warnBothPasswordChannels nor envx's own error can report it.
	warnBlankPasswordFilePointer()
	password, source, secretErr := envx.SecretWithSource("PFX_PASSWORD")
	// Emitted here rather than from logPasswordDelivery because every startup
	// REFUSAL below is about the file channel while PFX_PASSWORD is the variable the
	// operator can see is set: ErrEmptyPassword's "set PFX_PASSWORD" and envx's "read secret
	// file for PFX_PASSWORD" both point at the ignored variable unless this line
	// says the file wins. envx reports SourceFile on its error paths for exactly
	// this purpose.
	warnBothPasswordChannels(source)
	if secretErr != nil {
		var missing *envx.MissingError
		switch {
		case errors.As(secretErr, &missing):
			// Neither channel supplied a value: fall through to the blank guard,
			// which the operator can opt out of.
			password = ""
		case errors.Is(secretErr, envx.ErrBlankSecretFile):
			// Route a blank secret file through the same opt-out as a blank
			// environment value, so PFX_ALLOW_EMPTY_PASSWORD means one thing
			// regardless of how the secret was delivered.
			password, blankSecretFile = "", secretErr
		default:
			// Unreadable, oversized, or a rejected path: the operator configured a
			// secret file that cannot be used at all. That is never something the
			// empty-password opt-out should rescue, because silently degrading to no
			// password is the outcome the file channel exists to prevent.
			return Config{}, secretErr
		}
	}
	// One classification, three consumers: the empty-password guard below, the
	// weak-password WARN (warnPasswordStrength, emitted last), and the
	// Config.PasswordStatus the startup line reports. Deriving all three from this
	// single answer is what keeps a value the guard treats as blank from being
	// reported as "configured".
	status := classifyPassword(password)
	rawAllowEmpty := os.Getenv("PFX_ALLOW_EMPTY_PASSWORD")
	allowEmpty, allowEmptyRecognized := allowEmptyPassword(rawAllowEmpty)
	warnUnrecognizedAllowEmptyPassword(rawAllowEmpty, allowEmptyRecognized)
	// Encodability is asked BEFORE the blank guard, because the two overlap: the
	// invisible-rune class includes the supplementary variation selectors
	// (U+E0100-U+E01EF), which are non-BMP and so unencodable by PKCS#12. A
	// password made only of those is both blank and unencodable, and only one of
	// the two refusals carries an achievable remediation — PFX_ALLOW_EMPTY_PASSWORD
	// cannot rescue it, since opting out just reaches this error on the next start.
	// Encodable blank values (a BOM, a zero-width space) still fall through to the
	// opt-out below.
	if err := checkPasswordEncodable(password); err != nil {
		return Config{}, fmt.Errorf("%w (supplied via %s)", err, passwordChannel(source))
	}
	if status != PasswordConfigured && !allowEmpty {
		if blankSecretFile != nil {
			// A blank secret FILE is not "no password supplied": name the envx error,
			// which carries the configured path. A startup FAILURE is the deliberate
			// exception to omitting the secret-mount path from the logs.
			return Config{}, fmt.Errorf("%w: %w", ErrEmptyPassword, blankSecretFile)
		}
		if source == envx.SourceFile {
			// A mounted secret that is blank only after classification (an
			// invisible-only value; envx trimmed nothing) reaches here with no
			// envx error to carry the channel, so name it here or the refusal
			// sends a file-channel operator to the variable file-wins ignores.
			return Config{}, fmt.Errorf("%w (supplied via %s)", ErrEmptyPassword, passwordChannel(source))
		}
		return Config{}, ErrEmptyPassword
	}
	logPasswordDelivery(source, password, status, blankSecretFile != nil)

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

	fallbackInterval, rawFallback, repair := fallbackIntervalFromEnv()
	warnFallbackRepaired(rawFallback, repair)
	warnFallbackDisabled(fallbackInterval)
	maxScanEntries, rawScanEntries, scanRepair := maxScanEntriesFromEnv()
	warnMaxScanEntriesRepaired(rawScanEntries, scanRepair)
	// Warned last (see warnPasswordStrength), so the weak-password WARN lands after
	// the delivery, lifecycle, encoder, fallback and scan-ceiling diagnostics rather
	// than ahead of them.
	warnPasswordStrength(status, passwordChannel(source), blankSecretFile != nil)

	return Config{
		Password:         password,
		EncoderName:      encName,
		Lifecycle:        lifecycle,
		FallbackInterval: fallbackInterval,
		MaxScanEntries:   maxScanEntries,
		PasswordStatus:   status,
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
		digits != "" && strings.Trim(digits, "0123456789") == ""
}

// parseMaxScanEntries parses a MAX_SCAN_ENTRIES value into the number of /input
// paths one scan may enumerate, and reports how the value had to be repaired to get
// there. Surrounding whitespace is trimmed first, so " 5000 " parses as 5000.
// An empty or whitespace-only value — or any unparseable, zero, or negative value —
// yields defaultMaxScanEntries, matching an unset variable, so a misconfigured
// budget never becomes an unbounded walk. A value above maxScanEntriesCeiling is
// clamped to it, including a valid decimal too large for int64: a positive
// out-of-range number counts as above-ceiling, not as malformed input.
//
// There is deliberately no disable spelling (see maxScanEntriesCeiling): "0" and
// "false" are unusable input here, not an opt-out, because a scan with no entry
// budget is the exhaustion path the ceiling exists to close.
//
// A pure parse: it emits no log records, so maxScanEntriesFromEnv stays silent for
// any caller. The repaired-input diagnostics are warnMaxScanEntriesRepaired's, emitted
// once per process start from Load.
func parseMaxScanEntries(v string) (int, scanEntriesRepair) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return defaultMaxScanEntries, scanEntriesAccepted
	}
	// Atoi rather than ParseInt: the budget is an int, so parsing at the target
	// width keeps the clamp from needing a narrowing conversion, and an
	// int-overflowing value still arrives as ErrRange.
	n, err := strconv.Atoi(trimmed)
	if isPositiveOverflow(trimmed, err) || (err == nil && n > maxScanEntriesCeiling) {
		return maxScanEntriesCeiling, scanEntriesClamped
	}
	if err == nil && n > 0 {
		return n, scanEntriesAccepted
	}
	return defaultMaxScanEntries, scanEntriesInvalid
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
			"value", raw, "max_entries", maxScanEntriesCeiling)
	case scanEntriesInvalid:
		slog.Warn("invalid MAX_SCAN_ENTRIES, using default",
			"value", raw, "default", defaultMaxScanEntries,
			"expected", "a whole number of entries between 1 and "+strconv.Itoa(maxScanEntriesCeiling)+" (there is no value that disables the budget)")
	case scanEntriesAccepted:
		// The configured budget was used as-is; nothing to report.
	}
}

// warnFallbackDisabled warns when periodic recovery and the health-marker
// freshness deadline are both gone, because nothing else in the process ever
// reports it: either the explicit 0/false opt-out removed them, or the configured
// cadence sits at maxFallbackHours, where the rescan that refreshes the marker
// never arrives and the 3x deadline can never expire. The two are operationally
// the same state, so both earn the same tradeoff record.
//
// Three things go away together: the periodic re-scan that would convert a renewal
// whose fsnotify event never arrived; the marker's freshness deadline (main hands the
// probe WithMaxAge(3*interval), and health treats a non-positive max-age as no
// deadline), so the last clean scan reports HEALTHY for as long as the container
// runs; and any chance of noticing an /input watch dropped by an unmount or remount,
// which the kernel reports as IN_UNMOUNT/IN_IGNORED — fsnotify emits no event and
// closes no channel, so watch's root-watch-loss guard never fires.
//
// Deliberately a warning rather than a detector: with the fallback off, an idle
// deployment and a wedged one are indistinguishable without active probing, so any
// liveness timer would either restore the periodic work this setting exists to avoid
// or report a quiet deployment unhealthy.
//
// It keys on the parsed interval, which is zero only for the explicit "0"/"false"
// opt-out and at the ceiling for a value at or above maxFallbackHours (including one
// Load's warnFallbackRepaired clamped there), so repaired blank or invalid values
// remain enabled and silent here (warnFallbackRepaired reports those).
func warnFallbackDisabled(interval time.Duration) {
	if interval >= maxFallbackHours*time.Hour {
		// The ceiling is documented as far beyond any real cadence, so a rescan
		// at it never arrives: the periodic recovery and the marker's 3x
		// freshness deadline are both inert, exactly as with the 0/false opt-out.
		slog.Warn("FALLBACK_SCAN_HOURS is at the "+strconv.Itoa(maxFallbackHours)+"h ceiling, so no periodic re-scan will run and the health-marker freshness deadline (3x the interval) can never expire; "+
			"a wedged watch loop keeps reporting healthy while converting nothing",
			"hours", maxFallbackHours,
			"remediation", "set FALLBACK_SCAN_HOURS to a real cadence (unset it for the 6h default) so a missed fsnotify event is recovered and a wedged loop is reported unhealthy")
		return
	}
	if interval > 0 {
		return
	}
	slog.Warn("FALLBACK_SCAN_HOURS is 0/false: no periodic re-scan, and no health-marker freshness deadline with it; "+
		"an /input watch silently dropped by an unmount or remount emits no fsnotify event, so it goes undetected "+
		"and the container keeps reporting healthy while converting nothing",
		"remediation", "unset FALLBACK_SCAN_HOURS (or set it above 0) so the periodic rescan re-attaches the watch set "+
			"and the health marker's freshness deadline can report a wedged loop")
}

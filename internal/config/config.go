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
	"unicode"

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

// fallbackRepair classifies what parseFallbackInterval had to do with a
// configured FALLBACK_SCAN_HOURS value. The parse itself is silent — it derives
// the cadence and reports the condition — because FallbackInterval() is also
// called by the `health` subcommand, where a startup diagnostic would repeat on
// every probe (roughly every 30s under Docker's healthcheck, forever). Load is
// the single home for this setting's diagnostics, the same reason
// warnFallbackDisabled lives there.
//
// Three conditions, because they need three different operator messages: the
// value was used as configured, an unusable value was replaced by the default,
// or an above-ceiling value was clamped.
type fallbackRepair int

const (
	// fallbackAccepted means the derived cadence is the configured one: an
	// explicit interval, the explicit "0"/"false" opt-out (reported by
	// warnFallbackDisabled), or an unset/blank value taking the documented
	// default. Nothing was repaired, so nothing is warned about here.
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
}

// ErrEmptyPassword indicates PFX_PASSWORD is empty and the empty-password
// opt-out (PFX_ALLOW_EMPTY_PASSWORD=true) is not set. A PFX generated with an
// empty password protects the embedded private key with no password at all.
var ErrEmptyPassword = errors.New(
	"PFX_PASSWORD is empty or blank; set it, point PFX_PASSWORD_FILE at a secret file, " +
		"or set PFX_ALLOW_EMPTY_PASSWORD=true")

// ErrUnencodablePassword indicates the configured password contains invalid UTF-8,
// a non-BMP rune, or an embedded NUL and cannot be represented safely by PKCS#12.
//
// It is a startup refusal rather than a warning because every one of the three shapes
// is unconditionally broken and no scan recovers from it: a non-BMP rune fails every
// Encode, so the container would be permanently unhealthy, while invalid UTF-8 and an
// embedded NUL SUCCEED and report healthy, silently writing bundles protected by a
// password no consumer can reproduce.
var ErrUnencodablePassword = errors.New("the configured PFX password cannot be encoded by PKCS#12")

// PasswordStatus is a non-secret classification of how well PFX_PASSWORD
// protects the private key inside every generated PFX file.
type PasswordStatus string

// The PFX password classifications reported by classifyPassword.
const (
	// PasswordEmpty means no password at all was supplied.
	PasswordEmpty PasswordStatus = "empty"
	// PasswordWhitespaceOnly means the password consists only of whitespace,
	// which is effectively no protection.
	PasswordWhitespaceOnly PasswordStatus = "whitespace-only"
	// PasswordConfigured means a real password was supplied.
	PasswordConfigured PasswordStatus = "configured"
)

// classifyPassword classifies a PFX password. It is the single home for the
// blank-password predicate: Load's empty-password guard, Load's weak-password
// WARN, and the Config.PasswordStatus the startup log reports all derive their
// decision from it, so they cannot drift.
func classifyPassword(password string) PasswordStatus {
	switch {
	case password == "":
		return PasswordEmpty
	case strings.TrimSpace(password) == "":
		return PasswordWhitespaceOnly
	default:
		return PasswordConfigured
	}
}

// isBlank reports whether a password is empty or entirely Unicode whitespace, and
// therefore offers no real protection.
//
// This is the single blankness rule for BOTH delivery channels, so
// PFX_ALLOW_EMPTY_PASSWORD means one thing regardless of how the secret arrived.
// PFX_PASSWORD=" " (a quoting slip in a compose file or .env) is therefore REJECTED:
// README documents the guard as refusing to start when the password is empty, which an
// operator reasonably reads as covering a blank value.
func isBlank(password string) bool {
	return classifyPassword(password) != PasswordConfigured
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
	var blankSecretFile error
	password, source, secretErr := envx.SecretWithSource("PFX_PASSWORD")
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
	allowEmpty := allowEmptyPassword(os.Getenv("PFX_ALLOW_EMPTY_PASSWORD"))
	if isBlank(password) && !allowEmpty {
		if blankSecretFile != nil {
			// A blank secret FILE is not "no password supplied": name the envx error,
			// which carries the configured path. A startup FAILURE is the deliberate
			// exception to omitting the secret-mount path from the logs.
			return Config{}, fmt.Errorf("%w: %w", ErrEmptyPassword, blankSecretFile)
		}
		return Config{}, ErrEmptyPassword
	}
	// The classification and its WARN tree live together in this package (see
	// warnPasswordStrength), alongside every other configuration warning. The
	// status is classified next to the guard that consumes it, but its WARN is
	// emitted last, immediately before Load returns: that keeps the baseline
	// startup log order (delivery and channel diagnostics, then lifecycle,
	// encoder and fallback diagnostics, then the weak-password warning, then
	// main's "starting cert watcher" record). One configuration drops a record
	// from that order: a blank PFX_PASSWORD_FILE the opt-out let through is
	// reported once, by the channel-specific delivery WARN, and the generic
	// weak-password WARN is suppressed rather than repeating it with guidance
	// aimed at the other channel.
	status := classifyPassword(password)
	if err := checkPasswordEncodable(password); err != nil {
		return Config{}, fmt.Errorf("%w (supplied via %s)", err, passwordChannel(source))
	}
	logPasswordDelivery(source, password, blankSecretFile)

	rawLifecycle := os.Getenv("OUTPUT_LIFECYCLE")
	lifecycle, lifecycleKnown := outputpolicy.ParseLifecycle(rawLifecycle)
	if !lifecycleKnown {
		slog.Warn("unknown OUTPUT_LIFECYCLE, using warn", "value", rawLifecycle)
	}

	rawEncoder := os.Getenv("PFX_ENCODER")
	encName, known := convert.EncoderName(rawEncoder)
	if !known {
		slog.Warn("unknown PFX_ENCODER, using modern2023", "value", rawEncoder)
	}

	fallbackInterval, rawFallback, repair := fallbackIntervalFromEnv()
	warnFallbackRepaired(rawFallback, repair)
	warnFallbackDisabled(fallbackInterval)
	warnPasswordStrength(status, blankSecretFile != nil)

	return Config{
		Password:         password,
		EncoderName:      encName,
		Lifecycle:        lifecycle,
		FallbackInterval: fallbackInterval,
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

// checkPasswordEncodable rejects password shapes that PKCS#12 cannot carry intact.
// Empty passwords are handled separately by PFX_ALLOW_EMPTY_PASSWORD.
//
// Each shape is unconditionally broken and no scan recovers from it. What the
// PKCS#12 encoder does with each, absent any guard:
//
//   - NonBMP: UCS-2 cannot represent the rune, so go-pkcs12 refuses it and every
//     conversion fails, leaving the container unhealthy on every event and every
//     fallback tick.
//   - InvalidUTF8: go-pkcs12's bmpString ranges over the string, so each invalid byte
//     becomes U+FFFD and the encode SUCCEEDS. Bundles are written, the scan counts them
//     converted, health stays green — and no consumer can open them with the configured
//     secret, because distinct invalid bytes all collapse to the same replacement rune.
//   - EmbeddedNUL: PKCS#12 passwords are NUL-terminated, so an interior NUL encodes
//     verbatim and no consumer can reproduce the password the bundle was built with.
//     Also succeeds silently.
//
// The last two are the dangerous ones: were they to reach the encoder, nothing in the
// conversion path, the scan summary, or health would reflect them, and the README's
// Loki rules key on failure counts that stay at zero. Hence a startup refusal, per
// go.md's config rule: validate at startup, fail fast, do not discover invalid config
// at request time.
//
// convert.Encode refuses the same three shapes itself. That is NOT duplication to
// clean up: this gate is what makes the app fail fast and visibly for its one
// production caller, before a single file is scanned, with a diagnostic naming the
// env var; Encode's guard holds the codec's own contract for any caller, including
// one that never went through Load. Both are wanted — do not delete either.
//
// Only the SHAPE is reported, never the value. Recognition is
// convert.InspectPasswordEncoding's, the same package that encodes, so this gate cannot
// drift from the encoder; the shapes are reported in the order Encode reports them,
// so a password carrying several is named the same way by both.
func checkPasswordEncodable(password string) error {
	if password == "" {
		return nil
	}
	issues := convert.InspectPasswordEncoding(password)
	switch {
	case issues.InvalidUTF8:
		return fmt.Errorf("%w: not valid UTF-8, so every invalid byte would be encoded as U+FFFD and generated PFX files would be protected by a different, lower-entropy password than the configured secret; supply a text secret (for example base64) instead of raw binary bytes", ErrUnencodablePassword)
	case issues.NonBMP:
		return fmt.Errorf("%w: contains a character outside the Basic Multilingual Plane, which PKCS#12 cannot encode, so every conversion would fail; use a password made only of BMP characters (ASCII is safest)", ErrUnencodablePassword)
	case issues.EmbeddedNUL:
		return fmt.Errorf("%w: contains a NUL byte, and PKCS#12 passwords are NUL-terminated, so generated PFX files could not be opened with any password a consumer can supply; strip NUL bytes from the secret file (a UTF-16 or NUL-padded file is the usual cause)", ErrUnencodablePassword)
	}
	return nil
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
// A pure parse: it emits no log records. The repaired-input diagnostics are
// warnFallbackRepaired's, emitted once per process start from Load, following
// the LogLevel precedent in this package. Warning from here repeated the
// startup WARN on every `health` probe, because the probe calls
// FallbackInterval() too.
func parseFallbackInterval(v string) (time.Duration, fallbackRepair) {
	trimmed := strings.TrimSpace(v)
	switch strings.ToLower(trimmed) {
	case "0", envFalseValue:
		return 0, fallbackAccepted
	case "":
		return defaultFallbackInterval, fallbackAccepted
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
			return time.Duration(maxFallbackHours) * time.Hour, fallbackClamped
		}
		if err == nil && n > 0 {
			return time.Duration(n) * time.Hour, fallbackAccepted
		}
		return defaultFallbackInterval, fallbackInvalid
	}
}

// warnFallbackRepaired emits the operator-facing diagnostic for a
// FALLBACK_SCAN_HOURS value the parser could not use as configured. Both cases
// are silently repaired, so the WARN naming the rejected value is the operator's
// only way to tell an intended cadence from a default or a clamp.
//
// Called only from Load, so each line is emitted exactly once per process start
// and never from the `health` subcommand, whose FallbackInterval() call would
// otherwise reprint a startup diagnostic on every probe. raw is the value as
// configured, untrimmed, so the log shows what the operator actually set.
func warnFallbackRepaired(raw string, repair fallbackRepair) {
	switch repair {
	case fallbackClamped:
		slog.Warn("FALLBACK_SCAN_HOURS too large, clamping",
			"value", raw, "max_hours", maxFallbackHours)
	case fallbackInvalid:
		slog.Warn("invalid FALLBACK_SCAN_HOURS, using default",
			"value", raw, "default", defaultFallbackInterval.String())
	case fallbackAccepted:
		// The configured cadence was used as-is. The explicit "0"/"false"
		// opt-out lands here too and is reported by warnFallbackDisabled, which
		// keys on the interval rather than on the repair.
	}
}

// warnFallbackDisabled warns that FALLBACK_SCAN_HOURS=0/false runs the watcher
// unsupervised, naming the three things that go away together, because nothing
// else in the process ever will.
//
// There is no periodic re-scan, so a renewal whose fsnotify event never arrived
// stays unconverted. The health marker's freshness deadline goes with it (main
// hands the probe WithMaxAge(3*interval), and health treats a non-positive
// max-age as no deadline at all), so the marker written by the last clean scan
// reports HEALTHY for as long as the container runs. And an /input watch
// dropped by an unmount or remount is undetectable: the kernel reports that as
// IN_UNMOUNT/IN_IGNORED, which fsnotify swallows without emitting an event and
// without closing either channel, so watch's root-watch-loss guard (keyed on a
// Remove/Rename naming the root) never fires and the loop parks holding zero
// watches while health stays green.
//
// Deliberately a warning rather than a detector. With the fallback off, an idle
// deployment and a wedged one are indistinguishable without active probing, so
// any liveness timer or probe would either restore the periodic work this
// setting exists to avoid or report a quiet deployment unhealthy. Stating the
// tradeoff once, at startup, is the honest alternative.
//
// Keyed on the parsed interval, which is zero only for the explicit "0"/"false"
// opt-out: an empty, whitespace-only, or invalid value yields
// defaultFallbackInterval and stays silent here, because it is not the opt-out
// (Load's warnFallbackRepaired reports the values it had to repair).
func warnFallbackDisabled(interval time.Duration) {
	if interval > 0 {
		return
	}
	slog.Warn("FALLBACK_SCAN_HOURS is 0/false: no periodic re-scan, and no health-marker freshness deadline with it; "+
		"an /input watch silently dropped by an unmount or remount emits no fsnotify event, so it goes undetected "+
		"and the container keeps reporting healthy while converting nothing",
		"remediation", "unset FALLBACK_SCAN_HOURS (or set it above 0) so the periodic rescan re-attaches the watch set "+
			"and the health marker's freshness deadline can report a wedged loop")
}

// warnBothPasswordChannels warns when the operator supplied the PFX password through
// BOTH channels, because only one of them takes effect.
//
// PFX_PASSWORD_FILE wins by design — the whole point of the file channel is keeping the
// value out of the process environment — so a PFX_PASSWORD set alongside it is not a
// fallback. Without this line an operator who edits the wrong one gets no signal at all:
// startup succeeds, and every generated bundle carries the OTHER password. The mismatch
// only surfaces later, when a consumer cannot open a .pfx.
//
// Keyed on the source envx actually resolved rather than on os.Getenv, so the warning
// cannot claim a conflict that did not happen. Neither value is logged, and the path is
// omitted for the same reason the success line omits it.
func warnBothPasswordChannels(source envx.SecretSource) {
	if source != envx.SourceFile || isBlank(os.Getenv("PFX_PASSWORD")) {
		return
	}
	slog.Warn("both PFX_PASSWORD and PFX_PASSWORD_FILE are set; the file wins and PFX_PASSWORD is ignored",
		"source", "PFX_PASSWORD_FILE",
		"remediation", "remove PFX_PASSWORD from the environment so there is one place to change the secret")
}

// passwordChannel names the environment variable an operator must edit to change the
// configured PFX password. A startup refusal that always named PFX_PASSWORD sent an
// operator using a mounted secret to a variable the file-wins rule ignores.
func passwordChannel(source envx.SecretSource) string {
	if source == envx.SourceFile {
		return "PFX_PASSWORD_FILE"
	}
	return "PFX_PASSWORD"
}

// warnPasswordStrength emits the operator-facing warning for a password that
// offers no real protection. Every other configuration warning is emitted from
// Load's package, so this one is too: keeping the classification and its WARN
// tree in one place means a new PasswordStatus cannot gain a case without its
// warning being considered in the same edit.
//
// blankFileReported says logPasswordDelivery already reported this empty password
// as a blank PFX_PASSWORD_FILE. In that configuration the generic empty-password
// WARN is SUPPRESSED, because its remediation ("point PFX_PASSWORD_FILE at a
// mounted secret") names the step the operator has already taken, and it is the
// first line they read. The channel-specific WARN that replaces it reports the
// same empty-password condition at WARN and names the action that actually helps
// (write the secret into the mounted file), so nothing is quieter — the pair is
// one accurate record instead of a wrong one followed by a right one. Only
// PasswordEmpty can be reached this way: envx trims a file secret, so a
// whitespace-only file arrives as ErrBlankSecretFile with an empty password.
func warnPasswordStrength(status PasswordStatus, blankFileReported bool) {
	switch status {
	case PasswordEmpty:
		if blankFileReported {
			return
		}
		slog.Warn("PFX_PASSWORD is empty; generated PFX files protect the private key with an empty password",
			"remediation", "set PFX_PASSWORD, or point PFX_PASSWORD_FILE at a mounted secret")
	case PasswordWhitespaceOnly:
		slog.Warn("PFX_PASSWORD is whitespace-only; generated PFX files are protected by that whitespace string, which is effectively no protection",
			"remediation", "set PFX_PASSWORD to a real value (check for stray quotes or spaces in the env file)")
	case PasswordConfigured:
		// A real password is the healthy case: the value is a secret, so nothing
		// is logged about it beyond the non-secret status in the startup line.
	}
}

// logPasswordDelivery reports how the PFX password reached the process, never
// what it is: the resolved source, a blank mounted secret the opt-out let
// through, a conflicting pair of channels, and surrounding whitespace that
// silently becomes part of the password.
//
// The secret's SOURCE is recorded so an operator can confirm a mounted secret was
// actually consumed instead of silently falling back to PFX_PASSWORD. It is the
// source envx reported rather than one re-derived from the environment here, so the
// log cannot disagree with what was actually read. The configured path is
// deliberately omitted from these steady-state lines, which every log aggregator
// retains: it would publish the secret-mount topology on every healthy startup for
// no diagnostic gain. A startup FAILURE is the deliberate exception — the envx error
// Load returns names the path, and main logs it, because an unusable secret file
// cannot be diagnosed without it.
func logPasswordDelivery(source envx.SecretSource, password string, blankSecretFile error) {
	if source == envx.SourceFile {
		if blankSecretFile != nil {
			slog.Warn("PFX_PASSWORD_FILE is blank; starting with an empty PFX password because PFX_ALLOW_EMPTY_PASSWORD is set",
				"source", "PFX_PASSWORD_FILE",
				"remediation", "write the secret into the mounted file so generated PFX files protect the private key")
		} else {
			slog.Info("PFX password configured", "source", "PFX_PASSWORD_FILE")
		}
	}
	warnBothPasswordChannels(source)
	if source == envx.SourceEnv && !isBlank(password) &&
		password != strings.TrimSpace(password) {
		slog.Warn("PFX_PASSWORD has leading or trailing whitespace, which is part of the password embedded in every PFX file",
			"remediation", "remove the surrounding whitespace, or note that PFX_PASSWORD_FILE trims it, so the same value delivered as a mounted secret yields a different password")
	}
	// An INTERIOR control character survives both guards: envx trims only
	// surrounding whitespace, and PKCS#12 encodes a newline or tab verbatim, so
	// checkPasswordEncodable accepts it. The bundle is written, health stays
	// green, and the password cannot be typed into the consumers that need it.
	if strings.ContainsFunc(password, unicode.IsControl) {
		slog.Warn("the PFX password contains a control character (newline, carriage return, or tab), which is embedded verbatim in every PFX file and cannot be typed into most PKCS#12 consumers",
			"source", string(source),
			"remediation", "supply the secret on a single line (openssl rand -base64 wraps at 64 columns; add -A) so whatever opens the .pfx can reproduce the password")
	}
}

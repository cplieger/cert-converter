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
}

// ErrEmptyPassword indicates the resolved PFX password is empty or entirely
// Unicode whitespace and the PFX_ALLOW_EMPTY_PASSWORD opt-out is not set. Such
// a password provides no meaningful protection for the embedded private key.
var ErrEmptyPassword = errors.New(
	"the resolved PFX password is empty or blank; set PFX_PASSWORD, write a non-blank secret " +
		"to the file named by PFX_PASSWORD_FILE, or set PFX_ALLOW_EMPTY_PASSWORD=true")

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
// returns ErrEmptyPassword when neither supplies a value, or when the value is
// blank (empty or whitespace-only) — a whitespace-only PFX_PASSWORD_FILE
// included, because a blank file routes through the same guard as a blank
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
	// Classified next to the guard that consumes it, but warned last (see
	// warnPasswordStrength), so the weak-password WARN lands after the delivery,
	// lifecycle, encoder and fallback diagnostics rather than ahead of them.
	status := classifyPassword(password)
	if err := checkPasswordEncodable(password); err != nil {
		return Config{}, fmt.Errorf("%w (supplied via %s)", err, passwordChannel(source))
	}
	logPasswordDelivery(source, password, blankSecretFile)

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

// checkPasswordEncodable rejects password shapes PKCS#12 cannot preserve. The empty
// password is not one of them — InspectPasswordEncoding reports it as encodable — so
// this gate accepts it and PFX_ALLOW_EMPTY_PASSWORD owns whether it may be used.
//
// A startup refusal rather than a warning: a non-BMP rune fails every Encode, so the
// container would be unhealthy on every tick, while invalid UTF-8 (each bad byte
// becomes U+FFFD) and an embedded NUL (PKCS#12 passwords are NUL-terminated) both
// SUCCEED and report healthy, writing bundles no consumer can open with the
// configured secret.
//
// Only the SHAPE is reported, never the value. Recognition is
// convert.InspectPasswordEncoding's, the same package that encodes, so this gate
// cannot drift from the encoder; which shape is named when a password carries
// several is convert.PasswordEncodingIssues.Primary's, the single home of that
// precedence, so this gate and convert.Encode's own guard cannot disagree.
// This startup gate fails before scanning, while Encode's codec-level guard protects
// callers that bypass config loading — both are wanted.
//
// The switch is exhaustive and fails CLOSED, mirroring convert's
// unencodablePasswordError: PasswordEncodesFine is the explicit success arm, and any
// shape this gate does not recognise is refused rather than accepted by fallthrough.
// No shape escapes today (Primary returns exactly these four), so the default arm is
// unreachable for every current input; it exists so that a future recognised shape
// stops the container at startup instead of silently shipping bundles this gate never
// proved openable.
func checkPasswordEncodable(password string) error {
	switch shape := convert.InspectPasswordEncoding(password).Primary(); shape {
	case convert.PasswordInvalidUTF8:
		return fmt.Errorf("%w: not valid UTF-8, so every invalid byte would be encoded as U+FFFD and generated PFX files would be protected by a different, lower-entropy password than the configured secret; supply a text secret (for example base64) instead of raw binary bytes", ErrUnencodablePassword)
	case convert.PasswordNonBMP:
		return fmt.Errorf("%w: contains a character outside the Basic Multilingual Plane, which PKCS#12 cannot encode, so every conversion would fail; use a password made only of BMP characters (ASCII is safest)", ErrUnencodablePassword)
	case convert.PasswordEmbeddedNUL:
		return fmt.Errorf("%w: contains a NUL byte, and PKCS#12 passwords are NUL-terminated, so generated PFX files could not be opened with any password a consumer can supply; strip NUL bytes from the secret file (a UTF-16 or NUL-padded file is the usual cause)", ErrUnencodablePassword)
	case convert.PasswordEncodesFine:
		return nil
	default:
		return fmt.Errorf("%w: carries encoding shape %q, which this startup gate cannot prove PKCS#12 carries intact; refusing to start rather than writing bundles that may be protected by a different password than the configured secret", ErrUnencodablePassword, shape)
	}
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
			"value", raw, "default", defaultFallbackInterval.String())
	case fallbackAccepted:
		// The configured cadence was used as-is. The explicit "0"/"false"
		// opt-out lands here too and is reported by warnFallbackDisabled, which
		// keys on the interval rather than on the repair.
	}
}

// warnFallbackDisabled warns when the explicit 0/false opt-out removes both
// periodic recovery and the health-marker freshness deadline, because nothing else
// in the process ever will.
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
// opt-out, so repaired blank or invalid values remain enabled and silent here
// (Load's warnFallbackRepaired reports those).
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
		"source", passwordChannel(source),
		"remediation", "remove PFX_PASSWORD from the environment so there is one place to change the secret")
}

// warnBlankPasswordFilePointer warns when PFX_PASSWORD_FILE is present in the
// environment but blank — set to the empty string, or to whitespace only — so it
// names no secret file. A compose "${PFX_PASSWORD_FILE:-}" whose source variable is
// undefined produces exactly this shape.
//
// envx gates the file channel on a NON-EMPTY pointer, so an empty one is
// indistinguishable from unset and resolution silently falls through to
// PFX_PASSWORD: the file-wins rule the deployment relies on quietly inverts and
// warnBothPasswordChannels cannot fire (it keys on source == SourceFile). A
// whitespace-only pointer is opened as a filename instead: it names the file
// channel, so PFX_PASSWORD is never consulted, and startup normally fails with
// envx's "no such file or directory" for a filename made of spaces. The WARN is
// emitted before resolution so it precedes both outcomes.
//
// Deliberately a warning, not a refusal: an empty pointer resolving through
// PFX_PASSWORD is envx's documented rule (SecretWithSource's non-empty gate, whose
// caller contract envx.IsBlankSecretFilePath documents), and refusing here would
// break a deployment that materialises the variable empty on purpose.
//
// The blank-pointer detection itself is envx's: it owns the KEY_FILE naming and the
// whitespace-counts-as-blank rule, so asking it is what keeps this diagnostic from
// disagreeing with the resolver it exists to explain.
func warnBlankPasswordFilePointer() {
	if !envx.IsBlankSecretFilePath("PFX_PASSWORD") {
		return
	}
	outcome := "the PFX password is taken from PFX_PASSWORD instead"
	if os.Getenv("PFX_PASSWORD_FILE") != "" {
		// A whitespace-only pointer is non-empty to envx, so it IS the file
		// channel: envx treats the raw value as a filename rather than falling
		// back. Whether opening it then fails is up to the filesystem, so the
		// outcome states the channel choice, which is the part that is certain.
		outcome = "the whitespace value is treated as a filename instead of falling back to PFX_PASSWORD"
	}
	slog.Warn("PFX_PASSWORD_FILE is set but blank, so it names no secret file; "+outcome,
		"remediation", "unset PFX_PASSWORD_FILE to configure the secret through PFX_PASSWORD, "+
			"or point it at the mounted secret file (a compose ${PFX_PASSWORD_FILE:-} whose source variable is undefined is the usual cause)")
}

// passwordChannel names the environment variable an operator must edit to change the
// configured PFX password. A startup refusal that always named PFX_PASSWORD sent an
// operator using a mounted secret to a variable the file-wins rule ignores.
//
// It is also the single rendering of the "source" log attribute, so every
// operator-facing password record — the both-channels WARN, the blank-file WARN, the
// configured INFO, the surrounding-whitespace WARN, the control-character and
// invisible-formatting WARNs, and the ambiguous-space WARN — carries
// ONE vocabulary in that key: the variable name. Rendering envx's internal
// SourceEnv/SourceFile enum instead would make a Loki matcher or a saved query
// selecting the mounted-secret channel (source="PFX_PASSWORD_FILE") silently miss the
// records that explain an unopenable bundle.
func passwordChannel(source envx.SecretSource) string {
	if source == envx.SourceFile {
		return "PFX_PASSWORD_FILE"
	}
	return "PFX_PASSWORD"
}

// warnPasswordStrength warns when the password offers no real protection. Every
// other configuration warning is emitted from Load's package, so this one is too:
// a new PasswordStatus cannot gain a case without its warning being considered in
// the same edit.
//
// blankFileReported suppresses the duplicate generic guidance because
// logPasswordDelivery already emitted channel-specific remediation for a blank
// PFX_PASSWORD_FILE — the generic line's "point PFX_PASSWORD_FILE at a mounted
// secret" names a step the operator has already taken. Only PasswordEmpty can be
// reached that way: envx trims a file secret, so a whitespace-only file arrives as
// ErrBlankSecretFile with an empty password.
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

// logPasswordDelivery reports the resolved source and actionable delivery problems
// without logging the password or the steady-state secret path: a blank mounted
// secret the opt-out let through, and whitespace or control characters that
// silently become part of the password. The both-channels conflict is reported by
// Load itself, before the guards that can refuse to start, so a refusal never sends
// the operator to the variable the file-wins rule ignores.
//
// The source is the one envx reported rather than one re-derived here, so the log
// cannot disagree with what was read, and an operator can confirm a mounted secret
// was consumed instead of falling back to PFX_PASSWORD. It is rendered through
// passwordChannel, not as envx's SourceEnv/SourceFile enum, so the "source" attribute
// carries the same variable-name vocabulary on every record this package emits about
// the password. The configured path is
// omitted from these steady-state lines so a healthy startup does not publish the
// secret-mount topology to every aggregator; a startup FAILURE is the deliberate
// exception, because an unusable secret file cannot be diagnosed without it.
func logPasswordDelivery(source envx.SecretSource, password string, blankSecretFile error) {
	if source == envx.SourceFile {
		if blankSecretFile != nil {
			slog.Warn("PFX_PASSWORD_FILE is blank; starting with an empty PFX password because PFX_ALLOW_EMPTY_PASSWORD is set",
				"source", passwordChannel(source),
				"remediation", "write the secret into the mounted file so generated PFX files protect the private key")
		} else {
			slog.Info("PFX password configured", "source", passwordChannel(source))
		}
	}
	if source == envx.SourceEnv && !isBlank(password) &&
		password != strings.TrimSpace(password) {
		slog.Warn("PFX_PASSWORD has leading or trailing whitespace, which is part of the password embedded in every PFX file",
			"source", passwordChannel(source),
			"remediation", "remove the surrounding whitespace, or note that PFX_PASSWORD_FILE trims it, so the same value delivered as a mounted secret yields a different password")
	}
	// An INTERIOR control character survives both guards: envx trims only
	// surrounding whitespace, and PKCS#12 encodes a newline or tab verbatim, so
	// checkPasswordEncodable accepts it. The bundle is written, health stays
	// green, and the password cannot be typed into the consumers that need it.
	// A blank value is skipped: warnPasswordStrength already reports it, with the
	// remediation that helps (set a real password) rather than this one's.
	if !isBlank(password) && strings.ContainsFunc(password, unicode.IsControl) {
		slog.Warn("the PFX password contains a control character (newline, carriage return, or tab), which is embedded verbatim in every PFX file and cannot be typed into most PKCS#12 consumers",
			"source", passwordChannel(source),
			"remediation", "supply the secret on a single line (openssl rand -base64 wraps at 64 columns; add -A) so whatever opens the .pfx can reproduce the password")
	}
	// An invisible FORMAT character survives every guard above: it is valid UTF-8,
	// inside the BMP, not a NUL, not a control character, and not whitespace, so
	// envx does not trim it and checkPasswordEncodable accepts it. A UTF-8 BOM left
	// by an editor that saved the mounted secret as "UTF-8 with BOM", or a
	// zero-width space pasted from a web page, therefore becomes part of the
	// password with nothing to show for it: the bundle is written, health stays
	// green, and the .pfx cannot be opened with the secret's visible contents.
	if !isBlank(password) && strings.ContainsFunc(password, isFormatRune) {
		slog.Warn("the PFX password contains an invisible Unicode formatting character (byte-order mark, zero-width space, or soft hyphen), which is embedded verbatim in every PFX file and cannot be reproduced from the secret's visible contents",
			"source", passwordChannel(source),
			"remediation", "rewrite the secret without the invisible character (an editor saving the secret file as \"UTF-8 with BOM\" is the usual cause; printf %s writes the value verbatim)")
	}
	// A non-ASCII SPACE survives every guard above: U+00A0, U+2007 and U+3000 are
	// Zs, U+2028/U+2029 are Zl/Zp, none of them is Cc or Cf, and TrimSpace only
	// reaches the ends, so an interior one is embedded verbatim while rendering
	// exactly like the ASCII space a consumer retypes.
	if !isBlank(password) && strings.ContainsFunc(password, isAmbiguousSpaceRune) {
		slog.Warn("the PFX password contains a non-ASCII space character (no-break space, ideographic space, or line separator), which is embedded verbatim in every PFX file and is indistinguishable from the ordinary space a consumer would type",
			"source", passwordChannel(source),
			"remediation", "retype the secret using ordinary ASCII spaces (a value pasted from a rendered document, a PDF, or a word processor is the usual cause)")
	}
}

// isFormatRune reports whether r is a Unicode FORMAT character (category Cf): a
// byte-order mark, a zero-width space, a soft hyphen, or a word joiner. Kept
// separate from unicode.IsControl, whose category (Cc) is disjoint from this one,
// so a password carrying both shapes gets one record per shape rather than two
// records about the same rune.
func isFormatRune(r rune) bool {
	return unicode.Is(unicode.Cf, r)
}

// isAmbiguousSpaceRune reports whether r is a space-like rune other than the ASCII
// space: a Zs no-break/figure/ideographic space, or a Zl/Zp line or paragraph
// separator. Disjoint from unicode.IsControl (Cc) and isFormatRune (Cf), so a
// password carrying several shapes gets one record per shape; strings.TrimSpace
// removes these only at the ends, so an interior one reaches the encoder unseen.
func isAmbiguousSpaceRune(r rune) bool {
	return r != ' ' && (unicode.Is(unicode.Zs, r) ||
		unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r))
}

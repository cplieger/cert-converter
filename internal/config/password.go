package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"unicode"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/envx"
)

// ErrEmptyPassword indicates the resolved PFX password is blank — empty, entirely
// Unicode whitespace, or entirely invisible formatting runes — and the
// PFX_ALLOW_EMPTY_PASSWORD opt-out is not set. Such a password provides no
// meaningful protection for the embedded private key: nobody can reproduce it from
// the secret's visible contents.
var ErrEmptyPassword = errors.New(
	"the resolved PFX password is empty or blank (whitespace-only, or invisible formatting characters only); " +
		"set PFX_PASSWORD, write a non-blank secret " +
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
	// PasswordInvisibleOnly means the password consists only of invisible runes
	// and at least one of them is invisible rather than whitespace — a format
	// character, a variation selector, or another default-ignorable code point: a
	// secret file holding nothing but a byte-order mark an editor added, or a
	// pasted zero-width space. It is as unusable as a whitespace-only password —
	// nobody can retype it from the secret's visible contents — so it is
	// classified as blank rather than configured.
	PasswordInvisibleOnly PasswordStatus = "invisible-only"
	// PasswordConfigured means a real password was supplied.
	PasswordConfigured PasswordStatus = "configured"
)

// classifyPassword classifies a PFX password ONCE, and is the single home for the
// blank-password predicate: Load's empty-password guard, Load's weak-password
// WARN, and the Config.PasswordStatus the startup log reports all derive their
// decision from it, so they cannot drift.
//
// The order of the arms is the precedence: a password made only of whitespace stays
// PasswordWhitespaceOnly (its own WARN names the stray-quote cause), and
// PasswordInvisibleOnly is reserved for a value that survives TrimSpace yet still
// carries nothing an operator can see or retype.
func classifyPassword(password string) PasswordStatus {
	switch {
	case password == "":
		return PasswordEmpty
	case strings.TrimSpace(password) == "":
		return PasswordWhitespaceOnly
	case isInvisibleOnly(password):
		return PasswordInvisibleOnly
	default:
		return PasswordConfigured
	}
}

// isInvisibleOnly reports whether every rune of a non-empty password is invisible:
// whitespace, or a rune that renders as nothing — a Unicode FORMAT character (Cf)
// such as a byte-order mark, a zero-width space or a soft hyphen, a variation
// selector, or another default-ignorable code point.
//
// This is the shape TrimSpace cannot see. A secret file an editor saved as "UTF-8
// with BOM" and nothing else, or a value that is one pasted zero-width space, is
// valid UTF-8, inside the BMP, not a NUL and not whitespace, so every other guard
// accepts it — and the resulting bundle is protected by a password nobody can
// reproduce from the file's visible (empty) contents. Invalid UTF-8 decodes as
// U+FFFD, which is neither space nor invisible, so a binary secret stays configured.
func isInvisibleOnly(password string) bool {
	return !strings.ContainsFunc(password, func(r rune) bool {
		return !unicode.IsSpace(r) && !isInvisibleRune(r)
	})
}

// isBlank reports whether a password offers no real protection: empty, entirely
// Unicode whitespace, or entirely invisible formatting runes.
//
// This is the single blankness rule for BOTH delivery channels, so
// PFX_ALLOW_EMPTY_PASSWORD means one thing regardless of how the secret arrived.
// PFX_PASSWORD=" " (a quoting slip in a compose file or .env) is therefore REJECTED:
// README documents the guard as refusing to start when the password is empty, which an
// operator reasonably reads as covering a blank value. A BOM-only secret file is
// rejected for the same reason — it is blank to every human who reads it, and only
// the opt-out may start a container with it.
func isBlank(password string) bool {
	return classifyPassword(password) != PasswordConfigured
}

// allowEmptyPassword reports whether PFX_ALLOW_EMPTY_PASSWORD opts out of the
// empty-password guard. Only a literal "true" (trimmed, case-insensitive) opts
// out. Literal "false" is the documented, default-safe spelling and is accepted
// silently — warning on it would fire on every startup of a correctly
// configured deployment — while any other non-empty value warns and is treated
// as false, because the literal-true contract deliberately rejects 1/yes/on.
//
// A pure parse: it emits no log records, so a second caller cannot turn a
// once-per-start line into one per call; warnUnrecognizedAllowEmptyPassword owns the
// diagnostic, exactly as Load owns every other setting's.
func allowEmptyPassword(raw string) (allow, recognized bool) {
	trimmed := strings.TrimSpace(raw)
	switch {
	case strings.EqualFold(trimmed, "true"):
		return true, true
	case trimmed == "" || strings.EqualFold(trimmed, envFalseValue):
		// The documented, default-safe spellings: accepted silently, because
		// warning on them would fire on every startup of a correct deployment.
		return false, true
	default:
		return false, false
	}
}

// warnUnrecognizedAllowEmptyPassword reports a PFX_ALLOW_EMPTY_PASSWORD value that is neither
// spelling of the documented contract, which deliberately rejects 1/yes/on, so an operator who
// wrote one of those learns the guard is still armed. Called only from Load, so it fires once per
// process start and never from the `health` subcommand.
func warnUnrecognizedAllowEmptyPassword(raw string, recognized bool) {
	if recognized {
		return
	}
	slog.Warn("unrecognized PFX_ALLOW_EMPTY_PASSWORD, treating as false",
		"value", strings.TrimSpace(raw), "expected", "true or false")
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
// precedence; and the sentence describing it is
// convert.PasswordEncodingIssue.Explain's, the single home of that wording. So this
// gate and convert.Encode's own guard cannot disagree on either the shape or the
// advice, and this gate contributes only its own sentinel.
// This startup gate fails before scanning, while Encode's codec-level guard protects
// callers that bypass config loading — both are wanted.
//
// Explain fails CLOSED, so a future recognised shape stops the container at startup
// instead of silently shipping bundles this gate never proved openable; no shape
// escapes today (Primary returns exactly the four Explain covers).
func checkPasswordEncodable(password string) error {
	if why := convert.InspectPasswordEncoding(password).Primary().Explain(); why != "" {
		return fmt.Errorf("%w: %s", ErrUnencodablePassword, why)
	}
	return nil
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
// channel names the variable that delivered the secret (passwordChannel's single
// rendering), because PasswordInvisibleOnly is reachable through BOTH channels —
// envx judges a secret file blank on its whitespace-trimmed content and a BOM is not
// whitespace, so a BOM-only mounted secret arrives here as a non-blank file with an
// invisible-only value.
//
// blankFileReported suppresses the duplicate generic guidance because
// logPasswordDelivery already emitted channel-specific remediation for a blank
// PFX_PASSWORD_FILE — the generic line's "point PFX_PASSWORD_FILE at a mounted
// secret" names a step the operator has already taken. Only PasswordEmpty can be
// reached that way: envx judges a secret file blank on its whitespace-trimmed
// content, so a whitespace-only file arrives as ErrBlankSecretFile with an empty
// password.
func warnPasswordStrength(status PasswordStatus, channel string, blankFileReported bool) {
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
	case PasswordInvisibleOnly:
		// The one record for this shape: an invisible-only password is blank, so
		// logPasswordDelivery's per-shape rune WARNs are not reached and this line
		// carries their remediation. Only emitted when PFX_ALLOW_EMPTY_PASSWORD let
		// the value through — without the opt-out the guard refuses to start.
		slog.Warn("the PFX password consists only of invisible Unicode formatting characters (byte-order mark, zero-width space, or soft hyphen); generated PFX files are protected by a password nobody can reproduce from the secret's visible contents",
			"source", channel,
			"remediation", "rewrite the secret without the invisible characters (an editor saving the secret file as \"UTF-8 with BOM\" is the usual cause; printf %s writes the value verbatim)")
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
// exception, because an unusable secret file cannot be diagnosed without it. It takes
// the blank-file fact as a bool rather than the envx error, so the path it must not
// publish is not in scope at all.
func logPasswordDelivery(source envx.SecretSource, password string, status PasswordStatus, blankSecretFile bool) {
	// Derived from the one classification rather than recomputed, so the INFO can
	// never report "configured" for a value the guard treats as blank.
	blank := status != PasswordConfigured
	if source == envx.SourceFile {
		switch {
		case blankSecretFile:
			slog.Warn("PFX_PASSWORD_FILE is blank; starting with an empty PFX password because PFX_ALLOW_EMPTY_PASSWORD is set",
				"source", passwordChannel(source),
				"remediation", "write the secret into the mounted file so generated PFX files protect the private key")
		case blank:
			// A mounted secret envx did not consider blank but this package does —
			// today only an invisible-only value (envx judges blankness on the
			// whitespace-trimmed content, and an invisible rune is not whitespace).
			// Reporting it as configured is the defect the single classification
			// closes; warnPasswordStrength emits the actionable record for the shape.
		default:
			slog.Info("PFX password configured", "source", passwordChannel(source))
		}
	}
	// Channel-agnostic on purpose: envx delivers the configured value verbatim on
	// BOTH channels (a secret file loses at most one trailing line ending and
	// nothing else), so edge whitespace is part of the password however it arrived.
	// While this was gated on the env channel, a padded PFX_PASSWORD_FILE wrote
	// bundles protected by a password nobody can reproduce from the secret's visible
	// contents, with health green and no diagnostic at all.
	if !blank && password != strings.TrimSpace(password) {
		slog.Warn("the PFX password has leading or trailing whitespace, which is part of the password embedded in every PFX file",
			"source", passwordChannel(source),
			"remediation", "remove the surrounding whitespace, or keep it deliberately and reproduce it exactly wherever the .pfx is opened (stray quotes in an env file, or an editor padding the mounted secret, are the usual causes)")
	}
	// A blank value is skipped: warnPasswordStrength already reports it, with the
	// remediation that helps (set a real password, or rewrite the secret without the
	// invisible runes) rather than one per-rune-shape record about a value that
	// carries nothing else.
	if blank {
		return
	}
	warnPasswordCharacters(source, password)
}

// warnPasswordCharacters reports the hard-to-enter runes that survive every
// validation guard. The three predicates cover disjoint Unicode categories, so a
// password carrying several shapes receives one actionable record per shape.
func warnPasswordCharacters(source envx.SecretSource, password string) {
	channel := passwordChannel(source)
	// An INTERIOR control character survives both guards: envx delivers the
	// configured value verbatim on both channels (a secret file loses at most one
	// trailing line ending), and PKCS#12 encodes a newline or tab verbatim, so
	// checkPasswordEncodable accepts it. The bundle is written, health stays
	// green, and the password cannot be typed into the consumers that need it.
	if strings.ContainsFunc(password, unicode.IsControl) {
		slog.Warn("the PFX password contains a control character (newline, carriage return, or tab), which is embedded verbatim in every PFX file and cannot be typed into most PKCS#12 consumers",
			"source", channel,
			"remediation", "supply the secret on a single line (openssl rand -base64 wraps at 64 columns; add -A) so whatever opens the .pfx can reproduce the password")
	}
	// An invisible FORMAT character survives every guard above: it is valid UTF-8,
	// inside the BMP, not a NUL, not a control character, and not whitespace, so
	// envx delivers it verbatim and checkPasswordEncodable accepts it. A UTF-8 BOM left
	// by an editor that saved the mounted secret as "UTF-8 with BOM", or a
	// zero-width space pasted from a web page, therefore becomes part of the
	// password with nothing to show for it: the bundle is written, health stays
	// green, and the .pfx cannot be opened with the secret's visible contents.
	if strings.ContainsFunc(password, isInvisibleRune) {
		slog.Warn("the PFX password contains an invisible Unicode character (byte-order mark, zero-width space, soft hyphen, or variation selector), which is embedded verbatim in every PFX file and cannot be reproduced from the secret's visible contents",
			"source", channel,
			"remediation", "rewrite the secret without the invisible character (an editor saving the secret file as \"UTF-8 with BOM\" is the usual cause; printf %s writes the value verbatim)")
	}
	// A non-ASCII SPACE survives every guard above: U+00A0, U+2007 and U+3000 are
	// Zs, U+2028/U+2029 are Zl/Zp, none of them is Cc or Cf, and neither channel
	// trims the delivered value, so one is embedded verbatim wherever it sits while
	// rendering exactly like the ASCII space a consumer retypes.
	if strings.ContainsFunc(password, isAmbiguousSpaceRune) {
		slog.Warn("the PFX password contains a non-ASCII space character (no-break space, ideographic space, or line separator), which is embedded verbatim in every PFX file and is indistinguishable from the ordinary space a consumer would type",
			"source", channel,
			"remediation", "retype the secret using ordinary ASCII spaces (a value pasted from a rendered document, a PDF, or a word processor is the usual cause)")
	}
}

// isInvisibleRune reports whether r renders as nothing at all. It is Unicode's
// Default_Ignorable_Code_Point set, spelled as the three tables the stdlib exposes:
// a FORMAT character (category Cf - byte-order mark, zero-width space, soft hyphen,
// word joiner), a variation selector (U+FE00-FE0F), or another default-ignorable
// code point (U+034F combining grapheme joiner, U+17B4/U+17B5 Khmer invisible
// vowels, the Hangul fillers).
//
// The general category alone is NOT the set: a variation selector and the combining
// grapheme joiner are category Mn, so a Cf-only test classified a password made only
// of them as a real password and emitted no diagnostic for an interior one. A
// legitimate combining accent (U+0301) is Mn but not default-ignorable, so it stays
// a visible part of a password.
//
// Kept separate from unicode.IsControl, whose category (Cc) is disjoint from this
// set, so a password carrying both shapes gets one record per shape rather than two
// records about the same rune.
func isInvisibleRune(r rune) bool {
	return unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

// isAmbiguousSpaceRune reports whether r is a space-like rune other than the ASCII
// space: a Zs no-break/figure/ideographic space, or a Zl/Zp line or paragraph
// separator. Disjoint from unicode.IsControl (Cc) and isInvisibleRune, so a
// password carrying several shapes gets one record per shape; no delivery channel
// trims the password, so one of these reaches the encoder unseen wherever it sits.
func isAmbiguousSpaceRune(r rune) bool {
	return r != ' ' && (unicode.Is(unicode.Zs, r) ||
		unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r))
}

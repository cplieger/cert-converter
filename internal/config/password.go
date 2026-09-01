package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"unicode"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/envx/v2"
)

// ErrEmptyPassword indicates the resolved PFX password is blank — empty, entirely
// Unicode whitespace, or entirely invisible formatting runes — and the
// PFX_ALLOW_EMPTY_PASSWORD opt-out is not set.
var ErrEmptyPassword = errors.New(
	"the resolved PFX password is empty or blank (whitespace-only, or invisible formatting characters only); " +
		"set PFX_PASSWORD, write a non-blank secret " +
		"to the file named by PFX_PASSWORD_FILE, or set PFX_ALLOW_EMPTY_PASSWORD=true",
)

// ErrUnencodablePassword indicates the configured password contains invalid UTF-8,
// a non-BMP rune, or an embedded NUL and cannot be represented safely by PKCS#12.
var ErrUnencodablePassword = errors.New("the configured PFX password cannot be encoded by PKCS#12")

// PasswordStatus is a non-secret classification of how well the resolved PFX password
// protects the private key inside every generated PFX file.
type PasswordStatus string

// The PFX password classifications reported by classifyPassword.
const (
	// PasswordEmpty means the resolved password is empty.
	PasswordEmpty PasswordStatus = "empty"
	// PasswordWhitespaceOnly means the password consists only of whitespace,
	// which is effectively no protection.
	PasswordWhitespaceOnly PasswordStatus = "whitespace-only"
	// PasswordInvisibleOnly means the password consists only of invisible runes
	// and at least one of them is invisible rather than whitespace — a format
	// character, a variation selector, or another default-ignorable code point: a
	// secret file holding nothing but a byte-order mark an editor added, or a
	// pasted zero-width space.
	PasswordInvisibleOnly PasswordStatus = "invisible-only"
	// PasswordConfigured means a real password was supplied.
	PasswordConfigured PasswordStatus = "configured"
)

// resolvedPassword is the outcome of the PFX-password channel resolution: the value, its
// classification, the variable an operator must edit to change it, and whether a blank
// secret FILE is what the opt-out let through (suppresses warnPasswordStrength's generic
// guidance).
type resolvedPassword struct {
	Value     string
	Status    PasswordStatus
	Channel   string
	BlankFile bool
}

// resolvePassword resolves the PFX password from the two channels, classifies it once, and
// applies both startup refusals.
func resolvePassword() (resolvedPassword, error) {
	var blankSecretFile error
	// An EMPTY PFX_PASSWORD_FILE is not the file channel at all, so neither
	// warnBothPasswordChannels nor envx's own error can report it.
	warnBlankPasswordFilePointer()
	password, source, secretErr := envx.SecretWithSource("PFX_PASSWORD")
	// Every startup refusal below names PFX_PASSWORD; this line says the file wins
	// when both channels are set, or the refusal points at the ignored variable.
	warnBothPasswordChannels(source)
	channel := passwordChannel(source)
	if secretErr != nil {
		var missing *envx.MissingError
		switch {
		case errors.As(secretErr, &missing):
			password = ""
		case errors.Is(secretErr, envx.ErrBlankSecretFile):
			// Route through the same opt-out as a blank environment value, so
			// PFX_ALLOW_EMPTY_PASSWORD means one thing on both channels.
			password, blankSecretFile = "", secretErr
		default:
			return resolvedPassword{}, secretErr
		}
	}
	status := classifyPassword(password)
	rawAllowEmpty := os.Getenv("PFX_ALLOW_EMPTY_PASSWORD")
	allowEmpty, allowEmptyRecognized := allowEmptyPassword(rawAllowEmpty)
	warnUnrecognizedAllowEmptyPassword(rawAllowEmpty, allowEmptyRecognized)
	// Asked before the blank guard: the invisible-rune class includes the
	// supplementary variation selectors (U+E0100-U+E01EF), which are non-BMP and so
	// unencodable by PKCS#12 regardless of blankness.
	if err := checkPasswordEncodable(password); err != nil {
		return resolvedPassword{}, fmt.Errorf("%w (supplied via %s)", err, channel)
	}
	if status != PasswordConfigured && !allowEmpty {
		switch {
		case blankSecretFile != nil:
			return resolvedPassword{}, fmt.Errorf("%w: %w", ErrEmptyPassword, blankSecretFile)
		case source == envx.SourceFile:
			// An invisible-only mounted secret is blank only after
			// classification, so envx carries no error naming the channel here.
			return resolvedPassword{}, fmt.Errorf("%w (supplied via %s)", ErrEmptyPassword, channel)
		}
		return resolvedPassword{}, ErrEmptyPassword
	}
	logPasswordDelivery(source, password, status, blankSecretFile != nil)
	return resolvedPassword{
		Value:     password,
		Status:    status,
		Channel:   channel,
		BlankFile: blankSecretFile != nil,
	}, nil
}

// classifyPassword is the single home for the blank-password predicate: every consumer
// (the empty-password guard, the weak-password WARN, the startup status line, the
// both-channels WARN) derives from it, so they cannot drift.
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
func isInvisibleOnly(password string) bool {
	return !strings.ContainsFunc(password, func(r rune) bool {
		return !unicode.IsSpace(r) && !isInvisibleRune(r)
	})
}

// allowEmptyPassword reports whether PFX_ALLOW_EMPTY_PASSWORD opts out of the
// empty-password guard.
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

// warnUnrecognizedAllowEmptyPassword reports a PFX_ALLOW_EMPTY_PASSWORD value that
// matches neither documented spelling (1/yes/on are deliberately rejected).
func warnUnrecognizedAllowEmptyPassword(raw string, recognized bool) {
	if recognized {
		return
	}
	slog.Warn("unrecognized PFX_ALLOW_EMPTY_PASSWORD, treating as false",
		"value", rejectedValue(strings.TrimSpace(raw)), "expected", "true or false")
}

// checkPasswordEncodable rejects password shapes PKCS#12 cannot preserve.
func checkPasswordEncodable(password string) error {
	if err := convert.ValidatePasswordEncoding(password); err != nil {
		return fmt.Errorf("%w: %s", ErrUnencodablePassword, err)
	}
	return nil
}

// warnBothPasswordChannels warns when the operator supplied the PFX password through
// BOTH channels, because only one of them takes effect.
func warnBothPasswordChannels(source envx.SecretSource) {
	if source != envx.SourceFile || classifyPassword(os.Getenv("PFX_PASSWORD")) != PasswordConfigured {
		return
	}
	slog.Warn("both PFX_PASSWORD and PFX_PASSWORD_FILE are set; the file wins and PFX_PASSWORD is ignored",
		"source", passwordChannel(source),
		"remediation", "remove PFX_PASSWORD from the environment so there is one place to change the secret")
}

// warnBlankPasswordFilePointer warns when PFX_PASSWORD_FILE is present but blank (empty
// or whitespace-only), so it names no usable secret file.
func warnBlankPasswordFilePointer() {
	if !envx.IsBlankSecretFilePath("PFX_PASSWORD") {
		return
	}
	outcome := "the PFX password is taken from PFX_PASSWORD instead"
	if os.Getenv("PFX_PASSWORD_FILE") != "" {
		// A whitespace-only pointer is non-empty to envx, so it IS the file
		// channel and is used verbatim as a filename rather than falling back.
		outcome = "the whitespace value is treated as a filename instead of falling back to PFX_PASSWORD"
	}
	slog.Warn("PFX_PASSWORD_FILE is set but blank; "+outcome,
		"remediation", "unset PFX_PASSWORD_FILE to configure the secret through PFX_PASSWORD, "+
			"or point it at the mounted secret file (a compose ${PFX_PASSWORD_FILE:-} whose source variable is undefined is the usual cause)")
}

// passwordChannel names the environment variable an operator must edit to change the
// configured PFX password.
func passwordChannel(source envx.SecretSource) string {
	if source == envx.SourceFile {
		return "PFX_PASSWORD_FILE"
	}
	return "PFX_PASSWORD"
}

// warnPasswordStrength warns when the password offers no real protection.
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
		slog.Warn("the PFX password consists only of invisible Unicode formatting characters (byte-order mark, zero-width space, or soft hyphen); generated PFX files are protected by a password nobody can reproduce from the secret's visible contents",
			"source", channel,
			"remediation", "rewrite the secret without the invisible characters (an editor saving the secret file as \"UTF-8 with BOM\" is the usual cause; printf %s writes the value verbatim)")
	case PasswordConfigured:
		// The healthy case: the value is a secret, so nothing beyond the
		// non-secret status in the startup line is logged.
	}
}

// logPasswordDelivery reports the resolved source and actionable delivery problems
// without logging the password itself.
func logPasswordDelivery(source envx.SecretSource, password string, status PasswordStatus, blankSecretFile bool) {
	blank := status != PasswordConfigured
	if source == envx.SourceFile {
		switch {
		case blankSecretFile:
			slog.Warn("PFX_PASSWORD_FILE is blank; starting with an empty PFX password because PFX_ALLOW_EMPTY_PASSWORD is set",
				"source", passwordChannel(source),
				"remediation", "write the secret into the mounted file so generated PFX files protect the private key")
		case blank:
			// An invisible-only value: envx judges blankness on trimmed content,
			// and an invisible rune is not whitespace, so no envx warning fires.
		default:
			slog.Info("PFX password configured", "source", passwordChannel(source))
		}
	}
	// warnPasswordStrength already reports a blank value with its own remediation.
	if blank {
		return
	}
	// Channel-agnostic: envx delivers the configured value verbatim on both
	// channels, so edge whitespace is part of the password however it arrived.
	if password != strings.TrimSpace(password) {
		slog.Warn("the PFX password has leading or trailing whitespace, which is part of the password embedded in every PFX file",
			"source", passwordChannel(source),
			"remediation", "remove the surrounding whitespace, or keep it deliberately and reproduce it exactly wherever the .pfx is opened (stray quotes in an env file, or an editor padding the mounted secret, are the usual causes)")
	}
}

// isInvisibleRune reports whether r renders as nothing at all.
func isInvisibleRune(r rune) bool {
	return unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

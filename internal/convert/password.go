package convert

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// passwordEncodingIssues reports the ways a PFX password cannot survive the
// PKCS#12 BMPString (UCS-2) password encoding (RFC 7292 appendix B.1).
type passwordEncodingIssues struct {
	// InvalidUTF8 means the password is not valid UTF-8, so every invalid byte
	// is encoded as U+FFFD and the PFX ends up protected by a different,
	// lower-entropy password than the configured secret.
	InvalidUTF8 bool
	// NonBMP means the password holds a rune above U+FFFF, which UCS-2 cannot
	// represent at all, so every Encode call fails.
	NonBMP bool
	// EmbeddedNUL means the password contains U+0000. PKCS#12 passwords are
	// NUL-terminated BMPStrings (RFC 7292 appendix B.1), and go-pkcs12 encodes
	// an interior NUL verbatim before appending its own terminator, so no
	// consumer that builds the BMPString from a NUL-terminated string
	// (OpenSSL, Windows CryptoAPI) can reproduce the key-derivation input.
	EmbeddedNUL bool
}

// why says why the PKCS#12 UCS-2 password encoding cannot carry this password
// intact, or "" when it can.
func (i passwordEncodingIssues) why() string {
	switch {
	case i.InvalidUTF8:
		return "is not valid UTF-8, so the PKCS#12 UCS-2 password encoding would " +
			"replace every invalid byte with U+FFFD and protect the bundle with a " +
			"different, lower-entropy password than the one supplied; supply a text " +
			"secret (for example base64) instead of raw binary bytes"
	case i.NonBMP:
		return "contains a character outside the Basic Multilingual Plane, which the " +
			"PKCS#12 UCS-2 password encoding cannot represent, so every encode would " +
			"fail; choose a password made of BMP characters (ASCII is safest)"
	case i.EmbeddedNUL:
		return "contains a NUL byte, and PKCS#12 passwords are NUL-terminated, so no " +
			"consumer that builds the terminated BMPString itself could open the bundle " +
			"with the password supplied; strip NUL bytes from the secret (a UTF-16 or " +
			"NUL-padded secret file is the usual cause)"
	}
	return ""
}

// inspectPasswordEncoding reports how a PFX password fares under the PKCS#12
// UCS-2 password encoding.
func inspectPasswordEncoding(password string) passwordEncodingIssues {
	issues := passwordEncodingIssues{
		InvalidUTF8: !utf8.ValidString(password),
		EmbeddedNUL: strings.ContainsRune(password, 0),
	}
	for _, r := range password {
		if r > 0xFFFF {
			issues.NonBMP = true
			break
		}
	}
	return issues
}

// ValidatePasswordEncoding reports why the PKCS#12 UCS-2 password encoding
// (RFC 7292 appendix B.1) cannot carry password intact, or nil when it can.
func ValidatePasswordEncoding(password string) error {
	if why := inspectPasswordEncoding(password).why(); why != "" {
		return errors.New(why)
	}
	return nil
}

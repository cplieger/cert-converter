package convert

import (
	"crypto"
	"errors"
	"fmt"
)

// Encode produces the PKCS#12 bytes for an analysed certificate/key pair.
//
// It is pure: bytes in, bytes out, no filesystem and no *os.Root. The confined
// atomic write that used to be bolted onto the end of this operation belongs to
// whoever owns the output tree, which is internal/process; this package is a codec
// and never learns where its input came from or where its output goes.
//
// The bag order the encoder produces is the order Analysis defines: the leaf's
// bag first, then Chain nearest-parent-first. That is a contract rather than an
// implementation detail — PKCS#12 stores an ordered SEQUENCE of bags (RFC 7292
// §4.2) and decoders read it positionally, go-pkcs12's own DecodeChain included.
// The Analysis is taken by pointer only because the struct is large enough that
// copying it per call is wasteful (gocritic hugeParam); Encode does not mutate it.
func Encode(a *Analysis, encName EncoderType, password string) ([]byte, error) {
	// Defensive: config.Load rejects a password PKCS#12 cannot represent at
	// startup, so this should be unreachable in production. It stays because a
	// password delivered by file can be rotated at runtime, and because an
	// exported entry point should not depend on a caller having validated for it.
	if InspectPasswordEncoding(password).NonBMP {
		return nil, errors.New("pfx password contains a character outside the Basic Multilingual Plane, " +
			"which the PKCS#12 UCS-2 password encoding cannot represent; " +
			"choose a password made of BMP characters (ASCII is safest)")
	}

	pfxData, err := encoderFor(encName).Encode(a.Key, a.Leaf, a.Chain, password)
	if err != nil {
		return nil, fmt.Errorf("encode pfx: %w", err)
	}
	return pfxData, nil
}

// maxSubjectLogLen bounds the certificate-controlled subject interpolated into a
// diagnostic. The subject is parsed out of a PEM file the app does not control
// and is capped only by the reader's size limit, so an unbounded interpolation
// puts a multi-megabyte line into the logs of every scan that retries the pair.
const maxSubjectLogLen = 256

// boundSubject truncates a certificate subject to maxSubjectLogLen bytes for a
// log-bound diagnostic, dropping the partial rune the cut may leave behind so
// the %q form stays readable. It is a named alias for the package's shared
// boundLogText rule.
func boundSubject(subject string) string {
	return boundLogText(subject, maxSubjectLogLen)
}

// publicKeyMatches reports whether pub is the public half of signer's private
// key. supported is false when pub's type does not provide the
// Equal(crypto.PublicKey) bool method every crypto/x509 public key type
// implements, in which case matched carries no meaning and the caller must treat
// the key type as unverifiable rather than as a mismatch.
func publicKeyMatches(pub crypto.PublicKey, signer crypto.Signer) (matched, supported bool) {
	matcher, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false, false
	}
	return matcher.Equal(signer.Public()), true
}

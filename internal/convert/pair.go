package convert

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
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
	// startup and the password is read once there (a rotated PFX_PASSWORD_FILE
	// takes effect only on restart), so this is unreachable in production. It
	// stays because an exported entry point should not depend on a caller having
	// validated for it.
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

// Decoded is what a previously written PFX yields when read back.
type Decoded struct {
	// Leaf is the end-entity certificate stored in the first bag.
	Leaf *x509.Certificate
	// Key is the private key stored alongside it.
	Key crypto.PrivateKey
	// CACerts are the remaining certificate bags, in stored order. They are
	// returned rather than discarded because a currency check that compared only
	// the leaf and key would report a bundle as up to date after an intermediate
	// was renewed, a chain was corrected, or a cross-sign was replaced.
	CACerts []*x509.Certificate
}

// Decode reads a PKCS#12 bundle back into its parts.
//
// It exists so the output tree's owner can answer "is the file on disk still the
// right bundle for these inputs?" by reading the file rather than by remembering
// what it wrote. Decoding is codec work, so it belongs here; deciding what the
// answer means belongs to the caller.
//
// A decode failure is a legitimate, expected outcome — a rotated password, a
// truncated file, a foreign file at that path — and is NOT diagnosed further. The
// library's ErrIncorrectPassword also fires on a MAC failure from corruption, so
// "wrong password" and "damaged file" are not distinguishable, and the caller
// needs the same response either way: treat the output as stale and rewrite it.
func Decode(pfx []byte, password string) (Decoded, error) {
	key, leaf, caCerts, err := pkcs12.DecodeChain(pfx, password)
	if err != nil {
		return Decoded{}, fmt.Errorf("decode pfx: %w", err)
	}
	return Decoded{Leaf: leaf, Key: key, CACerts: caCerts}, nil
}

// MatchesAnalysis reports whether d is the bundle a would produce: the same
// end-entity certificate, the same private key, and the same chain in the same
// order.
//
// Order is compared, not just membership, because PKCS#12 stores an ordered
// SEQUENCE of bags (RFC 7292 §4.2) and decoders read it positionally. A bundle
// whose chain is correct but differently ordered is not the bundle this app emits
// today, and rewriting it makes the output match its own contract.
//
// Encoder profile is deliberately outside this method because Decoded contains
// only decoded material, not the algorithm identifiers. A currency caller must
// compare Inspect(pfx).Profile with the configured EncoderType before Decode and
// MatchesAnalysis; internal/process.store.isCurrent performs that sequence so a
// PFX_ENCODER change triggers a rewrite.
func (d Decoded) MatchesAnalysis(a *Analysis) bool {
	if d.Leaf == nil || a.Leaf == nil || !bytes.Equal(d.Leaf.Raw, a.Leaf.Raw) {
		return false
	}
	if len(d.CACerts) != len(a.Chain) {
		return false
	}
	for i := range a.Chain {
		if !bytes.Equal(d.CACerts[i].Raw, a.Chain[i].Raw) {
			return false
		}
	}
	return sameKey(d.Key, a.Key)
}

// sameKey reports whether two private keys are the same key, compared through
// their public halves: every key type crypto/x509 parses is a crypto.Signer, and
// a public half is safe to compare without touching secret material.
func sameKey(a, b crypto.PrivateKey) bool {
	sa, aok := a.(crypto.Signer)
	sb, bok := b.(crypto.Signer)
	if !aok || !bok {
		return false
	}
	return samePublicKey(sa.Public(), sb.Public())
}

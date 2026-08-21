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
func (a Analysis) Encode(encName EncoderType, password string) ([]byte, error) { //nolint:gocritic // hugeParam: the value Analyse hands back cannot be nil, so this body needs no nil arm; the 96-byte copy is noise beside the PBKDF2 that follows it.
	// Defensive, and deliberately NOT redundant with internal/config's
	// checkPasswordEncodable: both guards are wanted, and neither is the only line
	// of defence.
	if err := unencodablePasswordError(password); err != nil {
		return nil, err
	}

	enc := resolvedProfile(encName).encoder
	pfxData, err := enc.Encode(a.key, a.leaf, a.chain, password)
	if err != nil {
		return nil, fmt.Errorf("encode pfx: %w", boundedTextError{err})
	}
	return pfxData, nil
}

// unencodablePasswordError reports why the PKCS#12 UCS-2 password encoding
// (RFC 7292 appendix B.1) cannot carry password intact, or nil when it can.
func unencodablePasswordError(password string) error {
	if err := ValidatePasswordEncoding(password); err != nil {
		return errors.New("pfx password " + err.Error())
	}
	return nil
}

// --- Read-back: the currency check ---

// CurrencyReason names WHY an existing bundle is, or is not, the bundle a set of
// inputs would produce.
type CurrencyReason string

// The six outcomes of a currency check.
const (
	// CurrencyMatch: the bundle on disk was written by the wanted encoder profile
	// and carries exactly the leaf, key and chain these inputs produce.
	CurrencyMatch CurrencyReason = "match"
	// CurrencyPreflightFailed: the preflight refused to LOOK — the file declares
	// key-derivation work outside the range this app will spend — so nothing about
	// the bytes on disk was established.
	CurrencyPreflightFailed CurrencyReason = "preflight-failed"
	// CurrencyForeign: the preflight PROVED these bytes are not a bundle any of this
	// app's profiles writes, without decoding anything.
	CurrencyForeign CurrencyReason = "foreign"
	// CurrencyProfileMismatch: the preflight identified one of this app's profiles,
	// but not the wanted one — a deliberate PFX_ENCODER change; the bundle has not
	// been decoded.
	CurrencyProfileMismatch CurrencyReason = "profile-mismatch"
	// CurrencyDecodeFailed: the preflight passed but the bundle did not decode — a
	// rotated password, or a well-formed bundle in this profile that another tool wrote.
	// A truncated or foreign file is refused by the preflight instead, before any decode.
	CurrencyDecodeFailed CurrencyReason = "decode-failed"
	// CurrencyContentMismatch: the bundle decoded and its profile matches, but its
	// leaf, key or chain is not what these inputs produce — the ordinary "the
	// certificate was renewed" outcome, which needs no diagnostic of its own.
	CurrencyContentMismatch CurrencyReason = "content-mismatch"
)

// Currency is the outcome of CheckCurrency: the verdict plus the material the
// caller needs to explain it.
type Currency struct {
	// Reason is what the check concluded.
	Reason CurrencyReason
	// Err is the underlying failure for CurrencyPreflightFailed, CurrencyForeign and
	// CurrencyDecodeFailed, for a caller's diagnostic.
	Err error
	// Profile is the encoder profile the existing file was written with, set for
	// CurrencyProfileMismatch so the caller can name found-vs-configured.
	Profile EncoderType
}

// CheckCurrency reports whether pfx is already the bundle this analysis would
// produce under wantEncoder, and when it is not, why.
func (a Analysis) CheckCurrency(pfx []byte, password string, wantEncoder EncoderType) Currency { //nolint:gocritic // hugeParam: same reason as Encode — the value Analyse hands back cannot be nil, so this body needs no nil arm.
	priorProfile, err := inspect(pfx)
	if err != nil {
		return Currency{Reason: refusalReason(err), Err: boundedTextError{err}}
	}
	resolvedWant := resolvedProfile(wantEncoder).name
	if priorProfile != resolvedWant {
		return Currency{Reason: CurrencyProfileMismatch, Profile: priorProfile}
	}
	prior, err := decode(pfx, password)
	if err != nil {
		return Currency{Reason: CurrencyDecodeFailed, Err: err}
	}
	if !prior.matchesAnalysis(a) {
		return Currency{Reason: CurrencyContentMismatch}
	}
	return Currency{Reason: CurrencyMatch}
}

// decoded is what a previously written PFX yields when read back.
type decoded struct {
	// Leaf is the end-entity certificate stored in the first bag.
	Leaf *x509.Certificate
	// Key is the private key stored alongside it.
	Key crypto.PrivateKey
	// CACerts are the remaining certificate bags, in stored order.
	CACerts []*x509.Certificate
}

// decode reads a PKCS#12 bundle back into its parts.
func decode(pfx []byte, password string) (decoded, error) {
	key, leaf, caCerts, err := pkcs12.DecodeChain(pfx, password)
	if err != nil {
		return decoded{}, fmt.Errorf("decode pfx: %w", boundedTextError{err})
	}
	return decoded{Leaf: leaf, Key: key, CACerts: caCerts}, nil
}

// matchesAnalysis reports whether d is the bundle a would produce: the same
// end-entity certificate, the same private key, and the same chain in the same
// order.
func (d decoded) matchesAnalysis(a Analysis) bool { //nolint:gocritic // hugeParam: reached only from CheckCurrency, which already holds the value.
	if !bytes.Equal(d.Leaf.Raw, a.leaf.Raw) {
		return false
	}
	if len(d.CACerts) != len(a.chain) {
		return false
	}
	for i := range a.chain {
		if !bytes.Equal(d.CACerts[i].Raw, a.chain[i].Raw) {
			return false
		}
	}
	return sameKey(d.Key, a.key)
}

// sameKey reports whether the key read back from a bundle is the key the analysis
// holds, compared through their public halves: a public half is safe to compare
// without touching secret material.
func sameKey(decodedKey crypto.PrivateKey, analysed crypto.Signer) bool {
	signer, ok := decodedKey.(crypto.Signer)
	if !ok {
		return false
	}
	return samePublicKey(signer.Public(), analysed.Public())
}

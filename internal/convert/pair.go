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
// bag first, then its chain nearest-parent-first. That is a contract rather than an
// implementation detail — PKCS#12 stores an ordered SEQUENCE of bags (RFC 7292
// §4.2) and decoders read it positionally, go-pkcs12's own DecodeChain included.
// The Analysis is taken by pointer only because the struct is large enough that
// copying it per call is wasteful (gocritic hugeParam); Encode does not mutate it.
func Encode(a *Analysis, encName EncoderType, password string) ([]byte, error) {
	// Defensive, and deliberately NOT redundant with internal/config's
	// checkPasswordEncodable: both guards are wanted, and neither is the only line
	// of defence. config.Load refuses all three unencodable shapes at startup,
	// which is what makes this unreachable in production (the password is read once
	// there, so a rotated PFX_PASSWORD_FILE takes effect only on restart). This
	// guard refuses the same three shapes because an exported entry point should
	// not depend on a caller having validated for it. Do not delete either as
	// duplication: the startup gate fails the container fast for the one production
	// caller, this one holds the codec's own contract for every caller.
	if err := unencodablePasswordError(password); err != nil {
		return nil, err
	}

	// An Analysis is only ever produced by Analyse, which returns an error rather
	// than an incomplete value — but the zero value is constructible, and handing it
	// to the encoder dereferences a nil *x509.Certificate inside go-pkcs12
	// (sha1.Sum(certificate.Raw)), killing the process instead of failing one
	// conversion. The type's own doc promises a caller cannot null the leaf and hand
	// the value back here; this is what makes that true.
	if a.leaf == nil {
		return nil, errors.New("analysed pair carries no leaf certificate, so it did not come from Analyse")
	}

	pfxData, err := encoderFor(encName).Encode(a.key, a.leaf, a.chain, password)
	if err != nil {
		return nil, fmt.Errorf("encode pfx: %w", err)
	}
	return pfxData, nil
}

// unencodablePasswordError reports why the PKCS#12 UCS-2 password encoding
// (RFC 7292 appendix B.1) cannot carry password intact, or nil when it can.
//
// It refuses every shape PasswordEncodingIssues reports, not just the one
// go-pkcs12 refuses on its own. The two the library accepts are the worse
// outcomes: it replaces invalid UTF-8 rune-by-rune and encodes an interior NUL
// verbatim, so in both cases Encode would SUCCEED and write a bundle protected by
// a different password than the one supplied, with the failure surfacing at
// whatever later tries to open it.
//
// Recognition is InspectPasswordEncoding's, so the encoder cannot drift from the
// startup gate that consumes the same query, and which shape is named when a
// password carries several is PasswordEncodingIssues.Primary's, the single home of
// that precedence, so this guard and internal/config's checkPasswordEncodable name
// the same shape for the same password by construction.
//
// Only the SHAPE is named, never the value: these messages reach the container
// log and the password is a secret. No sentinel wraps them because no caller
// branches on the kind — the one production path treats any Encode error as a
// conversion failure, and config.ErrUnencodablePassword (which cannot be reused
// here anyway: internal/config imports this package) exists for callers of Load.
func unencodablePasswordError(password string) error {
	switch InspectPasswordEncoding(password).Primary() {
	case PasswordInvalidUTF8:
		return errors.New("pfx password is not valid UTF-8, so the PKCS#12 UCS-2 password encoding " +
			"would replace every invalid byte with U+FFFD and protect the bundle with a different, " +
			"lower-entropy password than the one supplied; " +
			"supply a text secret (for example base64) instead of raw binary bytes")
	case PasswordNonBMP:
		return errors.New("pfx password contains a character outside the Basic Multilingual Plane, " +
			"which the PKCS#12 UCS-2 password encoding cannot represent; " +
			"choose a password made of BMP characters (ASCII is safest)")
	case PasswordEmbeddedNUL:
		return errors.New("pfx password contains a NUL byte, and PKCS#12 passwords are NUL-terminated, " +
			"so no consumer that builds the terminated BMPString itself could open the bundle with the " +
			"password supplied; strip NUL bytes from the secret " +
			"(a UTF-16 or NUL-padded secret file is the usual cause)")
	}
	return nil
}

// --- Read-back: the currency check ---

// CurrencyReason names WHY an existing bundle is, or is not, the bundle a set of
// inputs would produce. It exists because the caller does not just act on the
// verdict, it narrates it: each value is a distinct diagnosis with its own
// operator meaning, and flattening them into a bare bool would make a deliberate
// PFX_ENCODER switch indistinguishable from a corrupt file.
//
// The zero value is deliberately not CurrencyMatch, so a Currency nobody filled
// in reads as "not current" rather than as a match.
type CurrencyReason string

// The five outcomes of a currency check. Every one that is not CurrencyMatch
// means the same ACTION — rewrite the bundle — and a different diagnosis.
const (
	// CurrencyMatch: the bundle on disk was written by the wanted encoder profile
	// and carries exactly the leaf, key and chain these inputs produce.
	CurrencyMatch CurrencyReason = "match"
	// CurrencyPreflightFailed: the preflight refused the bytes, so nothing was
	// decoded. Either the file is not one this app wrote, or it names a
	// key-derivation iteration count outside the bound. Currency.Err carries the
	// diagnosis; it wraps ErrProfileUnknown when the refusal came from one of this
	// app's own profile rules rather than from the DER parser.
	CurrencyPreflightFailed CurrencyReason = "preflight-failed"
	// CurrencyProfileMismatch: the file is a well-formed bundle from one of this
	// app's profiles, but not the wanted one — a deliberate PFX_ENCODER change.
	// Currency.Profile carries the profile the file was written with.
	CurrencyProfileMismatch CurrencyReason = "profile-mismatch"
	// CurrencyDecodeFailed: the preflight passed but the bundle did not decode — a
	// rotated password, a truncated file, a foreign file at that path. These are
	// not distinguishable from each other (see decode) and need no distinguishing.
	// Currency.Err carries the bounded decode error.
	CurrencyDecodeFailed CurrencyReason = "decode-failed"
	// CurrencyContentMismatch: the bundle decoded and its profile matches, but its
	// leaf, key or chain is not what these inputs produce — the ordinary "the
	// certificate was renewed" outcome, which needs no diagnostic of its own.
	CurrencyContentMismatch CurrencyReason = "content-mismatch"
)

// Currency is the outcome of CheckCurrency: the verdict plus the material the
// caller needs to explain it.
//
// Err is populated for CurrencyPreflightFailed and CurrencyDecodeFailed;
// Profile is populated only for CurrencyProfileMismatch. On the other reasons
// those fields are zero. The verdict is derived from Reason by Current() rather
// than stored, so there is only one thing to get right.
type Currency struct {
	// Reason is what the check concluded.
	Reason CurrencyReason
	// Err is the underlying failure for CurrencyPreflightFailed and
	// CurrencyDecodeFailed, for a caller's diagnostic. Both are expected outcomes
	// rather than faults: the caller's response to either is to rewrite the file.
	Err error
	// Profile is the encoder profile the existing file was written with, set for
	// CurrencyProfileMismatch so the caller can name found-vs-configured.
	Profile EncoderType
}

// Current reports whether the existing bundle needs no rewrite.
func (c Currency) Current() bool { return c.Reason == CurrencyMatch }

// CheckCurrency reports whether pfx is already the bundle want would produce
// under wantEncoder, and when it is not, why.
//
// This is the entire read-back side of the codec behind one call, deliberately.
// Reading an existing bundle safely has a mandatory ORDER:
//
//  1. the preflight (inspect), FIRST, because it bounds every key-derivation
//     iteration count the file itself dictates before any of them can reach
//     PBKDF2, and because it names the encoder profile that decoding cannot
//     reveal (see profile.go maxKDFIterations for exactly what it can and cannot
//     see);
//  2. the profile comparison, before any derivation, so a deliberate
//     PFX_ENCODER change is answered without decrypting anything;
//  3. the decode, whose derivation counts step 1 has now bounded;
//  4. the comparison against want.
//
// That order is a safety invariant of the codec, not a convention for callers to
// remember. It used to live in the one production consumer while this package
// exported the three steps separately, so a second consumer reaching for the
// decode alone would have run an unbounded derivation on counts taken from a file
// under /output. The steps are unexported now, so the order is unbypassable: this
// is the only door, and it always walks them in this sequence. It is the same rule
// the package already applies to parseCertChain, applied to the read-back side.
//
// Nothing here is fatal. Every non-match outcome means "rewrite the file", so a
// parse or decode failure is reported as a reason rather than as an error return;
// the caller owns what a reason is worth and, since this package takes no context,
// owns the shutdown classification too. pfx is never mutated.
//
// The Analysis is taken by pointer only because the struct is large enough that
// copying it per call is wasteful (gocritic hugeParam); CheckCurrency does not
// mutate it.
func CheckCurrency(pfx []byte, password string, want *Analysis, wantEncoder EncoderType) Currency {
	insp, err := inspect(pfx)
	if err != nil {
		return Currency{Reason: CurrencyPreflightFailed, Err: err}
	}
	if insp.Profile != resolvedName(wantEncoder) {
		return Currency{Reason: CurrencyProfileMismatch, Profile: insp.Profile}
	}
	prior, err := decode(pfx, password)
	if err != nil {
		return Currency{Reason: CurrencyDecodeFailed, Err: err}
	}
	if !prior.matchesAnalysis(want) {
		return Currency{Reason: CurrencyContentMismatch}
	}
	return Currency{Reason: CurrencyMatch}
}

// decoded is what a previously written PFX yields when read back.
//
// Unexported like the steps that produce and consume it: CheckCurrency is the
// only way in, so no caller outside this package can hold decoded material
// without having gone through the preflight first.
type decoded struct {
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

// decode reads a PKCS#12 bundle back into its parts.
//
// It exists so the output tree's owner can answer "is the file on disk still the
// right bundle for these inputs?" by reading the file rather than by remembering
// what it wrote. Decoding is codec work, so it belongs here; deciding what the
// answer means belongs to the caller.
//
// It is a step of CheckCurrency rather than an entry point of its own, because it
// must never run before the preflight: the iteration counts it feeds to PBKDF2
// come from the FILE, and inspect is what bounds them (see profile.go
// maxKDFIterations).
//
// A decode failure is a legitimate, expected outcome — a rotated password, a
// truncated file, a foreign file at that path — and is NOT diagnosed further. The
// library's ErrIncorrectPassword also fires on a MAC failure from corruption, so
// "wrong password" and "damaged file" are not distinguishable, and the caller
// needs the same response either way: treat the output as stale and rewrite it.
//
// The library's own message is bounded before it reaches a caller's log, because
// two of its decode diagnostics interpolate an OBJECT IDENTIFIER decoded from the
// bundle (go-pkcs12 v0.7.3: an unhandled safe-bag type, an unknown attribute),
// and a bundle-controlled OID is bounded only by the file size.
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
//
// Order is compared, not just membership, because PKCS#12 stores an ordered
// SEQUENCE of bags (RFC 7292 §4.2) and decoders read it positionally. A bundle
// whose chain is correct but differently ordered is not the bundle this app emits
// today, and rewriting it makes the output match its own contract.
//
// Encoder profile is deliberately outside this method because decoded contains
// only decoded material, not the algorithm identifiers. That comparison is
// CheckCurrency's second step, which is why the profile check cannot be forgotten
// by a caller any more: a PFX_ENCODER change reaches the verdict without anyone
// having to sequence it.
func (d decoded) matchesAnalysis(a *Analysis) bool {
	if d.Leaf == nil || a.leaf == nil || !bytes.Equal(d.Leaf.Raw, a.leaf.Raw) {
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

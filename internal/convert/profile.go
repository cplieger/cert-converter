package convert

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// maxKDFIterations caps every password-based key-derivation iteration count this
// app is willing to run when reading a bundle back.
//
// The four profiles this app writes use 1 (legacy MAC) or 2048 (everything else),
// so 10000 leaves ample headroom for a file written by some other tool while still
// bounding the work. The bound is the point: PKCS#12 stores the iteration counts
// IN THE FILE, and Decode honours them, so without a preflight a single crafted
// output could spend arbitrary CPU on the scan's only goroutine. The read-size cap
// and a decode deadline do not help — they bound how long the caller waits, not
// how much work is done.
const maxKDFIterations = 10000

// Object identifiers of the algorithms the four encoder profiles emit. Values
// verified against the pinned go-pkcs12 v0.7.3 (mac.go:64-67, crypto.go:28-31,
// pkcs12.go:214-215) rather than transcribed from a specification, so they match
// what this app actually writes.
var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

	// oidPKCS8ShroudedKeyBag identifies the encrypted private-key bag
	// (RFC 7292 §4.2.2). Verified against the pinned go-pkcs12 v0.7.3
	// (safebags.go:19).
	oidPKCS8ShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}

	oidPBES2                         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
)

// ErrProfileUnknown reports a bundle whose algorithm pair is not one this app
// emits. Callers treat it like any other inspection failure: the file is not one
// of ours, so replace it.
var ErrProfileUnknown = errors.New("pkcs12 bundle was not written by a known encoder profile")

// --- Minimal PKCS#12 shapes, for the preflight only ---
//
// These deliberately model just enough of RFC 7292 to read two algorithm
// identifiers and the iteration counts, with `asn1.RawValue` standing in for every
// part that is not needed. Full decoding stays go-pkcs12's job; parsing here is a
// GATE that runs before the expensive work, so an unparseable file costs nothing.

// pfxPreamble models just enough of the PFX PDU to reach the MAC algorithm and the
// authSafe. Field order is the DER SEQUENCE order from RFC 7292 and cannot be
// reordered for struct packing: encoding/asn1 maps fields positionally.
//
//nolint:govet // DER SEQUENCE order (RFC 7292); see the doc comment above.
type pfxPreamble struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm algorithmIdentifier
	Digest    []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

//nolint:govet // DER SEQUENCE order (RFC 7292); see pfxPreamble.
type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

// safeBag models RFC 7292 §4.2's SafeBag only as far as the bag payload;
// attributes are irrelevant to the preflight.
type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue `asn1:"tag:0,explicit"`
	Attributes asn1.RawValue `asn1:"set,optional"`
}

// encryptedPrivateKeyInfo is the pkcs8ShroudedKeyBag payload (RFC 5208 §6).
type encryptedPrivateKeyInfo struct {
	Algorithm     algorithmIdentifier
	EncryptedData []byte
}

// legacyPBEParams is the pkcs-12PbeParams of the SHA1-based profiles.
type legacyPBEParams struct {
	Salt       []byte
	Iterations int
}

// pbes2Params and pbkdf2Params reach PBES2's derivation iteration count.
type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
}

// Inspection is what the preflight learned about an existing bundle.
type Inspection struct {
	// Profile is the encoder profile the bundle was written with.
	Profile EncoderType
}

// Inspect identifies the encoder profile of an existing PKCS#12 bundle and
// verifies its key-derivation iteration counts are within range, WITHOUT running
// any derivation.
//
// It exists for two reasons that share one parser. Currency: comparing a bundle's
// leaf, key and chain cannot notice that PFX_ENCODER changed, so switching profiles
// would rewrite nothing and leave every file on the old algorithms while the startup
// log announced the new one. Safety: the iteration counts live in the file and the
// decoder honours them, so they must be bounded before the decode, not after.
//
// Every failure means the same thing to a caller — this is not a bundle we would
// have written, so replace it. That makes a parse failure safe by construction.
func Inspect(pfx []byte) (Inspection, error) {
	var preamble pfxPreamble
	rest, unmarshalErr := asn1.Unmarshal(pfx, &preamble)
	if unmarshalErr != nil {
		return Inspection{}, fmt.Errorf("parse pkcs12 preamble: %w", unmarshalErr)
	}
	if len(rest) != 0 {
		// asn1.Unmarshal returns trailing bytes rather than rejecting them. A bundle
		// with anything appended is not one this app wrote, and accepting it would
		// mean inspecting a prefix while the decoder sees the whole file.
		return Inspection{}, fmt.Errorf("%w: %d trailing byte(s) after the bundle", ErrProfileUnknown, len(rest))
	}
	macAlg := preamble.MacData.Mac.Algorithm
	if len(macAlg.Algorithm) == 0 {
		// A bundle with no MacData is not one of ours: all four profiles set a MAC.
		return Inspection{}, fmt.Errorf("%w: no MAC present", ErrProfileUnknown)
	}
	if err := checkMACIterations(&macAlg, preamble.MacData.Iterations); err != nil {
		return Inspection{}, err
	}

	certAlg, err := certBagAlgorithm(&preamble.AuthSafe)
	if err != nil {
		return Inspection{}, err
	}

	profile, err := profileFor(macAlg.Algorithm, certAlg.Algorithm)
	if err != nil {
		return Inspection{}, err
	}
	// The encryption iteration counts are bounded during the authenticated-safe
	// walk (certBagAlgorithm -> boundedSafeAlgorithm), which covers EVERY
	// encrypted safe plus the plaintext safe's shrouded key bag, not just the
	// one that identifies the profile. Re-checking certAlg here would be dead.
	return Inspection{Profile: profile}, nil
}

// certBagAlgorithm reaches the certificate bag's content-encryption algorithm,
// and bounds every derivation count the decoder would honour on the way.
//
// authSafe wraps an OCTET STRING holding the DER of AuthenticatedSafe, a SEQUENCE
// OF ContentInfo whose members are the plaintext bag (holding the shrouded key) and
// the encrypted bag (holding the certificates). Only the latter names an encryption
// algorithm, which is the field that separates the two legacy profiles from each
// other.
//
// The returned algorithm is the FIRST encrypted safe's, because that is the one
// that identifies the profile. The bound, however, cannot stop there: the decoder
// decrypts every encrypted safe (go-pkcs12 v0.7.3 pkcs12.go:604-616) and derives
// separately for the shrouded key bag, which for the modern profiles sits in the
// PLAINTEXT safe. Every one of those counts is checked here.
func certBagAlgorithm(authSafe *contentInfo) (algorithmIdentifier, error) {
	if !authSafe.ContentType.Equal(oidDataContentType) {
		return algorithmIdentifier{}, fmt.Errorf("%w: authSafe is not a data ContentInfo", ErrProfileUnknown)
	}
	var inner []byte
	if _, err := asn1.Unmarshal(authSafe.Content.Bytes, &inner); err != nil {
		return algorithmIdentifier{}, fmt.Errorf("parse authSafe content: %w", err)
	}
	var safes []contentInfo
	if _, err := asn1.Unmarshal(inner, &safes); err != nil {
		return algorithmIdentifier{}, fmt.Errorf("parse authenticated safe: %w", err)
	}
	var certAlg algorithmIdentifier
	found := false
	for i := range safes {
		alg, isCertBag, err := boundedSafeAlgorithm(&safes[i])
		if err != nil {
			return algorithmIdentifier{}, err
		}
		if isCertBag && !found {
			certAlg, found = alg, true
		}
	}
	if !found {
		return algorithmIdentifier{}, fmt.Errorf("%w: no encrypted certificate bag", ErrProfileUnknown)
	}
	return certAlg, nil
}

// boundedSafeAlgorithm bounds every derivation count a single authenticated safe
// would make the decoder honour, and reports that safe's content-encryption
// algorithm when it is an encrypted one — the field that identifies the profile.
// A plaintext safe names no encryption algorithm of its own, so isCertBag is
// false there and only its shrouded key bag is bounded.
func boundedSafeAlgorithm(safe *contentInfo) (alg algorithmIdentifier, isCertBag bool, err error) {
	switch {
	case safe.ContentType.Equal(oidEncryptedDataContentType):
		var enc encryptedData
		if _, err := asn1.Unmarshal(safe.Content.Bytes, &enc); err != nil {
			return algorithmIdentifier{}, false, fmt.Errorf("parse encrypted safe contents: %w", err)
		}
		certEnc := enc.EncryptedContentInfo.ContentEncryptionAlgorithm
		// Every encrypted safe is decrypted by the decoder, not just the
		// first, so every one of them must be bounded here.
		if err := checkEncryptionIterations(&certEnc); err != nil {
			return algorithmIdentifier{}, false, err
		}
		return certEnc, true, nil
	case safe.ContentType.Equal(oidDataContentType):
		if err := checkKeyBagIterations(safe.Content.Bytes); err != nil {
			return algorithmIdentifier{}, false, err
		}
	}
	return algorithmIdentifier{}, false, nil
}

// checkKeyBagIterations bounds the derivation count of a shrouded private-key
// bag. The decoder derives with the count stored in the bag itself
// (go-pkcs12 v0.7.3 pkcs12.go:487), and for the modern profiles that bag sits
// in the PLAINTEXT safe, so it is invisible to the encrypted-safe check.
func checkKeyBagIterations(content []byte) error {
	var inner []byte
	if _, err := asn1.Unmarshal(content, &inner); err != nil {
		return fmt.Errorf("parse plaintext safe content: %w", err)
	}
	var bags []safeBag
	if _, err := asn1.Unmarshal(inner, &bags); err != nil {
		return fmt.Errorf("parse plaintext safe bags: %w", err)
	}
	for i := range bags {
		bag := &bags[i]
		if !bag.ID.Equal(oidPKCS8ShroudedKeyBag) {
			continue
		}
		var info encryptedPrivateKeyInfo
		if _, err := asn1.Unmarshal(bag.Value.Bytes, &info); err != nil {
			return fmt.Errorf("parse shrouded key bag: %w", err)
		}
		if err := checkEncryptionIterations(&info.Algorithm); err != nil {
			return err
		}
	}
	return nil
}

// profileFor maps the (MAC, certificate-encryption) algorithm pair onto the
// encoder that produces it, reading the same profiles table encoderFor does so
// the two directions of the contract cannot drift apart.
//
// The pair is needed, not just the MAC: modern2023 and modern2026 differ only in
// their MAC, while legacydes and legacyrc2 share a SHA-1 MAC and differ only in
// their encryption. Either field alone leaves two profiles indistinguishable.
func profileFor(macAlg, certAlg asn1.ObjectIdentifier) (EncoderType, error) {
	for _, p := range profiles {
		if macAlg.Equal(p.macOID) && certAlg.Equal(p.certEncOID) {
			return p.name, nil
		}
	}
	return "", fmt.Errorf("%w: mac %v with encryption %v", ErrProfileUnknown, macAlg, certAlg)
}

// checkMACIterations bounds the MAC's derivation count.
//
// Where that count LIVES depends on the MAC algorithm, which is why this cannot
// simply read macData.iterations. The SHA-1 and SHA-256 profiles put it there, and
// ASN.1 gives it a DEFAULT of 1 that Go's decoder leaves as a zero value when the
// field is absent. PBMAC1 (modern2026) does not use that field at all: it carries a
// full PBKDF2 parameter block in the algorithm identifier, so the count is nested
// there and macData.iterations is legitimately absent.
func checkMACIterations(alg *algorithmIdentifier, macDataIterations int) error {
	if alg.Algorithm.Equal(oidPBMAC1) {
		return checkPBKDF2Iterations("pbmac1", alg.Parameters)
	}
	if macDataIterations == 0 {
		macDataIterations = 1 // the ASN.1 DEFAULT, which Go's decoder does not apply
	}
	return checkIterations("mac", macDataIterations)
}

// checkPBKDF2Iterations reads the iteration count out of a PBES2 or PBMAC1
// parameter block, both of which wrap a PBKDF2 AlgorithmIdentifier.
func checkPBKDF2Iterations(label string, params asn1.RawValue) error {
	var outer pbes2Params
	if _, err := asn1.Unmarshal(params.FullBytes, &outer); err != nil {
		return fmt.Errorf("parse %s parameters: %w", label, err)
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(outer.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
		return fmt.Errorf("parse %s PBKDF2 parameters: %w", label, err)
	}
	return checkIterations(label, kdf.Iterations)
}

// checkEncryptionIterations bounds the certificate bag's derivation count. The two
// parameter shapes differ by profile: the SHA-1 profiles carry pkcs-12PbeParams
// directly, while PBES2 nests the count inside its PBKDF2 parameters.
func checkEncryptionIterations(alg *algorithmIdentifier) error {
	switch {
	case alg.Algorithm.Equal(oidPBES2):
		return checkPBKDF2Iterations("pbkdf2", alg.Parameters)
	default:
		var params legacyPBEParams
		if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &params); err != nil {
			return fmt.Errorf("parse PBE parameters: %w", err)
		}
		return checkIterations("pbe", params.Iterations)
	}
}

// checkIterations rejects a count outside the range this app is willing to run.
// Non-positive is rejected too: it is not a value any profile emits, and treating
// it as "cheap" would accept a file whose framing we do not understand.
func checkIterations(label string, n int) error {
	if n <= 0 || n > maxKDFIterations {
		return fmt.Errorf("%w: %s iteration count %d outside 1..%d",
			ErrProfileUnknown, label, n, maxKDFIterations)
	}
	return nil
}

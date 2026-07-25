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

// reordered for struct packing: encoding/asn1 maps fields positionally.
//
//nolint:govet // Field order is the DER SEQUENCE order from RFC 7292 and cannot be
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
	if err := checkEncryptionIterations(&certAlg); err != nil {
		return Inspection{}, err
	}
	return Inspection{Profile: profile}, nil
}

// certBagAlgorithm reaches the certificate bag's content-encryption algorithm.
//
// authSafe wraps an OCTET STRING holding the DER of AuthenticatedSafe, a SEQUENCE
// OF ContentInfo whose members are the plaintext bag (holding the shrouded key) and
// the encrypted bag (holding the certificates). Only the latter names an encryption
// algorithm, which is the field that separates the two legacy profiles from each
// other.
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
	for _, safe := range safes {
		if !safe.ContentType.Equal(oidEncryptedDataContentType) {
			continue
		}
		var enc encryptedData
		if _, err := asn1.Unmarshal(safe.Content.Bytes, &enc); err != nil {
			return algorithmIdentifier{}, fmt.Errorf("parse encrypted safe contents: %w", err)
		}
		return enc.EncryptedContentInfo.ContentEncryptionAlgorithm, nil
	}
	return algorithmIdentifier{}, fmt.Errorf("%w: no encrypted certificate bag", ErrProfileUnknown)
}

// profileFor maps the (MAC, certificate-encryption) algorithm pair onto the
// encoder that produces it.
//
// The pair is needed, not just the MAC: modern2023 and modern2026 differ only in
// their MAC, while legacydes and legacyrc2 share a SHA-1 MAC and differ only in
// their encryption. Either field alone leaves two profiles indistinguishable.
func profileFor(macAlg, certAlg asn1.ObjectIdentifier) (EncoderType, error) {
	switch {
	case macAlg.Equal(oidSHA256) && certAlg.Equal(oidPBES2):
		return EncNameModern2023, nil
	case macAlg.Equal(oidPBMAC1) && certAlg.Equal(oidPBES2):
		return EncNameModern2026, nil
	case macAlg.Equal(oidSHA1) && certAlg.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC):
		return EncNameLegacyDES, nil
	case macAlg.Equal(oidSHA1) && certAlg.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		return EncNameLegacyRC2, nil
	default:
		return "", fmt.Errorf("%w: mac %v with encryption %v", ErrProfileUnknown, macAlg, certAlg)
	}
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

package convert

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// maxKDFIterations caps every password-based key-derivation iteration count the
// preflight can read before this app runs it.
//
// The four profiles this app writes use 1 (legacy MAC) or 2048 (everything else),
// so 10000 leaves ample headroom for a file written by some other tool while still
// bounding the work. The bound is the point: PKCS#12 stores the iteration counts
// IN THE FILE, and Decode honours them, so without a preflight a single crafted
// output could spend arbitrary CPU on the scan's only goroutine. The read-size cap
// and a decode deadline do not help — they bound how long the caller waits, not
// how much work is done.
//
// One count is out of reach: a pkcs8ShroudedKeyBag nested inside an encryptedData
// safe is still ciphertext while the preflight runs, so DecodeChain honours its
// stored count unbounded. Closing that needs go-pkcs12's unexported pbDecrypt, so
// it is a known limit of this gate rather than something it enforces.
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

// ErrProfileUnknown reports a bundle whose algorithm triple is not one this app
// emits. Callers treat it like any other inspection failure: the file is not one
// of ours, so replace it.
var ErrProfileUnknown = errors.New("pkcs12 bundle was not written by a known encoder profile")

// --- Minimal PKCS#12 shapes, for the preflight only ---
//
// These deliberately model just enough of RFC 7292 to read the three algorithm
// identifiers that identify a profile and the iteration counts, with
// `asn1.RawValue` standing in for every part that is not needed. Full decoding
// stays go-pkcs12's job; parsing here is a GATE that runs before the expensive
// work, so an unparseable file costs nothing.

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
	ContentType asn1.RawValue
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// contentTypeOID decodes this ContentInfo's content-type identifier under the
// preflight's bounds. See decodeOID for why the raw DER is retained.
func (c *contentInfo) contentTypeOID() (asn1.ObjectIdentifier, error) {
	return decodeOID(c.ContentType)
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
	Algorithm  asn1.RawValue
	Parameters asn1.RawValue `asn1:"optional"`
}

// algorithmOID decodes this AlgorithmIdentifier's algorithm identifier under the
// preflight's bounds. See decodeOID for why the raw DER is retained.
func (a *algorithmIdentifier) algorithmOID() (asn1.ObjectIdentifier, error) {
	return decodeOID(a.Algorithm)
}

// maxOIDBytes caps the content length of an object identifier the preflight is
// willing to decode. Every identifier the four profiles emit is 9 bytes or fewer,
// so 32 is generous headroom for a file written by some other tool.
const maxOIDBytes = 32

// decodeOID turns one retained identifier field into an asn1.ObjectIdentifier,
// rejecting anything oversized before it is decoded.
//
// The bound is the point, and it is why every identifier reached from untrusted
// bundle bytes is modelled as an asn1.RawValue rather than an
// asn1.ObjectIdentifier. Go's ASN.1 decoder allocates one int per encoded byte
// (len+1) when it decodes into asn1.ObjectIdentifier, roughly eight bytes of
// backing store per input byte. The store deliberately admits a prior PFX of up to
// 2*10 MiB plus framing, so a foreign or damaged bundle could spend almost that
// whole allowance on a single syntactically valid identifier and turn a ~20 MiB
// file into ~160 MiB of int slice — inside store.isCurrent, before any
// authentication, on the scan's only goroutine. Retaining the DER keeps the
// structural unmarshal slice-backed and makes this the only place that allocates.
func decodeOID(raw asn1.RawValue) (asn1.ObjectIdentifier, error) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagOID || raw.IsCompound {
		return nil, fmt.Errorf("%w: identifier field is not a primitive OBJECT IDENTIFIER", ErrProfileUnknown)
	}
	if len(raw.Bytes) > maxOIDBytes {
		return nil, fmt.Errorf("%w: %d-byte object identifier exceeds the %d-byte limit",
			ErrProfileUnknown, len(raw.Bytes), maxOIDBytes)
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(raw.FullBytes, &oid)
	if err != nil {
		return nil, fmt.Errorf("parse object identifier: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing byte(s) after an object identifier", ErrProfileUnknown, len(rest))
	}
	return oid, nil
}

//nolint:govet // DER SEQUENCE order (RFC 7292); see pfxPreamble.
type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.RawValue
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

// safeBag models RFC 7292 §4.2's SafeBag only as far as the bag payload;
// attributes are irrelevant to the preflight.
type safeBag struct {
	ID         asn1.RawValue
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
	if len(macAlg.Algorithm.FullBytes) == 0 {
		// A bundle with no MacData is not one of ours: all four profiles set a MAC.
		return Inspection{}, fmt.Errorf("%w: no MAC present", ErrProfileUnknown)
	}
	macOID, err := macAlg.algorithmOID()
	if err != nil {
		return Inspection{}, err
	}
	if iterErr := checkMACIterations(macOID, macAlg.Parameters, preamble.MacData.Iterations); iterErr != nil {
		return Inspection{}, iterErr
	}

	algs, err := bundleAlgorithms(&preamble.AuthSafe)
	if err != nil {
		return Inspection{}, err
	}

	profile, err := profileFor(macOID, algs.certEnc, algs.keyEnc)
	if err != nil {
		return Inspection{}, err
	}
	// The encryption iteration counts are bounded during the authenticated-safe
	// walk (bundleAlgorithms -> boundedSafeAlgorithms), which covers EVERY
	// encrypted safe plus the plaintext safe's shrouded key bag, not just the
	// ones that identify the profile. Re-checking them here would be dead.
	return Inspection{Profile: profile}, nil
}

// safeAlgorithms is the part of a bundle's profile identity that lives in the
// authenticated safe: the certificate-encryption algorithm of an encrypted safe
// and the encryption algorithm of the shrouded private-key bag. A nil field means
// that safe carried none of that kind.
type safeAlgorithms struct {
	certEnc asn1.ObjectIdentifier
	keyEnc  asn1.ObjectIdentifier
}

// bundleAlgorithms reaches the certificate bag's and the private-key bag's
// content-encryption algorithms, and bounds every derivation count the decoder
// would honour on the way.
//
// authSafe wraps an OCTET STRING holding the DER of AuthenticatedSafe, a SEQUENCE
// OF ContentInfo whose members are the encrypted bag (holding the certificates)
// and the plaintext bag (holding the shrouded key). Both algorithms are needed:
// legacyrc2 differs from legacydes only in its certificate encryption, while a
// bundle mixing a modern MAC and modern certificate encryption with a 3DES-wrapped
// private key is one no profile emits and must not be reported as modern.
//
// The certificate algorithm returned is the FIRST encrypted safe's, because that
// is the one that identifies the profile. The bound, however, cannot stop there:
// the decoder decrypts every encrypted safe (go-pkcs12 v0.7.3 pkcs12.go:604-616)
// and derives separately for the shrouded key bag, which for every profile sits in
// the PLAINTEXT safe. Every count VISIBLE without decrypting a safe is checked
// here; a shrouded key bag nested INSIDE an encryptedData safe stays ciphertext
// until DecodeChain decrypts it, so its own stored count is out of reach from here
// (see maxKDFIterations). Exactly one VISIBLE shrouded key bag must be present:
// none, or a second one, is not a shape this app writes and the decoder would
// reject it after paying for the derivation.
func bundleAlgorithms(authSafe *contentInfo) (safeAlgorithms, error) {
	contentType, err := authSafe.contentTypeOID()
	if err != nil {
		return safeAlgorithms{}, err
	}
	if !contentType.Equal(oidDataContentType) {
		return safeAlgorithms{}, fmt.Errorf("%w: authSafe is not a data ContentInfo", ErrProfileUnknown)
	}
	var inner []byte
	if _, err := asn1.Unmarshal(authSafe.Content.Bytes, &inner); err != nil {
		return safeAlgorithms{}, fmt.Errorf("parse authSafe content: %w", err)
	}
	var safes []contentInfo
	if _, err := asn1.Unmarshal(inner, &safes); err != nil {
		return safeAlgorithms{}, fmt.Errorf("parse authenticated safe: %w", err)
	}
	var algs safeAlgorithms
	for i := range safes {
		found, err := boundedSafeAlgorithms(&safes[i])
		if err != nil {
			return safeAlgorithms{}, err
		}
		if mergeErr := algs.merge(found); mergeErr != nil {
			return safeAlgorithms{}, mergeErr
		}
	}
	if algs.certEnc == nil {
		return safeAlgorithms{}, fmt.Errorf("%w: no encrypted certificate bag", ErrProfileUnknown)
	}
	if algs.keyEnc == nil {
		return safeAlgorithms{}, fmt.Errorf("%w: no shrouded private-key bag", ErrProfileUnknown)
	}
	return algs, nil
}

// merge folds one safe's contribution into the bundle-level identity. The first
// encrypted safe's certificate algorithm wins, because that is the one that
// identifies the profile; a second shrouded private-key bag is refused outright,
// since no profile writes two and the decoder would pay for both derivations
// before rejecting the file.
func (a *safeAlgorithms) merge(found safeAlgorithms) error {
	if found.certEnc != nil && a.certEnc == nil {
		a.certEnc = found.certEnc
	}
	if found.keyEnc != nil {
		if a.keyEnc != nil {
			return fmt.Errorf("%w: more than one shrouded private-key bag", ErrProfileUnknown)
		}
		a.keyEnc = found.keyEnc
	}
	return nil
}

// boundedSafeAlgorithms bounds every derivation count a single authenticated safe
// would make the decoder honour, and reports the profile-identifying algorithms it
// carries: an encrypted safe's content encryption, or a plaintext safe's shrouded
// key-bag encryption. A safe of neither kind contributes nothing.
func boundedSafeAlgorithms(safe *contentInfo) (safeAlgorithms, error) {
	contentType, err := safe.contentTypeOID()
	if err != nil {
		return safeAlgorithms{}, err
	}
	switch {
	case contentType.Equal(oidEncryptedDataContentType):
		var enc encryptedData
		if _, err := asn1.Unmarshal(safe.Content.Bytes, &enc); err != nil {
			return safeAlgorithms{}, fmt.Errorf("parse encrypted safe contents: %w", err)
		}
		certEnc := enc.EncryptedContentInfo.ContentEncryptionAlgorithm
		certOID, err := certEnc.algorithmOID()
		if err != nil {
			return safeAlgorithms{}, err
		}
		// Every encrypted safe is decrypted by the decoder, not just the
		// first, so every one of them must be bounded here.
		if err := checkEncryptionIterations(certOID, certEnc.Parameters); err != nil {
			return safeAlgorithms{}, err
		}
		return safeAlgorithms{certEnc: certOID}, nil
	case contentType.Equal(oidDataContentType):
		keyEnc, err := keyBagAlgorithm(safe.Content.Bytes)
		if err != nil {
			return safeAlgorithms{}, err
		}
		return safeAlgorithms{keyEnc: keyEnc}, nil
	}
	return safeAlgorithms{}, nil
}

// keyBagAlgorithm bounds the derivation count of a shrouded private-key bag and
// reports the algorithm that bag's private key is encrypted with — the third
// dimension of a profile's identity, and the one that says whether the key itself
// is protected by PBES2 or by 3DES. The decoder derives with the count stored in
// the bag itself (go-pkcs12 v0.7.3 pkcs12.go:487), and that bag sits in the
// PLAINTEXT safe, so it is invisible to the encrypted-safe check.
//
// A second shrouded key bag in one safe is rejected: it is not a shape this app
// writes, and the decoder would pay for both derivations before refusing it.
func keyBagAlgorithm(content []byte) (asn1.ObjectIdentifier, error) {
	var inner []byte
	if _, err := asn1.Unmarshal(content, &inner); err != nil {
		return nil, fmt.Errorf("parse plaintext safe content: %w", err)
	}
	var bags []safeBag
	if _, err := asn1.Unmarshal(inner, &bags); err != nil {
		return nil, fmt.Errorf("parse plaintext safe bags: %w", err)
	}
	var keyEnc asn1.ObjectIdentifier
	for i := range bags {
		bag := &bags[i]
		id, err := decodeOID(bag.ID)
		if err != nil {
			return nil, err
		}
		if !id.Equal(oidPKCS8ShroudedKeyBag) {
			continue
		}
		if keyEnc != nil {
			return nil, fmt.Errorf("%w: more than one shrouded private-key bag in one safe", ErrProfileUnknown)
		}
		var info encryptedPrivateKeyInfo
		if _, parseErr := asn1.Unmarshal(bag.Value.Bytes, &info); parseErr != nil {
			return nil, fmt.Errorf("parse shrouded key bag: %w", parseErr)
		}
		keyOID, err := info.Algorithm.algorithmOID()
		if err != nil {
			return nil, err
		}
		if err := checkEncryptionIterations(keyOID, info.Algorithm.Parameters); err != nil {
			return nil, err
		}
		keyEnc = keyOID
	}
	return keyEnc, nil
}

// profileFor maps the (MAC, certificate-encryption, key-encryption) algorithm
// triple onto the encoder that produces it, reading the same profiles table
// encoderFor does so the two directions of the contract cannot drift apart.
//
// All three fields are needed: modern2023 and modern2026 differ only in their MAC,
// legacydes and legacyrc2 share a SHA-1 MAC and differ only in their certificate
// encryption, and the key encryption is what separates a bundle this app wrote
// from one that keeps a modern MAC and modern certificates over a 3DES-wrapped
// private key.
func profileFor(macAlg, certAlg, keyAlg asn1.ObjectIdentifier) (EncoderType, error) {
	for _, p := range profiles {
		if macAlg.Equal(p.macOID) && certAlg.Equal(p.certEncOID) && keyAlg.Equal(p.keyEncOID) {
			return p.name, nil
		}
	}
	return "", fmt.Errorf("%w: mac %v with certificate encryption %v and key encryption %v",
		ErrProfileUnknown, macAlg, certAlg, keyAlg)
}

// checkMACIterations bounds the MAC's derivation count.
//
// Where that count LIVES depends on the MAC algorithm, which is why this cannot
// simply read macData.iterations. The SHA-1 and SHA-256 profiles put it there, and
// ASN.1 gives it a DEFAULT of 1 that Go's decoder leaves as a zero value when the
// field is absent. PBMAC1 (modern2026) does not use that field at all: it carries a
// full PBKDF2 parameter block in the algorithm identifier, so the count is nested
// there and macData.iterations is legitimately absent.
func checkMACIterations(macOID asn1.ObjectIdentifier, params asn1.RawValue, macDataIterations int) error {
	if macOID.Equal(oidPBMAC1) {
		return checkPBKDF2Iterations("pbmac1", params)
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
func checkEncryptionIterations(algOID asn1.ObjectIdentifier, params asn1.RawValue) error {
	switch {
	case algOID.Equal(oidPBES2):
		return checkPBKDF2Iterations("pbkdf2", params)
	default:
		var legacy legacyPBEParams
		if _, err := asn1.Unmarshal(params.FullBytes, &legacy); err != nil {
			return fmt.Errorf("parse PBE parameters: %w", err)
		}
		return checkIterations("pbe", legacy.Iterations)
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

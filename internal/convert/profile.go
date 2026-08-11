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
// One count is out of reach, so this cap is not a total bound. The preflight reads
// only what is plaintext: the MAC's own count, each encryptedData safe's OUTER
// content-encryption algorithm, and a shrouded key bag sitting in the plaintext
// data safe. DecodeChain accepts one or two authenticated safes, decrypts every
// encryptedData safe, flattens all the resulting bags, and derives with the stored
// count of the first shrouded key bag in that flattened order (go-pkcs12 v0.7.3
// pkcs12.go:591-626 and 481-489). A bundle that hides a shrouded key bag INSIDE
// its encryptedData safe, which is the safe Encode writes first, therefore passes
// every check here and then pays that bag's own count, which nothing bounds below
// the largest value an int holds. The decoder's "expected exactly one key bag"
// refusal does not help: it fires on the SECOND bag, which is the plaintext one
// this preflight already bounded.
//
// It cannot be bounded here. pbDecrypt, pbeCipherFor and decodePkcs8ShroudedKeyBag
// are unexported in v0.7.3 and DecodeChain takes only a bundle and a password, so
// no in-repo call can express the limit. Reaching the gap needs write access to
// /output AND a bundle whose MAC verifies, because DecodeChain verifies the MAC
// before it decrypts any safe (pkcs12.go:569-584), which means knowing the
// configured PFX_PASSWORD; PFX_ALLOW_EMPTY_PASSWORD=true removes that second
// requirement, because the MAC over an empty password is computable by anyone.
// Whoever holds both can already replace the bundle outright, so the residual is
// accepted rather than worked around. A fix needs a decode-time
// maximum-iterations option upstream.
const maxKDFIterations = 10000

// minKDFIterations is the floor those same counts must clear. Every derivation
// location all four profiles emit uses 2048 (go-pkcs12 v0.7.3 pkcs12.go:101, 122,
// 163, 190); the one exception is the legacy profiles' MAC, which uses 1
// (pkcs12.go:100, 121) and is floored separately in checkMACIterations. Without a
// floor the bound is one-sided, and the decoder honours ANY count it is given
// (crypto.go:253 and mac.go pass the stored value straight to pbkdf2.Key), so a
// bundle whose certificates and private key are wrapped with AES-256-CBC over a
// ONE-iteration PBKDF2 matches the profile triple, decodes, matches the analysis
// and is reported current forever — the same missing dimension the PRF and
// AES-256 checks already close.
const minKDFIterations = 2048

// minLegacyMACIterations is the floor for the one derivation location that does not
// use 2048: the SHA-1 MAC of the two legacy profiles, which derives with a single
// iteration (go-pkcs12 v0.7.3 pkcs12.go:100, 121). Named here so every bound the
// preflight applies is declared with the version it was read from.
const minLegacyMACIterations = 1

// minPBKDF2SaltBytes and minLegacySaltBytes are the salt lengths the profiles
// emit: 16 octets for both modern profiles (go-pkcs12 v0.7.3 pkcs12.go:164, 191
// saltLen: 16) and 8 for both legacy profiles (pkcs12.go:102, 123 saltLen: 8).
// The decoder imposes no minimum at all — crypto.go:253 and mac.go hand
// kdfParams.Salt.Bytes to pbkdf2.Key whatever its length, including zero — so a
// short or empty salt is accepted, and a zero-length salt makes the derived key a
// pure function of the password and iteration count, precomputable across every
// bundle that shares the PFX password. Same missing dimension as the accepted
// weaker cipher and PRF the preflight already refuses, on the remaining PBKDF2
// parameter.
const (
	minPBKDF2SaltBytes = 16
	minLegacySaltBytes = 8
)

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

	// oidAES256CBC is the only PBES2 encryption scheme either modern profile
	// emits: go-pkcs12 v0.7.3 sets it unconditionally (crypto.go:324).
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	// oidPBKDF2 is the only key-derivation function either modern profile names
	// inside a PBES2 or PBMAC1 parameter block: go-pkcs12 v0.7.3 sets it
	// unconditionally (crypto.go:320, mac.go:55).
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	// oidHMACWithSHA256 is the only PBKDF2 pseudorandom function, and the only
	// PBMAC1 message-authentication scheme, either modern profile emits
	// (go-pkcs12 v0.7.3 crypto.go:317, mac.go:51 and mac.go:58). It is a
	// different arc from oidSHA256 above: that one names a bare digest, this one
	// the keyed HMAC construction built from it.
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
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

type macData struct {
	Mac        digestInfo
	MacSalt    asn1.RawValue
	Iterations int `asn1:"optional,default:1"`
}

// The digest itself is retained but never read: the preflight only needs to know it
// is THERE and well-shaped. It is modelled as an asn1.RawValue rather than a []byte
// because encoding/asn1 copies a []byte field, which would duplicate up to
// MaxBundleBytes of unauthenticated input on the scan's only goroutine — while
// DROPPING the field entirely would silently widen the accepted set, since asn1
// tolerates the trailing element and a required OCTET STRING would become optional
// to this parser. octetStringBytes re-imposes the shape asn1 enforced for a []byte
// field, without the copy.
type digestInfo struct {
	Algorithm algorithmIdentifier
	Digest    asn1.RawValue
}

type algorithmIdentifier struct {
	Algorithm  asn1.RawValue
	Parameters asn1.RawValue `asn1:"optional"`
}

// MaxBundleBytes is the largest prior bundle the app admits to this codec through
// the store. Every bound below (maxOIDBytes, maxAuthenticatedSafes, maxSafeBags) is
// sized against it, so the limit belongs here rather than in whichever caller
// happens to read the file. It is
// two of this package's own input files plus PKCS#12 framing, derived from
// MaxInputBytes rather than restated, so raising the input cap raises this with it
// instead of silently invalidating the allocation analysis these bounds were sized
// against.
const MaxBundleBytes = 2*MaxInputBytes + 64<<10

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
// backing store per input byte. The store admits a bundle of up to
// MaxBundleBytes, so a foreign or damaged bundle could spend almost that
// whole allowance on a single syntactically valid identifier and turn a ~20 MiB
// file into ~160 MiB of int slice — inside store.isCurrent, before any
// authentication, on the scan's only goroutine. Retaining the DER keeps the
// structural unmarshal slice-backed; the other allocation the untrusted bytes
// can drive is the element count of a SEQUENCE OF, bounded by
// maxAuthenticatedSafes and maxSafeBags.
func decodeOID(raw asn1.RawValue) (asn1.ObjectIdentifier, error) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagOID || raw.IsCompound {
		return nil, fmt.Errorf("%w: identifier field is not a primitive OBJECT IDENTIFIER", ErrProfileUnknown)
	}
	if len(raw.Bytes) > maxOIDBytes {
		return nil, fmt.Errorf("%w: %d-byte object identifier exceeds the %d-byte limit",
			ErrProfileUnknown, len(raw.Bytes), maxOIDBytes)
	}
	var oid asn1.ObjectIdentifier
	if err := unmarshalExact(raw.FullBytes, &oid, "object identifier", "an object identifier"); err != nil {
		return nil, err
	}
	return oid, nil
}

// octetStringBytes returns the content of a primitive OCTET STRING WITHOUT
// copying it, refusing any other shape. It is the non-allocating counterpart of
// modelling a field as []byte: encoding/asn1 copies a []byte field
// (asn1.go MakeSlice+Copy), so a field the preflight only measures or walks would
// otherwise duplicate up to MaxBundleBytes of unauthenticated input on the
// scan's only goroutine. The shape check keeps the accepted set exactly what the
// []byte field admitted, since asn1 required an OCTET STRING there too.
func octetStringBytes(raw asn1.RawValue, what string) ([]byte, error) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagOctetString || raw.IsCompound {
		return nil, fmt.Errorf("%w: %s is not a primitive OCTET STRING", ErrProfileUnknown, what)
	}
	return raw.Bytes, nil
}

// unmarshalExact decodes one complete DER element into out. Every decode in the
// preflight must consume its whole input: accepting a prefix would mean gating on
// one shape while go-pkcs12 then decodes another.
//
// parseWhat names the element for a parse failure ("parse <parseWhat>: ...");
// trailingWhat names it for the trailing-byte refusal ("... after <trailingWhat>"),
// which reads as a noun phrase and so differs per site.
func unmarshalExact(der []byte, out any, parseWhat, trailingWhat string) error {
	rest, err := asn1.Unmarshal(der, out)
	if err != nil {
		return fmt.Errorf("parse %s: %w", parseWhat, err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("%w: %d trailing byte(s) after %s", ErrProfileUnknown, len(rest), trailingWhat)
	}
	return nil
}

const (
	// maxAuthenticatedSafes and maxSafeBags bound how many elements the preflight
	// admits from a SEQUENCE OF before it stops parsing.
	//
	// The bound is the point, in the same way maxOIDBytes is. sequenceElements
	// deliberately does NOT decode into a []contentInfo or []safeBag: Go's ASN.1
	// decoder would size such a slice from the input's ELEMENT COUNT, at 144 bytes
	// (contentInfo) or 216 bytes (safeBag) of RawValue headers per element however
	// small its encoding is, which is why it parses one element at a time instead.
	// What still grows with the element count is the INDEX it builds: one 24-byte
	// []byte header per element. asn1.Unmarshal accepts a 2-byte TLV as an element,
	// so MaxBundleBytes holds ~10.5 million of them and turns a ~20 MiB file into
	// ~240 MB of live headers (more again while the slice doubles), inside
	// store.isCurrent, before any authentication, on the scan's only goroutine.
	//
	// Neither bound can refuse a bundle this app wrote: go-pkcs12 v0.7.3's Encode
	// writes exactly two safes with the single shrouded key bag alone in the
	// plaintext one (pkcs12.go 'var authenticatedSafe [2]contentInfo').
	// maxAuthenticatedSafes also matches the decoder exactly — DecodeChain
	// refuses an authenticated safe outside 1..2 items before it decrypts
	// anything (pkcs12.go:591, called with 1, 2) — while maxSafeBags is
	// stricter than the decoder, which walks a safe's bags unbounded: a 65-bag
	// safe is decodable but is not a shape this app emits, so refusing it means
	// the file is regenerated, which is what every Inspect failure means.
	maxAuthenticatedSafes = 2
	maxSafeBags           = 64
)

// sequenceElements splits one DER SEQUENCE OF into its elements' raw DER,
// refusing a sequence with more elements than the preflight will look at. It
// parses one element at a time, so the walk holds a bounded amount of memory
// whatever the input claims to contain.
func sequenceElements(der []byte, what string, maxElements int) ([][]byte, error) {
	var seq asn1.RawValue
	if err := unmarshalExact(der, &seq, what, what); err != nil {
		return nil, err
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, fmt.Errorf("%w: %s is not a SEQUENCE", ErrProfileUnknown, what)
	}
	elements := make([][]byte, 0, maxElements)
	for body := seq.Bytes; len(body) > 0; {
		if len(elements) == maxElements {
			return nil, fmt.Errorf("%w: more than %d element(s) in %s", ErrProfileUnknown, maxElements, what)
		}
		var elem asn1.RawValue
		remaining, unmarshalErr := asn1.Unmarshal(body, &elem)
		if unmarshalErr != nil {
			return nil, fmt.Errorf("parse %s element: %w", what, unmarshalErr)
		}
		elements = append(elements, elem.FullBytes)
		body = remaining
	}
	return elements, nil
}

//nolint:govet // DER SEQUENCE order (RFC 7292); see pfxPreamble.
type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

// EncryptedContent is retained but never read, for the reason recorded on
// digestInfo: it is the largest single field an untrusted bundle controls, so a
// []byte field here would copy it (go-pkcs12 v0.7.3 declares it that way,
// pkcs12.go:244). Unlike digestInfo.Digest and encryptedPrivateKeyInfo.EncryptedData
// it gets NO octetStringBytes shape check, and must not: RFC 5652 tags it
// [0] IMPLICIT, so it parses as a context-specific element (class 2, tag 0) rather
// than a universal OCTET STRING, and octetStringBytes would refuse the encrypted
// safe of every bundle this app writes.
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
//
// The encrypted key is retained but never read, for the reason recorded on
// digestInfo: only Algorithm is inspected, the ciphertext is the largest single field
// an untrusted bundle controls (so it must not be copied), and dropping the field
// would make a required OCTET STRING optional to this parser and widen the accepted
// set the []byte field defined.
type encryptedPrivateKeyInfo struct {
	Algorithm     algorithmIdentifier
	EncryptedData asn1.RawValue
}

// legacyPBEParams is the pkcs-12PbeParams of the SHA1-based profiles.
type legacyPBEParams struct {
	Salt       asn1.RawValue
	Iterations int
}

// pbes2Params and pbmac1Params are the two outer parameter blocks the modern
// profiles use (RFC 8018 §A.4 and RFC 9579 §4). Both are a PBKDF2 identifier
// followed by one more algorithm identifier, but they are modelled separately
// because that second field means a cipher in one and a MAC in the other, and
// mistaking them for each other is exactly the confusion these checks exist to
// prevent.
type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type pbmac1Params struct {
	KeyDerivationFunc algorithmIdentifier
	MessageAuthScheme algorithmIdentifier
}

// pbkdf2Params is RFC 8018 §A.2's PBKDF2-params, modelled far enough to reach
// every fixed choice a profile makes: the iteration count, the derived key length
// PBMAC1 must state, and the pseudorandom function.
//
// keyLength and prf are ASN.1 OPTIONAL, and an ABSENT prf is not "unspecified":
// the definition's DEFAULT is algid-hmacWithSHA1, and the decoder implements that
// default (go-pkcs12 v0.7.3 crypto.go:234-236, mac.go:103-105). An absent field
// therefore has to be refused like an explicit SHA-1, not silently accepted.
//
//nolint:govet // DER SEQUENCE order (RFC 8018 §A.2); see pfxPreamble.
type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                 `asn1:"optional"`
	PRF        algorithmIdentifier `asn1:"optional"`
}

// inspect identifies the encoder profile of an existing PKCS#12 bundle and
// verifies the key-derivation iteration counts it can read are within range,
// WITHOUT running any derivation. The profile it names is the whole of what the
// preflight learned about the bundle; on every failure it is "" (no profile).
//
// It exists for two reasons that share one parser. Currency: comparing a bundle's
// leaf, key and chain cannot notice that PFX_ENCODER changed, so switching profiles
// would rewrite nothing and leave every file on the old algorithms while the startup
// log announced the new one. Safety: the iteration counts live in the file and the
// decoder honours them, so every count this parser can reach is bounded before the
// decode, not after. One nested count is unreachable and stays unbounded (see
// maxKDFIterations).
//
// It is the FIRST step of CheckCurrency and is not reachable on its own, because
// running it after a decode would bound nothing. Every failure means the same thing
// to a caller — this is not a bundle we would have written, so replace it. That
// makes a parse failure safe by construction.
func inspect(pfx []byte) (EncoderType, error) {
	var preamble pfxPreamble
	// asn1.Unmarshal returns trailing bytes rather than rejecting them. A bundle
	// with anything appended is not one this app wrote, and accepting it would mean
	// inspecting a prefix while the decoder sees the whole file, so unmarshalExact
	// refuses it here and at every other decode below.
	if unmarshalErr := unmarshalExact(pfx, &preamble, "pkcs12 preamble", "the bundle"); unmarshalErr != nil {
		return "", unmarshalErr
	}
	// All four profiles write a v3 PFX (go-pkcs12 v0.7.3 pkcs12.go:665, 835) and
	// DecodeChain refuses any other version outright, before it verifies the MAC
	// (pkcs12.go:556), so a different version is not a bundle we wrote. Refusing
	// it here keeps every caller's diagnosis "not one of ours", the same reasoning
	// as the no-MAC guard below.
	const pfxVersion = 3
	if preamble.Version != pfxVersion {
		return "", fmt.Errorf("%w: pfx version %d, want %d",
			ErrProfileUnknown, preamble.Version, pfxVersion)
	}
	macAlg := preamble.MacData.Mac.Algorithm
	if len(macAlg.Algorithm.FullBytes) == 0 {
		// A bundle with no MacData is not one of ours: all four profiles set a MAC.
		return "", fmt.Errorf("%w: no MAC present", ErrProfileUnknown)
	}
	macOID, err := decodeOID(macAlg.Algorithm)
	if err != nil {
		return "", err
	}
	if iterErr := checkMACIterations(macOID, macAlg.Parameters, preamble.MacData.MacSalt,
		preamble.MacData.Iterations); iterErr != nil {
		return "", iterErr
	}

	algs, err := bundleAlgorithms(&preamble.AuthSafe)
	if err != nil {
		return "", err
	}

	profileName, err := profileFor(macOID, algs.certEnc, algs.keyEnc)
	if err != nil {
		return "", err
	}
	// The encryption iteration counts are bounded during the authenticated-safe
	// walk (bundleAlgorithms -> boundedSafeAlgorithms), which covers EVERY
	// encrypted safe's outer algorithm plus the plaintext safe's shrouded key bag,
	// not just the ones that identify the profile. Re-checking them here would be
	// dead.
	//
	// The digest is measured, never copied, and it is checked last so a bundle with a
	// more specific defect still reports that one: RFC 7292 requires the field, so an
	// absent or mistyped digest is not a bundle this app wrote. Retaining it as a
	// RawValue keeps the accepted set the former []byte field defined, without its
	// copy of unauthenticated input.
	if _, digestErr := octetStringBytes(preamble.MacData.Mac.Digest, "mac digest"); digestErr != nil {
		return "", digestErr
	}
	return profileName, nil
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
// content-encryption algorithms, and bounds every derivation count that is
// readable without decrypting a safe on the way.
//
// authSafe wraps an OCTET STRING holding the DER of AuthenticatedSafe, a SEQUENCE
// OF ContentInfo whose members are the encrypted bag (holding the certificates)
// and the plaintext bag (holding the shrouded key). Both algorithms are needed:
// legacyrc2 differs from legacydes only in its certificate encryption, while a
// bundle mixing a modern MAC and modern certificate encryption with a 3DES-wrapped
// private key is one no profile emits and must not be reported as modern.
//
// Exactly one encrypted safe must be present, because that safe's algorithm IS the
// bundle's certificate-encryption identity: with two, the identity would be read
// from one safe while the certificates could live in the other, and a bundle whose
// certificates are RC2-40 encrypted would be reported as modern. The bound, in any
// case, cannot stop at the first safe:
// the decoder decrypts every encrypted safe (go-pkcs12 v0.7.3 pkcs12.go:606-616)
// and derives separately for the shrouded key bag, which for every profile sits in
// the PLAINTEXT safe. Every count VISIBLE without decrypting a safe is checked
// here; a shrouded key bag nested INSIDE an encryptedData safe stays ciphertext
// until DecodeChain decrypts it, so its own stored count is out of reach from here
// (see maxKDFIterations). Exactly one VISIBLE shrouded key bag must be present:
// none, or a second one, is not a shape this app writes and the decoder would
// reject it after paying for the derivation.
func bundleAlgorithms(authSafe *contentInfo) (safeAlgorithms, error) {
	elements, err := authenticatedSafeElements(authSafe)
	if err != nil {
		return safeAlgorithms{}, err
	}
	var algs safeAlgorithms
	for _, element := range elements {
		var safe contentInfo
		if unmarshalErr := unmarshalExact(element, &safe, "authenticated safe", "an authenticated safe"); unmarshalErr != nil {
			return safeAlgorithms{}, unmarshalErr
		}
		found, err := boundedSafeAlgorithms(&safe)
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

// authenticatedSafeElements validates the outer authSafe framing — a data
// ContentInfo wrapping an OCTET STRING that holds the AuthenticatedSafe DER — and
// returns the bounded SEQUENCE OF ContentInfo elements inside it.
func authenticatedSafeElements(authSafe *contentInfo) ([][]byte, error) {
	contentType, err := decodeOID(authSafe.ContentType)
	if err != nil {
		return nil, err
	}
	if !contentType.Equal(oidDataContentType) {
		return nil, fmt.Errorf("%w: authSafe is not a data ContentInfo", ErrProfileUnknown)
	}
	var wrapper asn1.RawValue
	if unmarshalErr := unmarshalExact(authSafe.Content.Bytes, &wrapper, "authSafe content", "the authSafe content"); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	inner, err := octetStringBytes(wrapper, "the authSafe content")
	if err != nil {
		return nil, err
	}
	return sequenceElements(inner, "authenticated safe", maxAuthenticatedSafes)
}

// merge folds one safe's contribution into the bundle-level identity. A second
// encrypted certificate safe and a second shrouded private-key bag are both refused
// outright: every profile writes exactly one of each (one encryptedData safe
// holding the certificates, one data safe holding the shrouded key), so a bundle
// carrying two is not a shape this app emits, and the decoder would pay for every
// derivation before rejecting the file.
func (a *safeAlgorithms) merge(found safeAlgorithms) error {
	if found.certEnc != nil {
		if a.certEnc != nil {
			return fmt.Errorf("%w: more than one encrypted certificate bag", ErrProfileUnknown)
		}
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

// boundedSafeAlgorithms bounds the derivation count a single authenticated safe
// exposes without being decrypted, and reports the profile-identifying algorithms it
// carries: an encrypted safe's content encryption, or a plaintext safe's shrouded
// key-bag encryption. A safe of neither kind contributes nothing.
func boundedSafeAlgorithms(safe *contentInfo) (safeAlgorithms, error) {
	contentType, err := decodeOID(safe.ContentType)
	if err != nil {
		return safeAlgorithms{}, err
	}
	switch {
	case contentType.Equal(oidEncryptedDataContentType):
		var enc encryptedData
		if encErr := unmarshalExact(safe.Content.Bytes, &enc, "encrypted safe contents",
			"an encrypted safe's contents"); encErr != nil {
			return safeAlgorithms{}, encErr
		}
		// go-pkcs12 writes version 0 (pkcs12.go:984) and its decoder refuses any
		// other value before it decrypts the safe (pkcs12.go:611), so a different
		// version is not a shape this app emits.
		if enc.Version != 0 {
			return safeAlgorithms{}, fmt.Errorf("%w: encrypted safe version %d, want 0",
				ErrProfileUnknown, enc.Version)
		}
		certEnc := enc.EncryptedContentInfo.ContentEncryptionAlgorithm
		certOID, err := decodeOID(certEnc.Algorithm)
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
	var wrapper asn1.RawValue
	if err := unmarshalExact(content, &wrapper, "plaintext safe content", "a plaintext safe's content"); err != nil {
		return nil, err
	}
	inner, err := octetStringBytes(wrapper, "a plaintext safe's content")
	if err != nil {
		return nil, err
	}
	elements, err := sequenceElements(inner, "plaintext safe bags", maxSafeBags)
	if err != nil {
		return nil, err
	}
	var keyBag *safeBag
	for _, element := range elements {
		bag, bagErr := shroudedKeyBag(element)
		if bagErr != nil {
			return nil, bagErr
		}
		if bag == nil {
			continue
		}
		if keyBag != nil {
			return nil, fmt.Errorf("%w: more than one shrouded private-key bag in one safe", ErrProfileUnknown)
		}
		keyBag = bag
	}
	if keyBag == nil {
		return nil, nil
	}
	return boundedKeyBagEncryption(keyBag)
}

// shroudedKeyBag decodes one bag of a plaintext safe and reports it only when it is
// a shrouded private-key bag; any other kind of bag reports nil, because only the
// key bag carries a profile-identifying algorithm.
func shroudedKeyBag(element []byte) (*safeBag, error) {
	var bag safeBag
	if unmarshalErr := unmarshalExact(element, &bag, "plaintext safe bags", "a plaintext safe bag"); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	id, err := decodeOID(bag.ID)
	if err != nil {
		return nil, err
	}
	if !id.Equal(oidPKCS8ShroudedKeyBag) {
		return nil, nil
	}
	return &bag, nil
}

// boundedKeyBagEncryption bounds the derivation count stored in a shrouded
// private-key bag and reports the algorithm the key inside it is encrypted with.
func boundedKeyBagEncryption(bag *safeBag) (asn1.ObjectIdentifier, error) {
	var info encryptedPrivateKeyInfo
	if unmarshalErr := unmarshalExact(bag.Value.Bytes, &info, "shrouded key bag",
		"a shrouded key bag's EncryptedPrivateKeyInfo"); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	keyOID, err := decodeOID(info.Algorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	// Measured, never copied: the ciphertext is required by RFC 5208, so a bundle
	// whose key bag omits it or mistypes it is not one this app wrote.
	if _, dataErr := octetStringBytes(info.EncryptedData, "shrouded key bag ciphertext"); dataErr != nil {
		return nil, dataErr
	}
	if iterErr := checkEncryptionIterations(keyOID, info.Algorithm.Parameters); iterErr != nil {
		return nil, iterErr
	}
	return keyOID, nil
}

// profileFor maps the (MAC, certificate-encryption, key-encryption) algorithm
// triple onto the encoder that produces it, reading the same profiles table
// resolvedProfile does so the two directions of the contract cannot drift apart.
//
// All three fields are needed: modern2023 and modern2026 differ only in their MAC,
// legacydes and legacyrc2 share a SHA-1 MAC and differ only in their certificate
// encryption, and the key encryption is what separates a bundle this app wrote
// from one that keeps a modern MAC and modern certificates over a 3DES-wrapped
// private key.
func profileFor(macAlg, certAlg, keyAlg asn1.ObjectIdentifier) (EncoderType, error) {
	// Indexed rather than ranged by value: a profile row is over gocritic's copy
	// threshold, and nothing here needs a copy.
	for i := range profiles {
		p := &profiles[i]
		if macAlg.Equal(p.macOID) && certAlg.Equal(p.certEncOID) && keyAlg.Equal(p.keyEncOID) {
			return p.name, nil
		}
	}
	return "", fmt.Errorf("%w: mac %v with certificate encryption %v and key encryption %v",
		ErrProfileUnknown, macAlg, certAlg, keyAlg)
}

// checkMACIterations bounds the MAC's derivation count and, for PBMAC1, checks the
// nested algorithm choices its parameter block carries.
//
// Where that count LIVES depends on the MAC algorithm, which is why this cannot
// simply read macData.iterations. The SHA-1 and SHA-256 profiles put it there:
// legacydes and legacyrc2 omit the field and encoding/asn1 applies its ASN.1
// DEFAULT of 1, modern2023 encodes 2048. PBMAC1 (modern2026) does not use the field
// at all — it carries a full PBKDF2 parameter block in the algorithm identifier, so
// the count is nested there and go-pkcs12 writes macData.iterations as an explicit
// 0 beside an empty salt, which is why that profile returns above without reading
// it. A zero reaching checkIterationsRange therefore comes only from a file that spelled
// one out, which is not a value any profile emits and is rejected like any other
// out-of-range count.
//
// The salt is floored on the same per-algorithm basis, for the reason recorded on
// minPBKDF2SaltBytes: an unsalted derivation is precomputable across every bundle
// sharing the password. PBMAC1 carries its salt inside the nested PBKDF2 block, so
// that arm is floored by decodeProfilePBKDF2 instead.
func checkMACIterations(macOID asn1.ObjectIdentifier, params, macSalt asn1.RawValue, macDataIterations int) error {
	// The salt's SHAPE is checked for every MAC algorithm, including PBMAC1, even
	// though only the sized arms below read its length. The field was a []byte before
	// the RawValue change, so asn1 refused a non-OCTET-STRING there for every
	// algorithm; returning for PBMAC1 without this check would quietly widen the
	// accepted set to bundles this app never writes.
	salt, saltErr := octetStringBytes(macSalt, "mac salt")
	if saltErr != nil {
		return saltErr
	}
	if macOID.Equal(oidPBMAC1) {
		return checkPBMAC1Parameters(params)
	}
	// Both floors are per-algorithm: the legacy SHA-1 MAC derives with one iteration
	// over an 8-octet salt, modern2023's SHA-256 MAC with 2048 over 16 (go-pkcs12
	// v0.7.3 pkcs12.go:162).
	//
	// The legacy pair is the DEFAULT, so a MAC algorithm this file does not know
	// gets the weakest floor here. That is safe only because profileFor refuses any
	// MAC identifier outside the profiles table later in inspect, before anything
	// derives — this check must not be read as the gate on WHICH MAC algorithms are
	// accepted. Two consequences for a future edit: adding a profile whose MAC is
	// neither SHA-1 nor SHA-256 must add an arm below (otherwise the new algorithm
	// silently inherits the 1-iteration/8-octet floor), and inspect must keep
	// calling profileFor on every path that reaches a derivation.
	minIterations := minLegacyMACIterations
	minSalt := minLegacySaltBytes
	if macOID.Equal(oidSHA256) {
		minIterations = minKDFIterations
		minSalt = minPBKDF2SaltBytes
	}
	if saltLenErr := checkSaltLength("mac", salt, minSalt); saltLenErr != nil {
		return saltLenErr
	}
	return checkIterationsRange("mac", macDataIterations, minIterations)
}

// parseProfilePBKDF2 checks one PBKDF2 AlgorithmIdentifier, nested inside either a
// PBES2 or a PBMAC1 block, against the single derivation the modern profiles emit,
// and returns the parsed parameters so a caller can check the fields that are
// specific to its own block.
//
// The PRF is part of profile identity, not a detail. modern2023 and modern2026 are
// selected for their SHA-256 algorithms, and go-pkcs12 always writes
// HMAC-SHA256 here, but its decoder ACCEPTS HMAC-SHA1 and applies the ASN.1
// DEFAULT of HMAC-SHA1 when the field is absent. Without this check a bundle
// deriving from SHA-1 decodes, matches the analysis and is reported current, so an
// operator who selected a modern profile keeps SHA-1 derivation on disk forever
// and the log says otherwise — the same missing-dimension the (MAC, certificate,
// key) triple and the AES-256 check already close at the outer levels.
func parseProfilePBKDF2(label string, alg *algorithmIdentifier) (pbkdf2Params, error) {
	kdf, err := decodeProfilePBKDF2(label, alg)
	if err != nil {
		return pbkdf2Params{}, err
	}
	if prfErr := checkProfilePBKDF2PRF(label, &kdf.PRF); prfErr != nil {
		return pbkdf2Params{}, prfErr
	}
	return kdf, nil
}

// decodeProfilePBKDF2 identifies the derivation as PBKDF2, decodes its parameter
// block, and checks the fields that describe the derivation itself: the salt's
// encoding and the iteration count.
func decodeProfilePBKDF2(label string, alg *algorithmIdentifier) (pbkdf2Params, error) {
	algOID, err := decodeOID(alg.Algorithm)
	if err != nil {
		return pbkdf2Params{}, err
	}
	if !algOID.Equal(oidPBKDF2) {
		return pbkdf2Params{}, fmt.Errorf("%w: %s key derivation is %v, want PBKDF2", ErrProfileUnknown, label, algOID)
	}
	var kdf pbkdf2Params
	if err := unmarshalExact(alg.Parameters.FullBytes, &kdf, label+" PBKDF2 parameters",
		"the "+label+" PBKDF2 parameters"); err != nil {
		return pbkdf2Params{}, err
	}
	// The salt is a CHOICE, and only the specified-OCTET-STRING arm is a shape
	// either modern profile writes or the decoder can consume (go-pkcs12 v0.7.3
	// crypto.go:222-224, mac.go:89-91).
	salt, saltErr := octetStringBytes(kdf.Salt, label+" PBKDF2 salt")
	if saltErr != nil {
		return pbkdf2Params{}, saltErr
	}
	if saltLenErr := checkSaltLength(label+" PBKDF2", salt, minPBKDF2SaltBytes); saltLenErr != nil {
		return pbkdf2Params{}, saltLenErr
	}
	if iterErr := checkIterationsRange(label, kdf.Iterations, minKDFIterations); iterErr != nil {
		return pbkdf2Params{}, iterErr
	}
	return kdf, nil
}

// checkProfilePBKDF2PRF checks the pseudorandom function a PBKDF2 block names
// against the only one either modern profile emits.
func checkProfilePBKDF2PRF(label string, prf *algorithmIdentifier) error {
	// An absent PRF means HMAC-SHA1 by definition, so it is refused here rather
	// than reaching decodeOID as an empty field with a misleading message.
	if len(prf.Algorithm.FullBytes) == 0 {
		return fmt.Errorf("%w: %s PBKDF2 names no PRF, which defaults to HMAC-SHA1",
			ErrProfileUnknown, label)
	}
	prfOID, err := decodeOID(prf.Algorithm)
	if err != nil {
		return err
	}
	if !prfOID.Equal(oidHMACWithSHA256) {
		return fmt.Errorf("%w: %s PBKDF2 PRF is %v, want HMAC-SHA256", ErrProfileUnknown, label, prfOID)
	}
	return nil
}

// checkPBES2Parameters checks a PBES2 block against what both modern profiles emit:
// PBKDF2 with an HMAC-SHA256 PRF and an in-range iteration count, over
// AES-256-CBC.
//
// PBES2 names its cipher and its derivation in its PARAMETERS, not in the algorithm
// identifier, so the (MAC, certificate, key) OID triple cannot tell AES-256-CBC from
// AES-192-CBC or AES-128-CBC, and the decoder accepts all three (go-pkcs12 v0.7.3
// crypto.go:241-250). Without this, a bundle that wraps the certificates or the
// private key with a weaker cipher, or derives its key with SHA-1, would be reported
// as modern2023 and kept as current indefinitely.
func checkPBES2Parameters(params asn1.RawValue) error {
	var outer pbes2Params
	if err := unmarshalExact(params.FullBytes, &outer, "pbes2 parameters", "the pbes2 parameters"); err != nil {
		return err
	}
	if _, kdfErr := parseProfilePBKDF2("pbes2", &outer.KeyDerivationFunc); kdfErr != nil {
		return kdfErr
	}
	schemeOID, err := decodeOID(outer.EncryptionScheme.Algorithm)
	if err != nil {
		return err
	}
	if !schemeOID.Equal(oidAES256CBC) {
		return fmt.Errorf("%w: pbes2 encryption scheme %v", ErrProfileUnknown, schemeOID)
	}
	return nil
}

// checkPBMAC1Parameters checks a PBMAC1 block against what modern2026 emits: PBKDF2
// with an HMAC-SHA256 PRF and a 32-octet derived key, authenticated with
// HMAC-SHA256.
//
// Both nested algorithms matter for the same reason the PBES2 cipher does. The MAC
// algorithm identifier is the bare oidPBMAC1 whatever is nested inside it, and the
// decoder accepts HMAC-SHA1 as both the PRF and the MAC (go-pkcs12 v0.7.3
// mac.go:96-121). The key length is checked too because RFC 9579 makes it mandatory
// and go-pkcs12 writes exactly 32 (mac.go:50): a shorter key the decoder still
// accepts (down to 20 octets) is a weaker MAC than the profile promises.
func checkPBMAC1Parameters(params asn1.RawValue) error {
	var outer pbmac1Params
	if err := unmarshalExact(params.FullBytes, &outer, "pbmac1 parameters", "the pbmac1 parameters"); err != nil {
		return err
	}
	kdf, err := parseProfilePBKDF2("pbmac1", &outer.KeyDerivationFunc)
	if err != nil {
		return err
	}
	const pbmac1KeyOctets = 32
	if kdf.KeyLength != pbmac1KeyOctets {
		return fmt.Errorf("%w: pbmac1 derives a %d-octet key, want %d",
			ErrProfileUnknown, kdf.KeyLength, pbmac1KeyOctets)
	}
	macOID, err := decodeOID(outer.MessageAuthScheme.Algorithm)
	if err != nil {
		return err
	}
	if !macOID.Equal(oidHMACWithSHA256) {
		return fmt.Errorf("%w: pbmac1 message authentication is %v, want HMAC-SHA256", ErrProfileUnknown, macOID)
	}
	return nil
}

// checkEncryptionIterations bounds the certificate bag's derivation count and, for
// PBES2, checks the nested algorithm choices too. The two parameter shapes differ by
// profile: the SHA-1 profiles carry pkcs-12PbeParams directly, while PBES2 nests its
// count and its algorithms inside a PBKDF2 parameter block.
func checkEncryptionIterations(algOID asn1.ObjectIdentifier, params asn1.RawValue) error {
	switch {
	case algOID.Equal(oidPBES2):
		return checkPBES2Parameters(params)
	default:
		var legacy legacyPBEParams
		if err := unmarshalExact(params.FullBytes, &legacy, "PBE parameters", "the PBE parameters"); err != nil {
			return err
		}
		salt, saltErr := octetStringBytes(legacy.Salt, "pbe salt")
		if saltErr != nil {
			return saltErr
		}
		if saltLenErr := checkSaltLength("pbe", salt, minLegacySaltBytes); saltLenErr != nil {
			return saltLenErr
		}
		return checkIterationsRange("pbe", legacy.Iterations, minKDFIterations)
	}
}

// checkIterationsRange rejects a count outside the range this app is willing to
// run AND willing to trust. The ceiling is the work cap (see maxKDFIterations);
// the floor is profile identity — a count below what the profile emits is a
// weaker derivation than the operator configured, and the decoder accepts it
// silently. Non-positive is still rejected by the floor: it is not a value any
// profile emits, and treating it as "cheap" would accept a file whose framing we
// do not understand.
func checkIterationsRange(label string, n, minIterations int) error {
	if n < minIterations || n > maxKDFIterations {
		return fmt.Errorf("%w: %s iteration count %d outside %d..%d",
			ErrProfileUnknown, label, n, minIterations, maxKDFIterations)
	}
	return nil
}

// checkSaltLength rejects a derivation salt shorter than the length the profile
// emits, the salt half of what checkIterationsRange does for a count. what names
// the derivation for the refusal ("mac", "pbe", "pbes2 PBKDF2"), so the floor
// comparison and its message have one home rather than one per refusal site; the
// floors themselves stay per-algorithm at the call sites (see minPBKDF2SaltBytes).
func checkSaltLength(what string, salt []byte, minBytes int) error {
	if len(salt) < minBytes {
		return fmt.Errorf("%w: %s salt is %d octet(s), want at least %d",
			ErrProfileUnknown, what, len(salt), minBytes)
	}
	return nil
}

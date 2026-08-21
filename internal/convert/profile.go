package convert

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// maxKDFIterations caps every password-based key-derivation iteration count the
// preflight can read before this app runs it.
//
// One count is out of reach, so this cap is not a total bound.
const maxKDFIterations = 10000

// minKDFIterations is the floor those same counts must clear. Every derivation
// location all four profiles emit uses 2048 (go-pkcs12 v0.7.3 pkcs12.go:101, 122,
// 163, 190); the one exception is the legacy profiles' MAC, which uses 1
// (pkcs12.go:100, 121) and is floored separately in checkMACIterations.
const minKDFIterations = 2048

// minLegacyMACIterations is the floor for the one derivation location that does not
// use 2048: the SHA-1 MAC of the two legacy profiles, which derives with a single
// iteration (go-pkcs12 v0.7.3 pkcs12.go:100, 121).
const minLegacyMACIterations = 1

// minPBKDF2SaltBytes and minLegacySaltBytes are the salt lengths the profiles
// emit: 16 octets for both modern profiles (go-pkcs12 v0.7.3 pkcs12.go:164, 191
// saltLen: 16) and 8 for both legacy profiles (pkcs12.go:102, 123 saltLen: 8).
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
	// (RFC 7292 §4.2.2).
	oidPKCS8ShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}

	oidPBES2                         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}

	// oidAES256CBC is the only PBES2 encryption scheme either modern profile
	// emits: go-pkcs12 v0.7.3 sets it unconditionally (crypto.go:324).
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	// oidPBKDF2 is the only key-derivation function either modern profile names
	// inside a PBES2 or PBMAC1 parameter block: go-pkcs12 v0.7.3 sets it
	// unconditionally (crypto.go:320, mac.go:54).
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	// oidHMACWithSHA256 is the only PBKDF2 pseudorandom function, and the only
	// PBMAC1 message-authentication scheme, either modern profile emits
	// (go-pkcs12 v0.7.3 crypto.go:317, mac.go:51 and mac.go:58).
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
)

// ErrProfileUnknown reports a bundle the preflight refused as one this app's encoder
// profiles do not produce — anything from its DER framing to an algorithm, parameter,
// salt or iteration count it declares. It does not say WHICH, so a caller cannot tell
// refusal kinds apart with it.
var ErrProfileUnknown = errors.New("pkcs12 bundle was not written by a known encoder profile")

// errKDFBudget marks the one preflight refusal that is not a positive
// identification: the file declares derivation work outside the range this app will
// spend, so nothing about its interior was read. Minted at the site that declines the
// work (checkIterationsRange) and read once, by refusalReason, so no consumer
// re-derives which refusal was made.
var errKDFBudget = fmt.Errorf("%w: declared key-derivation work outside the accepted range", ErrProfileUnknown)

// refusalReason names WHICH refusal the preflight made. Every refusal but the
// derivation budget's is a positive identification that these bytes are not a bundle
// any of this app's profiles writes.
func refusalReason(err error) CurrencyReason {
	if errors.Is(err, errKDFBudget) {
		return CurrencyPreflightFailed
	}
	return CurrencyForeign
}

// --- Minimal PKCS#12 shapes, for the preflight only ---

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
// is THERE and well-shaped.
type digestInfo struct {
	Algorithm algorithmIdentifier
	Digest    asn1.RawValue
}

type algorithmIdentifier struct {
	Algorithm  asn1.RawValue
	Parameters asn1.RawValue `asn1:"optional"`
}

// MaxBundleBytes is the largest prior bundle the app admits to this codec through
// the store.
const MaxBundleBytes = 2*MaxInputBytes + 64<<10

// maxOIDBytes caps the content length of an object identifier the preflight is
// willing to decode.
const maxOIDBytes = 32

// decodeOID turns one retained identifier field into an asn1.ObjectIdentifier,
// rejecting anything oversized before it is decoded.
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
// copying it, refusing any other shape.
func octetStringBytes(raw asn1.RawValue, what string) ([]byte, error) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagOctetString || raw.IsCompound {
		return nil, fmt.Errorf("%w: %s is not a primitive OCTET STRING", ErrProfileUnknown, what)
	}
	return raw.Bytes, nil
}

// unmarshalExact decodes one complete DER element into out.
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
	maxAuthenticatedSafes = 2
	maxSafeBags           = 64
)

// sequenceElements splits one DER SEQUENCE OF into its elements' raw DER,
// refusing a sequence with more elements than the preflight will look at.
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
// pkcs12.go:244).
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
	EncryptedData asn1.RawValue
}

// legacyPBEParams is the pkcs-12PbeParams of the SHA1-based profiles.
type legacyPBEParams struct {
	Salt       asn1.RawValue
	Iterations int
}

// pbes2Params and pbmac1Params are the two outer parameter blocks the modern
// profiles use (RFC 8018 §A.4 and RFC 9579 §4).
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
//nolint:govet // DER SEQUENCE order (RFC 8018 §A.2); see pfxPreamble.
type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                 `asn1:"optional"`
	PRF        algorithmIdentifier `asn1:"optional"`
}

// inspect identifies the encoder profile of an existing PKCS#12 bundle and
// verifies the key-derivation iteration counts it can read are within range,
// WITHOUT running any derivation.
func inspect(pfx []byte) (EncoderType, error) {
	var preamble pfxPreamble
	// asn1.Unmarshal returns trailing bytes rather than rejecting them.
	if unmarshalErr := unmarshalExact(pfx, &preamble, "pkcs12 preamble", "the bundle"); unmarshalErr != nil {
		return "", unmarshalErr
	}
	// All four profiles write a v3 PFX (go-pkcs12 v0.7.3 pkcs12.go:665, 835) and
	// DecodeChain refuses any other version outright, before it verifies the MAC
	// (pkcs12.go:556), so a different version is not a bundle we wrote.
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
	if _, digestErr := octetStringBytes(preamble.MacData.Mac.Digest, "mac digest"); digestErr != nil {
		return "", digestErr
	}
	return profileName, nil
}

// safeAlgorithms is the part of a bundle's profile identity that lives in the
// authenticated safe: the certificate-encryption algorithm of an encrypted safe
// and the encryption algorithm of the shrouded private-key bag.
type safeAlgorithms struct {
	certEnc asn1.ObjectIdentifier
	keyEnc  asn1.ObjectIdentifier
}

// bundleAlgorithms reaches the certificate bag's and the private-key bag's
// content-encryption algorithms, and bounds every derivation count that is
// readable without decrypting a safe on the way.
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

// merge folds one safe's contribution into the bundle-level identity.
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
func checkMACIterations(macOID asn1.ObjectIdentifier, params, macSalt asn1.RawValue, macDataIterations int) error {
	// The salt's SHAPE is checked for every MAC algorithm, including PBMAC1, even
	// though only the sized arms below read its length.
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
	// crypto.go:222-224, mac.go:90-92).
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
// PBES2, checks the nested algorithm choices too.
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
// run AND willing to trust.
func checkIterationsRange(label string, n, minIterations int) error {
	if n < minIterations || n > maxKDFIterations {
		return fmt.Errorf("%w: %s iteration count %d outside %d..%d",
			errKDFBudget, label, n, minIterations, maxKDFIterations)
	}
	return nil
}

// checkSaltLength rejects a derivation salt shorter than the length the profile
// emits, the salt half of what checkIterationsRange does for a count.
func checkSaltLength(what string, salt []byte, minBytes int) error {
	if len(salt) < minBytes {
		return fmt.Errorf("%w: %s salt is %d octet(s), want at least %d",
			ErrProfileUnknown, what, len(salt), minBytes)
	}
	return nil
}

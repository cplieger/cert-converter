package convert

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// maxBundleKDFWork caps decoder-equivalent key-derivation work in one PFX.
// maxScanKDFWork caps the sum across one scan, so many individually legal
// bundles cannot multiply the bound without limit. The scan ceiling fits
// hundreds of ordinary modern bundles while bounding worst-case work to four
// per-bundle ceilings.
const (
	maxBundleKDFWork int64 = 5_000_000
	maxScanKDFWork   int64 = 20_000_000

	// MaxPEMOutputBytes bounds either PEM artifact produced from one PFX. DER
	// inside an admitted bundle expands under base64 and line wrapping; twice the
	// bundle ceiling leaves room for that expansion without making output
	// writes unbounded.
	MaxPEMOutputBytes = 2 * MaxBundleBytes
)

// ErrBundleUnbounded reports a PFX the preflight refused to hand to the decoder
// because its per-bundle or scan-wide derivation work exceeds a ceiling.
var ErrBundleUnbounded = errors.New("input bundle declares key-derivation work above the accepted ceiling")

// BundleWorkBudget carries decoder-equivalent KDF work across one input scan.
// Construct one per scan and pass it to every AnalyseBundleWithBudget call.
type BundleWorkBudget struct {
	total int64
}

// NewBundleWorkBudget constructs an empty scan-wide bundle-work budget.
func NewBundleWorkBudget() *BundleWorkBudget { return new(BundleWorkBudget) }

type inputWorkBudget struct {
	scan   *BundleWorkBudget
	bundle int64
}

func (b *inputWorkBudget) add(what string, iterations, weight int) error {
	if iterations <= 0 {
		return nil // malformed counts are the decoder's cheap refusal
	}
	// Any value above this quotient exceeds the bundle ceiling and is refused
	// before multiplication, so attacker-controlled int overflow is impossible.
	if int64(iterations) > maxBundleKDFWork/int64(weight) {
		return fmt.Errorf("%w: %s declares %d iterations at weight %d, bundle limit %d",
			ErrBundleUnbounded, what, iterations, weight, maxBundleKDFWork)
	}
	work := int64(iterations) * int64(weight)
	nextBundle := b.bundle + work
	if nextBundle > maxBundleKDFWork {
		return fmt.Errorf("%w: %s brings bundle work to %d weighted rounds, limit %d",
			ErrBundleUnbounded, what, nextBundle, maxBundleKDFWork)
	}
	if b.scan.total > maxScanKDFWork-nextBundle {
		return fmt.Errorf("%w: %s would bring scan work to %d weighted rounds, limit %d",
			ErrBundleUnbounded, what, b.scan.total+nextBundle, maxScanKDFWork)
	}
	b.bundle = nextBundle
	return nil
}

// AnalyseBundle resolves one PKCS#12 bundle with a fresh work budget. A scanner
// handling several bundles uses AnalyseBundleWithBudget instead.
func AnalyseBundle(ctx context.Context, pfx []byte, password string) (Analysis, error) {
	return AnalyseBundleWithBudget(ctx, pfx, password, NewBundleWorkBudget())
}

// AnalyseBundleWithBudget resolves a PKCS#12 bundle into the same Analysis a PEM
// pair yields. It charges decoder-equivalent work to budget, decodes the bundle,
// and routes recovered parts through the one analysis pipeline.
func AnalyseBundleWithBudget(ctx context.Context, pfx []byte, password string, budget *BundleWorkBudget) (Analysis, error) {
	if err := ctx.Err(); err != nil {
		return Analysis{}, fmt.Errorf("analyse bundle cancelled: %w", err)
	}
	if budget == nil {
		budget = NewBundleWorkBudget()
	}
	if err := boundInputBundle(pfx, budget); err != nil {
		return Analysis{}, err
	}
	if err := ctx.Err(); err != nil {
		return Analysis{}, fmt.Errorf("analyse bundle cancelled: %w", err)
	}
	key, leaf, caCerts, err := pkcs12.DecodeChain(pfx, password)
	if err != nil {
		return Analysis{}, fmt.Errorf("decode input bundle: %w", boundedTextError{err})
	}
	certPEM, err := encodeCertsPEM(append([]*x509.Certificate{leaf}, caCerts...))
	if err != nil {
		return Analysis{}, err
	}
	keyPEM, err := encodeKeyPEM(key)
	if err != nil {
		return Analysis{}, err
	}
	return Analyse(ctx, certPEM, keyPEM)
}

// EncodePEM renders the analysis as a PEM pair: the leaf and its chain as
// CERTIFICATE blocks, leaf first, and the private key as an unencrypted PKCS#8
// block. The output is deterministic for one analysed identity, which is what
// lets a byte comparison decide whether a prior PEM artifact is current.
func (a Analysis) EncodePEM() (certPEM, keyPEM []byte, err error) { //nolint:gocritic // hugeParam: same reason as Encode — the value Analyse hands back cannot be nil, so this body needs no nil arm.
	certPEM, err = encodeCertsPEM(append([]*x509.Certificate{a.leaf}, a.chain...))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKeyPEM(a.key)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// encodeCertsPEM renders certificates as concatenated PEM CERTIFICATE blocks.
func encodeCertsPEM(certs []*x509.Certificate) ([]byte, error) {
	var out []byte
	for _, cert := range certs {
		if cert == nil {
			return nil, errors.New("encode certificates: nil certificate")
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if len(out) == 0 {
		return nil, errors.New("encode certificates: no certificate to encode")
	}
	return out, nil
}

// encodeKeyPEM renders a private key as an unencrypted PKCS#8 PEM block.
func encodeKeyPEM(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// --- The input-bundle preflight ---

// boundInputBundle caps the sum of every key-derivation count readable without
// decrypting, before any derivation runs. Unknown or malformed shapes stay the
// decoder's job because it refuses them cheaply. One shrouded key bag nested in
// an encrypted safe remains unreachable (go-pkcs12 decrypts before exposing its
// count; SSLMate/go-pkcs12#80). PFX input requires a non-blank password, so
// an untrusted writer cannot reach that residual without the secret that
// authenticates the bundle MAC.
func boundInputBundle(pfx []byte, scan *BundleWorkBudget) (err error) {
	var preamble pfxPreamble
	if parseErr := unmarshalExact(pfx, &preamble, "pkcs12 preamble", "the bundle"); parseErr != nil {
		return nil // not parseable as a PFX at all: the decoder fails the same parse
	}
	budget := inputWorkBudget{scan: scan}
	defer func() {
		if err == nil {
			scan.total += budget.bundle
		}
	}()
	if workErr := boundMACWork(&preamble.MacData, &budget); workErr != nil {
		return workErr
	}
	elements, err := authenticatedSafeElements(&preamble.AuthSafe)
	if err != nil {
		return nil // a framing the decoder must judge (it refuses >2 safes itself)
	}
	for _, element := range elements {
		var safe contentInfo
		if unmarshalErr := unmarshalExact(element, &safe, "authenticated safe", "an authenticated safe"); unmarshalErr != nil {
			return nil
		}
		if err := boundSafeWork(&safe, &budget); err != nil {
			return err
		}
	}
	return nil
}

// boundMACWork bounds the two derivation counts the MAC can declare: the outer
// MacData iteration count every profile family uses, and a PBMAC1 parameter
// block's nested PBKDF2 count.
func boundMACWork(mac *macData, budget *inputWorkBudget) error {
	macOID, err := decodeOID(mac.Mac.Algorithm.Algorithm)
	if err != nil {
		return nil
	}
	if !macOID.Equal(oidPBMAC1) {
		return budget.add("mac", mac.Iterations, 1)
	}
	var params pbmac1Params
	if unmarshalErr := unmarshalExact(mac.Mac.Algorithm.Parameters.FullBytes, &params,
		"pbmac1 parameters", "the pbmac1 parameters"); unmarshalErr != nil {
		return nil
	}
	return boundKDFAlgorithm("mac key derivation", &params.KeyDerivationFunc, budget)
}

// boundSafeWork bounds what one authenticated safe declares: an encrypted safe's
// content-encryption derivation, or the shrouded key bags of a plaintext safe.
func boundSafeWork(safe *contentInfo, budget *inputWorkBudget) error {
	contentType, err := decodeOID(safe.ContentType)
	if err != nil {
		return nil
	}
	switch {
	case contentType.Equal(oidEncryptedDataContentType):
		var enc encryptedData
		if unmarshalErr := unmarshalExact(safe.Content.Bytes, &enc, "encrypted safe contents",
			"an encrypted safe's contents"); unmarshalErr != nil {
			return nil
		}
		return boundEncryptionAlgorithm("encrypted safe", &enc.EncryptedContentInfo.ContentEncryptionAlgorithm, budget)
	case contentType.Equal(oidDataContentType):
		return boundPlaintextSafeBags(safe.Content.Bytes, budget)
	}
	return nil
}

// boundPlaintextSafeBags bounds every shrouded private-key bag in a plaintext
// safe. Every bag is checked rather than only the first the decoder derives from,
// because which bag a decoder picks is its own detail.
func boundPlaintextSafeBags(content []byte, budget *inputWorkBudget) error {
	var wrapper asn1.RawValue
	if err := unmarshalExact(content, &wrapper, "plaintext safe content", "a plaintext safe's content"); err != nil {
		return nil
	}
	inner, err := octetStringBytes(wrapper, "a plaintext safe's content")
	if err != nil {
		return nil
	}
	elements, err := sequenceElements(inner, "plaintext safe bags", maxSafeBags)
	if errors.Is(err, errElementBudget) {
		return fmt.Errorf("%w: plaintext safe holds more than %d bags", ErrBundleUnbounded, maxSafeBags)
	}
	if err != nil {
		return nil
	}
	for _, element := range elements {
		var bag safeBag
		if unmarshalErr := unmarshalExact(element, &bag, "safe bag", "a safe bag"); unmarshalErr != nil {
			return nil
		}
		bagID, idErr := decodeOID(bag.ID)
		if idErr != nil || !bagID.Equal(oidPKCS8ShroudedKeyBag) {
			continue
		}
		var keyInfo encryptedPrivateKeyInfo
		if unmarshalErr := unmarshalExact(bag.Value.Bytes, &keyInfo, "shrouded key bag", "a shrouded key bag"); unmarshalErr != nil {
			return nil
		}
		if err := boundEncryptionAlgorithm("shrouded key bag", &keyInfo.Algorithm, budget); err != nil {
			return err
		}
	}
	return nil
}

// boundEncryptionAlgorithm bounds one password-based encryption algorithm's
// declared derivation count, for the two parameter shapes the decoder derives
// from: PBES2's nested PBKDF2, and the single salt-plus-iterations shape every
// PKCS#12 and PKCS#5 v1 PBE scheme uses.
func boundEncryptionAlgorithm(what string, alg *algorithmIdentifier, budget *inputWorkBudget) error {
	algOID, err := decodeOID(alg.Algorithm)
	if err != nil {
		return nil
	}
	if algOID.Equal(oidPBES2) {
		var params pbes2Params
		if unmarshalErr := unmarshalExact(alg.Parameters.FullBytes, &params,
			"pbes2 parameters", "the pbes2 parameters"); unmarshalErr != nil {
			return nil
		}
		return boundKDFAlgorithm(what, &params.KeyDerivationFunc, budget)
	}
	if !isPasswordBasedEncryptionOID(algOID) {
		return nil
	}
	var params legacyPBEParams
	if unmarshalErr := unmarshalExact(alg.Parameters.FullBytes, &params,
		"pbe parameters", "the pbe parameters"); unmarshalErr != nil {
		return nil
	}
	weight := 2 // key and IV each need at least one legacy PKCS#12 KDF block
	if algOID.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC) {
		weight = 3 // 24-byte 3DES key spans two SHA-1 blocks; IV spans one
	}
	return budget.add(what, params.Iterations, weight)
}

// boundKDFAlgorithm bounds a named key-derivation function's count; only PBKDF2
// is readable, and anything else is the decoder's to refuse.
func boundKDFAlgorithm(what string, kdf *algorithmIdentifier, budget *inputWorkBudget) error {
	kdfOID, err := decodeOID(kdf.Algorithm)
	if err != nil || !kdfOID.Equal(oidPBKDF2) {
		return nil
	}
	var params pbkdf2Params
	if unmarshalErr := unmarshalExact(kdf.Parameters.FullBytes, &params,
		"pbkdf2 parameters", "the pbkdf2 parameters"); unmarshalErr != nil {
		return nil
	}
	// Four PBKDF2 blocks is the dependency's worst accepted case: a 64-byte
	// PBMAC1 key with SHA-1. PBES2 needs no more work, so this conservative
	// weight bounds both paths without reimplementing their algorithm tables.
	return budget.add(what, params.Iterations, 4)
}

// oidPKCS12PBEArc and oidPKCS5PBEArc are the OID arcs under which every
// salt-plus-iterations PBE scheme lives: pkcs-12PbeIds (RFC 7292 appendix C) and
// PKCS#5 v1's pbeWithMD2/MD5/SHA1 family (RFC 8018 appendix A.3).
var (
	oidPKCS12PBEArc = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1}
	oidPKCS5PBEArc  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5}
)

// isPasswordBasedEncryptionOID reports whether oid names a scheme whose
// parameters are the salt-plus-iterations shape.
func isPasswordBasedEncryptionOID(oid asn1.ObjectIdentifier) bool {
	return underArc(oid, oidPKCS12PBEArc) || (underArc(oid, oidPKCS5PBEArc) && !oid.Equal(oidPBES2) && !oid.Equal(oidPBKDF2) && !oid.Equal(oidPBMAC1))
}

// underArc reports whether oid sits strictly under arc.
func underArc(oid, arc asn1.ObjectIdentifier) bool {
	if len(oid) <= len(arc) {
		return false
	}
	for i := range arc {
		if oid[i] != arc[i] {
			return false
		}
	}
	return true
}

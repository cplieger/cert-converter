package convert

import (
	"encoding/asn1"
	"slices"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// EncoderType is a typed string for PFX encoding selection.
type EncoderType string

// Encoder name constants for PFX encoding selection.
const (
	EncNameModern2023 EncoderType = "modern2023"
	EncNameModern2026 EncoderType = "modern2026"
	EncNameLegacyDES  EncoderType = "legacydes"
	EncNameLegacyRC2  EncoderType = "legacyrc2"
)

// profile is one row of the encoder-profile contract: the app-owned name, the
// spellings accepted for it, the go-pkcs12 encoder it selects, and the (MAC,
// certificate-encryption, key-encryption) algorithm triple that encoder emits.
// One row per profile so the forward mapping (name -> encoder) and the reverse one
// (algorithm triple -> name, profileFor) cannot disagree: adding a profile here is
// the single edit, where previously the same knowledge lived in three
// hand-maintained switches and a missed one made Inspect reject this app's own
// output.
//
// All three algorithms are part of a profile's identity because they vary
// independently: legacyrc2 encrypts certificates with RC2-40 but its private key
// with 3DES, so a bundle carrying a modern MAC and PBES2 certificates over a
// 3DES-encrypted key is NOT a bundle any profile here emits. Recording only the
// first two would report such a mixed bundle as modern2023 and leave a weakly
// protected private key on disk.
type profile struct {
	name       EncoderType
	aliases    []string
	encoder    *pkcs12.Encoder
	macOID     asn1.ObjectIdentifier
	certEncOID asn1.ObjectIdentifier
	keyEncOID  asn1.ObjectIdentifier
}

// profiles is the one home of the encoder-profile contract. The OID values it
// names are declared in profile.go beside the rest of the preflight's OIDs. The
// triples match the pinned go-pkcs12 v0.7.3 encoders (pkcs12.go:96-188), whose
// macAlgorithm/certAlgorithm/keyAlgorithm fields these three columns mirror.
var profiles = []profile{
	{EncNameModern2023, []string{"", "modern"}, pkcs12.Modern2023, oidSHA256, oidPBES2, oidPBES2},
	{EncNameModern2026, nil, pkcs12.Modern2026, oidPBMAC1, oidPBES2, oidPBES2},
	{EncNameLegacyDES, []string{"legacy"}, pkcs12.LegacyDES, oidSHA1, oidPBEWithSHAAnd3KeyTripleDESCBC, oidPBEWithSHAAnd3KeyTripleDESCBC},
	{EncNameLegacyRC2, nil, pkcs12.LegacyRC2, oidSHA1, oidPBEWithSHAAnd40BitRC2CBC, oidPBEWithSHAAnd3KeyTripleDESCBC},
}

// EncoderName normalizes a raw PFX_ENCODER value to one of the known encoder
// names. It owns the normalization rule but not the diagnostic: known reports
// whether raw matched a recognized spelling, so the caller that read the
// environment variable is the one that names it in a warning. An unrecognized
// value falls back to modern2023 with known false.
func EncoderName(raw string) (name EncoderType, known bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	for _, p := range profiles {
		if v == string(p.name) || slices.Contains(p.aliases, v) {
			return p.name, true
		}
	}
	return EncNameModern2023, false
}

// resolvedProfile resolves an EncoderType to the profile row it selects: the
// matching row when this package knows the name, and the modern2023 row
// otherwise. It is the ONE home of the matching-and-fallback rule, because the
// write side and the read-back side must agree about an unrecognized name — with
// each side searching the table itself, Encode could write a modern2023 bundle
// while CheckCurrency compared the file against the name it was handed, reporting
// profile-mismatch on every scan and rewriting the bundle forever. Both values are
// returned together so a caller cannot take one side's answer from a different row.
func resolvedProfile(name EncoderType) (EncoderType, *pkcs12.Encoder) {
	for _, p := range profiles {
		if p.name == name {
			return p.name, p.encoder
		}
	}
	return EncNameModern2023, pkcs12.Modern2023
}

// resolvedName reports the profile name an EncoderType actually selects — the same
// total fallback encoderFor applies, since both read it from resolvedProfile.
func resolvedName(name EncoderType) EncoderType {
	resolved, _ := resolvedProfile(name)
	return resolved
}

// encoderFor resolves an already-normalized encoder name to its PKCS#12
// encoder. It never validates (EncoderName owns name normalization) and
// never returns nil: an unknown name yields the modern2023 default, so the
// vendor type stays confined to this package while callers pass the app-owned
// name around.
func encoderFor(name EncoderType) *pkcs12.Encoder {
	_, encoder := resolvedProfile(name)
	return encoder
}

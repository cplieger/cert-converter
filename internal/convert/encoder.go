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
// Keeping both directions in this table prevents the name-to-encoder and
// algorithm-triple-to-name mappings from drifting apart.
//
// The modern2023 row's empty-string alias is not a spelling an operator types: it is the
// UNSET PFX_ENCODER case, and it is what keeps internal/config's
// "unknown PFX_ENCODER" WARN off every default deployment (config.go calls EncoderName
// with the raw environment value and warns whenever known is false). Do not drop it when
// aligning the alias sets with the documented spellings.
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
// environment variable is the one that names it in a warning. An empty or
// whitespace-only value is the unset case and is RECOGNIZED: it returns modern2023
// with known true, so leaving PFX_ENCODER unset warns about nothing. Any other
// unrecognized value falls back to modern2023 with known false.
func EncoderName(raw string) (name EncoderType, known bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	for _, p := range profiles {
		if v == string(p.name) || slices.Contains(p.aliases, v) {
			return p.name, true
		}
	}
	return defaultProfile.name, false
}

// defaultProfile is the row every unrecognized name resolves to, and the one home
// of that answer: EncoderName's fallback and resolvedProfile's both read it, so
// "which profile is the default" is one edit in the table rather than three
// literals to keep aligned. A partial edit is what would make the write side emit
// one profile while the read side compared against another — the permanent
// rewrite loop resolvedProfile exists to prevent.
var defaultProfile = profiles[0]

// EncoderNames returns the canonical PFX_ENCODER spellings in profile-table
// order. The profiles table stays the single home of the value domain, while the
// caller that read the environment variable names the accepted set in its own
// diagnostic — the same split EncoderName already documents for the warning.
func EncoderNames() []EncoderType {
	names := make([]EncoderType, 0, len(profiles))
	for _, p := range profiles {
		names = append(names, p.name)
	}
	return names
}

// ModernMACIterations is the KDF iteration count the modern profiles derive their
// MAC with, and the baseline a legacy-profile warning is read against. Named here
// rather than restated by a caller so the number a diagnostic prints and the floor
// the decode preflight enforces cannot drift.
const ModernMACIterations = minKDFIterations

// Protection reports what one profile's bundles do to protect the embedded
// password and the private key. It exists so a caller that must WARN about a weak
// PFX_ENCODER choice does not re-enumerate which profiles are weak: this package
// owns the profile table, so the table answers it and a row added there cannot
// escape the warning.
type Protection struct {
	// MACIterations is the iteration count this profile's MAC derives with.
	MACIterations int
	// NominalOnly reports a profile whose MAC derives with a single iteration, so an
	// offline password search over a leaked bundle costs about one hash per guess.
	NominalOnly bool
	// WeakCertCipher reports a profile that encrypts the certificate bag with 40-bit
	// RC2, which is a second, independent weakness on top of the MAC.
	WeakCertCipher bool
}

// ProtectionOf reports the protection facts for an encoder name, resolving an
// unrecognized name exactly as Encode does (resolvedProfile), so a warning and the
// bundle that is actually written can never describe different profiles.
func ProtectionOf(name EncoderType) Protection {
	p := resolvedProfile(name)
	legacyMAC := p.macOID.Equal(oidSHA1)
	iterations := ModernMACIterations
	if legacyMAC {
		iterations = minLegacyMACIterations
	}
	return Protection{
		MACIterations:  iterations,
		NominalOnly:    legacyMAC,
		WeakCertCipher: p.certEncOID.Equal(oidPBEWithSHAAnd40BitRC2CBC),
	}
}

// resolvedProfile resolves an EncoderType to the profile row it selects: the
// matching row when this package knows the name, and the modern2023 row
// otherwise. It is the ONE home of the matching-and-fallback rule, because the
// write side and the read-back side must agree about an unrecognized name — with
// each side searching the table itself, Encode could write a modern2023 bundle
// while CheckCurrency compared the file against the name it was handed, reporting
// profile-mismatch on every scan and rewriting the bundle forever. Returning the
// row keeps its name and encoder inseparable.
func resolvedProfile(name EncoderType) profile {
	for _, p := range profiles {
		if p.name == name {
			return p
		}
	}
	return defaultProfile
}

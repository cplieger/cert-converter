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
type profile struct {
	name          EncoderType
	aliases       []string
	encoder       *pkcs12.Encoder
	macOID        asn1.ObjectIdentifier
	certEncOID    asn1.ObjectIdentifier
	keyEncOID     asn1.ObjectIdentifier
	macIterations int
}

// profiles is the one home of the encoder-profile contract. The OID values it
// names are declared in profile.go beside the rest of the preflight's OIDs. The
// triples match the pinned go-pkcs12 v0.7.3 encoders (pkcs12.go:96-188), whose
// macAlgorithm/certAlgorithm/keyAlgorithm fields these three columns mirror, and
// the trailing count is the iteration count that encoder's MAC derives with.
var profiles = []profile{
	{EncNameModern2023, []string{"", "modern"}, pkcs12.Modern2023, oidSHA256, oidPBES2, oidPBES2, minKDFIterations},
	{EncNameModern2026, nil, pkcs12.Modern2026, oidPBMAC1, oidPBES2, oidPBES2, minKDFIterations},
	{EncNameLegacyDES, []string{"legacy"}, pkcs12.LegacyDES, oidSHA1, oidPBEWithSHAAnd3KeyTripleDESCBC, oidPBEWithSHAAnd3KeyTripleDESCBC, minLegacyMACIterations},
	{EncNameLegacyRC2, nil, pkcs12.LegacyRC2, oidSHA1, oidPBEWithSHAAnd40BitRC2CBC, oidPBEWithSHAAnd3KeyTripleDESCBC, minLegacyMACIterations},
}

// EncoderName normalizes a raw PFX_ENCODER value to one of the known encoder
// names.
func EncoderName(raw string) (name EncoderType, known bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	// Indexed rather than ranged by value: a profile row is over gocritic's copy
	// threshold, and nothing here needs a copy.
	for i := range profiles {
		p := &profiles[i]
		if v == string(p.name) || slices.Contains(p.aliases, v) {
			return p.name, true
		}
	}
	return defaultProfile.name, false
}

// defaultProfile is the row every unrecognized name resolves to, and the one home
// of that answer: EncoderName's fallback and resolvedProfile's both read it, so
// "which profile is the default" is one edit in the table rather than three
// literals to keep aligned.
var defaultProfile = profiles[0]

// EncoderNames returns the canonical PFX_ENCODER spellings in profile-table
// order.
func EncoderNames() []EncoderType {
	names := make([]EncoderType, 0, len(profiles))
	for i := range profiles {
		names = append(names, profiles[i].name)
	}
	return names
}

// ModernMACIterations is the KDF iteration count the modern profiles derive their
// MAC with, and the baseline a legacy-profile warning is read against.
const ModernMACIterations = minKDFIterations

// Protection reports what one profile's bundles do to protect the embedded
// password and the private key.
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
	return Protection{
		MACIterations:  p.macIterations,
		NominalOnly:    p.macIterations == minLegacyMACIterations,
		WeakCertCipher: p.certEncOID.Equal(oidPBEWithSHAAnd40BitRC2CBC),
	}
}

// resolvedProfile resolves an EncoderType to the profile row it selects: the
// matching row when this package knows the name, and the modern2023 row
// otherwise.
func resolvedProfile(name EncoderType) profile {
	for i := range profiles {
		if profiles[i].name == name {
			return profiles[i]
		}
	}
	return defaultProfile
}

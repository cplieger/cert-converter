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
// certificate-encryption) algorithm pair that encoder emits. One row per profile
// so the forward mapping (name -> encoder) and the reverse one (algorithm pair ->
// name, profileFor) cannot disagree: adding a profile here is the single edit,
// where previously the same knowledge lived in three hand-maintained switches and
// a missed one made Inspect reject this app's own output.
type profile struct {
	name       EncoderType
	aliases    []string
	encoder    *pkcs12.Encoder
	macOID     asn1.ObjectIdentifier
	certEncOID asn1.ObjectIdentifier
}

// profiles is the one home of the encoder-profile contract. The OID values it
// names are declared in profile.go beside the rest of the preflight's OIDs.
var profiles = []profile{
	{EncNameModern2023, []string{"", "modern"}, pkcs12.Modern2023, oidSHA256, oidPBES2},
	{EncNameModern2026, nil, pkcs12.Modern2026, oidPBMAC1, oidPBES2},
	{EncNameLegacyDES, []string{"legacy"}, pkcs12.LegacyDES, oidSHA1, oidPBEWithSHAAnd3KeyTripleDESCBC},
	{EncNameLegacyRC2, nil, pkcs12.LegacyRC2, oidSHA1, oidPBEWithSHAAnd40BitRC2CBC},
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

// encoderFor resolves an already-normalized encoder name to its PKCS#12
// encoder. It never validates (EncoderName owns name normalization) and
// never returns nil: an unknown name yields the modern2023 default, so the
// vendor type stays confined to this package while callers pass the app-owned
// name around.
func encoderFor(name EncoderType) *pkcs12.Encoder {
	for _, p := range profiles {
		if p.name == name {
			return p.encoder
		}
	}
	return pkcs12.Modern2023
}

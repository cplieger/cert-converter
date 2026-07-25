package convert

import (
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

// EncoderName normalizes a raw PFX_ENCODER value to one of the known encoder
// names. It owns the normalization rule but not the diagnostic: known reports
// whether raw matched a recognized spelling, so the caller that read the
// environment variable is the one that names it in a warning. An unrecognized
// value falls back to modern2023 with known false.
func EncoderName(raw string) (name EncoderType, known bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(EncNameLegacyRC2):
		return EncNameLegacyRC2, true
	case "legacy", string(EncNameLegacyDES):
		return EncNameLegacyDES, true
	case string(EncNameModern2026):
		return EncNameModern2026, true
	case "", "modern", string(EncNameModern2023):
		return EncNameModern2023, true
	default:
		return EncNameModern2023, false
	}
}

// encoderFor resolves an already-normalized encoder name to its PKCS#12
// encoder. It never validates (EncoderName owns name normalization) and
// never returns nil: an unknown name yields the modern2023 default, so the
// vendor type stays confined to this package while callers pass the app-owned
// name around.
func encoderFor(name EncoderType) *pkcs12.Encoder {
	switch name {
	case EncNameLegacyRC2:
		return pkcs12.LegacyRC2
	case EncNameLegacyDES:
		return pkcs12.LegacyDES
	case EncNameModern2026:
		return pkcs12.Modern2026
	case EncNameModern2023:
		return pkcs12.Modern2023
	default:
		return pkcs12.Modern2023
	}
}

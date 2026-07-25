package convert

import (
	"log/slog"
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

// PickEncoder returns the PFX encoder and its name based on the raw env value.
// It lives beside ToPFX, the only other consumer of the PKCS#12 vendor types,
// so the vendor dependency stays confined to the package that encodes.
func PickEncoder(raw string) (enc *pkcs12.Encoder, name EncoderType) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(EncNameLegacyRC2):
		return pkcs12.LegacyRC2, EncNameLegacyRC2
	case "legacy", string(EncNameLegacyDES):
		return pkcs12.LegacyDES, EncNameLegacyDES
	case string(EncNameModern2026):
		return pkcs12.Modern2026, EncNameModern2026
	case "", "modern", string(EncNameModern2023):
		return pkcs12.Modern2023, EncNameModern2023
	default:
		slog.Warn("unknown PFX_ENCODER, using modern2023", "value", raw)
		return pkcs12.Modern2023, EncNameModern2023
	}
}

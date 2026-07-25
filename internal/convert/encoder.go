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
// It composes EncoderName and EncoderFor for callers that need both the
// normalized app-owned name and the resolved vendor encoder, keeping the
// PKCS#12 vendor types confined to this package.
func PickEncoder(raw string) (enc *pkcs12.Encoder, name EncoderType) {
	name = EncoderName(raw)
	return EncoderFor(name), name
}

// EncoderName normalizes a raw PFX_ENCODER value to one of the known encoder
// names. It is the single validation point for the env value: an unrecognized
// value warns once here and falls back to modern2023.
func EncoderName(raw string) EncoderType {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(EncNameLegacyRC2):
		return EncNameLegacyRC2
	case "legacy", string(EncNameLegacyDES):
		return EncNameLegacyDES
	case string(EncNameModern2026):
		return EncNameModern2026
	case "", "modern", string(EncNameModern2023):
		return EncNameModern2023
	default:
		slog.Warn("unknown PFX_ENCODER, using modern2023", "value", raw)
		return EncNameModern2023
	}
}

// EncoderFor resolves an already-normalized encoder name to its PKCS#12
// encoder. It never warns (EncoderName owns the env-boundary validation) and
// never returns nil: an unknown name yields the modern2023 default, so the
// vendor type stays confined to this package while callers pass the app-owned
// name around.
func EncoderFor(name EncoderType) *pkcs12.Encoder {
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

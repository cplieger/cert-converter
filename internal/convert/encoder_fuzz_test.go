package convert_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
)

// FuzzEncoderName_unknownNeverSelectsALegacyProfile pins the safety
// invariant of the knob that selects the cipher suite of every emitted
// bundle: whatever PFX_ENCODER holds, an unrecognised value must resolve
// to the modern default and be reported unknown, never land on a legacy
// profile or pass as recognised. The accepted set is spelled here
// independently of the profile table, so a table row or alias the parser
// grows is caught instead of excusing itself.
func FuzzEncoderName_unknownNeverSelectsALegacyProfile(f *testing.F) {
	for _, seed := range []string{
		"", "modern", "modern2023", "MODERN2023", "  modern2023\t",
		"modern2026", "legacy", "legacydes", "legacyrc2", "LEGACYRC2",
		"legcy", "legacy des", "legacyrc2\u212a", "legacyrc2\x00",
		"\uff4c\uff45\uff47\uff41\uff43\uff59", "legacyrc2\u00a0",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		name, known := convert.EncoderName(raw)
		if !slices.Contains(convert.EncoderNames(), name) {
			t.Fatalf("EncoderName(%q) = %q, want a canonical profile name", raw, name)
		}
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "", "modern", string(convert.EncNameModern2023),
			string(convert.EncNameModern2026), "legacy",
			string(convert.EncNameLegacyDES), string(convert.EncNameLegacyRC2):
			if !known {
				t.Fatalf("EncoderName(%q) = (%q, false), want an accepted spelling recognised", raw, name)
			}
		default:
			if known {
				t.Fatalf("EncoderName(%q) = (%q, true), want an unrecognised value reported unknown", raw, name)
			}
			if name != convert.EncNameModern2023 {
				t.Fatalf("EncoderName(%q) = (%q, false), want the modern default for an unrecognised value", raw, name)
			}
		}
		again, againKnown := convert.EncoderName(string(name))
		if again != name || !againKnown {
			t.Fatalf("EncoderName(%q) = (%q, %v), want (%q, true): a canonical name must round-trip as known",
				string(name), again, againKnown, name)
		}
	})
}

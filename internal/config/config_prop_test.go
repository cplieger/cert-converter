package config

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

// TestParseFallbackInterval_permitted_cadence_and_padding_invariant pins the
// properties of the FALLBACK_SCAN_HOURS parser over arbitrary env values:
// surrounding whitespace can never change the decision, every accepted value
// is "disabled", the default, or a whole number of hours inside the overflow
// ceiling, and the repair classification always agrees with the value derived
// (a clamp reports the ceiling, an invalid value reports the default).
func TestParseFallbackInterval_permitted_cadence_and_padding_invariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// A plain rapid.String() generator almost never produces the values that
		// decide this parser ("0", "false", a numeric string), so the interesting
		// inputs are drawn explicitly alongside arbitrary text.
		v := rapid.OneOf(
			rapid.SampledFrom([]string{"", " ", "0", "00", "+0", "false", "FALSE", "-1", "1", "6", "12", "87600", "87601"}),
			rapid.StringMatching(`[ \t]*[-+]?[0-9]{0,7}[ \t]*`),
			rapid.String(),
		).Draw(t, "env_value")
		got, repair := parseFallbackInterval(v)

		// Surrounding whitespace is trimmed, so padding can never change the
		// decision: a padded "0" still disables, a padded number still parses,
		// and a padded blank still takes the default.
		padded, paddedRepair := parseFallbackInterval(" \t" + v + "\n ")
		if padded != got || paddedRepair != repair {
			t.Errorf("parseFallbackInterval(%q) = %v/%d but padded variant = %v/%d, want padding-invariant",
				v, got, repair, padded, paddedRepair)
		}

		// Every accepted value is either "disabled", the default, or a whole
		// number of hours no greater than the 10-year overflow ceiling.
		switch {
		case got == 0 || got == defaultFallbackInterval:
		case got > 0 && got <= 87600*time.Hour && got%time.Hour == 0:
		default:
			t.Errorf("parseFallbackInterval(%q) = %v, want 0, %v, or whole hours in (0, 87600h]", v, got, defaultFallbackInterval)
		}

		// The classification Load turns into a WARN must describe the value the
		// parse actually derived, or the operator reads a message about a repair
		// that did not happen.
		switch repair {
		case fallbackClamped:
			if got != maxFallbackHours*time.Hour {
				t.Errorf("parseFallbackInterval(%q) reported a clamp but returned %v, want %v",
					v, got, maxFallbackHours*time.Hour)
			}
		case fallbackInvalid:
			if got != defaultFallbackInterval {
				t.Errorf("parseFallbackInterval(%q) reported an invalid value but returned %v, want %v",
					v, got, defaultFallbackInterval)
			}
		case fallbackAccepted:
		default:
			t.Errorf("parseFallbackInterval(%q) reported an unknown repair kind %d", v, repair)
		}
	})
}

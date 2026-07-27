package config

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

// TestParseFallbackInterval_permitted_cadence_and_padding_invariant pins the two
// properties of the FALLBACK_SCAN_HOURS parser over arbitrary env values:
// surrounding whitespace can never change the decision, and every accepted value
// is "disabled", the default, or a whole number of hours inside the overflow
// ceiling.
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
		got := parseFallbackInterval(v)

		// Surrounding whitespace is trimmed, so padding can never change the
		// decision: a padded "0" still disables, a padded number still parses,
		// and a padded blank still takes the default.
		if padded := parseFallbackInterval(" \t" + v + "\n "); padded != got {
			t.Errorf("parseFallbackInterval(%q) = %v but padded variant = %v, want padding-invariant", v, got, padded)
		}

		// Every accepted value is either "disabled", the default, or a whole
		// number of hours no greater than the 10-year overflow ceiling.
		switch {
		case got == 0 || got == defaultFallbackInterval:
		case got > 0 && got <= 87600*time.Hour && got%time.Hour == 0:
		default:
			t.Errorf("parseFallbackInterval(%q) = %v, want 0, %v, or whole hours in (0, 87600h]", v, got, defaultFallbackInterval)
		}
	})
}

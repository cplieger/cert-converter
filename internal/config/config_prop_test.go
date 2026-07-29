package config

import (
	"math"
	"strconv"
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

// TestParseFallbackInterval_scales_linearly_with_the_configured_hours anchors the
// derived cadence to the configured NUMBER across the whole accepted range, which
// the invariant property above cannot: that property accepts ANY whole-hour value,
// so a parse that rounded to a coarser step, floored, or drifted by an hour would
// satisfy it everywhere except the three values the table happens to name ("1",
// "12", "87600").
//
// The unit comes from parseFallbackInterval("1") rather than being written as
// time.Hour, so this property tests linearity in the configured number instead of
// restating the conversion it is checking; TestParseFallbackInterval pins the
// one-hour anchor itself.
func TestParseFallbackInterval_scales_linearly_with_the_configured_hours(t *testing.T) {
	unit, unitRepair := parseFallbackInterval("1")
	if unitRepair != fallbackAccepted || unit <= 0 {
		t.Fatalf("parseFallbackInterval(%q) = %v/%s, want an accepted positive unit cadence",
			"1", unit, repairName(unitRepair))
	}
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, maxFallbackHours).Draw(t, "hours")
		raw := strconv.Itoa(n)
		got, repair := parseFallbackInterval(raw)
		if repair != fallbackAccepted {
			t.Fatalf("parseFallbackInterval(%q) repair = %s, want fallbackAccepted: every whole number of hours up to the ceiling is usable as configured",
				raw, repairName(repair))
		}
		if want := time.Duration(n) * unit; got != want {
			t.Errorf("parseFallbackInterval(%q) = %v, want %v (%d x the one-hour cadence)", raw, got, want, n)
		}
	})
}

// TestParseFallbackInterval_clamps_every_value_above_the_ceiling covers the clamp
// arm over the whole above-ceiling range rather than at the three values the tables
// name. The ceiling exists so time.Duration(n)*time.Hour cannot overflow int64, and
// the largest in-range value any table uses (1000000) does not overflow, so nothing
// currently exercises the guard at a value that would. A wrapped cadence is a
// fallback rescan that fires immediately or never while startup logs a clean
// interval, so the arm has to hold for every value a deployment can write.
func TestParseFallbackInterval_clamps_every_value_above_the_ceiling(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.Int64Range(maxFallbackHours+1, math.MaxInt64).Draw(t, "hours")
		raw := strconv.FormatInt(n, 10)
		got, repair := parseFallbackInterval(raw)
		if repair != fallbackClamped || got != maxFallbackHours*time.Hour {
			t.Errorf("parseFallbackInterval(%q) = %v/%s, want %v/fallbackClamped: an above-ceiling cadence must clamp instead of overflowing int64",
				raw, got, repairName(repair), maxFallbackHours*time.Hour)
		}
	})
}

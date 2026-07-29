package config

import (
	"math"
	"slices"
	"strconv"
	"strings"
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

// TestClassifyPassword_blankness_matches_the_visible_content pins the single
// password classification over arbitrary values built from the runes that decide
// it: a password is PasswordConfigured exactly when it carries at least one rune an
// operator can see, and every other value is one of the three blank classes.
//
// This is the property the guard, the WARN and the startup status all read, so a
// widened or narrowed predicate would have to break it here rather than in one
// consumer at a time. The rune pools are drawn explicitly because arbitrary text
// almost never produces a value made ONLY of invisible runes, which is the class
// that used to be reported as configured.
func TestClassifyPassword_blankness_matches_the_visible_content(t *testing.T) {
	invisible := []rune{' ', '\t', '\n', '\r', '\u00a0', '\u3000', '\u2028', '\ufeff', '\u200b', '\u00ad', '\u2060'}
	visible := []rune{'a', 'Z', '9', '!', 'é', '日', '\x00', '\ufffd'}
	rapid.Check(t, func(t *rapid.T) {
		runes := rapid.SliceOf(rapid.OneOf(
			rapid.SampledFrom(invisible),
			rapid.SampledFrom(visible),
		)).Draw(t, "runes")
		password := string(runes)
		hasVisible := false
		for _, r := range runes {
			if slices.Contains(visible, r) {
				hasVisible = true
				break
			}
		}

		status := classifyPassword(password)
		if hasVisible != (status == PasswordConfigured) {
			t.Fatalf("classifyPassword(%q) = %q, but the value %s a visible rune: a password nobody can read must never classify as configured",
				password, status, map[bool]string{true: "carries", false: "carries no"}[hasVisible])
		}
		// The guard and the classification are one decision: everything that is
		// not configured is blank, and the opt-out governs all of it.
		if isBlank(password) == (status == PasswordConfigured) {
			t.Errorf("isBlank(%q) = %v disagrees with status %q: the guard must derive from the classification",
				password, isBlank(password), status)
		}
		// Each blank class describes what the value actually is, so the WARN the
		// operator reads matches the value they configured.
		switch status {
		case PasswordEmpty:
			if password != "" {
				t.Errorf("classifyPassword(%q) = %q, want that class only for an empty value", password, status)
			}
		case PasswordWhitespaceOnly:
			if strings.TrimSpace(password) != "" {
				t.Errorf("classifyPassword(%q) = %q, but the value survives TrimSpace", password, status)
			}
		case PasswordInvisibleOnly:
			if strings.TrimSpace(password) == "" {
				t.Errorf("classifyPassword(%q) = %q, but the value is whitespace-only, which has its own class and WARN", password, status)
			}
		case PasswordConfigured:
		default:
			t.Errorf("classifyPassword(%q) reported an unknown status %q", password, status)
		}
	})
}

// TestParseMaxScanEntries_permitted_budget_and_padding_invariant pins the
// properties of the MAX_SCAN_ENTRIES parser over arbitrary env values: surrounding
// whitespace can never change the decision, every derived budget is a positive
// count no greater than the ceiling (there is deliberately no value that disables
// it), and the repair classification always agrees with the value derived.
func TestParseMaxScanEntries_permitted_budget_and_padding_invariant(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// A plain rapid.String() generator almost never produces the values that
		// decide this parser, so the interesting inputs are drawn explicitly
		// alongside arbitrary text.
		v := rapid.OneOf(
			rapid.SampledFrom([]string{"", " ", "0", "00", "+0", "false", "-1", "1", "5000", "10000", "200000", "200001"}),
			rapid.StringMatching(`[ \t]*[-+]?[0-9]{0,7}[ \t]*`),
			rapid.String(),
		).Draw(t, "env_value")
		got, repair := parseMaxScanEntries(v)

		padded, paddedRepair := parseMaxScanEntries(" \t" + v + "\n ")
		if padded != got || paddedRepair != repair {
			t.Errorf("parseMaxScanEntries(%q) = %d/%d but padded variant = %d/%d, want padding-invariant",
				v, got, repair, padded, paddedRepair)
		}

		// No input may yield a non-positive or above-ceiling budget: a zero budget
		// would refuse every tree, and an above-ceiling one would reopen the
		// single-scan exhaustion path the ceiling exists to close.
		if got < 1 || got > maxScanEntriesCeiling {
			t.Errorf("parseMaxScanEntries(%q) = %d, want a budget in [1, %d]", v, got, maxScanEntriesCeiling)
		}

		switch repair {
		case scanEntriesClamped:
			if got != maxScanEntriesCeiling {
				t.Errorf("parseMaxScanEntries(%q) reported a clamp but returned %d, want %d",
					v, got, maxScanEntriesCeiling)
			}
		case scanEntriesInvalid:
			if got != defaultMaxScanEntries {
				t.Errorf("parseMaxScanEntries(%q) reported an invalid value but returned %d, want %d",
					v, got, defaultMaxScanEntries)
			}
		case scanEntriesAccepted:
		default:
			t.Errorf("parseMaxScanEntries(%q) reported an unknown repair kind %d", v, repair)
		}
	})
}

// TestParseMaxScanEntries_accepts_every_count_up_to_the_ceiling anchors the derived
// budget to the configured NUMBER across the whole accepted range, which the
// invariant property above cannot: that property accepts ANY count in range, so a
// parse that rounded, floored, or substituted the default would satisfy it
// everywhere except the handful of values the table names.
func TestParseMaxScanEntries_accepts_every_count_up_to_the_ceiling(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, maxScanEntriesCeiling).Draw(t, "entries")
		raw := strconv.Itoa(n)
		got, repair := parseMaxScanEntries(raw)
		if repair != scanEntriesAccepted {
			t.Fatalf("parseMaxScanEntries(%q) repair = %s, want scanEntriesAccepted: every count up to the ceiling is usable as configured",
				raw, scanRepairName(repair))
		}
		if got != n {
			t.Errorf("parseMaxScanEntries(%q) = %d, want %d", raw, got, n)
		}
	})
}

// TestParseMaxScanEntries_clamps_every_value_above_the_ceiling covers the clamp arm
// over the whole above-ceiling range rather than at the values the table names. The
// ceiling is the bound that keeps ONE scan from enumerating an unbounded tree, so
// the arm has to hold for every value a deployment can write, including values past
// int64 that reach it through the overflow path rather than the comparison.
func TestParseMaxScanEntries_clamps_every_value_above_the_ceiling(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.Int64Range(maxScanEntriesCeiling+1, math.MaxInt64).Draw(t, "entries")
		raw := strconv.FormatInt(n, 10)
		got, repair := parseMaxScanEntries(raw)
		if repair != scanEntriesClamped || got != maxScanEntriesCeiling {
			t.Errorf("parseMaxScanEntries(%q) = %d/%s, want %d/scanEntriesClamped: an above-ceiling budget must clamp instead of being accepted",
				raw, got, scanRepairName(repair), maxScanEntriesCeiling)
		}
	})
}

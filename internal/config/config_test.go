package config

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/watch"
	"github.com/cplieger/slogx/capture"
)

func TestLoad_empty_password_optout_warns_only_on_unrecognized_values(t *testing.T) {
	// slog.Default is process-global: this test swaps it, so it must not run
	// in parallel with anything that logs.
	for _, tc := range []struct {
		name     string
		optout   string
		wantWarn bool
	}{
		{"explicit false is silent", "false", false},
		{"uppercase FALSE is silent", "FALSE", false},
		{"padded false is silent", "  false  ", false},
		{"unset is silent", "", false},
		{"true is silent", "true", false},
		{"1 warns", "1", true},
		{"yes warns", "yes", true},
		{"on warns", "on", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", tc.optout)

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			warned := logs.CountLevel(slog.LevelWarn, "unrecognized PFX_ALLOW_EMPTY_PASSWORD") > 0
			if warned != tc.wantWarn {
				t.Errorf("Load() with PFX_ALLOW_EMPTY_PASSWORD=%q warned = %v, want %v (log: %v)",
					tc.optout, warned, tc.wantWarn, logs.Messages())
			}
		})
	}
}

// TestParseFallbackInterval pins the derived cadence for every shape of
// FALLBACK_SCAN_HOURS, and — alongside each value — the repair classification
// Load turns into a diagnostic. The two travel together so a value can never
// change class without this table saying so.
func TestParseFallbackInterval(t *testing.T) {
	for _, tc := range []struct {
		name       string
		val        string
		want       time.Duration
		wantRepair fallbackRepair
	}{
		{"empty uses default", "", 6 * time.Hour, fallbackAccepted},
		{"zero", "0", 0, fallbackAccepted},
		{"false", "false", 0, fallbackAccepted},
		{"FALSE", "FALSE", 0, fallbackAccepted},
		{"valid", "12", 12 * time.Hour, fallbackAccepted},
		{"one", "1", 1 * time.Hour, fallbackAccepted},
		{"negative", "-1", 6 * time.Hour, fallbackInvalid},
		// Non-canonical zeros reach the numeric branch (the "0" switch case
		// only matches the literal string "0"), so they exercise the n > 0
		// boundary: ParseInt yields 0, which must NOT be treated as a positive
		// interval. Pins the n > 0 guard: a parsed zero falls through to the
		// default, never accepted as a (disabling) zero interval.
		{"non-canonical zero", "00", 6 * time.Hour, fallbackInvalid},
		{"signed zero", "+0", 6 * time.Hour, fallbackInvalid},
		{"non-numeric", "abc", 6 * time.Hour, fallbackInvalid},
		// strconv reports ErrRange (not ErrSyntax) once the digit prefix
		// overflows, even when junk follows, so a malformed value must stay
		// malformed instead of being mistaken for an above-ceiling number.
		{"overflowing prefix with junk", "999999999999999999999999999999x", 6 * time.Hour, fallbackInvalid},
		{"leading spaces", "  12", 12 * time.Hour, fallbackAccepted},
		{"trailing spaces", "12  ", 12 * time.Hour, fallbackAccepted},
		{"padded zero", " 0 ", 0, fallbackAccepted},
		{"padded false", " false ", 0, fallbackAccepted},
		{"padded empty uses default", "   ", 6 * time.Hour, fallbackAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, repair := parseFallbackInterval(tc.val)
			if got != tc.want {
				t.Errorf("parseFallbackInterval(%q) = %v, want %v", tc.val, got, tc.want)
			}
			if repair != tc.wantRepair {
				t.Errorf("parseFallbackInterval(%q) repair = %s, want %s",
					tc.val, repairName(repair), repairName(tc.wantRepair))
			}
		})
	}
}

// repairName renders a fallbackRepair for a test failure message. Test-local on
// purpose: the production type needs no String method for its own diagnostics,
// which are message-per-case rather than formatted from the enum.
func repairName(r fallbackRepair) string {
	switch r {
	case fallbackAccepted:
		return "fallbackAccepted"
	case fallbackInvalid:
		return "fallbackInvalid"
	case fallbackClamped:
		return "fallbackClamped"
	}
	return "fallbackRepair(" + strconv.Itoa(int(r)) + ")"
}

func TestParseFallbackInterval_clamps_excessive_values(t *testing.T) {
	for _, tc := range []struct {
		name       string
		val        string
		want       time.Duration
		wantRepair fallbackRepair
	}{
		// 87600h (10 years) is the clamp ceiling: at the ceiling the value
		// passes through unchanged; above it the value is clamped down to it.
		{"at ceiling unclamped", "87600", 87600 * time.Hour, fallbackAccepted},
		{"one above ceiling clamped", "87601", 87600 * time.Hour, fallbackClamped},
		{"far above ceiling clamped", "1000000", 87600 * time.Hour, fallbackClamped},
		// Beyond int64: a valid decimal that overflows is still a positive
		// above-ceiling value, so it clamps rather than falling through to the
		// 6h default. An optional leading "+" is still a valid decimal.
		{"beyond int64 clamped", "999999999999999999999999999999", 87600 * time.Hour, fallbackClamped},
		{"signed beyond int64 clamped", "+999999999999999999999999999999", 87600 * time.Hour, fallbackClamped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, repair := parseFallbackInterval(tc.val)
			if got != tc.want {
				t.Errorf("parseFallbackInterval(%q) = %v, want %v", tc.val, got, tc.want)
			}
			if repair != tc.wantRepair {
				t.Errorf("parseFallbackInterval(%q) repair = %s, want %s",
					tc.val, repairName(repair), repairName(tc.wantRepair))
			}
		})
	}
}

// TestFallbackInterval_is_silent pins the exported reader's contract for every
// parse class: the health subcommand calls it on every probe, so it must never
// emit startup diagnostics. This is the regression the parser/Load split exists
// to prevent: with the WARNs back in the parser, a misconfigured or
// above-ceiling FALLBACK_SCAN_HOURS printed a startup-shaped WARN on every
// healthcheck, forever.
// slog.Default is process-global, so this test must not run in parallel with
// anything that logs.
func TestFallbackInterval_is_silent(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{
		{"", 6 * time.Hour},
		{"   ", 6 * time.Hour},
		{"abc", 6 * time.Hour},
		{"-1", 6 * time.Hour},
		{"00", 6 * time.Hour},
		{"87601", 87600 * time.Hour},
		{"999999999999999999999999999999", 87600 * time.Hour},
		{"12", 12 * time.Hour},
		{"0", 0},
		{"false", 0},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv("FALLBACK_SCAN_HOURS", tc.raw)

			logs := capture.Default(t)

			if got := FallbackInterval(); got != tc.want {
				t.Errorf("FallbackInterval() with FALLBACK_SCAN_HOURS=%q = %v, want %v", tc.raw, got, tc.want)
			}
			if logs.Len() != 0 {
				t.Errorf("FallbackInterval() with FALLBACK_SCAN_HOURS=%q logged %v, want no records: "+
					"the health subcommand calls it on every probe", tc.raw, logs.Messages())
			}
		})
	}
}

// TestLoad_warns_when_the_fallback_value_is_repaired pins the two repair
// diagnostics at their new home. Both values are silently repaired, so the WARN
// naming the rejected value is the operator's only way to tell an intended
// cadence from a default or a clamp. Message text, level and attribute keys are
// asserted verbatim: a documented Loki matcher or an operator's grep keys on
// them. Exactly one record per process start, and the derived value is asserted
// beside the warning so the two cannot drift.
// slog.Default is process-global, so this test must not run in parallel with
// anything that logs.
func TestLoad_warns_when_the_fallback_value_is_repaired(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		want     time.Duration
		message  string
		attrKey  string
		attrWant string
	}{
		{
			name: "invalid value uses default", raw: "abc", want: 6 * time.Hour,
			message: "invalid FALLBACK_SCAN_HOURS, using default", attrKey: "default", attrWant: "6h0m0s",
		},
		{
			name: "excessive value is clamped", raw: "87601", want: 87600 * time.Hour,
			message: "FALLBACK_SCAN_HOURS too large, clamping", attrKey: "max_hours", attrWant: "87600",
		},
		// Both WARNs quote the value as CONFIGURED, untrimmed: a value that is
		// unusable only because of a stray space or newline looks correct in the
		// log once it is trimmed, and nothing else reports the difference.
		{
			name: "padded invalid value is quoted untrimmed", raw: " abc\t", want: 6 * time.Hour,
			message: "invalid FALLBACK_SCAN_HOURS, using default", attrKey: "default", attrWant: "6h0m0s",
		},
		{
			name: "padded excessive value is quoted untrimmed", raw: " 87601 ", want: 87600 * time.Hour,
			message: "FALLBACK_SCAN_HOURS too large, clamping", attrKey: "max_hours", attrWant: "87600",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("FALLBACK_SCAN_HOURS", tc.raw)

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if cfg.FallbackInterval != tc.want {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q FallbackInterval = %v, want %v",
					tc.raw, cfg.FallbackInterval, tc.want)
			}
			if n := logs.CountLevel(slog.LevelWarn, tc.message); n != 1 {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q logged %d WARN records matching %q, want exactly 1 (logs %v)",
					tc.raw, n, tc.message, logs.Messages())
			}
			if n := logs.CountExact(tc.message); n != 1 {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q logged %d records with the exact message %q, want 1 (logs %v)",
					tc.raw, n, tc.message, logs.Messages())
			}
			if !logs.AttrContains(tc.message, "value", tc.raw) {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q WARN does not name the rejected value (logs %v)",
					tc.raw, logs.Messages())
			}
			if !logs.HasAttr(tc.message, tc.attrKey, tc.attrWant) {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q WARN %q = %q, want %q=%q (logs %v)",
					tc.raw, tc.attrKey, mustAttr(t, logs, tc.message, tc.attrKey), tc.attrKey, tc.attrWant, logs.Messages())
			}
		})
	}
}

// TestLoad_does_not_repair_a_usable_fallback_value keeps invalid-value and
// clamp diagnostics off accepted values. The explicit 0/false opt-outs still
// emit warnFallbackDisabled, which is pinned by its dedicated test below.
func TestLoad_does_not_repair_a_usable_fallback_value(t *testing.T) {
	for _, raw := range []string{"", "   ", "12", "1", "87600", "  12", "0", "false"} {
		t.Run(raw, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("FALLBACK_SCAN_HOURS", raw)

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			for _, unwanted := range []string{
				"invalid FALLBACK_SCAN_HOURS, using default",
				"FALLBACK_SCAN_HOURS too large, clamping",
			} {
				if n := logs.Count(unwanted); n != 0 {
					t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q logged %d records matching %q, want none (logs %v)",
						raw, n, unwanted, logs.Messages())
				}
			}
		})
	}
}

// mustAttr renders an attribute for a failure message, or a marker when the
// record carried no such key.
func mustAttr(t *testing.T, logs *capture.Recorder, msgSub, key string) string {
	t.Helper()
	got, ok := logs.AttrValue(msgSub, key)
	if !ok {
		return "<absent>"
	}
	return got
}

// messageIndex reports the position of the first captured record whose message
// contains sub, failing the test when none does: an order assertion against an
// absent record would otherwise pass vacuously.
func messageIndex(t *testing.T, logs *capture.Recorder, sub string) int {
	t.Helper()
	for i, msg := range logs.Messages() {
		if strings.Contains(msg, sub) {
			return i
		}
	}
	t.Fatalf("no captured record matches %q (logs %v)", sub, logs.Messages())
	return -1
}

// TestLoad_emits_the_password_strength_warning_last pins the emission order Load
// chooses deliberately: the weak-password WARN is emitted after the delivery,
// lifecycle, encoder and fallback diagnostics, so the records explaining the rest
// of the configuration are not buried beneath it. Nothing else pins the order, so
// moving the call back beside the classification that feeds it would silently
// reshuffle every startup log with the suite still green. Serial: it swaps
// slog.Default().
func TestLoad_emits_the_password_strength_warning_last(t *testing.T) {
	isolatePasswordFile(t)
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")
	t.Setenv("OUTPUT_LIFECYCLE", "delete")
	t.Setenv("PFX_ENCODER", "modern2029")
	t.Setenv("FALLBACK_SCAN_HOURS", "abc")

	logs := capture.Default(t)

	if _, err := Load(); err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}

	strength := messageIndex(t, logs, "PFX_PASSWORD is empty")
	for _, earlier := range []string{
		"unknown OUTPUT_LIFECYCLE",
		"unknown PFX_ENCODER",
		"invalid FALLBACK_SCAN_HOURS",
	} {
		if i := messageIndex(t, logs, earlier); i > strength {
			t.Errorf("Load() logged %q at index %d, after the password-strength WARN at index %d: the strength WARN is emitted last so the diagnostics explaining the configuration are not buried beneath it (logs %v)",
				earlier, i, strength, logs.Messages())
		}
	}
}

// isolatePasswordFile clears PFX_PASSWORD_FILE so an ambient value inherited
// from the host cannot take precedence over the PFX_PASSWORD the test sets:
// envx.Secret prefers the <KEY>_FILE indirection whenever it is non-empty.
func isolatePasswordFile(t *testing.T) {
	t.Helper()
	t.Setenv("PFX_PASSWORD_FILE", "")
}

// TestLoad_warns_only_for_a_blank_PFX_PASSWORD_FILE_pointer pins both halves of
// warnBlankPasswordFilePointer's guard. A pointer that expands to nothing inverts the
// file-wins rule silently, so the WARN must fire; an UNSET pointer is the normal
// deployment, so it must stay silent, and losing that set-vs-unset distinction (which
// envx.IsBlankSecretFilePath owns) would warn every correctly configured operator that
// their secret pointer is broken. Serial: it swaps slog.Default().
func TestLoad_warns_only_for_a_blank_PFX_PASSWORD_FILE_pointer(t *testing.T) {
	const blankPointer = "PFX_PASSWORD_FILE is set but blank"
	for _, tc := range []struct {
		name     string
		set      bool
		wantWarn bool
	}{
		{"set but empty warns", true, true},
		{"unset is silent", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("PFX_PASSWORD_FILE", "")
			} else {
				// t.Setenv cannot unset, so restore by hand.
				prev, had := os.LookupEnv("PFX_PASSWORD_FILE")
				if err := os.Unsetenv("PFX_PASSWORD_FILE"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if had {
						if err := os.Setenv("PFX_PASSWORD_FILE", prev); err != nil {
							t.Error(err)
						}
					}
				})
			}
			t.Setenv("PFX_PASSWORD", "a-real-password")

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			got := logs.CountLevel(slog.LevelWarn, blankPointer)
			want := 0
			if tc.wantWarn {
				want = 1
			}
			if got != want {
				t.Errorf("Load() logged %d %q WARN records, want %d: the WARN reports a pointer that expands to nothing and must stay silent when PFX_PASSWORD_FILE is unset (logs %v)",
					got, blankPointer, want, logs.Messages())
			}
		})
	}
}

// TestLoad_blank_password_file_pointer_reports_whitespace_outcome pins the second
// arm of that WARN's message, which the test above does not reach: a WHITESPACE-only
// pointer is non-empty to envx, so it IS the selected channel and PFX_PASSWORD is
// never consulted. Reporting the empty-pointer outcome here would tell an operator
// the env password was used when it was not. The message names that channel choice
// rather than predicting the open: whether a file whose name is whitespace exists is
// the filesystem's business, and only the channel selection is certain.
// Serial: it swaps slog.Default().
func TestLoad_blank_password_file_pointer_reports_whitespace_outcome(t *testing.T) {
	t.Setenv("PFX_PASSWORD_FILE", " \t ")
	t.Setenv("PFX_PASSWORD", "a-real-password")
	// An empty working directory, so the "opening it fails" assertion below cannot
	// depend on whether the package directory happens to hold a whitespace-named file.
	t.Chdir(t.TempDir())

	logs := capture.Default(t)

	if _, err := Load(); err == nil {
		t.Fatal("Load() = nil error, want the whitespace-only file pointer to fail when envx opens it")
	}

	const msg = "PFX_PASSWORD_FILE is set but blank"
	if n := logs.CountLevel(slog.LevelWarn, msg); n != 1 {
		t.Errorf("Load() logged %d %q WARN records, want 1 (logs %v)", n, msg, logs.Messages())
	}
	const outcome = "the whitespace value is treated as a filename instead of falling back to PFX_PASSWORD"
	if !logs.Contains(outcome) {
		t.Errorf("Load() WARN does not report %q (logs %v)", outcome, logs.Messages())
	}
}

// TestLoad_blank_password_reports_only_the_strength_warning pins the suppression
// logPasswordDelivery applies to a blank value. A whitespace-only PFX_PASSWORD is
// padded and (for a tab or newline) control-character-bearing by construction, so
// both value-shape WARNs would fire and tell the operator to trim the value or
// re-generate the secret on one line, when the actual problem is that no password
// is configured at all. warnPasswordStrength owns that report, and its remediation
// is the only one that helps. Serial: it swaps slog.Default().
func TestLoad_blank_password_reports_only_the_strength_warning(t *testing.T) {
	for _, password := range []string{" ", "\t\n ", "\u00a0"} {
		t.Run(strconv.Quote(password), func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", password)
			// A blank password only gets past the guard with the opt-out set.
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			if n := logs.CountLevel(slog.LevelWarn, "PFX_PASSWORD is whitespace-only"); n != 1 {
				t.Errorf("Load(PFX_PASSWORD=%q) logged %d whitespace-only WARN records, want exactly 1 (logs %v)",
					password, n, logs.Messages())
			}
			for _, unwanted := range []string{
				paddedPasswordWarn,
				"contains a control character",
				// U+00A0 in the table above is both blank and Zs, so this is the
				// record that the one blank guard in logPasswordDelivery suppresses;
				// an invisible-formatting entry would be vacuous (no blank input
				// carries a Cf rune).
				"contains a non-ASCII space character",
			} {
				if n := logs.Count(unwanted); n != 0 {
					t.Errorf("Load(PFX_PASSWORD=%q) logged %d records matching %q, want none: the blank password is already reported, and this line's remediation sends the operator to fix the wrong thing (logs %v)",
						password, n, unwanted, logs.Messages())
				}
			}
		})
	}
}

// TestLoad_warns_when_the_fallback_rescan_is_disabled pins the startup WARN for
// the FALLBACK_SCAN_HOURS opt-out. The tradeoff it names is now a LATENCY one: the
// watcher keeps a reconciliation floor and a health-marker deadline in every
// configuration, so what the operator gives up is recovery on their own cadence, not
// the app's ability to notice that it has stopped working. The record must say that
// much, or an operator reads the old "converting nothing while reporting healthy"
// wording and either panics or ignores the line.
//
// It must fire ONLY for the explicit opt-out. An empty, whitespace-only, or
// invalid value falls back to the 6h default, which is supervised and must stay
// silent: warning there would train an operator to ignore the line that matters.
// The interval is asserted alongside the warning so the two cannot drift apart.
// slog.Default is process-global, so this test must not run in parallel with
// anything that logs.
func TestLoad_warns_when_the_fallback_rescan_is_disabled(t *testing.T) {
	// Matches only the opt-out WARN: the repair diagnostics read "invalid
	// FALLBACK_SCAN_HOURS, ..." and "FALLBACK_SCAN_HOURS too large, ...".
	const optOutWarn = "FALLBACK_SCAN_HOURS is 0/false"

	for _, tc := range []struct {
		name         string
		raw          string
		wantInterval time.Duration
		wantWarn     bool
	}{
		{"zero opts out and warns", "0", 0, true},
		{"false opts out and warns", "false", 0, true},
		{"uppercase FALSE opts out and warns", "FALSE", 0, true},
		{"padded zero opts out and warns", " 0 ", 0, true},
		{"unset default is silent", "", 6 * time.Hour, false},
		{"whitespace-only value is silent", "   ", 6 * time.Hour, false},
		{"invalid value is silent", "abc", 6 * time.Hour, false},
		{"non-canonical zero is silent", "00", 6 * time.Hour, false},
		{"explicit interval is silent", "12", 12 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("FALLBACK_SCAN_HOURS", tc.raw)

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if cfg.FallbackInterval != tc.wantInterval {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q FallbackInterval = %v, want %v",
					tc.raw, cfg.FallbackInterval, tc.wantInterval)
			}

			warnings := logs.CountLevel(slog.LevelWarn, optOutWarn)
			if (warnings > 0) != tc.wantWarn {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q logged %d WARN records matching %q, want warn = %v (logs %v)",
					tc.raw, warnings, optOutWarn, tc.wantWarn, logs.Messages())
			}
			if !tc.wantWarn {
				return
			}
			if warnings != 1 {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q logged %d opt-out WARN records, want exactly 1 (logs %v)",
					tc.raw, warnings, logs.Messages())
			}
			// What the operator gives up, what still covers them, and the way back.
			for _, want := range []string{"no routine periodic re-scan", "reconciliation", "freshness deadline"} {
				if !logs.Contains(want) {
					t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q WARN does not name %q (logs %v)",
						tc.raw, want, logs.Messages())
				}
			}
			// The old wording promised the opposite of the current contract, and an
			// operator who has read it must not find it here again.
			if logs.Contains("converting nothing") {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q WARN still claims the container reports healthy while converting nothing; the reconciliation floor and the marker deadline both hold in this mode now (logs %v)",
					tc.raw, logs.Messages())
			}
			if !logs.AttrContains(optOutWarn, "remediation", "FALLBACK_SCAN_HOURS") {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q WARN carries no remediation naming the variable (logs %v)",
					tc.raw, logs.Messages())
			}
		})
	}
}

// TestLoad_warns_when_the_fallback_cadence_is_above_the_reconciliation_floor pins the
// third arm of warnFallbackDisabled: a cadence the watcher's floor overrides never fires,
// so the operator pays more full-tree walks than they configured and this startup record
// is the only place that says so.
//
// The BOUNDARY matters as much as the band. At exactly the floor the two clocks coincide
// and the cadence is still the operator's, so the record must stay silent there — the arm
// reaches that by arithmetic (safetyNetIntervalFor returns the cadence itself, so
// interval > floor is false) rather than by an explicit case, which is why widening its
// `>` to `>=` would tell an operator running the floor's own cadence that it never runs
// and leave every other test in this package green.
//
// slog.Default is process-global, so this must not run in parallel with anything that logs.
func TestLoad_warns_when_the_fallback_cadence_is_above_the_reconciliation_floor(t *testing.T) {
	const aboveFloorWarn = "FALLBACK_SCAN_HOURS is above the watcher's reconciliation floor"

	// Derived, not hardcoded: the assertion is about this arm's relation to the floor, so
	// a floor move must not silently turn the boundary row into an in-band one.
	floor := watch.MarkerRefreshFloor(365 * 24 * time.Hour)
	floorHours := int(floor / time.Hour)

	for _, tc := range []struct {
		name     string
		raw      string
		wantWarn bool
	}{
		{"a cadence well above the floor warns", strconv.Itoa(floorHours * 2), true},
		{"a cadence one hour above the floor warns", strconv.Itoa(floorHours + 1), true},
		{"a cadence at the floor is silent", strconv.Itoa(floorHours), false},
		{"a cadence one hour below the floor is silent", strconv.Itoa(floorHours - 1), false},
		{"the opt-out is reported by its own record", "0", false},
		{"a repaired invalid value lands below the floor and is silent", "abc", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("FALLBACK_SCAN_HOURS", tc.raw)

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			want := 0
			if tc.wantWarn {
				want = 1
			}
			if got := logs.CountLevel(slog.LevelWarn, aboveFloorWarn); got != want {
				t.Fatalf("Load() with FALLBACK_SCAN_HOURS=%q logged %d WARN records matching %q, want %d: at or below the floor the operator's own cadence fires (logs %v)",
					tc.raw, got, aboveFloorWarn, want, logs.Messages())
			}
			if !tc.wantWarn {
				return
			}
			// Both cadences travel together, exactly as the watcher's own degraded-path
			// records carry them: without scan_floor the operator cannot see what
			// overrode the setting they chose.
			for key, wantVal := range map[string]string{
				"fallback_scan": (time.Duration(mustAtoi(t, tc.raw)) * time.Hour).String(),
				"scan_floor":    floor.String(),
			} {
				if got, ok := logs.AttrValue(aboveFloorWarn, key); !ok || got != wantVal {
					t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q WARN %s = %q (present %v), want %q (logs %v)",
						tc.raw, key, got, ok, wantVal, logs.Messages())
				}
			}
			if !logs.AttrContains(aboveFloorWarn, "remediation", "FALLBACK_SCAN_HOURS") {
				t.Errorf("Load() with FALLBACK_SCAN_HOURS=%q WARN carries no remediation naming the variable (logs %v)",
					tc.raw, logs.Messages())
			}
		})
	}
}

// mustAtoi parses one of the table's own hour strings. The rows above build them from
// the floor, so a parse failure is a broken fixture rather than a finding about Load.
func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("setup: strconv.Atoi(%q): %v", s, err)
	}
	return n
}

// TestLoad_password_file_is_verbatim_and_takes_precedence_over_env pins BOTH halves
// of the mounted-secret contract as envx v1.5.0 defines it: the file still wins over
// PFX_PASSWORD, and the value it delivers is the file's bytes VERBATIM apart from at
// most ONE trailing line ending. Edge spaces and tabs, a second trailing newline and a
// leading newline are content, because whitespace an operator put in a secret is part
// of the credential and trimming it turns a valid password into a subtly wrong one.
// envx used to run TrimSpace over the file's content, which is why this test used to
// expect a trimmed value: rewriting the secret on the way in protects every generated
// .pfx with a password nobody configured, encoding succeeds either way, and health
// never notices.
func TestLoad_password_file_is_verbatim_and_takes_precedence_over_env(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contents string
		want     string
	}{
		{"edge whitespace is content, one trailing newline is not", "  from-file\n", "  from-file"},
		{"a trailing tab is content", "from-file\t\n", "from-file\t"},
		{"a CRLF line ending is removed whole", "from-file\r\n", "from-file"},
		{"only ONE trailing newline is removed", "from-file\n\n", "from-file\n"},
		{"a leading newline is content", "\nfrom-file", "\nfrom-file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pfx-password")
			if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PFX_PASSWORD", "from-env")
			t.Setenv("PFX_PASSWORD_FILE", path)
			t.Setenv("PFX_ENCODER", "")

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() with PFX_PASSWORD_FILE = %v, want nil", err)
			}
			if cfg.Password != tc.want {
				t.Errorf("Load() Password = %q, want %q (the file wins over PFX_PASSWORD, and its bytes are the password apart from one trailing line ending)",
					cfg.Password, tc.want)
			}
		})
	}
}

func TestLoad_unreadable_password_file_fails_loudly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"missing file", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "absent")
		}},
		// A readable file the operator could reach by hand: envx still refuses
		// the path, and the refusal must not degrade to PFX_PASSWORD.
		{"uncleaned path with .. is rejected", func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "pfx"), []byte("from-file"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			// Built by concatenation: filepath.Join would clean the ".." away.
			return dir + "/sub/../pfx"
		}},
		// Deliberately NOT pinned here: which NON-traversing spellings envx
		// refuses (a "pfx..v2" filename, say). That is envx's acceptance set,
		// not this app's contract — envx documented its substring test as
		// over-broad pending analysis, and narrowing it to a ".." COMPONENT
		// rule must not read as a cert-converter regression. What this app
		// depends on is the case above: a path that actually traverses is a
		// hard startup failure the opt-out cannot rescue.
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PFX_PASSWORD", "from-env")
			t.Setenv("PFX_PASSWORD_FILE", tc.setup(t))
			// The opt-out must not rescue a broken secret file.
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

			// Serial: capture.Default swaps slog.Default().
			logs := capture.Default(t)

			if _, err := Load(); err == nil {
				t.Fatal("Load() = nil error, want a startup failure for an unusable PFX_PASSWORD_FILE")
			} else if errors.Is(err, ErrEmptyPassword) {
				t.Errorf("Load() = %v, want the underlying secret-file error, not ErrEmptyPassword", err)
			}
			// The refusal quotes envx's message, which names PFX_PASSWORD — the
			// variable the file-wins rule ignores. The conflict WARN is the only
			// record that redirects the operator to PFX_PASSWORD_FILE, so it must be
			// emitted before this gate returns, not from logPasswordDelivery.
			const conflict = "both PFX_PASSWORD and PFX_PASSWORD_FILE are set"
			if n := logs.CountLevel(slog.LevelWarn, conflict); n != 1 {
				t.Errorf("Load(unusable file, PFX_PASSWORD set) logged %d WARN records matching %q, want exactly 1 (logs %v)",
					n, conflict, logs.Messages())
			}
		})
	}
}

func TestLoad_empty_password_optout_requires_literal_true(t *testing.T) {
	for _, tc := range []struct {
		name      string
		optout    string
		wantAllow bool
	}{
		{"lowercase true allows", "true", true},
		{"uppercase TRUE allows", "TRUE", true},
		{"mixed-case True allows", "True", true},
		{"padded true allows", "  true  ", true},
		{"padded uppercase allows", " TRUE ", true},
		{"1 does not allow", "1", false},
		{"yes does not allow", "yes", false},
		{"on does not allow", "on", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "")
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", tc.optout)

			_, err := Load()

			if tc.wantAllow && err != nil {
				t.Errorf("Load() with PFX_ALLOW_EMPTY_PASSWORD=%q got err %v, want nil (trimmed, case-insensitive true opts out)", tc.optout, err)
			}
			if !tc.wantAllow && !errors.Is(err, ErrEmptyPassword) {
				t.Errorf("Load() with PFX_ALLOW_EMPTY_PASSWORD=%q got err %v, want ErrEmptyPassword (only literal true opts out)", tc.optout, err)
			}
		})
	}
}

// TestClassifyPassword pins the blank-password predicate directly in
// its owning package, covering every classification without going through
// Load's guards (TestLoad_password_status_agrees_with_its_warning covers the
// same statuses end to end). No t.Parallel: every test in this file mutates
// process state (env / slog default) and the file is deliberately serial.
func TestClassifyPassword(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		want     PasswordStatus
	}{
		{"empty is empty", "", PasswordEmpty},
		{"single space is whitespace-only", " ", PasswordWhitespaceOnly},
		{"tab newline and space are whitespace-only", "\t\n ", PasswordWhitespaceOnly},
		// unicode.IsSpace covers U+00A0, so a non-breaking space pasted from a
		// document is whitespace-only, not a real password.
		{"non-breaking space is whitespace-only", "\u00a0", PasswordWhitespaceOnly},
		{"real value is configured", "s3cret", PasswordConfigured},
		{"padded real value is configured", "  s3cret  ", PasswordConfigured},
		{"single printable char is configured", "x", PasswordConfigured},
		// TrimSpace does not trim NUL, so a binary secret is a real password.
		{"NUL byte is configured", "\x00", PasswordConfigured},
		// The invisible-only class: every rune survives TrimSpace yet none of them
		// can be seen or retyped. A secret file an editor saved as "UTF-8 with BOM"
		// and nothing else is the realistic case, and it used to classify as
		// "configured" — starting the container without the opt-out and reporting a
		// password that protects the key against nobody.
		{"a byte-order mark alone is invisible-only", "\ufeff", PasswordInvisibleOnly},
		{"a zero-width space alone is invisible-only", "\u200b", PasswordInvisibleOnly},
		{"a soft hyphen alone is invisible-only", "\u00ad", PasswordInvisibleOnly},
		{"several format runes are invisible-only", "\ufeff\u200b\u00ad", PasswordInvisibleOnly},
		// Whitespace mixed with a format rune is not whitespace-only (TrimSpace
		// leaves the BOM behind), so it lands in the invisible-only class rather
		// than being read as a configured password.
		{"a byte-order mark beside whitespace is invisible-only", "\ufeff \t\n", PasswordInvisibleOnly},
		// One visible rune is a real password: the class is about a value with
		// nothing an operator can read, not about carrying an invisible rune.
		{"a byte-order mark beside a real value is configured", "\ufeffhunter2", PasswordConfigured},
		{"an interior zero-width space is configured", "pw\u200bsecret", PasswordConfigured},
		// Invalid UTF-8 decodes as U+FFFD, which is neither space nor Cf, so a
		// binary secret stays a configured password (checkPasswordEncodable owns
		// refusing it).
		{"the replacement rune is configured", "\ufffd", PasswordConfigured},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyPassword(tc.password); got != tc.want {
				t.Errorf("classifyPassword(%q) = %q, want %q", tc.password, got, tc.want)
			}
		})
	}
}

// TestLoad_password_status_agrees_with_its_warning pins the startup
// password-status decision where it now lives: the Config.PasswordStatus main
// reports and the WARN branch must agree, and a real password must produce no
// password-quality warning (the value is a secret, so nothing about it is
// logged beyond the non-secret status). Load emits other startup records --
// including the padded-value whitespace WARN -- so the assertion is scoped to
// the "PFX_PASSWORD is ..." family rather than to total silence. Moved here
// from main_test.go with Load as the entry point, so the warning and the status
// stay pinned in the package that owns both. No t.Parallel: it mutates env and
// slog.Default.
func TestLoad_password_status_agrees_with_its_warning(t *testing.T) {
	for _, tc := range []struct {
		name        string
		password    string
		wantStatus  PasswordStatus
		wantWarnSub string
	}{
		{"empty reports empty", "", PasswordEmpty, "PFX_PASSWORD is empty"},
		{"single space is whitespace-only", " ", PasswordWhitespaceOnly, "PFX_PASSWORD is whitespace-only"},
		{"tab and newline are whitespace-only", "\t\n ", PasswordWhitespaceOnly, "PFX_PASSWORD is whitespace-only"},
		{"real value is configured", "s3cret", PasswordConfigured, ""},
		{"padded value is configured", "  s3cret  ", PasswordConfigured, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", tc.password)
			// A blank password only reaches the warning with the opt-out set;
			// without it Load refuses to start (ErrEmptyPassword).
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			if cfg.PasswordStatus != tc.wantStatus {
				t.Errorf("Load() with PFX_PASSWORD=%q status = %q, want %q", tc.password, cfg.PasswordStatus, tc.wantStatus)
			}
			if tc.wantWarnSub == "" {
				if logs.Contains("PFX_PASSWORD is ") {
					t.Errorf("Load() with PFX_PASSWORD=%q logged %v, want no password warning for a real password",
						tc.password, logs.Messages())
				}
				return
			}
			if n := logs.CountLevel(slog.LevelWarn, tc.wantWarnSub); n != 1 {
				t.Errorf("Load() with PFX_PASSWORD=%q logged %d WARN records matching %q, want 1 (logs %v)",
					tc.password, n, tc.wantWarnSub, logs.Messages())
			}
			if !logs.AttrContains(tc.wantWarnSub, "remediation", "PFX_PASSWORD") {
				t.Errorf("Load() with PFX_PASSWORD=%q WARN is missing an actionable remediation attr (logs %v)",
					tc.password, logs.Messages())
			}
		})
	}
}

func TestLogLevel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    string
		want   slog.Level
		wantOK bool
	}{
		{"unset uses info default", "", slog.LevelInfo, true},
		{"debug", "debug", slog.LevelDebug, true},
		{"uppercase INFO", "INFO", slog.LevelInfo, true},
		{"padded warn", "  warn  ", slog.LevelWarn, true},
		{"warning alias", "warning", slog.LevelWarn, true},
		{"error", "error", slog.LevelError, true},
		{"slog offset", "info+2", slog.LevelInfo + 2, true},
		{"unparseable reports not ok and keeps info", "loud", slog.LevelInfo, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LOG_LEVEL", tc.raw)

			// LogLevel is the silent reader (like FallbackInterval); the
			// diagnostic is WarnInvalidLogLevel's, so a parse failure is only
			// observable through the captured WARN. Serial: capture.Default
			// swaps slog.Default().
			logs := capture.Default(t)

			if lvl := LogLevel(); lvl != tc.want {
				t.Errorf("LogLevel() with LOG_LEVEL=%q = %v, want %v", tc.raw, lvl, tc.want)
			}
			if logs.Len() != 0 {
				t.Errorf("LogLevel() with LOG_LEVEL=%q logged %v; it must stay silent so the "+
					"health subcommand does not reprint a startup WARN on every probe",
					tc.raw, logs.Messages())
			}

			WarnInvalidLogLevel()

			warned := logs.Contains("invalid LOG_LEVEL")
			if warned == tc.wantOK {
				t.Fatalf("WarnInvalidLogLevel() with LOG_LEVEL=%q warned = %v, want %v (logs %v)",
					tc.raw, warned, !tc.wantOK, logs.Messages())
			}
			if tc.wantOK {
				return
			}
			if got := mustAttr(t, logs, "invalid LOG_LEVEL", "value"); got != tc.raw {
				t.Errorf("the WARN for LOG_LEVEL=%q carried value=%q, want the raw value verbatim so "+
					"an operator can see what was misspelled", tc.raw, got)
			}
			wantDefault := strings.ToLower(tc.want.String())
			if got := mustAttr(t, logs, "invalid LOG_LEVEL", "default"); got != wantDefault {
				t.Errorf("the WARN for LOG_LEVEL=%q carried default=%q, want %q (the level actually in effect)",
					tc.raw, got, wantDefault)
			}
		})
	}
}

func TestLoad_password_file_log_records_source_without_secret_or_path(t *testing.T) {
	const secret = "sup3r-s3cret-pfx-value"
	path := filepath.Join(t.TempDir(), "pfx-password")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_PASSWORD_FILE", path)

	logs := capture.Default(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with PFX_PASSWORD_FILE = %v, want nil", err)
	}
	if cfg.Password != secret {
		t.Fatalf("Load() Password = %q, want the file's contents", cfg.Password)
	}

	if !logs.HasAttr("PFX password configured", "source", "PFX_PASSWORD_FILE") {
		t.Errorf("Load() logged %v, want a record naming PFX_PASSWORD_FILE as the secret source", logs.Messages())
	}
	// Walk every captured record end to end, the form the sibling
	// TestLoad_env_password_logs_no_secret_source documents: it catches the secret
	// or the mount path leaking as an attr under ANY message, not only the one that
	// carries it today.
	for _, r := range logs.Records() {
		if strings.Contains(r.Message, secret) || strings.Contains(r.Message, path) {
			t.Errorf("Load() leaked the PFX password or the secret-mount path in message %q", r.Message)
		}
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Value.String(), secret) || strings.Contains(a.Value.String(), path) {
				t.Errorf("Load() leaked the PFX password or the secret-mount path in attr %s=%v on %q", a.Key, a.Value, r.Message)
			}
			return true
		})
	}
}

func TestLoad_env_password_logs_no_secret_source(t *testing.T) {
	const (
		secret       = "sentinel-env-pfx-password"
		secretSource = "PFX_PASSWORD_FILE"
	)
	t.Setenv(secretSource, "")
	t.Setenv("PFX_PASSWORD", secret)
	t.Setenv("PFX_ENCODER", "")

	logs := capture.Default(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if cfg.Password != secret {
		t.Fatalf("Load() Password = %q, want the configured environment value", cfg.Password)
	}

	if n := logs.Count("PFX password configured"); n != 0 {
		t.Errorf("Load() logged %v, want no secret-source record when PFX_PASSWORD_FILE is unset", logs.Messages())
	}
	// The pre-capture form scanned the whole rendered line, so it also caught the
	// env var leaking as an ATTR (key or value) under ANY message, not just the
	// one that happens to carry it today; Count sees messages only. Walk every
	// captured record end to end to keep that strictly stronger guard on the
	// password VALUE: the sibling PFX_PASSWORD_FILE test guards its secret value,
	// and a future diagnostic that logged the env-sourced password would otherwise
	// keep this test green.
	//
	// The channel NAME is deliberately not guarded here: this test sets
	// PFX_PASSWORD_FILE to the empty string, which is the blank-pointer shape
	// warnBlankPasswordFilePointer exists to report, so a record naming the
	// variable is correct. The "PFX password configured" count above is what pins
	// the absence of a secret-source delivery record.
	for _, r := range logs.Records() {
		if strings.Contains(r.Message, secret) {
			t.Errorf("Load() leaked the environment-sourced PFX password in message %q", r.Message)
		}
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Key, secret) || strings.Contains(a.Value.String(), secret) {
				t.Errorf("Load() leaked the environment-sourced PFX password in attr %s=%v on %q", a.Key, a.Value, r.Message)
			}
			return true
		})
	}
}

func TestLoad_unknown_encoder_warns_and_falls_back_to_modern2023(t *testing.T) {
	// slog.Default is process-global: this test swaps it, so it must not run
	// in parallel with anything that logs.
	for _, tc := range []struct {
		name     string
		raw      string
		wantName convert.EncoderType
		wantWarn bool
	}{
		{"unrecognized value warns and falls back", "modern2029", convert.EncNameModern2023, true},
		{"typo in a known name warns", "legcy", convert.EncNameModern2023, true},
		{"unset is silent and defaults", "", convert.EncNameModern2023, false},
		{"recognized alias is silent", "modern", convert.EncNameModern2023, false},
		{"recognized legacy is silent", "legacy", convert.EncNameLegacyDES, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("PFX_ENCODER", tc.raw)

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() with PFX_ENCODER=%q = %v, want nil (an unknown value must not fail startup)", tc.raw, err)
			}
			if cfg.EncoderName != tc.wantName {
				t.Errorf("Load() with PFX_ENCODER=%q EncoderName = %q, want %q", tc.raw, cfg.EncoderName, tc.wantName)
			}
			warned := logs.CountLevel(slog.LevelWarn, "unknown PFX_ENCODER") > 0
			if warned != tc.wantWarn {
				t.Errorf("Load() with PFX_ENCODER=%q warned = %v, want %v (log: %v)", tc.raw, warned, tc.wantWarn, logs.Messages())
			}
			if tc.wantWarn && !logs.AttrContains("unknown PFX_ENCODER", "value", tc.raw) {
				t.Errorf("Load() with PFX_ENCODER=%q logged %v, want the rejected value named so an operator can spot the typo", tc.raw, logs.Messages())
			}
			// The message says only "using the default profile", so these two attrs
			// are the record's only statement of WHICH profile is in effect and which
			// spellings are accepted. Dropping either, or wiring a stale list, leaves
			// every assertion above green while the operator loses the answer.
			if tc.wantWarn && !logs.HasAttr("unknown PFX_ENCODER", "using", string(tc.wantName)) {
				t.Errorf("Load() with PFX_ENCODER=%q WARN does not name the effective profile %q (logs %v)", tc.raw, tc.wantName, logs.Messages())
			}
			if tc.wantWarn && !logs.HasAttr("unknown PFX_ENCODER", "expected", "[modern2023 modern2026 legacydes legacyrc2]") {
				t.Errorf("Load() with PFX_ENCODER=%q WARN does not list every canonical profile (logs %v)", tc.raw, logs.Messages())
			}
		})
	}
}

// TestCheckPasswordEncodable_refuses_every_unrepresentable_shape pins a DELIBERATE
// reversal: all three shapes are now a startup REFUSAL rather than a warning that let
// the container start.
//
// Each must be rejected, must name its shape and remediation so an operator can act,
// and must never put the secret value in the error — the error text reaches the startup
// log, which every aggregator retains.
func TestCheckPasswordEncodable_refuses_every_unrepresentable_shape(t *testing.T) {
	for _, tc := range []struct {
		name            string
		password        string
		wantMessage     string
		wantRemediation string
		secretNeedle    string
	}{
		{
			name:            "invalid UTF-8",
			password:        string([]byte{0xff}) + "sentinel-secret",
			wantMessage:     "not valid UTF-8",
			wantRemediation: "supply a text secret",
			secretNeedle:    "sentinel-secret",
		},
		{
			name:            "non-BMP character",
			password:        "password-\U0001F600",
			wantMessage:     "outside the Basic Multilingual Plane",
			wantRemediation: "choose a password made of BMP characters",
			secretNeedle:    "password-\U0001F600",
		},
		{
			name:            "embedded NUL",
			password:        "sentinel-secret\x00",
			wantMessage:     "contains a NUL byte",
			wantRemediation: "strip NUL bytes from the secret",
			secretNeedle:    "sentinel-secret",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkPasswordEncodable(tc.password)
			if !errors.Is(err, ErrUnencodablePassword) {
				t.Fatalf("checkPasswordEncodable(%q) = %v, want ErrUnencodablePassword: the container must refuse to start", tc.password, err)
			}
			got := err.Error()
			if !strings.Contains(got, tc.wantMessage) || !strings.Contains(got, tc.wantRemediation) {
				t.Errorf("checkPasswordEncodable(%q) = %q, want shape %q and remediation %q",
					tc.password, got, tc.wantMessage, tc.wantRemediation)
			}
			if strings.Contains(got, tc.secretNeedle) {
				t.Errorf("checkPasswordEncodable(%q) leaked the password in %q", tc.password, got)
			}
		})
	}
}

// TestCheckPasswordEncodable_invalid_utf8_wins_over_non_bmp pins the branch precedence:
// a password that is both invalid UTF-8 and carries a non-BMP rune reports only the
// UTF-8 shape, so the operator gets one actionable reason rather than two.
func TestCheckPasswordEncodable_invalid_utf8_wins_over_non_bmp(t *testing.T) {
	t.Parallel()
	err := checkPasswordEncodable(string([]byte{0xff}) + "pw-\U0001F600")
	if err == nil {
		t.Fatal("checkPasswordEncodable = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Errorf("checkPasswordEncodable = %v, want the invalid-UTF-8 reason", err)
	}
	if strings.Contains(err.Error(), "Basic Multilingual Plane") {
		t.Errorf("checkPasswordEncodable = %v, want only the invalid-UTF-8 reason", err)
	}
}

// TestCheckPasswordEncodable_accepts_a_usable_password pins that the gate does not
// reject what PKCS#12 can carry: an ordinary ASCII password, a BMP non-ASCII one, and
// the empty password (whose acceptability is the PFX_ALLOW_EMPTY_PASSWORD opt-out's
// business, not this gate's).
func TestCheckPasswordEncodable_accepts_a_usable_password(t *testing.T) {
	t.Parallel()
	for _, pw := range []string{"", "hunter2", "pässwörd-Ünicode", "日本語パスワード"} {
		if err := checkPasswordEncodable(pw); err != nil {
			t.Errorf("checkPasswordEncodable(%q) = %v, want nil", pw, err)
		}
	}
}

// TestLoad_rejects_a_whitespace_only_password pins the other half of the unification:
// the blank guard now trims, so PFX_PASSWORD=" " — a quoting
// slip in a compose file or .env — is REFUSED where it previously started and embedded a
// single space into every generated bundle as the only protection on the private key.
//
// The opt-out still works, and it now means the same thing for a blank value as for an
// absent one.
func TestLoad_rejects_a_whitespace_only_password(t *testing.T) {
	for _, tc := range []struct {
		name, password, allowEmpty string
		wantErr                    bool
	}{
		{"a single space is blank", " ", "", true},
		{"tabs and newlines are blank", "\t\n ", "", true},
		{"exactly empty is blank", "", "", true},
		{"the opt-out accepts a blank value", " ", "true", false},
		{"a real password is accepted", "hunter2", "", false},
		{"a password with inner spaces is not blank", "two words", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PFX_PASSWORD", tc.password)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", tc.allowEmpty)
			t.Setenv("PFX_PASSWORD_FILE", "")

			_, err := Load()
			if tc.wantErr {
				if !errors.Is(err, ErrEmptyPassword) {
					t.Errorf("Load(PFX_PASSWORD=%q) = %v, want ErrEmptyPassword", tc.password, err)
				}
				return
			}
			if err != nil {
				t.Errorf("Load(PFX_PASSWORD=%q, allow=%q) = %v, want nil", tc.password, tc.allowEmpty, err)
			}
		})
	}
}

// TestLoad_refuses_an_unencodable_password pins that the encoding gate is reached from
// Load, not just callable in isolation: the container must not start.
func TestLoad_refuses_an_unencodable_password(t *testing.T) {
	t.Setenv("PFX_PASSWORD", "pw-\U0001F600")
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")
	t.Setenv("PFX_PASSWORD_FILE", "")

	_, err := Load()
	if !errors.Is(err, ErrUnencodablePassword) {
		t.Fatalf("Load(non-BMP password) = %v, want ErrUnencodablePassword", err)
	}
	if !strings.Contains(err.Error(), "supplied via PFX_PASSWORD") {
		t.Errorf("Load(non-BMP env password) = %v, want the refusal to name the channel that supplied the secret", err)
	}
}

// TestLoad_refuses_a_supplementary_variation_selector_as_unencodable pins the
// precedence between the two refusals that overlap for one class of password.
//
// The invisible-rune class spans Unicode's Default_Ignorable set, which includes the
// SUPPLEMENTARY variation selectors U+E0100-U+E01EF. A password made only of those is
// simultaneously blank (nothing renders) and unencodable (non-BMP, so PKCS#12's
// BMPString cannot carry it). Only one of the two refusals has an achievable
// remediation: PFX_ALLOW_EMPTY_PASSWORD cannot rescue it, because opting out of the
// blank guard merely reaches the encoding refusal on the next start. So the encoding
// check must be asked FIRST, on both channels and with the opt-out both ways.
//
// The bug this catches: classifying before checking encodability, which sent the
// operator to an opt-out that cannot resolve their situation.
func TestLoad_refuses_a_supplementary_variation_selector_as_unencodable(t *testing.T) {
	const selectorOnly = "\U000E0100"

	for _, tc := range []struct {
		name       string
		envValue   string
		fileBody   string
		allowEmpty string
	}{
		{name: "env channel, no opt-out", envValue: selectorOnly},
		{name: "env channel, opt-out set", envValue: selectorOnly, allowEmpty: "true"},
		{name: "file channel, no opt-out", fileBody: selectorOnly},
		{name: "file channel, opt-out set", fileBody: selectorOnly, allowEmpty: "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", tc.allowEmpty)
			t.Setenv("PFX_PASSWORD", tc.envValue)
			if tc.fileBody == "" {
				t.Setenv("PFX_PASSWORD_FILE", "")
			} else {
				path := filepath.Join(t.TempDir(), "pfx-password")
				if err := os.WriteFile(path, []byte(tc.fileBody), 0o600); err != nil {
					t.Fatalf("write secret file: %v", err)
				}
				t.Setenv("PFX_PASSWORD_FILE", path)
			}

			_, err := Load()
			if !errors.Is(err, ErrUnencodablePassword) {
				t.Errorf("Load(supplementary variation selector) = %v, want ErrUnencodablePassword", err)
			}
			if errors.Is(err, ErrEmptyPassword) {
				t.Errorf("Load(supplementary variation selector) = %v, want the encoding refusal rather than the blank one: PFX_ALLOW_EMPTY_PASSWORD cannot resolve a non-BMP password", err)
			}
		})
	}
}

// TestLoad_still_routes_an_encodable_blank_through_the_optout guards the other side of
// the precedence change: moving the encoding check ahead of the blank guard must NOT
// take BMP-only invisible values (a byte-order mark, a zero-width space) away from the
// PFX_ALLOW_EMPTY_PASSWORD opt-out, which is the documented way to run without a
// password.
func TestLoad_still_routes_an_encodable_blank_through_the_optout(t *testing.T) {
	const bomOnly = "\ufeff"

	t.Setenv("PFX_PASSWORD_FILE", "")
	t.Setenv("PFX_PASSWORD", bomOnly)

	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")
	if _, err := Load(); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("Load(BOM-only, no opt-out) = %v, want ErrEmptyPassword", err)
	}

	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")
	if _, err := Load(); err != nil {
		t.Errorf("Load(BOM-only, opt-out set) = %v, want the opt-out to still start the container", err)
	}
}

// TestLoad_blank_secret_file_obeys_the_same_optout pins the unification:
// PFX_ALLOW_EMPTY_PASSWORD now means ONE thing regardless of how the secret was
// delivered.
//
// Before, the same question had three answers: a blank PFX_PASSWORD was accepted with a
// warning, a blank PFX_PASSWORD_FILE aborted startup inside envx before the opt-out was
// ever consulted, and the opt-out governed only the environment channel. An operator who
// set PFX_ALLOW_EMPTY_PASSWORD=true and mounted an empty secret file got a container that
// refused to start, for the exact configuration they had just asked for.
//
// This is a deliberate behaviour change in BOTH directions: a blank file now starts WITH
// the opt-out where it previously failed, and fails with ErrEmptyPassword WITHOUT it
// where it previously failed with envx's error. An unusable file — unreadable, oversized,
// rejected path — is still never rescued; that is TestLoad_unreadable_password_file_fails_loudly.
func TestLoad_blank_secret_file_obeys_the_same_optout(t *testing.T) {
	blankFile := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "blank")
		if err := os.WriteFile(path, []byte("   \n\t"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("blank file without the opt-out is ErrEmptyPassword", func(t *testing.T) {
		t.Setenv("PFX_PASSWORD", "")
		t.Setenv("PFX_PASSWORD_FILE", blankFile(t))
		t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

		if _, err := Load(); !errors.Is(err, ErrEmptyPassword) {
			t.Errorf("Load(blank file, no opt-out) = %v, want ErrEmptyPassword", err)
		}
	})

	t.Run("blank file with the opt-out starts", func(t *testing.T) {
		t.Setenv("PFX_PASSWORD", "")
		t.Setenv("PFX_PASSWORD_FILE", blankFile(t))
		t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

		logs := capture.Default(t)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load(blank file, opt-out) = %v, want nil: the opt-out must mean the same thing for both channels", err)
		}
		if cfg.Password != "" {
			t.Errorf("Password = %q, want empty: a blank file must never silently fall back to PFX_PASSWORD", cfg.Password)
		}
		// The blank FILE must say so: an INFO "PFX password configured" here
		// reported a secret that was never configured.
		if n := logs.CountLevel(slog.LevelWarn, "PFX_PASSWORD_FILE is blank"); n != 1 {
			t.Errorf("Load(blank file, opt-out) logged %d WARN records naming the blank secret file, want 1 (logs %v)",
				n, logs.Messages())
		}
		if logs.Contains("PFX password configured") {
			t.Errorf("Load(blank file, opt-out) logged the configured-secret INFO for a blank file (logs %v)", logs.Messages())
		}
	})

	// The blank-file-plus-opt-out configuration used to emit TWO WARNs for one
	// condition: the channel-specific blank-file record from logPasswordDelivery,
	// then the generic empty-password record from warnPasswordStrength, whose
	// remediation said "point PFX_PASSWORD_FILE at a mounted secret" — the step
	// the operator had already taken. The generic record is now suppressed when the
	// channel-specific one will report the same empty password, so the only
	// instruction names the action that actually helps. The empty-password
	// condition itself must still surface at WARN.
	t.Run("the only guidance is to write the secret into the mounted file", func(t *testing.T) {
		t.Setenv("PFX_PASSWORD", "")
		t.Setenv("PFX_PASSWORD_FILE", blankFile(t))
		t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

		logs := capture.Default(t)

		if _, err := Load(); err != nil {
			t.Fatalf("Load(blank file, opt-out) = %v, want nil", err)
		}

		const blankFileWarn = "PFX_PASSWORD_FILE is blank"
		if n := logs.CountLevel(slog.LevelWarn, "empty PFX password"); n != 1 {
			t.Errorf("Load(blank file, opt-out) logged %d WARN records reporting the empty password, want exactly 1 (logs %v)",
				n, logs.Messages())
		}
		if n := logs.Count("PFX_PASSWORD is empty"); n != 0 {
			t.Errorf("Load(blank file, opt-out) logged %d generic empty-password records, want 0: the channel-specific WARN already reports it (logs %v)",
				n, logs.Messages())
		}
		if !logs.AttrContains(blankFileWarn, "remediation", "write the secret into the mounted file") {
			t.Errorf("Load(blank file, opt-out) %q WARN does not tell the operator to write the secret into the mounted file (logs %v)",
				blankFileWarn, logs.Messages())
		}
		// No record may send an operator to point PFX_PASSWORD_FILE at a secret
		// when it is already pointed at one. Checked across every attr of every
		// record, not just the remediation of the record that carried it, so a
		// future diagnostic repeating the wrong advice is caught too.
		for _, r := range logs.Records() {
			r.Attrs(func(a slog.Attr) bool {
				if strings.Contains(a.Value.String(), "point PFX_PASSWORD_FILE") {
					t.Errorf("Load(blank file, opt-out) record %q carries %s=%v, telling the operator to point PFX_PASSWORD_FILE at a secret it is already pointed at",
						r.Message, a.Key, a.Value)
				}
				return true
			})
		}
	})

	t.Run("a blank file never falls back to PFX_PASSWORD", func(t *testing.T) {
		t.Setenv("PFX_PASSWORD", "from-env")
		t.Setenv("PFX_PASSWORD_FILE", blankFile(t))
		t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load = %v, want nil", err)
		}
		if cfg.Password == "from-env" {
			t.Error("a blank secret file fell back to PFX_PASSWORD; the file channel exists to be authoritative")
		}
	})
}

// TestLoad_blank_secret_file_error_names_configured_path pins the startup
// diagnostic: a blank secret file must fail as ErrEmptyPassword AND name the
// configured path, which is the only way an operator can tell which mounted
// secret to repair. Classifying the error alone stays green if Load stops
// wrapping envx's path-bearing ErrBlankSecretFile.
func TestLoad_blank_secret_file_error_names_configured_path(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blank-pfx-password")
	if err := os.WriteFile(path, []byte("  \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_PASSWORD_FILE", path)
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

	_, err := Load()
	if !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Load(blank password file) = %v, want ErrEmptyPassword", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("Load(blank password file) error = %q, want configured path %q", err, path)
	}
	if !strings.Contains(err.Error(), "write a non-blank secret to the file named by PFX_PASSWORD_FILE") {
		t.Errorf("Load(blank password file) error = %q, want remediation for the configured file channel", err)
	}
}

// TestLoad_warns_when_the_env_password_is_padded pins the whitespace diagnostic on the
// env channel: PFX_PASSWORD is used verbatim, so the padding is part of the password
// embedded in every bundle and the WARN is the only signal an operator gets.
// TestLoad_warns_when_a_mounted_secret_password_is_padded pins the same record on the
// file channel, which envx v1.5.0 made reachable. Serial: it
// swaps slog.Default().
func TestLoad_warns_when_the_env_password_is_padded(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		wantWarn bool
	}{
		{"padded value warns", "  s3cret  ", true},
		{"clean value is quiet", "s3cret", false},
		{"inner spaces are not padding", "two words", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", tc.password)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() with PFX_PASSWORD=%q = %v, want nil", tc.password, err)
			}
			if warned := logs.CountLevel(slog.LevelWarn, paddedPasswordWarn) > 0; warned != tc.wantWarn {
				t.Errorf("Load() with PFX_PASSWORD=%q warned = %v, want %v (logs %v)",
					tc.password, warned, tc.wantWarn, logs.Messages())
			}
			if tc.wantWarn && !logs.HasAttr(paddedPasswordWarn, "source", "PFX_PASSWORD") {
				t.Errorf("padding WARN does not name the delivery channel as the env-var name an operator filters on (logs %v)", logs.Messages())
			}
		})
	}
}

// TestLoad_warns_when_a_mounted_secret_password_is_padded pins the padding WARN on the
// channel envx v1.5.0 made reachable. The file channel used to run the secret's content
// through TrimSpace, so a padded PFX_PASSWORD_FILE could not produce a padded password
// and the WARN was gated on the env channel. It now returns every byte the operator
// wrote apart from at most one trailing line ending, so a mounted secret an editor left
// with a leading space or a trailing tab yields a .pfx nobody can open with the secret's
// visible contents — written, health green, and (before this record) with no diagnostic
// at all. Restoring the source == envx.SourceEnv gate must fail this test.
//
// The quiet cases are what keep it honest: one trailing newline is the line ending every
// editor and `kubectl create secret --from-file` appends, so a secret that only carries
// that must NOT warn, or the record fires on every correctly mounted deployment. Serial:
// it swaps slog.Default().
func TestLoad_warns_when_a_mounted_secret_password_is_padded(t *testing.T) {
	for _, tc := range []struct {
		name         string
		contents     string
		wantPassword string
		wantWarn     bool
	}{
		{"leading and trailing spaces warn", "  s3cret  \n", "  s3cret  ", true},
		{"a trailing tab warns", "s3cret\t\n", "s3cret\t", true},
		{"the second trailing newline is padding and warns", "s3cret\n\n", "s3cret\n", true},
		{"a leading newline warns", "\ns3cret\n", "\ns3cret", true},
		{"the one trailing line ending is not padding", "s3cret\n", "s3cret", false},
		{"a CRLF line ending is not padding", "s3cret\r\n", "s3cret", false},
		{"inner spaces are not padding", "two words\n", "two words", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pfx-password")
			if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PFX_PASSWORD", "")
			t.Setenv("PFX_PASSWORD_FILE", path)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() with PFX_PASSWORD_FILE=%q = %v, want nil: padding is a WARN, not a startup refusal", tc.contents, err)
			}
			// Asserted alongside the WARN so the two cannot drift: the record is only
			// truthful if the padding really is part of the delivered password.
			if cfg.Password != tc.wantPassword {
				t.Errorf("Load() with PFX_PASSWORD_FILE=%q Password = %q, want %q verbatim",
					tc.contents, cfg.Password, tc.wantPassword)
			}
			wantCount := 0
			if tc.wantWarn {
				wantCount = 1
			}
			if n := logs.CountLevel(slog.LevelWarn, paddedPasswordWarn); n != wantCount {
				t.Errorf("Load() with PFX_PASSWORD_FILE=%q logged %d padding WARN records, want %d (logs %v)",
					tc.contents, n, wantCount, logs.Messages())
			}
			if tc.wantWarn && !logs.HasAttr(paddedPasswordWarn, "source", "PFX_PASSWORD_FILE") {
				t.Errorf("padding WARN does not name the mounted-secret channel an operator filters on, got source=%q (logs %v)",
					mustAttr(t, logs, paddedPasswordWarn, "source"), logs.Messages())
			}
		})
	}
}

// TestLoad_uses_the_env_password_verbatim pins the contract the padding WARN only
// describes: PFX_PASSWORD is embedded in every bundle exactly as configured,
// surrounding whitespace included — and since envx v1.5.0 the FILE channel is
// verbatim too (TestLoad_password_file_is_verbatim_and_takes_precedence_over_env
// pins that half). Normalising the
// value on the way into Config keeps the padding WARN -- and every other test in this
// package -- green while silently protecting every generated .pfx with a password the
// operator never configured; encoding succeeds either way, so health never notices.
// Serial: it swaps slog.Default().
func TestLoad_uses_the_env_password_verbatim(t *testing.T) {
	const padded = "  s3cret\t"
	isolatePasswordFile(t)
	t.Setenv("PFX_PASSWORD", padded)
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

	logs := capture.Default(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if cfg.Password != padded {
		t.Errorf("Load() Password = %q, want %q verbatim: the whitespace is part of the password embedded in every PFX file",
			cfg.Password, padded)
	}
	for _, r := range logs.Records() {
		if strings.Contains(r.Message, padded) {
			t.Errorf("Load() leaked the configured password in message %q", r.Message)
		}
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Key, padded) || strings.Contains(a.Value.String(), padded) {
				t.Errorf("Load() leaked the configured password in attr %s=%v on %q", a.Key, a.Value, r.Message)
			}
			return true
		})
	}
}

// TestLoad_warns_when_both_password_channels_are_set pins the ambiguity warning.
// PFX_PASSWORD_FILE wins by design, so a PFX_PASSWORD set
// beside it is silently ignored — an operator who edits the wrong one gets a successful
// startup and bundles carrying the other password, and only finds out when a consumer
// cannot open a .pfx. Runs serially: it swaps slog.Default().
func TestLoad_warns_when_both_password_channels_are_set(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pfx")
	if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, env, file string
		wantWarn        bool
	}{
		{"both set warns", "from-env", path, true},
		{"file only is quiet", "", path, false},
		{"env only is quiet", "from-env", "", false},
		{"whitespace-only env is not a real conflict", "   ", path, false},
		// The invisible-only class the single classification added: a PFX_PASSWORD
		// holding nothing but a byte-order mark is blank, so the file does not
		// "win" over anything and the conflict WARN must stay silent. The
		// suppression reads classifyPassword, so narrowing it back to a TrimSpace test
		// would send the operator to remove a variable that carries nothing.
		{"invisible-only env is not a real conflict", "\ufeff", path, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			t.Setenv("PFX_PASSWORD", tc.env)
			t.Setenv("PFX_PASSWORD_FILE", tc.file)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			if _, err := Load(); err != nil {
				t.Fatalf("Load = %v, want nil", err)
			}

			got := logs.Contains("both PFX_PASSWORD and PFX_PASSWORD_FILE are set")
			if got != tc.wantWarn {
				t.Errorf("Load(env=%q file=%q) warned = %v, want %v; log = %v", tc.env, tc.file, got, tc.wantWarn, logs.Messages())
			}
			for _, r := range logs.Records() {
				if strings.Contains(r.Message, "from-env") || strings.Contains(r.Message, "from-file") {
					t.Errorf("the log leaked a password value in message %q", r.Message)
				}
				r.Attrs(func(a slog.Attr) bool {
					if strings.Contains(a.Value.String(), "from-env") || strings.Contains(a.Value.String(), "from-file") {
						t.Errorf("the log leaked a password value in attr %s=%v on %q", a.Key, a.Value, r.Message)
					}
					return true
				})
			}
		})
	}
}

// TestLoad_warns_when_a_blank_file_overrides_a_configured_env_password pins the
// conflict WARN in the configuration that needs it most: the mounted file is blank
// and the opt-out lets startup proceed, so the file channel still wins and the
// PFX_PASSWORD the operator did configure is discarded. Every generated bundle then
// protects the private key with NO password while health stays green, and the
// conflict WARN is the only line that says the env value was ignored. The existing
// both-channels test only covers a file that supplied a secret, so moving the
// conflict check beside the success INFO would drop this case silently. Serial: it
// swaps slog.Default().
func TestLoad_warns_when_a_blank_file_overrides_a_configured_env_password(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blank")
	if err := os.WriteFile(path, []byte("  \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_PASSWORD", "from-env")
	t.Setenv("PFX_PASSWORD_FILE", path)
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

	logs := capture.Default(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(blank file, opt-out) = %v, want nil", err)
	}
	if cfg.Password != "" {
		t.Fatalf("Load() Password = %q, want empty: a blank file must never fall back to PFX_PASSWORD", cfg.Password)
	}
	const conflict = "both PFX_PASSWORD and PFX_PASSWORD_FILE are set"
	if n := logs.CountLevel(slog.LevelWarn, conflict); n != 1 {
		t.Errorf("Load(blank file, opt-out, PFX_PASSWORD set) logged %d WARN records matching %q, want exactly 1: "+
			"nothing else tells the operator the configured password was discarded (logs %v)",
			n, conflict, logs.Messages())
	}
}

// TestLoad_wires_output_lifecycle pins the OUTPUT_LIFECYCLE knob end to end:
// Load must carry the parsed mode into Config.Lifecycle (nothing else reads the
// env var, so a dropped assignment would silently revert every deployment to
// warn and leave orphaned .pfx files behind forever), and an unrecognised value
// must warn while still starting. Serial: it swaps slog.Default().
func TestLoad_wires_output_lifecycle(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		want     outputpolicy.Lifecycle
		wantWarn bool
	}{
		{"unset defaults to warn", "", outputpolicy.LifecycleWarn, false},
		{"explicit warn", "warn", outputpolicy.LifecycleWarn, false},
		{"sync is wired through", "sync", outputpolicy.LifecycleSync, false},
		{"keep is wired through", "keep", outputpolicy.LifecycleKeep, false},
		{"padded mixed case is normalised", "  SyNc  ", outputpolicy.LifecycleSync, false},
		{"unknown value warns and falls back to warn", "delete", outputpolicy.LifecycleWarn, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("OUTPUT_LIFECYCLE", tc.raw)

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() with OUTPUT_LIFECYCLE=%q = %v, want nil (an unknown value must not fail startup)", tc.raw, err)
			}
			if cfg.Lifecycle != tc.want {
				t.Errorf("Load() with OUTPUT_LIFECYCLE=%q Lifecycle = %q, want %q", tc.raw, cfg.Lifecycle, tc.want)
			}
			warned := logs.CountLevel(slog.LevelWarn, "unknown OUTPUT_LIFECYCLE") > 0
			if warned != tc.wantWarn {
				t.Errorf("Load() with OUTPUT_LIFECYCLE=%q warned = %v, want %v (log: %v)", tc.raw, warned, tc.wantWarn, logs.Messages())
			}
			if tc.wantWarn && !logs.AttrContains("unknown OUTPUT_LIFECYCLE", "value", tc.raw) {
				t.Errorf("Load() with OUTPUT_LIFECYCLE=%q logged %v, want the rejected value named so an operator can spot the typo", tc.raw, logs.Messages())
			}
			// The message says only "using the default", so these two attrs are the
			// record's only statement of the effective mode and the accepted set.
			// Removing either, or sourcing a stale list, keeps every assertion above
			// green while the operator loses the actionable half.
			if tc.wantWarn && !logs.HasAttr("unknown OUTPUT_LIFECYCLE", "using", string(tc.want)) {
				t.Errorf("Load() with OUTPUT_LIFECYCLE=%q WARN does not name the effective mode %q (logs %v)", tc.raw, tc.want, logs.Messages())
			}
			if tc.wantWarn && !logs.HasAttr("unknown OUTPUT_LIFECYCLE", "expected", "[warn sync keep]") {
				t.Errorf("Load() with OUTPUT_LIFECYCLE=%q WARN does not list every accepted mode (logs %v)", tc.raw, logs.Messages())
			}
		})
	}
}

// TestLoad_warns_when_the_password_contains_a_control_character pins the
// interior-control-character diagnostic, the one shape both existing guards
// miss: envx delivers the configured value verbatim and PKCS#12 encodes a newline or
// tab verbatim, so the bundle is written, health stays green, and the password
// cannot be typed into the consumers that need it. The clean case is what keeps
// the WARN from firing on every healthy startup.
//
// The "source" attribute is pinned to the exact env-var NAME, not envx's internal
// SourceEnv/SourceFile enum: every other password record in this package renders the
// variable name, so an operator or Loki matcher selecting a delivery channel by
// source= must see this record too. Equality, not substring, because "PFX_PASSWORD"
// is a prefix of "PFX_PASSWORD_FILE" and a substring assertion would pass for either
// channel. Serial: it swaps slog.Default().
func TestLoad_warns_when_the_password_contains_a_control_character(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		wantWarn bool
	}{
		{"an interior newline warns", "line1\nline2", true},
		{"an interior tab warns", "pw\tsecret", true},
		{"a clean password is silent", "hunter2", false},
		// The Cc/Cf disjointness isInvisibleRune's comment relies on, pinned from this
		// side too: a byte-order mark is not a control character, so one rune must
		// not produce two records about itself. Widening this guard to "not
		// printable" catches every Cf rune here as well, and the sibling
		// invisible-formatting test stays green when it does.
		{"a byte-order mark alone is silent", "\ufeffhunter2", false},
		{"a zero-width space alone is silent", "pw\u200bsecret", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", tc.password)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil: a control character is a WARN, not a startup refusal", err)
			}
			const msg = "contains a control character"
			warned := logs.CountLevel(slog.LevelWarn, msg) > 0
			if warned != tc.wantWarn {
				t.Errorf("Load(%s) control-character WARN = %v, want %v (logs %v)", tc.name, warned, tc.wantWarn, logs.Messages())
			}
			if tc.wantWarn && !logs.HasAttr(msg, "source", "PFX_PASSWORD") {
				t.Errorf("control-character WARN does not name the delivery channel as the env-var name an operator filters on (logs %v)", logs.Messages())
			}
		})
	}
}

// TestLoad_warns_when_a_mounted_secret_contains_a_control_character pins the
// control-character WARN on the delivery channel that actually produces one: envx
// removes at most one trailing line ending, so a secret file written from wrapped
// `openssl rand -base64` output -- the exact cause the remediation names -- keeps its
// interior newline, PKCS#12 embeds it verbatim, and no consumer can type the
// password back. Both this guard and its sibling padding WARN are channel-agnostic,
// so folding either into an env-only branch would silence the file channel with
// every other test still green.
//
// It also pins the record's "source" attribute to PFX_PASSWORD_FILE: this is the
// mounted-secret channel an operator filters on, and rendering envx's "file" enum
// here instead would drop this WARN out of exactly that filter. Serial: it swaps
// slog.Default().
func TestLoad_warns_when_a_mounted_secret_contains_a_control_character(t *testing.T) {
	const secret = "line1\nline2"
	path := filepath.Join(t.TempDir(), "pfx-password")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_PASSWORD_FILE", path)
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

	logs := capture.Default(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil: a control character is a WARN, not a startup refusal", err)
	}
	if cfg.Password != secret {
		t.Fatalf("Load() Password = %q, want the file contents with only the one trailing line ending removed", cfg.Password)
	}
	const msg = "contains a control character"
	if n := logs.CountLevel(slog.LevelWarn, msg); n != 1 {
		t.Errorf("Load() with a wrapped mounted secret logged %d WARN records matching %q, want exactly 1 (logs %v)",
			n, msg, logs.Messages())
	}
	if !logs.HasAttr(msg, "source", "PFX_PASSWORD_FILE") {
		t.Errorf("control-character WARN does not name the mounted-secret channel an operator filters on (logs %v)", logs.Messages())
	}
	for _, r := range logs.Records() {
		if strings.Contains(r.Message, secret) || strings.Contains(r.Message, path) {
			t.Errorf("Load() leaked the mounted secret or secret-mount path in message %q", r.Message)
		}
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Key, secret) || strings.Contains(a.Value.String(), secret) ||
				strings.Contains(a.Key, path) || strings.Contains(a.Value.String(), path) {
				t.Errorf("Load() leaked the mounted secret or secret-mount path in attr %s=%v on %q", a.Key, a.Value, r.Message)
			}
			return true
		})
	}
}

// TestLoad_unencodable_secret_file_names_the_file_channel pins the half of the
// refusal that actually redirects the operator: when the rejected secret came
// from the mounted file, the error must name PFX_PASSWORD_FILE, because the
// file-wins rule means editing PFX_PASSWORD would change nothing. The secret
// value itself must stay out of the startup log.
func TestLoad_unencodable_secret_file_names_the_file_channel(t *testing.T) {
	const secret = "pw-\U0001F600"
	path := filepath.Join(t.TempDir(), "pfx-password")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_PASSWORD", "")
	t.Setenv("PFX_PASSWORD_FILE", path)
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

	_, err := Load()
	if !errors.Is(err, ErrUnencodablePassword) {
		t.Fatalf("Load(unencodable secret file) = %v, want ErrUnencodablePassword", err)
	}
	if !strings.Contains(err.Error(), "supplied via PFX_PASSWORD_FILE") {
		t.Errorf("Load(unencodable secret file) = %v, want it to name PFX_PASSWORD_FILE, not the ignored env variable", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("Load(unencodable secret file) leaked the secret into %q", err.Error())
	}
}

// TestFallbackInterval_agrees_with_the_interval_Load_reports pins the shared
// source of truth behind the health-marker freshness deadline: main derives the
// probe's max age from cfg.FallbackInterval, while the `health` subcommand
// derives it from the exported FallbackInterval() (which exists precisely so the
// probe need not load a full Config). Both read FALLBACK_SCAN_HOURS through
// fallbackIntervalFromEnv today, and nothing else notices if one of them stops:
// the deadline would then describe a cadence the watch loop does not run, either
// restarting a healthy container or never firing at all. Every parse class is
// exercised, because a divergence could be introduced in the clamp or repair
// arms alone. Serial: it mutates the environment and swaps slog.Default().
func TestFallbackInterval_agrees_with_the_interval_Load_reports(t *testing.T) {
	for _, raw := range []string{
		"", "   ", "abc", "-1", "00", "12", "87600", "87601",
		"999999999999999999999999999999", "0", "false", " FALSE ",
	} {
		t.Run(strconv.Quote(raw), func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("FALLBACK_SCAN_HOURS", raw)

			capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if got := FallbackInterval(); got != cfg.FallbackInterval {
				t.Errorf("FallbackInterval() = %v but Load() reported FallbackInterval = %v for FALLBACK_SCAN_HOURS=%q: "+
					"the health probe's freshness deadline is 3x this value, so a divergence either restarts a healthy container or never fires",
					got, cfg.FallbackInterval, raw)
			}
		})
	}
}

// TestLoad_warns_when_the_password_contains_an_invisible_formatting_character pins
// the Cf-rune diagnostic that sits beside the control-character WARN: a UTF-8 BOM or
// a zero-width space is valid UTF-8, inside the BMP, not a NUL, not a control
// character and not whitespace, so every other guard accepts it and this WARN is the
// operator's only signal that the bundle's password is not the secret's visible
// contents. The clean case keeps it from firing on every healthy startup, and the
// control-character-only case pins the Cc/Cf disjointness that keeps one rune from
// producing two records. The "source" attribute is pinned to the env-var NAME by
// equality for the same reason its control-character sibling is: one vocabulary per
// attribute key, and "PFX_PASSWORD" is a prefix of "PFX_PASSWORD_FILE". Serial: it
// swaps slog.Default().
func TestLoad_warns_when_the_password_contains_an_invisible_formatting_character(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		wantWarn bool
	}{
		{"a byte-order mark warns", "\ufeffhunter2", true},
		{"an interior zero-width space warns", "pw\u200bsecret", true},
		{"a soft hyphen warns", "soft\u00adhyphen", true},
		{"a clean password is silent", "hunter2", false},
		{"a control character alone is silent", "line1\nline2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", tc.password)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil: an invisible formatting character is a WARN, not a startup refusal", err)
			}
			const msg = "invisible Unicode character"
			warned := logs.CountLevel(slog.LevelWarn, msg) > 0
			if warned != tc.wantWarn {
				t.Errorf("Load(%s) invisible-formatting WARN = %v, want %v (logs %v)", tc.name, warned, tc.wantWarn, logs.Messages())
			}
			if tc.wantWarn && !logs.HasAttr(msg, "source", "PFX_PASSWORD") {
				t.Errorf("invisible-formatting WARN does not name the delivery channel as the env-var name an operator filters on (logs %v)", logs.Messages())
			}
		})
	}
}

// TestLoad_warns_when_the_password_contains_a_non_ascii_space pins the third shape
// guard beside its Cc and Cf siblings: U+00A0, U+3000 and U+2028 are Zs/Zl, so they
// are neither control characters nor Cf, nothing trims the delivered value on either
// channel, and each renders as (or invisibly as) the ordinary space a consumer retypes --
// this WARN is the operator's only signal that the bundle's password is not what
// the secret appears to say. The ASCII-space case keeps it from firing on every
// password with a space in it; the Cc-only and Cf-only cases pin the disjointness
// isAmbiguousSpaceRune's comment claims, so widening any one predicate to "not
// printable" cannot silently produce two records about one rune. Serial: it swaps
// slog.Default().
func TestLoad_warns_when_the_password_contains_a_non_ascii_space(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		wantWarn bool
	}{
		{"an interior no-break space warns", "pw\u00a0secret", true},
		{"an interior ideographic space warns", "pw\u3000secret", true},
		{"an interior line separator warns", "pw\u2028secret", true},
		{"an ordinary ASCII space is silent", "pw secret", false},
		{"a clean password is silent", "hunter2", false},
		{"a control character alone is silent", "line1\nline2", false},
		{"a byte-order mark alone is silent", "\ufeffhunter2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", tc.password)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil: a non-ASCII space is a WARN, not a startup refusal", err)
			}
			const msg = "non-ASCII space character"
			warned := logs.CountLevel(slog.LevelWarn, msg) > 0
			if warned != tc.wantWarn {
				t.Errorf("Load(%s) non-ASCII-space WARN = %v, want %v (logs %v)", tc.name, warned, tc.wantWarn, logs.Messages())
			}
			if tc.wantWarn && !logs.HasAttr(msg, "source", "PFX_PASSWORD") {
				t.Errorf("non-ASCII-space WARN does not name the delivery channel as the env-var name an operator filters on (logs %v)", logs.Messages())
			}
		})
	}
}

// TestLoad_reports_every_hard_to_enter_rune_shape_once pins the one-record-per-shape
// contract warnPasswordCharacters' comment claims, on both delivery channels: a
// password carrying a control character, an invisible formatting rune AND a non-ASCII
// space must produce all three WARNs, each exactly once.
//
// Every other rune-shape case carries a single shape, so collapsing the three
// independent guards into an else-if chain drops the second and third record with the
// rest of the suite green -- and an operator fixing the one shape that was reported
// still ships a password no consumer can retype. The file channel is asserted too
// because the ambiguous-space guard is channel-agnostic while its sibling padding WARN
// is env-only: folding it into the env-only shape would silence the mounted-secret
// channel, which is the one where a value pasted from a rendered document arrives.
// Serial: it mutates env and slog.Default.
func TestLoad_reports_every_hard_to_enter_rune_shape_once(t *testing.T) {
	for _, channel := range []string{"PFX_PASSWORD", "PFX_PASSWORD_FILE"} {
		t.Run(channel, func(t *testing.T) {
			setPasswordChannel(t, channel, "pw\n\ufeff\u00a0secret")
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load(%s) = %v, want nil: a hard-to-enter rune is a WARN, not a startup refusal", channel, err)
			}
			for _, msg := range []string{
				"contains a control character",
				"invisible Unicode character",
				"non-ASCII space character",
			} {
				if n := logs.CountLevel(slog.LevelWarn, msg); n != 1 {
					t.Errorf("Load(%s) with a password carrying all three shapes logged %d WARN records matching %q, want exactly 1: each shape needs its own actionable record (logs %v)",
						channel, n, msg, logs.Messages())
				}
			}
		})
	}
}

// TestLoad_warns_when_a_mounted_secret_contains_a_format_character is the
// file-channel half: the invisible-formatting guard is channel-agnostic today, and
// the mounted file is where the failure mode actually originates (an editor saving
// the secret as "UTF-8 with BOM"). Without this, folding the guard into the env-only
// shape of its sibling padding WARN would silence the file channel with every other
// test still green. It pins "source" to PFX_PASSWORD_FILE by equality, the channel
// name an operator's saved query and Loki matcher select on. Serial: it swaps
// slog.Default().
func TestLoad_warns_when_a_mounted_secret_contains_a_format_character(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		wantWarn bool
	}{
		{"a byte-order mark warns", "\ufeffsecret", true},
		{"an interior zero-width space warns", "pw\u200bsecret", true},
		{"a plain password is silent", "hunter2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pfx-password")
			if err := os.WriteFile(path, []byte(tc.password), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PFX_PASSWORD", "")
			t.Setenv("PFX_PASSWORD_FILE", path)
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "")

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil: an invisible formatting character is a WARN, not a startup refusal", err)
			}
			if cfg.Password != tc.password {
				t.Errorf("Load() Password = %q, want %q verbatim", cfg.Password, tc.password)
			}

			const msg = "invisible Unicode character"
			wantCount := 0
			if tc.wantWarn {
				wantCount = 1
			}
			if got := logs.CountLevel(slog.LevelWarn, msg); got != wantCount {
				t.Errorf("Load(%s) logged %d invisible-formatting WARNs, want %d (logs %v)", tc.name, got, wantCount, logs.Messages())
			}
			if tc.wantWarn && !logs.HasAttr(msg, "source", "PFX_PASSWORD_FILE") {
				t.Errorf("invisible-formatting WARN does not name the mounted-secret channel an operator filters on (logs %v)", logs.Messages())
			}
		})
	}
}

// TestLoad_refuses_an_invisible_only_password_on_both_channels pins the guard half
// of the single password classification: a value made only of invisible formatting
// runes is BLANK, so the PFX_ALLOW_EMPTY_PASSWORD opt-out governs it exactly as it
// governs a whitespace-only value — and it does so identically whichever channel
// delivered it.
//
// The file channel is the one that matters in practice and the one that used to
// escape every guard: envx judges a secret file blank on its whitespace-trimmed
// content and a BOM is not whitespace, so a secret file holding nothing but a
// BOM an editor added is NOT blank to envx, arrived here as a real password, and
// started a container whose bundles are protected by a password nobody can retype.
// Serial: it mutates env and slog.Default.
func TestLoad_refuses_an_invisible_only_password_on_both_channels(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
	}{
		{"a byte-order mark", "\ufeff"},
		{"a zero-width space", "\u200b"},
		{"a soft hyphen", "\u00ad"},
		{"a byte-order mark beside whitespace", "\ufeff \t"},
	} {
		for _, ch := range []struct {
			channel  string
			optout   string
			wantErr  bool
			wantName string
		}{
			{"PFX_PASSWORD", "", true, "env without the opt-out is refused"},
			{"PFX_PASSWORD", "true", false, "env with the opt-out starts"},
			{"PFX_PASSWORD_FILE", "", true, "file without the opt-out is refused"},
			{"PFX_PASSWORD_FILE", "true", false, "file with the opt-out starts"},
		} {
			t.Run(tc.name+": "+ch.wantName, func(t *testing.T) {
				setPasswordChannel(t, ch.channel, tc.password)
				t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", ch.optout)

				logs := capture.Default(t)

				cfg, err := Load()
				if ch.wantErr {
					if !errors.Is(err, ErrEmptyPassword) {
						t.Fatalf("Load(%s=%q) = %v, want ErrEmptyPassword: an invisible-only password is blank, so the opt-out must govern it",
							ch.channel, tc.password, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("Load(%s=%q, opt-out) = %v, want nil", ch.channel, tc.password, err)
				}
				// The opt-out accepts the value verbatim, exactly as it does a
				// whitespace-only one: the guard is what the opt-out waives, not
				// the classification. Both channels deliver the configured bytes
				// verbatim (a secret file loses at most one trailing line ending,
				// and these cases write none), so the delivered value is identical
				// on either channel — which is why an invisible rune beside padding
				// still reaches the encoder unseen.
				if cfg.Password != tc.password {
					t.Errorf("Load(%s=%q, opt-out) Password = %q, want %q verbatim",
						ch.channel, tc.password, cfg.Password, tc.password)
				}
				if cfg.PasswordStatus != PasswordInvisibleOnly {
					t.Errorf("Load(%s=%q, opt-out) status = %q, want %q: the startup line must not report a password nobody can retype as configured",
						ch.channel, tc.password, cfg.PasswordStatus, PasswordInvisibleOnly)
				}
				if n := logs.CountLevel(slog.LevelWarn, invisibleOnlyWarn); n != 1 {
					t.Errorf("Load(%s=%q, opt-out) logged %d WARN records matching %q, want exactly 1 (logs %v)",
						ch.channel, tc.password, n, invisibleOnlyWarn, logs.Messages())
				}
				if !logs.HasAttr(invisibleOnlyWarn, "source", ch.channel) {
					t.Errorf("Load(%s=%q, opt-out) invisible-only WARN source = %q, want %q: the record must name the variable an operator edits (logs %v)",
						ch.channel, tc.password, mustAttr(t, logs, invisibleOnlyWarn, "source"), ch.channel, logs.Messages())
				}
				// One record per shape: the per-rune WARN for a password that
				// CONTAINS an invisible rune must not also fire for a password that
				// consists of nothing else, or the operator reads two records about
				// one condition.
				if n := logs.Count("contains an invisible Unicode character"); n != 0 {
					t.Errorf("Load(%s=%q, opt-out) logged %d per-rune invisible-formatting records alongside the invisible-only WARN, want 0 (logs %v)",
						ch.channel, tc.password, n, logs.Messages())
				}
				// "PFX password configured" is the INFO that reported the defect:
				// a mounted secret holding only a BOM is not a configured secret.
				if logs.Contains("PFX password configured") {
					t.Errorf("Load(%s=%q, opt-out) logged the configured-secret INFO for a blank value (logs %v)",
						ch.channel, tc.password, logs.Messages())
				}
			})
		}
	}
}

// invisibleOnlyWarn is the message substring of the invisible-only strength WARN.
// Named once: three tests key on it, and it is the operator-facing text a Loki
// matcher selects.
const invisibleOnlyWarn = "consists only of invisible Unicode formatting characters"

// paddedPasswordWarn is the message substring of the leading/trailing-whitespace WARN.
// Named once: three tests key on it (both delivery channels plus the blank-password
// suppression), and it is the operator-facing text a Loki matcher selects. Channel-
// neutral by design — the record fires for a padded PFX_PASSWORD and a padded
// PFX_PASSWORD_FILE alike, and names which one in its "source" attribute.
const paddedPasswordWarn = "the PFX password has leading or trailing whitespace"

// setPasswordChannel configures the PFX password through exactly one delivery
// channel, so a test can assert that both channels reach the same decision without
// each case re-deriving the isolation. The file channel writes the value verbatim
// (no trailing newline), because envx removes at most one trailing line ending from a
// secret file and that removal would change the classification under test.
func setPasswordChannel(t *testing.T, channel, password string) {
	t.Helper()
	switch channel {
	case "PFX_PASSWORD":
		isolatePasswordFile(t)
		t.Setenv("PFX_PASSWORD", password)
	case "PFX_PASSWORD_FILE":
		path := filepath.Join(t.TempDir(), "pfx-password")
		if err := os.WriteFile(path, []byte(password), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PFX_PASSWORD", "")
		t.Setenv("PFX_PASSWORD_FILE", path)
	default:
		t.Fatalf("unknown password channel %q", channel)
	}
}

// TestLoad_derives_status_and_warnings_from_one_classification pins the whole point
// of the single classification: for every class, on both delivery channels, the
// status Config reports and the WARN set Load emits describe the SAME answer. A
// guard, a warning or a status that drifted from the other two is exactly the defect
// this shape closes, and each of the three is observable here.
//
// The absent-message assertions are what make it a derivation test rather than three
// unrelated checks: a whitespace-only password must not also produce the
// invisible-only record, an invisible-only one must not produce the whitespace text,
// and a configured one must produce neither. Serial: it mutates env and slog.Default.
func TestLoad_derives_status_and_warnings_from_one_classification(t *testing.T) {
	const (
		emptyWarn      = "PFX_PASSWORD is empty"
		whitespaceWarn = "PFX_PASSWORD is whitespace-only"
		blankFileWarn  = "PFX_PASSWORD_FILE is blank"
	)
	// Every operator-facing record this test reasons about. Each case names the
	// ones that must appear; every other one must not.
	all := []string{emptyWarn, whitespaceWarn, invisibleOnlyWarn, blankFileWarn}

	for _, tc := range []struct {
		name       string
		channel    string
		password   string
		wantStatus PasswordStatus
		wantWarns  []string
	}{
		{"env empty", "PFX_PASSWORD", "", PasswordEmpty, []string{emptyWarn}},
		{"env whitespace-only", "PFX_PASSWORD", " \t", PasswordWhitespaceOnly, []string{whitespaceWarn}},
		{"env invisible-only", "PFX_PASSWORD", "\ufeff", PasswordInvisibleOnly, []string{invisibleOnlyWarn}},
		{"env configured", "PFX_PASSWORD", "hunter2", PasswordConfigured, nil},
		// envx judges a secret file's blankness on its whitespace-trimmed content, so
		// an empty and a whitespace-only file are the
		// same delivery failure and both arrive as ErrBlankSecretFile with an empty
		// password: the channel-specific record reports it and the generic
		// empty-password line is deliberately suppressed.
		{"file empty", "PFX_PASSWORD_FILE", "", PasswordEmpty, []string{blankFileWarn}},
		{"file whitespace-only", "PFX_PASSWORD_FILE", "  \n", PasswordEmpty, []string{blankFileWarn}},
		{"file invisible-only", "PFX_PASSWORD_FILE", "\u200b", PasswordInvisibleOnly, []string{invisibleOnlyWarn}},
		{"file configured", "PFX_PASSWORD_FILE", "hunter2", PasswordConfigured, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setPasswordChannel(t, tc.channel, tc.password)
			// A blank value of any class only reaches its warning with the opt-out
			// set; without it Load refuses to start, which the guard tests pin.
			t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "true")

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if cfg.PasswordStatus != tc.wantStatus {
				t.Errorf("Load(%s=%q) status = %q, want %q", tc.channel, tc.password, cfg.PasswordStatus, tc.wantStatus)
			}
			for _, msg := range all {
				want := 0
				if slices.Contains(tc.wantWarns, msg) {
					want = 1
				}
				if got := logs.CountLevel(slog.LevelWarn, msg); got != want {
					t.Errorf("Load(%s=%q, status %q) logged %d WARN records matching %q, want %d: the WARN set must describe the same classification the status reports (logs %v)",
						tc.channel, tc.password, tc.wantStatus, got, msg, want, logs.Messages())
				}
			}
			// The healthy case is also a derivation: a configured password produces
			// no quality WARN at all, and the file channel says so at INFO.
			if tc.wantStatus == PasswordConfigured && tc.channel == "PFX_PASSWORD_FILE" &&
				logs.CountLevel(slog.LevelInfo, "PFX password configured") != 1 {
				t.Errorf("Load(%s=%q) did not report the configured mounted secret at INFO (logs %v)",
					tc.channel, tc.password, logs.Messages())
			}
		})
	}
}

// TestParseMaxScanEntries pins the derived scan budget for every shape of
// MAX_SCAN_ENTRIES, and — alongside each value — the repair classification Load
// turns into a diagnostic. The two travel together so a value can never change
// class without this table saying so.
func TestParseMaxScanEntries(t *testing.T) {
	for _, tc := range []struct {
		name       string
		val        string
		want       int
		wantRepair scanEntriesRepair
	}{
		{"empty uses default", "", defaultMaxScanEntries, scanEntriesAccepted},
		{"whitespace uses default", "   ", defaultMaxScanEntries, scanEntriesAccepted},
		{"valid", "5000", 5000, scanEntriesAccepted},
		{"padded valid", "  5000  ", 5000, scanEntriesAccepted},
		// 1 is the smallest usable budget: a tree with a single entry still scans.
		{"one is usable", "1", 1, scanEntriesAccepted},
		{"at ceiling unclamped", "200000", maxScanEntriesCeiling, scanEntriesAccepted},
		{"one above ceiling clamped", "200001", maxScanEntriesCeiling, scanEntriesClamped},
		{"far above ceiling clamped", "10000000", maxScanEntriesCeiling, scanEntriesClamped},
		// A valid decimal too large for int is still a positive above-ceiling
		// value, so it clamps rather than falling through to the default.
		{"beyond int64 clamped", "999999999999999999999999999999", maxScanEntriesCeiling, scanEntriesClamped},
		{"signed beyond int64 clamped", "+999999999999999999999999999999", maxScanEntriesCeiling, scanEntriesClamped},
		// strconv reports ErrRange once the digit prefix overflows even when junk
		// follows, so a malformed value must stay malformed instead of being
		// mistaken for an above-ceiling number.
		{"overflowing prefix with junk", "999999999999999999999999999999x", defaultMaxScanEntries, scanEntriesInvalid},
		{"non-numeric", "abc", defaultMaxScanEntries, scanEntriesInvalid},
		// There is deliberately no disable spelling: "0" and "false" are unusable
		// input, not an opt-out, because a scan with no entry budget is the
		// exhaustion path the ceiling exists to close.
		{"zero is not a disable value", "0", defaultMaxScanEntries, scanEntriesInvalid},
		{"padded zero is not a disable value", " 0 ", defaultMaxScanEntries, scanEntriesInvalid},
		{"false is not a disable value", "false", defaultMaxScanEntries, scanEntriesInvalid},
		{"negative uses default", "-1", defaultMaxScanEntries, scanEntriesInvalid},
		{"beyond negative int64 uses default", "-999999999999999999999999999999", defaultMaxScanEntries, scanEntriesInvalid},
		{"a decimal fraction is invalid", "1.5", defaultMaxScanEntries, scanEntriesInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, repair := parseMaxScanEntries(tc.val)
			if got != tc.want {
				t.Errorf("parseMaxScanEntries(%q) = %d, want %d", tc.val, got, tc.want)
			}
			if repair != tc.wantRepair {
				t.Errorf("parseMaxScanEntries(%q) repair = %s, want %s",
					tc.val, scanRepairName(repair), scanRepairName(tc.wantRepair))
			}
		})
	}
}

// scanRepairName renders a scanEntriesRepair for a test failure message.
// Test-local for the same reason repairName is: the production diagnostics are
// message-per-case rather than formatted from the enum.
func scanRepairName(r scanEntriesRepair) string {
	switch r {
	case scanEntriesAccepted:
		return "scanEntriesAccepted"
	case scanEntriesInvalid:
		return "scanEntriesInvalid"
	case scanEntriesClamped:
		return "scanEntriesClamped"
	}
	return "scanEntriesRepair(" + strconv.Itoa(int(r)) + ")"
}

// TestMaxScanEntries_is_silent pins the env reader's contract for every parse class:
// the budget is read through a plain reader, so it must never emit the startup
// diagnostics Load owns. Without this, moving the WARNs into the parser would print a
// startup-shaped record from every caller that only wanted the number. The budget has
// no exported reader (it travels to the composition root on Config), so
// maxScanEntriesFromEnv is the reader whose silence this holds.
// slog.Default is process-global, so this test must not run in parallel with
// anything that logs.
func TestMaxScanEntries_is_silent(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"", defaultMaxScanEntries},
		{"   ", defaultMaxScanEntries},
		{"abc", defaultMaxScanEntries},
		{"0", defaultMaxScanEntries},
		{"-1", defaultMaxScanEntries},
		{"5000", 5000},
		{"200000", maxScanEntriesCeiling},
		{"200001", maxScanEntriesCeiling},
		{"999999999999999999999999999999", maxScanEntriesCeiling},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv("MAX_SCAN_ENTRIES", tc.raw)

			logs := capture.Default(t)

			if got, _, _ := maxScanEntriesFromEnv(); got != tc.want {
				t.Errorf("maxScanEntriesFromEnv() with MAX_SCAN_ENTRIES=%q = %d, want %d", tc.raw, got, tc.want)
			}
			if logs.Len() != 0 {
				t.Errorf("maxScanEntriesFromEnv() with MAX_SCAN_ENTRIES=%q logged %v, want no records: the reader is silent and Load owns the diagnostics",
					tc.raw, logs.Messages())
			}
		})
	}
}

// TestLoad_warns_when_the_scan_entry_budget_is_repaired pins the two repair
// diagnostics at their only home. Both values are silently repaired, so the WARN
// naming the rejected value is the operator's only way to tell an intended budget
// from a default or a clamp — a deployment that meant to raise the ceiling would
// otherwise keep failing its scan at the default with nothing to explain why.
// Message text, level and attribute keys are asserted verbatim: a documented Loki
// matcher or an operator's grep keys on them. Exactly one record per process start.
// slog.Default is process-global, so this test must not run in parallel with
// anything that logs.
func TestLoad_warns_when_the_scan_entry_budget_is_repaired(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		message  string
		attrKey  string
		attrWant string
	}{
		{
			name: "invalid value uses default", raw: "abc",
			message: "invalid MAX_SCAN_ENTRIES, using default", attrKey: "default", attrWant: "10000",
		},
		{
			name: "zero is not a disable value", raw: "0",
			message: "invalid MAX_SCAN_ENTRIES, using default", attrKey: "default", attrWant: "10000",
		},
		{
			name: "excessive value is clamped", raw: "200001",
			message: "MAX_SCAN_ENTRIES too large, clamping", attrKey: "max_entries", attrWant: "200000",
		},
		// Both WARNs quote the value as CONFIGURED, untrimmed: a value that is
		// unusable only because of a stray space or newline looks correct in the
		// log once it is trimmed, and nothing else reports the difference.
		{
			name: "padded invalid value is quoted untrimmed", raw: " abc\t",
			message: "invalid MAX_SCAN_ENTRIES, using default", attrKey: "default", attrWant: "10000",
		},
		{
			name: "padded excessive value is quoted untrimmed", raw: " 200001 ",
			message: "MAX_SCAN_ENTRIES too large, clamping", attrKey: "max_entries", attrWant: "200000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("MAX_SCAN_ENTRIES", tc.raw)

			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil: an unusable MAX_SCAN_ENTRIES is repaired, not a startup refusal", err)
			}
			if n := logs.CountLevel(slog.LevelWarn, tc.message); n != 1 {
				t.Errorf("Load() with MAX_SCAN_ENTRIES=%q logged %d WARN records matching %q, want exactly 1 (logs %v)",
					tc.raw, n, tc.message, logs.Messages())
			}
			if n := logs.CountExact(tc.message); n != 1 {
				t.Errorf("Load() with MAX_SCAN_ENTRIES=%q logged %d records with the exact message %q, want 1 (logs %v)",
					tc.raw, n, tc.message, logs.Messages())
			}
			if !logs.AttrContains(tc.message, "value", tc.raw) {
				t.Errorf("Load() with MAX_SCAN_ENTRIES=%q WARN does not name the rejected value (logs %v)",
					tc.raw, logs.Messages())
			}
			if !logs.HasAttr(tc.message, tc.attrKey, tc.attrWant) {
				t.Errorf("Load() with MAX_SCAN_ENTRIES=%q WARN %q = %q, want %q=%q (logs %v)",
					tc.raw, tc.attrKey, mustAttr(t, logs, tc.message, tc.attrKey), tc.attrKey, tc.attrWant, logs.Messages())
			}
			// The value the scanner will use must agree with the record that
			// explains the repair, or the log describes a budget nothing enforces.
			wantLimit, _, _ := maxScanEntriesFromEnv()
			if cfg.MaxScanEntries != wantLimit {
				t.Errorf("Load().MaxScanEntries = %d, want %d", cfg.MaxScanEntries, wantLimit)
			}
		})
	}
}

// TestLoad_scan_entry_default_warn_names_the_accepted_range pins the one attribute
// that answers the question an operator who wrote MAX_SCAN_ENTRIES=0 actually has:
// the WARN's "expected" text states the usable range AND that no value disables the
// budget. The sibling PFX_ENCODER and OUTPUT_LIFECYCLE warnings both have their
// "expected" attribute pinned; this one did not, so dropping it would leave the
// operator with a rejected value, a substituted default, and nothing saying that
// "0"/"false" are not opt-outs here. Serial: it mutates env and slog.Default.
func TestLoad_scan_entry_default_warn_names_the_accepted_range(t *testing.T) {
	isolatePasswordFile(t)
	t.Setenv("PFX_PASSWORD", "pw")
	t.Setenv("MAX_SCAN_ENTRIES", "0")

	logs := capture.Default(t)

	if _, err := Load(); err != nil {
		t.Fatalf("Load() = %v, want nil: an unusable MAX_SCAN_ENTRIES is repaired, not a startup refusal", err)
	}
	const msg = "invalid MAX_SCAN_ENTRIES, using default"
	const want = "a whole number of entries between 1 and 200000 (there is no value that disables the budget)"
	if !logs.HasAttr(msg, "expected", want) {
		t.Errorf("Load() with MAX_SCAN_ENTRIES=0 WARN expected = %q, want %q: nothing else tells an operator that no value disables the budget (logs %v)",
			mustAttr(t, logs, msg, "expected"), want, logs.Messages())
	}
}

// TestLoad_does_not_repair_a_usable_scan_entry_budget keeps the invalid-value and
// clamp diagnostics off accepted values: an operator running the default, or an
// explicit in-range budget, must see no record about MAX_SCAN_ENTRIES at all.
func TestLoad_does_not_repair_a_usable_scan_entry_budget(t *testing.T) {
	for _, raw := range []string{"", "   ", "1", "5000", "  5000 ", "200000"} {
		t.Run(raw, func(t *testing.T) {
			isolatePasswordFile(t)
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("MAX_SCAN_ENTRIES", raw)

			logs := capture.Default(t)

			if _, err := Load(); err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}

			for _, unwanted := range []string{
				"invalid MAX_SCAN_ENTRIES, using default",
				"MAX_SCAN_ENTRIES too large, clamping",
			} {
				if n := logs.Count(unwanted); n != 0 {
					t.Errorf("Load() with MAX_SCAN_ENTRIES=%q logged %d records matching %q, want none (logs %v)",
						raw, n, unwanted, logs.Messages())
				}
			}
		})
	}
}

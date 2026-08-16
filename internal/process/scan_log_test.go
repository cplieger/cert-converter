package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
)

// TestLogScanOutcome_levels pins the level and message of the end-of-scan
// summary. The README's Loki alerts key on exactly these: a completed scan must
// emit "scan complete" at Info (its absence for 8h is the stall alert), a
// shutdown-cancelled walk must stay at Debug so a normal restart never pages,
// and any other abort must be a Warn an operator sees.
func TestLogScanOutcome_levels(t *testing.T) {
	result := ScanResult{Total: 2, Converted: 1, Unchanged: 1}
	tests := []struct {
		walkErr   error
		name      string
		wantMsg   string
		wantLevel slog.Level
	}{
		{nil, "completed walk logs scan complete at info", "scan complete", slog.LevelInfo},
		{context.Canceled, "cancelled walk logs at debug", "scan cancelled during shutdown", slog.LevelDebug},
		{context.DeadlineExceeded, "deadline exceeded logs at debug", "scan cancelled during shutdown", slog.LevelDebug},
		{errors.New("permission denied"), "other abort logs at warn", "scan aborted before completion", slog.LevelWarn},
		{
			fmt.Errorf("%w: stopped at 3 entries (a.crt)", errScanBudgetExceeded),
			"entry-budget abort logs its own summary at warn", scanBudgetSummaryMsg, slog.LevelWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			logScanOutcome(t.Context(), &result, tt.walkErr)

			// CountExact, not a substring: these messages are pinned by the README's
			// Loki rules, so a superstring must not satisfy them.
			if got := logs.CountExact(tt.wantMsg); got != 1 {
				t.Errorf("logScanOutcome(walkErr=%v) logged %q, want message %q", tt.walkErr, logs.Messages(), tt.wantMsg)
			}
			if got := logs.CountLevel(tt.wantLevel, tt.wantMsg); got != 1 {
				t.Errorf("logScanOutcome(walkErr=%v) logged %q at %s %d times, want 1", tt.walkErr, tt.wantMsg, tt.wantLevel, got)
			}
			if !logs.HasAttr(tt.wantMsg, "converted", "1") {
				got, _ := logs.AttrValue(tt.wantMsg, "converted")
				t.Errorf("logScanOutcome(walkErr=%v) logged converted=%q, want the converted count in the summary", tt.walkErr, got)
			}
		})
	}
}

// TestFailEntry_levels pins the per-entry failure level split: a failure
// caused by shutdown stays at Debug, so stopping the container never emits an
// operator-facing error line, while every real conversion failure is an Error
// the log-based alerting can act on. Both cases keep the cert's relative path.
func TestFailEntry_levels(t *testing.T) {
	tests := []struct {
		err       error
		name      string
		wantMsg   string
		wantLevel slog.Level
	}{
		{errors.New("permission denied"), "real failure logs at error", "conversion failed", slog.LevelError},
		{context.Canceled, "cancellation logs at debug", "conversion failed (shutdown)", slog.LevelDebug},
		{context.DeadlineExceeded, "deadline exceeded logs at debug", "conversion failed (shutdown)", slog.LevelDebug},
		{errors.Join(errors.New("read certificate"), context.Canceled), "wrapped cancellation logs at debug", "conversion failed (shutdown)", slog.LevelDebug},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			if got := failEntry("example.com/tls.crt", "conversion failed", tt.err); got != statusFailed {
				t.Errorf("failEntry(%v) = %v, want statusFailed", tt.err, got)
			}

			// CountExact: the shutdown variant is a SUPERSTRING of the plain message, so
			// a substring check would let the wrong one pass for the real-failure case.
			if got := logs.CountExact(tt.wantMsg); got != 1 {
				t.Errorf("failEntry(%v) logged %q, want %s", tt.err, logs.Messages(), tt.wantMsg)
			}
			if got := logs.CountLevel(tt.wantLevel, tt.wantMsg); got != 1 {
				t.Errorf("failEntry(%v) logged %q at %s %d times, want 1", tt.err, tt.wantMsg, tt.wantLevel, got)
			}
			if !logs.HasAttr(tt.wantMsg, "path", "example.com/tls.crt") {
				t.Errorf("failEntry(%v) logged %q, want the cert's relative path", tt.err, logs.Messages())
			}
		})
	}
}

// TestReadPair_distinguishes_a_missing_key_from_an_unstattable_one pins the
// diagnosability split in readPair. Both outcomes are health-neutral, so neither
// flips the container unhealthy -- but they are DIFFERENT
// conditions and must not be reported as the same one.
//
// A cert with no sibling key at all is a genuine orphan: the normal, quiet steady
// state, Debug. A sibling key that exists but cannot be stat-ed through the confined
// root (a symlink escaping /input, or a permission error) is statusUnreadable and Warn:
// the key IS there, so calling it an orphan misdescribes it in the scan summary and in
// the all-orphan diagnostic, and Warn is what makes the broken layout diagnosable
// instead of hidden behind LOG_LEVEL=debug. Runs serially: it
// swaps slog.Default().
//
// The observation log is EMPTY here, which is the condition that makes the orphan arm
// the right reading: nothing in this process has ever read either pair whole, so there
// is no evidence any of these keys was ever there, and noteMissingKey's transient arm
// must not be reached. TestReadPair_separates_a_key_that_vanished_from_a_key_that_was_never_there
// pins the other side of that split.
func TestReadPair_distinguishes_a_missing_key_from_an_unstattable_one(t *testing.T) {
	base := t.TempDir()
	input := filepath.Join(base, "input")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{input, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "real.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lonely.crt", "escape.crt"} {
		if err := os.WriteFile(filepath.Join(input, name), []byte("pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A sibling key that exists but escapes the input root: the confined Stat
	// refuses it with a non-ENOENT error, which is not a genuine "no key".
	if err := os.Symlink(filepath.Join(outside, "real.key"), filepath.Join(input, "escape.key")); err != nil {
		t.Fatal(err)
	}
	inHandle, err := os.OpenRoot(input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inHandle.Close() })
	sw := &scanWalk{src: &source{root: inHandle}, observations: newObservationLog(0)}

	for _, tt := range []struct {
		certRel, keyRel, wantMsg string
		wantLevel                slog.Level
		wantOutcome              conversionStatus
	}{
		{"lonely.crt", "lonely.key", "skipping cert without matching key", slog.LevelDebug, statusOrphan},
		{"escape.crt", "escape.key", "skipping cert: cannot stat sibling key", slog.LevelWarn, statusUnreadable},
	} {
		// A fresh recorder per case, replacing the buffer reset the text handler needed.
		logs := captureLogs(t)

		_, outcome := sw.readPair(t.Context(), tt.certRel, tt.keyRel)

		if outcome == statusUnset {
			t.Errorf("readPair(%q) outcome = statusUnset, want a failure outcome (an unusable sibling key is never a readable pair)", tt.certRel)
		}
		if outcome != tt.wantOutcome {
			t.Errorf("readPair(%q) outcome = %d, want %d", tt.certRel, outcome, tt.wantOutcome)
		}
		if outcome == statusFailed {
			t.Errorf("readPair(%q) outcome flips health; neither condition is clearable by a restart", tt.certRel)
		}
		if got := logs.CountLevel(tt.wantLevel, tt.wantMsg); got != 1 {
			t.Errorf("readPair(%q) logged %q, want message %q at %s", tt.certRel, logs.Messages(), tt.wantMsg, tt.wantLevel)
		}
	}
}

// TestLogScanOutcome_flags_an_input_tree_with_no_certificate_pairs pins the
// empty-input notice the README documents (a certbot-style directory of
// fullchain.pem/privkey.pem "produces no output and logs `no certificate pairs
// found under the input root`"). A completed scan that visited no .crt is
// indistinguishable from a healthy steady state in the summary counts -- failed
// is 0, so the marker stays set and none of the README's Loki rules fire -- so
// this line is the only signal of a wrong or vanished /input mount. It must fire
// for exactly that shape: a scan that converted a pair, one whose empty result
// is already explained by an unreadable sub-path, and an aborted scan must all
// stay quiet, or the notice becomes noise on every fsnotify event and every
// fallback tick. Runs serially: it swaps slog.Default().
func TestLogScanOutcome_flags_an_input_tree_with_no_certificate_pairs(t *testing.T) {
	const wantMsg = "no certificate pairs found under the input root"
	tests := []struct {
		walkErr  error
		name     string
		result   ScanResult
		wantWarn bool
	}{
		{nil, "an empty input tree is named", ScanResult{}, true},
		{nil, "a scan that converted a pair stays quiet", ScanResult{Total: 1, Converted: 1}, false},
		{nil, "an unreadable sub-path already explains the empty result", ScanResult{Unreadable: 1}, false},
		// An unresolved input symlink hides part of the tree, so "no certificate
		// pairs" is not a claim this scan can make. The symlink WARN one flow
		// earlier already carries the correct diagnosis; repeating it here fires
		// the README's CertConverterNoCertificatePairs alert with the wrong one.
		{nil, "an unresolved symlink already explains the empty result", ScanResult{Unresolved: 1}, false},
		{errors.New("permission denied"), "an aborted scan stays quiet", ScanResult{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			logScanOutcome(t.Context(), &tt.result, tt.walkErr)

			if got := logs.Contains(wantMsg); got != tt.wantWarn {
				t.Errorf("logScanOutcome(%+v, %v) logged %q; empty-input notice present = %v, want %v",
					tt.result, tt.walkErr, logs.Messages(), got, tt.wantWarn)
			}
			if tt.wantWarn && logs.CountLevel(slog.LevelWarn, wantMsg) != 1 {
				t.Errorf("logScanOutcome(%+v, nil) logged %q, want the empty-input notice at level WARN", tt.result, logs.Messages())
			}
		})
	}
}

// TestLogScanOutcome_flags_an_input_tree_whose_certs_all_lack_a_key pins the
// all-orphan notice: a scan that visited certs but converted nothing because
// every .crt lacks its sibling .key reports failed=0, so the health marker
// stays set and the per-cert reason is Debug-only -- this WARN is the only
// default-level evidence of the naming misconfiguration. It must fire for
// exactly that shape and stay quiet otherwise, or it becomes noise on every
// fsnotify event and every fallback tick. An incomplete enumeration
// (Unreadable > 0) must stay quiet too: Run continues past an unreadable
// sub-path, so "every certificate" is unproven — the unreadable-path WARN carries the
// actionable diagnosis, and the per-path "some certificates" notice names the missing
// keys this scan did observe. Runs serially: it swaps
// slog.Default().
func TestLogScanOutcome_flags_an_input_tree_whose_certs_all_lack_a_key(t *testing.T) {
	const wantMsg = "every certificate under the input root is missing its sibling .key"
	tests := []struct {
		walkErr  error
		name     string
		result   ScanResult
		wantWarn bool
	}{
		{nil, "an all-orphan tree is named", ScanResult{Total: 2, Orphan: 2}, true},
		{nil, "an all-orphan tree with an unreadable sub-path stays quiet", ScanResult{Total: 1, Orphan: 1, Unreadable: 1}, false},
		{nil, "a partially converted tree stays quiet", ScanResult{Total: 2, Converted: 1, Orphan: 1}, false},
		{nil, "an empty tree stays quiet (the Total==0 notice owns it)", ScanResult{}, false},
		{errors.New("permission denied"), "an aborted scan stays quiet", ScanResult{Total: 2, Orphan: 2}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			logScanOutcome(t.Context(), &tt.result, tt.walkErr)

			if got := logs.Contains(wantMsg); got != tt.wantWarn {
				t.Errorf("logScanOutcome(%+v, %v) logged %q; all-orphan notice present = %v, want %v",
					tt.result, tt.walkErr, logs.Messages(), got, tt.wantWarn)
			}
			if tt.wantWarn && logs.CountLevel(slog.LevelWarn, wantMsg) != 1 {
				t.Errorf("logScanOutcome(%+v, nil) logged %q, want the all-orphan notice at level WARN", tt.result, logs.Messages())
			}
		})
	}
}

// TestLogConversionObservations_levels pins this package's mapping from
// convert.ObservationClass onto log levels, one case per class: a duplicate-block
// artefact is Quiet and stays at Debug, a chain that stops at an absent trust anchor
// is Info (a true fact about the documented Caddy fullchain shape, with nothing for
// the operator to do) and reaches INFO, and everything the operator probably did not
// intend is Warning and must reach WARN.
//
// The Info case is the one a regression collapses: the old boolean classification had
// no room for it, so it was reported as a problem — a WARN on every conversion of a
// perfectly normal fullchain. Inverting the other two would either bury a reordered
// bundle, a multi-key file or an expired identity under LOG_LEVEL=debug, or WARN on
// every conversion of a bundle whose only oddity is a repeated certificate. Runs
// serially: it swaps slog.Default().
func TestLogConversionObservations_levels(t *testing.T) {
	for _, tc := range []struct {
		kind      convert.ObservationKind
		wantLevel slog.Level
	}{
		{convert.ObsDuplicateCerts, slog.LevelDebug},
		// The expected shape of a Caddy/ACME fullchain: named so it is not invisible,
		// deliberately not as a problem.
		{convert.ObsChainTrustAnchorAbsent, slog.LevelInfo},
		{convert.ObsLeafNotFirst, slog.LevelWarn},
		{convert.ObsMultipleKeys, slog.LevelWarn},
		{convert.ObsIdentityExpired, slog.LevelWarn},
		{convert.ObsChainUnverified, slog.LevelWarn},
		// A non-compliant CA is carried in the bundle rather than dropped, so this
		// WARN is the only thing that tells the operator a strict consumer will
		// reject the chain. Classifying it as noise would make that silent.
		{convert.ObsChainCertCannotIssue, slog.LevelWarn},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			logs := captureLogs(t)
			logConversionObservations("example.com/tls.crt", []convert.Observation{
				{Kind: tc.kind, Detail: "detail text"},
			})
			const msg = "cert input observation"
			if !logs.Contains(msg) {
				t.Fatalf("logConversionObservations(%s) logged %q, want a record", tc.kind, logs.Messages())
			}
			if got := logs.CountLevel(tc.wantLevel, msg); got != 1 {
				t.Errorf("logConversionObservations(%s) logged at %s %d times, want 1: %q", tc.kind, tc.wantLevel, got, logs.Messages())
			}
			// Keyed attributes: the kind must be the `kind` attribute, not text that
			// happens to appear in the detail or the path.
			for key, want := range map[string]string{"kind": string(tc.kind), "path": "example.com/tls.crt"} {
				if !logs.HasAttr(msg, key, want) {
					got, _ := logs.AttrValue(msg, key)
					t.Errorf("logConversionObservations(%s) logged %s=%q, want %q", tc.kind, key, got, want)
				}
			}
			if !logs.AttrContains(msg, "detail", "detail") {
				t.Errorf("logConversionObservations(%s) carries no detail attribute", tc.kind)
			}
		})
	}
}

// TestLogConversionObservations_is_silent_without_observations pins the steady
// state: a clean pair converts without a single observation line. This runs on
// every conversion, so a guard that logged an empty summary would add a line per
// cert per renewal. Runs serially: it swaps slog.Default().
func TestLogConversionObservations_is_silent_without_observations(t *testing.T) {
	logs := captureLogs(t)
	logConversionObservations("example.com/tls.crt", nil)
	if logs.Len() != 0 {
		t.Errorf("logConversionObservations(no observations) logged %q, want no output at all", logs.Messages())
	}
}

// TestNoteUnreadableInput_levels pins the benign-race half of the unreadable-input
// notice, which the escaping-symlink tests only exercise from the Warn side. A
// file that vanished between readdir and the read is a normal renewal race — the
// next scan converts the replacement — so it stays at Debug, carries no
// remediation hint, and is classified statusVanished rather than statusUnreadable.
// Promoting either would put an operator-facing warning, pointing at /input
// permissions, into the log (or into the alerted unreadable count) every time a
// certificate is atomically replaced.
//
// ENOENT alone does not make it that race, which is the other half pinned here: a
// symlink that is STILL THERE pointing at a missing target returns the same ENOENT
// on every scan for as long as it exists, so it is the steady-state arm — Warn, the
// remediation hint, and the alerted unreadable count — not the transient one. Reading
// it as a race left such a certificate producing no PFX indefinitely with no
// default-level signal anywhere. Runs serially: it swaps slog.Default().
func TestNoteUnreadableInput_levels(t *testing.T) {
	const logRel = "example.com/tls.crt"
	for _, tc := range []struct {
		err        error
		name       string
		what       string
		inputRel   string
		setup      func(t *testing.T, dir string)
		wantMsg    string
		wantLevel  slog.Level
		wantStatus conversionStatus
	}{
		{
			err: fs.ErrNotExist, name: "a vanished certificate is a benign race", what: "certificate",
			inputRel: "tls.crt", wantMsg: "certificate vanished during the scan",
			wantLevel: slog.LevelDebug, wantStatus: statusVanished,
		},
		{
			err: fs.ErrNotExist, name: "a vanished key is a benign race", what: "private key",
			inputRel: "tls.key", wantMsg: "private key vanished during the scan",
			wantLevel: slog.LevelDebug, wantStatus: statusVanished,
		},
		{
			err: fs.ErrNotExist, name: "a path replaced under the read is a benign race too", what: "certificate",
			inputRel: "tls.crt",
			setup: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("the replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantMsg: "certificate vanished during the scan", wantLevel: slog.LevelDebug, wantStatus: statusVanished,
		},
		{
			err: fs.ErrNotExist, name: "a surviving symlink to a missing target is steady-state, not a race", what: "certificate",
			inputRel: "tls.crt",
			setup: func(t *testing.T, dir string) {
				if err := os.Symlink("never-existed.pem", filepath.Join(dir, "tls.crt")); err != nil {
					t.Fatal(err)
				}
			},
			wantMsg: "cannot read certificate", wantLevel: slog.LevelWarn, wantStatus: statusUnreadable,
		},
		{
			err: errors.New("permission denied"), name: "an unreadable certificate warns", what: "certificate",
			inputRel: "tls.crt", wantMsg: "cannot read certificate",
			wantLevel: slog.LevelWarn, wantStatus: statusUnreadable,
		},
		{
			err: context.Canceled, name: "a cancelled read is the shutdown, not an unreadable path", what: "certificate",
			inputRel: "tls.crt", wantMsg: "certificate read interrupted by shutdown",
			wantLevel: slog.LevelDebug, wantStatus: statusUnreadable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			t.Cleanup(func() { _ = root.Close() })
			sw := &scanWalk{src: &source{root: root}}
			logs := captureLogs(t)

			if got := sw.noteUnreadableInput(logRel, tc.inputRel, tc.what, tc.err); got != tc.wantStatus {
				t.Errorf("noteUnreadableInput(%v) = %v, want %v: the diagnostic and the counted outcome must agree",
					tc.err, got, tc.wantStatus)
			}
			if got := logs.CountLevel(tc.wantLevel, tc.wantMsg); got != 1 {
				t.Fatalf("noteUnreadableInput(%v) logged %q, want %q at %s", tc.err, logs.Messages(), tc.wantMsg, tc.wantLevel)
			}
			if !logs.HasAttr(tc.wantMsg, "path", logRel) {
				t.Errorf("noteUnreadableInput(%v) logged %q, want the cert's relative path", tc.err, logs.Messages())
			}
			// The remediation hint belongs to the actionable arm only: on the benign
			// race there is nothing for the operator to do.
			_, hasHint := logs.AttrValue(tc.wantMsg, "remediation")
			if wantHint := tc.wantLevel == slog.LevelWarn; hasHint != wantHint {
				t.Errorf("noteUnreadableInput(%v) remediation hint present = %v, want %v: %q", tc.err, hasHint, wantHint, logs.Messages())
			}
		})
	}
}

// TestNoteUnreadableInput_names_the_published_unreachable_prefix pins the exact substring
// the README publishes as one of CertConverterInputPathUnreachable's four matchers,
// `skipping cert: cannot read`.
//
// The table above asserts the SUFFIX only ("cannot read certificate"), and every other
// assertion in this package compares a captured record against the production string
// itself -- so rewording the emitted message (to "cannot read the certificate for cert",
// say) keeps the whole suite green while the documented alert stops matching and an
// operator whose /input has become unreadable is never paged. The rule's other three
// matchers are each spelled out literally somewhere in the suite; this was the one that
// was not.
//
// Both `what` values are driven because the message is composed at the call site
// ("skipping cert: cannot read " + what) rather than held as a const, so the prefix is not
// pinned by any single string.
// Runs serially: it swaps slog.Default().
func TestNoteUnreadableInput_names_the_published_unreachable_prefix(t *testing.T) {
	const published = "skipping cert: cannot read"

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	sw := &scanWalk{src: &source{root: root}}

	for _, what := range []string{"certificate", "private key"} {
		logs := captureLogs(t)
		if got := sw.noteUnreadableInput("example.com/tls.crt", "tls.crt", what,
			errors.New("permission denied")); got != statusUnreadable {
			t.Fatalf("noteUnreadableInput(%s, permission denied) = %v, want statusUnreadable", what, got)
		}
		if got := logs.CountLevel(slog.LevelWarn, published); got != 1 {
			t.Errorf("noteUnreadableInput(%s, permission denied) logged %q at WARN %d times, want exactly"+
				" 1: the README publishes that substring as CertConverterInputPathUnreachable's matcher,"+
				" so rewording it silently stops the documented alert from ever firing again: %q",
				what, published, got, logs.Messages())
		}
	}
}

// TestLogScanOutcome_flags_an_input_tree_whose_certs_partially_lack_a_key pins the
// partial-orphan notice, the sibling of the all-orphan one above: when only SOME
// .crt files lack their .key, the pairs that do have a key still convert, so the
// scan reports failed=0 and the health marker stays set while those certificates
// produce no PFX and their existing bundles go stale unreaped. It must fire for
// exactly that shape and stay quiet when the all-orphan or empty-tree notice owns the
// case (they are earlier switch arms).
//
// The three enumeration vetoes do NOT silence it, and that is the contract this table
// pins after the 2026-07 decision: each coverage message is gated by the evidence IT
// needs. Every counted orphan is proven path by path (readPair stats the sibling
// through the confined root and only ENOENT becomes statusOrphan), so an unreadable
// path, an unresolved symlink or a renewal elsewhere in the tree cannot make an
// observed missing key unobserved. The previous shape required silence on all three
// and that stated defence is VOID: it suppressed a proven fact because of an unrelated
// hole, for as long as the hole stood. Only the whole-tree claims (empty tree, EVERY
// certificate) still need a complete enumeration — which is why the all-orphan shape
// with a veto present falls through to this notice rather than going silent.
//
// An aborted scan stays quiet — a walk that stopped for an arbitrary reason, or during
// shutdown, observed a prefix chosen by whatever stopped it. The ENTRY-BUDGET stop is
// the one exception, because it stopped on the tree's SIZE having read every path it
// visited: those counts are observations, so they are reported (with the coverage
// attribute) rather than silenced. TestLogScanOutcome_reports_observed_per_path_counts_when_the_entry_budget_stopped_the_scan
// owns that case in full.
// Runs serially: it swaps slog.Default().
func TestLogScanOutcome_flags_an_input_tree_whose_certs_partially_lack_a_key(t *testing.T) {
	const wantMsg = "some certificates under the input root are missing their sibling .key"
	for _, tt := range []struct {
		walkErr   error
		name      string
		result    ScanResult
		wantWarn  bool
		wantCount string
	}{
		{nil, "a partially orphaned tree is named", ScanResult{Total: 2, Converted: 1, Orphan: 1}, true, "1"},
		{nil, "an all-orphan tree stays quiet (the earlier arm owns it)", ScanResult{Total: 2, Orphan: 2}, false, ""},
		{nil, "an empty tree stays quiet (the Total==0 notice owns it)", ScanResult{}, false, ""},
		{nil, "a fully converted tree stays quiet", ScanResult{Total: 2, Converted: 2}, false, ""},
		{nil, "an unreadable sub-path does not silence a proven missing key", ScanResult{Total: 3, Converted: 1, Orphan: 1, Unreadable: 1}, true, "1"},
		{nil, "an unresolved symlink does not silence a proven missing key", ScanResult{Total: 2, Converted: 1, Orphan: 1, Unresolved: 1}, true, "1"},
		{nil, "a cert that vanished mid-scan does not silence a proven missing key", ScanResult{Total: 3, Converted: 1, Orphan: 1, Vanished: 1}, true, "1"},
		// "every certificate" is not provable here, but "some" still is, so the
		// unprovable arm hands the case to this one instead of the scan going silent.
		{nil, "an all-orphan tree with a veto falls through to the per-path notice", ScanResult{Total: 2, Orphan: 2, Unreadable: 1}, true, "2"},
		{errors.New("permission denied"), "an aborted scan stays quiet", ScanResult{Total: 2, Converted: 1, Orphan: 1}, false, ""},
		{context.Canceled, "a shutdown-cancelled scan stays quiet", ScanResult{Total: 2, Converted: 1, Orphan: 1}, false, ""},
		{
			fmt.Errorf("%w: stopped at 3 entries (a.crt)", errScanBudgetExceeded),
			"an entry-budget stop reports the missing keys it observed",
			ScanResult{Total: 2, Converted: 1, Orphan: 1},
			true, "1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			logScanOutcome(t.Context(), &tt.result, tt.walkErr)

			if got := logs.Contains(wantMsg); got != tt.wantWarn {
				t.Errorf("logScanOutcome(%+v, %v) logged %q; partial-orphan notice present = %v, want %v",
					tt.result, tt.walkErr, logs.Messages(), got, tt.wantWarn)
			}
			if !tt.wantWarn {
				return
			}
			if logs.CountLevel(slog.LevelWarn, wantMsg) != 1 {
				t.Errorf("logScanOutcome(%+v, nil) logged %q, want the partial-orphan notice at level WARN", tt.result, logs.Messages())
			}
			if !logs.HasAttr(wantMsg, "orphan", tt.wantCount) {
				got, _ := logs.AttrValue(wantMsg, "orphan")
				t.Errorf("logScanOutcome(%+v, nil) logged orphan=%q, want %q on the notice", tt.result, got, tt.wantCount)
			}
		})
	}
}

// TestLogScanOutcome_names_the_unresolved_symlink_count pins the summary's
// unresolved attribute. It is the ONLY aggregate trace of an input symlink the
// confined root could not resolve: the count is carried as its own ScanResult
// field, never folded into Unreadable, so without naming it here the summary
// reports an all-zero, apparently healthy scan while an unresolvable link hid an
// entire certificate subtree. Runs serially: it swaps slog.Default().
func TestLogScanOutcome_names_the_unresolved_symlink_count(t *testing.T) {
	logs := captureLogs(t)

	logScanOutcome(t.Context(), &ScanResult{Total: 1, Converted: 1, Unresolved: 2}, nil)

	if !logs.HasAttr("scan complete", "unresolved", "2") {
		got, _ := logs.AttrValue("scan complete", "unresolved")
		t.Errorf("logScanOutcome(unresolved=2) logged unresolved=%q, want the unresolved-symlink count in the summary", got)
	}
}

// TestLogScanOutcome_names_the_vanished_count pins the summary's vanished
// attribute. A cert replaced between readdir and the bounded read is counted in its
// own ScanResult field, deliberately never folded into Unreadable, so this attribute
// is the only aggregate trace that a scan ran while /input was being rewritten.
// Runs serially: it swaps slog.Default().
func TestLogScanOutcome_names_the_vanished_count(t *testing.T) {
	logs := captureLogs(t)

	logScanOutcome(t.Context(), &ScanResult{Total: 1, Vanished: 1}, nil)

	if !logs.HasAttr("scan complete", "vanished", "1") {
		got, _ := logs.AttrValue("scan complete", "vanished")
		t.Errorf("logScanOutcome(vanished=1) logged vanished=%q, want the renewal-race count in the summary", got)
	}
}

// TestScannerRun_an_unopenable_root_emits_the_scan_outcome_record pins the RECORD side
// of the two pre-walk hard errors, which nothing else in the suite reaches: an /input
// or /output root that cannot be opened at all must still emit the end-of-scan summary
// the README's CertConverterScanAborted rule matches, not only return an error to
// main. That is the whole reason both returns route through failScan rather than
// returning directly, and it is the one failure class that stops every renewal, so
// without this the wrapper can be dropped again with the suite green and the
// documented alert silent. Runs serially: it swaps slog.Default().
func TestScannerRun_an_unopenable_root_emits_the_scan_outcome_record(t *testing.T) {
	const aborted = "scan aborted before completion"
	for _, tc := range []struct {
		name      string
		breakCert bool
	}{
		{name: "input root", breakCert: true},
		{name: "output root", breakCert: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certsRoot, outRoot := t.TempDir(), t.TempDir()
			if tc.breakCert {
				certsRoot = filepath.Join(certsRoot, "never-created")
			} else {
				outRoot = filepath.Join(outRoot, "never-created")
			}
			logs := captureLogs(t)

			scanner := New(&Options{
				CertsRoot: certsRoot, OutRoot: outRoot,
				Password: "pw", Encoder: convert.EncNameModern2023,
			})
			if _, err := scanner.Run(t.Context()); err == nil {
				t.Fatalf("Run(unopenable %s) = nil error, want a hard error so health flips", tc.name)
			}
			if got := logs.CountLevel(slog.LevelWarn, aborted); got != 1 {
				t.Errorf("Run(unopenable %s) logged %q, want exactly one WARN %q: the documented scan-aborted alert never fires otherwise",
					tc.name, logs.Messages(), aborted)
			}
		})
	}
}

// TestLogScanOutcome_reports_observed_per_path_counts_when_the_entry_budget_stopped_the_scan
// pins the whole of the entry-budget exception, which is a narrow one in three separate
// directions.
//
// The condition it fixes: logInputCoverageWarnings used to return on ANY non-nil walk
// error, so a scan the budget truncated told the operator the tree was too large and
// nothing else. The certificates it HAD read that were unreadable, or missing their
// sibling .key, went unnamed — facts proven path by path, silenced by a stop that
// happened further along the tree.
//
// What must stay narrow, and is asserted below:
//   - Only the budget stop qualifies. A shutdown and an arbitrary walk failure stay
//     silent (the shutdown case is also pinned in the table above, deliberately
//     unweakened: emitting WARNs while the container stops is the failure this guards).
//   - Only the PER-PATH arms are reported. The whole-tree claims ("no certificate pairs
//     at all", "EVERY certificate lacks its key") stay gated on a complete walk, since a
//     truncated scan is precisely one that did not see the whole tree — the all-orphan
//     shape therefore falls through to the "some certificates" arm.
//
// This test fails when its subject is reverted. Checked by restoring the unconditional
// `if walkErr != nil { return }`: every assertion in the budget subtests then fails
// (both arms absent), while the shutdown and arbitrary-abort subtests keep passing —
// which is what shows the test pins the exception rather than the silence.
// Runs serially: it swaps slog.Default().
func TestLogScanOutcome_reports_observed_per_path_counts_when_the_entry_budget_stopped_the_scan(t *testing.T) {
	const (
		unreadableMsg = "some /input paths were unreadable and were skipped"
		orphanMsg     = "some certificates under the input root are missing their sibling .key"
		emptyTreeMsg  = "no certificate pairs found under the input root"
		allOrphanMsg  = "every certificate under the input root is missing its sibling .key"
	)
	budgetErr := fmt.Errorf("%w: stopped at 3 entries (a.crt)", errScanBudgetExceeded)

	for _, tt := range []struct {
		walkErr        error
		name           string
		result         ScanResult
		wantUnreadable bool
		wantOrphan     bool
	}{
		{
			budgetErr, "a budget stop reports both observed per-path counts",
			ScanResult{Total: 3, Converted: 1, Orphan: 1, Unreadable: 1},
			true, true,
		},
		{
			budgetErr, "a budget stop reports an observed unreadable path on its own",
			ScanResult{Total: 2, Converted: 2, Unreadable: 1},
			true, false,
		},
		{
			// The whole-tree "every certificate" claim is unprovable on a truncated scan,
			// so the case lands on the per-path arm instead of going silent — the same
			// fallthrough the enumeration vetoes already take.
			budgetErr, "an all-orphan budget stop falls through to the per-path arm",
			ScanResult{Total: 2, Orphan: 2},
			false, true,
		},
		{
			// Nothing was observed worth naming: the budget WARN is the whole signal.
			budgetErr, "a budget stop with nothing observed stays quiet",
			ScanResult{Total: 2, Converted: 2},
			false, false,
		},
		{
			context.Canceled, "a shutdown stays silent on both arms",
			ScanResult{Total: 3, Converted: 1, Orphan: 1, Unreadable: 1},
			false, false,
		},
		{
			errors.New("permission denied"), "an arbitrary walk failure stays silent on both arms",
			ScanResult{Total: 3, Converted: 1, Orphan: 1, Unreadable: 1},
			false, false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			logScanOutcome(t.Context(), &tt.result, tt.walkErr)

			if got := logs.Contains(unreadableMsg); got != tt.wantUnreadable {
				t.Errorf("logScanOutcome(%+v, %v) logged %q; unreadable notice present = %v, want %v",
					tt.result, tt.walkErr, logs.Messages(), got, tt.wantUnreadable)
			}
			if got := logs.Contains(orphanMsg); got != tt.wantOrphan {
				t.Errorf("logScanOutcome(%+v, %v) logged %q; missing-key notice present = %v, want %v",
					tt.result, tt.walkErr, logs.Messages(), got, tt.wantOrphan)
			}

			// The whole-tree claims must never appear on a truncated scan, whatever the
			// counts look like: this scan did not see the whole tree.
			for _, msg := range []string{emptyTreeMsg, allOrphanMsg} {
				if logs.Contains(msg) {
					t.Errorf("logScanOutcome(%+v, %v) logged the whole-tree claim %q: a scan that did not"+
						" complete cannot make it", tt.result, tt.walkErr, msg)
				}
			}

			// A reported count on a truncated scan is named once, at WARN.
			for _, c := range []struct {
				msg  string
				want bool
			}{{unreadableMsg, tt.wantUnreadable}, {orphanMsg, tt.wantOrphan}} {
				if !c.want {
					continue
				}
				if logs.CountLevel(slog.LevelWarn, c.msg) != 1 {
					t.Errorf("logScanOutcome(%+v, %v) did not log %q once at WARN", tt.result, tt.walkErr, c.msg)
				}
			}
		})
	}
}

package process

import (
	"context"
	"errors"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			logScanOutcome(t.Context(), result, 0, tt.walkErr)

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

// TestLogEntryFailure_levels pins the per-entry failure level split: a failure
// caused by shutdown stays at Debug, so stopping the container never emits an
// operator-facing error line, while every real conversion failure is an Error
// the log-based alerting can act on. Both cases keep the cert's relative path.
func TestLogEntryFailure_levels(t *testing.T) {
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

			logEntryFailure("example.com/tls.crt", "conversion failed", tt.err)

			// CountExact: the shutdown variant is a SUPERSTRING of the plain message, so
			// a substring check would let the wrong one pass for the real-failure case.
			if got := logs.CountExact(tt.wantMsg); got != 1 {
				t.Errorf("logEntryFailure(%v) logged %q, want %s", tt.err, logs.Messages(), tt.wantMsg)
			}
			if got := logs.CountLevel(tt.wantLevel, tt.wantMsg); got != 1 {
				t.Errorf("logEntryFailure(%v) logged %q at %s %d times, want 1", tt.err, tt.wantMsg, tt.wantLevel, got)
			}
			if !logs.HasAttr(tt.wantMsg, "path", "example.com/tls.crt") {
				t.Errorf("logEntryFailure(%v) logged %q, want the cert's relative path", tt.err, logs.Messages())
			}
		})
	}
}

// TestReadPair_distinguishes_a_missing_key_from_an_unstattable_one pins the
// diagnosability split in readPair. Both outcomes are the same health-neutral
// health-neutral, so neither flips the container unhealthy -- but they are DIFFERENT
// conditions and must not be reported as the same one.
//
// A cert with no sibling key at all is a genuine orphan: the normal, quiet steady
// state, Debug. A sibling key that exists but cannot be stat-ed through the confined
// root (a symlink escaping /input, or a permission error) is statusUnreadable and Warn:
// the key IS there, so calling it an orphan misdescribes it in the scan summary and in
// the all-orphan diagnostic, and Warn is what makes the broken layout diagnosable
// instead of hidden behind LOG_LEVEL=debug. Runs serially: it
// swaps slog.Default().
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
	sw := &scanWalk{src: &source{root: inHandle}}

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

		_, outcome, ok := sw.readPair(t.Context(), tt.certRel, tt.keyRel)

		if ok {
			t.Errorf("readPair(%q) ok = true, want false (an unusable sibling key is never a readable pair)", tt.certRel)
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
		walkErr    error
		name       string
		result     ScanResult
		unresolved int
		wantWarn   bool
	}{
		{nil, "an empty input tree is named", ScanResult{}, 0, true},
		{nil, "a scan that converted a pair stays quiet", ScanResult{Total: 1, Converted: 1}, 0, false},
		{nil, "an unreadable sub-path already explains the empty result", ScanResult{Unreadable: 1}, 0, false},
		// An unresolved input symlink hides part of the tree, so "no certificate
		// pairs" is not a claim this scan can make. The symlink WARN one flow
		// earlier already carries the correct diagnosis; repeating it here fires
		// the README's CertConverterNoCertificatePairs alert with the wrong one.
		{nil, "an unresolved symlink already explains the empty result", ScanResult{}, 1, false},
		{errors.New("permission denied"), "an aborted scan stays quiet", ScanResult{}, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			logScanOutcome(t.Context(), tt.result, tt.unresolved, tt.walkErr)

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
// sub-path, so "every certificate" is unproven and the unreadable-path WARN
// already carries the actionable diagnosis. Runs serially: it swaps
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

			logScanOutcome(t.Context(), tt.result, 0, tt.walkErr)

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

// TestLogConversionObservations_levels pins the one observation-reporting split
// this package makes: a duplicate-block artefact is noise and stays at Debug,
// while every other observation names something the operator probably did not
// intend and must reach the default level. Inverting it would either bury a
// reordered bundle, a multi-key file or an expired identity under
// LOG_LEVEL=debug, or WARN on every conversion of a bundle whose only oddity is a
// repeated certificate. Runs serially: it swaps slog.Default().
func TestLogConversionObservations_levels(t *testing.T) {
	for _, tc := range []struct {
		kind      convert.ObservationKind
		wantLevel slog.Level
	}{
		{convert.ObsDuplicateCerts, slog.LevelDebug},
		{convert.ObsLeafNotFirst, slog.LevelWarn},
		{convert.ObsMultipleKeys, slog.LevelWarn},
		{convert.ObsIdentityExpired, slog.LevelWarn},
		{convert.ObsChainUnverified, slog.LevelWarn},
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
// next scan converts the replacement — so it stays at Debug and carries no
// remediation hint. Promoting it would put an operator-facing warning, pointing at
// /input permissions, into the log every time a certificate is atomically
// replaced. Runs serially: it swaps slog.Default().
func TestNoteUnreadableInput_levels(t *testing.T) {
	for _, tc := range []struct {
		err       error
		name      string
		what      string
		wantMsg   string
		wantLevel slog.Level
	}{
		{fs.ErrNotExist, "a vanished certificate is a benign race", "certificate", "certificate vanished during the scan", slog.LevelDebug},
		{fs.ErrNotExist, "a vanished key is a benign race", "private key", "private key vanished during the scan", slog.LevelDebug},
		{errors.New("permission denied"), "an unreadable certificate warns", "certificate", "cannot read certificate", slog.LevelWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			noteUnreadableInput("example.com/tls.crt", tc.what, tc.err)
			if got := logs.CountLevel(tc.wantLevel, tc.wantMsg); got != 1 {
				t.Fatalf("noteUnreadableInput(%v) logged %q, want %q at %s", tc.err, logs.Messages(), tc.wantMsg, tc.wantLevel)
			}
			if !logs.HasAttr(tc.wantMsg, "path", "example.com/tls.crt") {
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

// TestLogScanOutcome_flags_an_input_tree_whose_certs_partially_lack_a_key pins the
// partial-orphan notice, the sibling of the all-orphan one above: when only SOME
// .crt files lack their .key, the pairs that do have a key still convert, so the
// scan reports failed=0 and the health marker stays set while those certificates
// produce no PFX and their existing bundles go stale unreaped. It must fire for
// exactly that shape, stay quiet when the all-orphan or empty-tree notice owns the
// case (they are earlier switch arms), and stay quiet on an unproven enumeration.
// Runs serially: it swaps slog.Default().
func TestLogScanOutcome_flags_an_input_tree_whose_certs_partially_lack_a_key(t *testing.T) {
	const wantMsg = "some certificates under the input root are missing their sibling .key"
	for _, tt := range []struct {
		walkErr    error
		name       string
		result     ScanResult
		unresolved int
		wantWarn   bool
	}{
		{nil, "a partially orphaned tree is named", ScanResult{Total: 2, Converted: 1, Orphan: 1}, 0, true},
		{nil, "an all-orphan tree stays quiet (the earlier arm owns it)", ScanResult{Total: 2, Orphan: 2}, 0, false},
		{nil, "an empty tree stays quiet (the Total==0 notice owns it)", ScanResult{}, 0, false},
		{nil, "a fully converted tree stays quiet", ScanResult{Total: 2, Converted: 2}, 0, false},
		{nil, "an unreadable sub-path stays quiet", ScanResult{Total: 3, Converted: 1, Orphan: 1, Unreadable: 1}, 0, false},
		{nil, "an unresolved symlink stays quiet", ScanResult{Total: 2, Converted: 1, Orphan: 1}, 1, false},
		{errors.New("permission denied"), "an aborted scan stays quiet", ScanResult{Total: 2, Converted: 1, Orphan: 1}, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)

			logScanOutcome(t.Context(), tt.result, tt.unresolved, tt.walkErr)

			if got := logs.Contains(wantMsg); got != tt.wantWarn {
				t.Errorf("logScanOutcome(%+v, unresolved=%d, %v) logged %q; partial-orphan notice present = %v, want %v",
					tt.result, tt.unresolved, tt.walkErr, logs.Messages(), got, tt.wantWarn)
			}
			if !tt.wantWarn {
				return
			}
			if logs.CountLevel(slog.LevelWarn, wantMsg) != 1 {
				t.Errorf("logScanOutcome(%+v, nil) logged %q, want the partial-orphan notice at level WARN", tt.result, logs.Messages())
			}
			if !logs.HasAttr(wantMsg, "orphan", "1") {
				t.Errorf("logScanOutcome(%+v, nil) logged %q, want the orphan count on the notice", tt.result, logs.Messages())
			}
		})
	}
}

// TestLogScanOutcome_names_the_unresolved_symlink_count pins the summary's
// unresolved attribute. It is the ONLY aggregate trace of an input symlink the
// confined root could not resolve: that count is deliberately not a ScanResult
// field, so without it the summary reports an all-zero, apparently healthy scan
// while an unresolvable link hid an entire certificate subtree. Runs serially: it
// swaps slog.Default().
func TestLogScanOutcome_names_the_unresolved_symlink_count(t *testing.T) {
	logs := captureLogs(t)

	logScanOutcome(t.Context(), ScanResult{Total: 1, Converted: 1}, 2, nil)

	if !logs.HasAttr("scan complete", "unresolved", "2") {
		got, _ := logs.AttrValue("scan complete", "unresolved")
		t.Errorf("logScanOutcome(unresolved=2) logged unresolved=%q, want the unresolved-symlink count in the summary", got)
	}
}

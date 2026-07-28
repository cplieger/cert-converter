package process

import (
	"crypto/sha256"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// missingKeyAggregate is logInputCoverageWarnings' partial-orphan line: the
// default-level diagnostic whose remediation tells the operator to RENAME their keys.
// It is the false alarm a mid-scan key replacement must not raise, and the signal a
// genuinely misnamed key must still raise, so both halves of this file assert on it.
const missingKeyAggregate = "some certificates under the input root are missing their sibling .key"

// vanishedKeyMsg is noteMissingKey's transient line, deliberately the same wording the
// bounded reads use for the same renewal window.
const vanishedKeyMsg = "skipping cert: private key vanished during the scan"

// TestReadPair_separates_a_key_that_vanished_from_a_key_that_was_never_there pins
// noteMissingKey's whole decision at the unit level: one ENOENT from the sibling-key
// stat, three readings.
//
// Without memory of the pair the key was never observed, so the answer must stay the
// steady-state orphan whose aggregate WARN names the rename remediation. With memory --
// this process read the pair whole on an earlier scan, so the key WAS there -- an
// absent key path is the renewal race and must be the transient statusVanished, which
// is Debug-only and keeps the orphan aggregate from firing. A surviving symlink at the
// key path is not a replacement at all (pathVanished says so), so it stays an orphan
// even with memory: the certbot live/ -> archive/ shape returns the same ENOENT on
// every scan forever, and calling it transient would silence it permanently.
//
// The last case is the safety property, and it is why the memory is spent rather than
// kept: a key that is still gone on the NEXT scan has no memory behind it and reads as
// the genuine orphan again, so a key deleted for good is quiet for exactly one scan.
// Runs serially: it swaps slog.Default().
func TestReadPair_separates_a_key_that_vanished_from_a_key_that_was_never_there(t *testing.T) {
	input := t.TempDir()
	for _, name := range []string{"fresh.crt", "renewed.crt", "linked.crt"} {
		if err := os.WriteFile(filepath.Join(input, name), []byte("pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A key path that still EXISTS as a symlink whose target does not: the confined
	// Stat reports ENOENT exactly like an absent key, and this is the steady state.
	if err := os.Symlink("nowhere.key", filepath.Join(input, "linked.key")); err != nil {
		t.Fatal(err)
	}
	inHandle, err := os.OpenRoot(input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inHandle.Close() })

	sw := &scanWalk{src: &source{root: inHandle}, observations: newObservationLog()}
	// "renewed.crt" and "linked.crt" were read whole by an earlier scan of this
	// process; "fresh.crt" never was. record is the same call convertEntry makes on
	// its success path, which is what makes the presence of an entry mean "this pair's
	// key was there".
	for _, remembered := range []string{"renewed.crt", "linked.crt"} {
		sw.observations.record(remembered, sha256.Sum256([]byte(remembered)), nil)
	}

	for _, tc := range []struct {
		certRel, keyRel, wantMsg string
		wantOutcome              conversionStatus
	}{
		{"fresh.crt", "fresh.key", "skipping cert without matching key", statusOrphan},
		{"renewed.crt", "renewed.key", vanishedKeyMsg, statusVanished},
		{"linked.crt", "linked.key", "skipping cert without matching key", statusOrphan},
		// The same pair as the second case, one scan later, with its memory spent.
		{"renewed.crt", "renewed.key", "skipping cert without matching key", statusOrphan},
	} {
		logs := captureLogs(t)

		_, outcome := sw.readPair(t.Context(), tc.certRel, tc.keyRel)

		if outcome != tc.wantOutcome {
			t.Errorf("readPair(%q) outcome = %d, want %d", tc.certRel, outcome, tc.wantOutcome)
		}
		if outcome == statusFailed || outcome == statusUnreadable {
			t.Errorf("readPair(%q) outcome = %d: a key that is simply not there is neither a conversion failure nor an unreadable path",
				tc.certRel, outcome)
		}
		if got := logs.CountLevel(slog.LevelDebug, tc.wantMsg); got != 1 {
			t.Errorf("readPair(%q) logged %q, want %q once at DEBUG", tc.certRel, logs.Messages(), tc.wantMsg)
		}
		if got := logs.CountLevel(slog.LevelWarn, ""); got != 0 {
			t.Errorf("readPair(%q) logged %d WARN records (%q); a missing key is never operator-actionable at the per-path level",
				tc.certRel, got, logs.Messages())
		}
	}
}

// TestScannerRun_reports_a_key_replaced_mid_scan_as_transient_then_names_a_key_that_stays_gone
// is the operator-facing half, end to end through Scanner.Run: what the two cases look
// like in the log and in the counts.
//
// A key that disappears from a pair this process has already converted is the renewal
// window this daemon exists to process. That scan must count it in Vanished (not
// Orphan, not Unreadable), keep the per-path line at Debug, and emit NO default-level
// missing-key aggregate -- the aggregate's remediation tells the operator to rename
// their keys, which is wrong for a file that is being rewritten correctly.
//
// A key that is still gone on the next scan is a genuine misnaming, and it must be
// named at WARN with that rename remediation: an input tree whose keys are misnamed is
// the steady state the aggregate was written for, and this fix must not make it quiet.
//
// Reaping safety is asserted on both scans under OUTPUT_LIFECYCLE=sync, where a reap
// really can delete: the pair's own bundle is never an orphan candidate in either case,
// because visit records the .crt in `seen` before dispatching it. The second pair is
// there to keep Orphan < Total, so the arm under test is the partial-orphan one rather
// than the all-orphan notice a single-pair tree would produce. Runs serially: it swaps
// slog.Default().
func TestScannerRun_reports_a_key_replaced_mid_scan_as_transient_then_names_a_key_that_stays_gone(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	for _, name := range []string{"renewing", "stable"} {
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, name+".example.com", "ecdsa")
		if err := os.WriteFile(filepath.Join(certsRoot, name+".crt"), certPEM, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(certsRoot, name+".key"), keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
		Lifecycle: outputpolicy.LifecycleSync,
	})
	bundle := filepath.Join(outRoot, "renewing.pfx")

	res1, err := scanner.Run(t.Context())
	if err != nil || res1.Converted != 2 {
		t.Fatalf("initial Run = %+v, %v, want Converted 2 and nil", res1, err)
	}

	// The renewal window: the key is gone while the cert is still there.
	if err := os.Remove(filepath.Join(certsRoot, "renewing.key")); err != nil {
		t.Fatal(err)
	}

	logs := captureLogs(t)
	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(key gone from a converted pair) = %v, want nil", err)
	}
	if res2.Vanished != 1 || res2.Orphan != 0 || res2.Unreadable != 0 || res2.Failed != 0 {
		t.Errorf("Run(key gone from a converted pair) = %+v, want Vanished 1 Orphan 0 Unreadable 0 Failed 0: a key replaced mid-scan is the transient race, not a misnamed key and not an unreadable path",
			res2)
	}
	if got := logs.CountLevel(slog.LevelDebug, vanishedKeyMsg); got != 1 {
		t.Errorf("Run(key gone from a converted pair) logged %q, want %q once at DEBUG", logs.Messages(), vanishedKeyMsg)
	}
	if logs.Contains(missingKeyAggregate) {
		t.Errorf("Run(key gone from a converted pair) logged %q, want no missing-key aggregate: its remediation tells the operator to rename keys that are correct",
			logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelWarn, ""); got != 0 {
		t.Errorf("Run(key gone from a converted pair) logged %d WARN records (%q), want none at the default level", got, logs.Messages())
	}
	if _, statErr := os.Stat(bundle); statErr != nil {
		t.Errorf("os.Stat(%q) = %v after the transient scan, want the bundle left in place: its certificate is still under /input, so it is never an orphan candidate",
			bundle, statErr)
	}

	// One scan later the key is still gone, so this is not a renewal: it is a key that
	// is not named <name>.key, and the operator has to be told.
	logs = captureLogs(t)
	res3, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(key still gone) = %v, want nil", err)
	}
	if res3.Orphan != 1 || res3.Vanished != 0 {
		t.Errorf("Run(key still gone) = %+v, want Orphan 1 Vanished 0: a key that does not come back is a genuine missing key", res3)
	}
	if got := logs.CountLevel(slog.LevelWarn, missingKeyAggregate); got != 1 {
		t.Errorf("Run(key still gone) logged %q, want %q once at WARN", logs.Messages(), missingKeyAggregate)
	}
	if !logs.AttrContains(missingKeyAggregate, "remediation", "name each private key <name>.key") {
		t.Errorf("Run(key still gone) logged %q without the rename remediation on the aggregate: the operator has to be told what to fix", logs.Messages())
	}
	if _, statErr := os.Stat(bundle); statErr != nil {
		t.Errorf("os.Stat(%q) = %v after the orphan scan, want the bundle left in place: an orphaned .crt is still recorded as seen, so its bundle is not an orphan candidate",
			bundle, statErr)
	}
}

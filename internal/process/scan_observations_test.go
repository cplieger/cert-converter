package process

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/slogx/capture"
)

// TestScannerRun_reports_a_new_input_observation_once_on_an_unchanged_output pins
// the split between the two questions a scan answers about a pair: whether the PFX
// on disk needs rewriting (output-derived currency) and whether the INPUT bytes
// changed enough to deserve a fresh diagnostic (the raw input fingerprint).
//
// A semantically equivalent edit — here a chain reordered root-first, with the same
// selected leaf, key and chain set — must NOT rewrite the bundle (that would churn
// its mtime and re-replicate it downstream) yet must still name the new input
// condition exactly ONCE. Suppressing it entirely leaves the operator with no signal
// that the file they just edited is malformed; logging it unconditionally re-emits a
// WARN on every fsnotify event and every fallback tick for the life of the
// deployment.
//
// Serial, not parallel: captureLogs swaps the process-global slog.Default().
func TestScannerRun_reports_a_new_input_observation_once_on_an_unchanged_output(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	leafPEM, keyPEM, caPEM, chainPEM := testcerts.GenerateCertChain(t)
	crtPath := filepath.Join(certsRoot, "chain.crt")
	if err := os.WriteFile(crtPath, chainPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "chain.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	})

	res1, err := scanner.Run(t.Context())
	if err != nil || res1.Converted != 1 {
		t.Fatalf("initial Run = %+v, %v, want Converted 1 and nil", res1, err)
	}
	pfxPath := filepath.Join(outRoot, "chain.pfx")
	before, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx after the first conversion: %v", err)
	}

	// Reorder the SAME certificates root-first. The selected leaf, its key and the
	// chain set are unchanged, so the bundle on disk stays correct.
	rootFirst := make([]byte, 0, len(caPEM)+len(leafPEM))
	rootFirst = append(rootFirst, caPEM...)
	rootFirst = append(rootFirst, leafPEM...)
	if err := os.WriteFile(crtPath, rootFirst, 0o644); err != nil {
		t.Fatal(err)
	}

	logs := captureLogs(t)
	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("post-reorder Run = %v, want nil", err)
	}
	if res2.Unchanged != 1 || res2.Converted != 0 {
		t.Errorf("post-reorder Run = %+v, want Unchanged 1 Converted 0: the pfx on disk is still the right bundle", res2)
	}
	if got := countObservation(logs, convert.ObsLeafNotFirst); got != 1 {
		t.Errorf("post-reorder Run logged %d leaf-not-first observations, want exactly 1: a new input condition must be named once", got)
	}
	after, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx after the reorder: %v", err)
	}
	if string(before) != string(after) {
		t.Error("the pfx was rewritten for a semantically identical reorder; want it left alone")
	}

	// A third scan over the SAME bytes must stay silent: the condition was already
	// reported, and repeating it on every scan is the log noise this gate prevents.
	// A fresh recorder replaces the buffer reset the text handler needed.
	logs = captureLogs(t)
	res3, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("steady-state Run = %v, want nil", err)
	}
	if res3.Unchanged != 1 {
		t.Errorf("steady-state Run = %+v, want Unchanged 1", res3)
	}
	if got := countObservation(logs, convert.ObsLeafNotFirst); got != 0 {
		t.Errorf("steady-state Run logged %d leaf-not-first observations, want 0: an already-reported input condition must not re-emit", got)
	}
}

// countObservation counts the cert-input-observation records of the given kind in the
// captured slog records, keyed on the `kind` ATTRIBUTE rather than on a rendered
// substring, so an observation kind that appears in some other attribute (a detail
// string, a path) cannot be miscounted.
func countObservation(logs *capture.Recorder, kind convert.ObservationKind) int {
	n := 0
	for _, r := range logs.Records() {
		if r.Message != "cert input observation" {
			continue
		}
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "kind" && a.Value.String() == string(kind) {
				n++
				return false
			}
			return true
		})
	}
	return n
}

// TestScannerRun_keeps_observation_state_across_an_incomplete_enumeration pins the
// gate on Run's observation-state prune, which forget's own doc comment names but
// no test exercises: the prune may only run when the walk proved the enumeration
// COMPLETE.
//
// Without the gate, a scan that could not see the whole input tree -- here an
// input symlink the confined root refuses to resolve, the shape the certbot
// live/ -> archive/ layout produces -- forgets every pair it did not reach. The
// next clean scan then re-emits their input observations, so the odd-but-convertible
// bundle the operator was told about once is WARNed about again, which is exactly
// the per-scan noise observationLog exists to prevent.
//
// Runs serially: it swaps slog.Default().
func TestScannerRun_keeps_observation_state_across_an_incomplete_enumeration(t *testing.T) {
	base := t.TempDir()
	certsRoot := filepath.Join(base, "input")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{certsRoot, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	outRoot := t.TempDir()

	// Root-first, so the pair is convertible AND carries one observation: it is
	// that observation's re-emission that makes a lost memory visible.
	leafPEM, keyPEM, caPEM, _ := testcerts.GenerateCertChain(t)
	rootFirst := append(append([]byte{}, caPEM...), leafPEM...)
	crt := filepath.Join(certsRoot, "chain.crt")
	key := filepath.Join(certsRoot, "chain.key")
	if err := os.WriteFile(crt, rootFirst, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	})

	logs := captureLogs(t)
	res1, err := scanner.Run(t.Context())
	if err != nil || res1.Converted != 1 {
		t.Fatalf("initial Run = %+v, %v, want Converted 1 and nil", res1, err)
	}
	if got := countObservation(logs, convert.ObsLeafNotFirst); got != 1 {
		t.Fatalf("initial Run logged %d leaf-not-first observations, want exactly 1", got)
	}

	// The pair leaves the walk's reach while an unresolvable symlink proves the
	// enumeration incomplete: os.Root refuses to resolve a link out of the mount
	// whatever uid the process runs as, so this needs no permission staging.
	if err := os.Remove(crt); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(certsRoot, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run over an incomplete tree = %v, want nil", err)
	}
	if res2.Total != 0 {
		t.Fatalf("Run over an incomplete tree = %+v, want Total 0: the pair must be out of the walk's reach", res2)
	}

	// Put the tree back exactly as it was. The bundle on disk is still current, so
	// this scan converts nothing -- and must say nothing either.
	if err := os.WriteFile(crt, rootFirst, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(escape); err != nil {
		t.Fatal(err)
	}
	logs = captureLogs(t)
	res3, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run after the tree was restored = %v, want nil", err)
	}
	if res3.Unchanged != 1 {
		t.Errorf("Run after the tree was restored = %+v, want Unchanged 1", res3)
	}
	if got := countObservation(logs, convert.ObsLeafNotFirst); got != 0 {
		t.Errorf("Run after the tree was restored logged %d leaf-not-first observations, want 0: state kept across an incomplete enumeration must not be pruned",
			got)
	}
}

// TestObservationLog_reports_a_new_time_derived_observation_without_input_change
// pins the identity of the de-duplication state: it covers the input bytes AND the
// observations derived from them, not the bytes alone.
//
// Analyse derives the validity-window observations from the current scan time, so a
// leaf that crosses NotAfter while the daemon stays up yields a NEW observation over
// UNCHANGED bytes on the next fallback scan. Keying suppression on the input
// fingerprint alone silenced that transition until a restart cleared the map, which
// left the operator distributing an expired identity with no warning. The
// once-per-condition rule still holds: the second scan over the same observation set
// stays silent.
//
// Serial, not parallel: captureLogs swaps the process-global slog.Default().
func TestObservationLog_reports_a_new_time_derived_observation_without_input_change(t *testing.T) {
	logs := captureLogs(t)
	o := newObservationLog(0)
	fp := pairFingerprint([]byte("cert"), []byte("key"))
	o.record("tls.crt", fp, nil)

	expired := []convert.Observation{{
		Kind:   convert.ObsIdentityExpired,
		Detail: "selected identity expired at 2026-01-01T00:00:00Z",
	}}
	o.note("tls.crt", fp, expired)
	o.note("tls.crt", fp, expired)

	if got := countObservation(logs, convert.ObsIdentityExpired); got != 1 {
		t.Fatalf("same input with a newly derived expiry observation logged %d times, want exactly 1", got)
	}
}

// TestObservationLog_forgetPair_spends_wholeness_without_resetting_deduplication pins
// the reason `seen` and `whole` are two fields rather than one map: the two facts the
// log carries are spent on different schedules.
//
// forgetPair exists for the structural half only — it spends the single scan of grace
// completedPair grants a vanished key, so a key that stays gone is reported as the
// genuine orphan. When both facts lived in one map, that delete also destroyed the
// observation signature, so a producer replacing /input with BYTE-IDENTICAL content by
// unlink-then-write (rsync --delete-before, `docker cp` of a whole tree) made every
// affected pair re-emit its input WARN on the next scan even though neither the bytes
// nor the derived observations had changed — precisely the repeat this log exists to
// suppress.
//
// Serial, not parallel: captureLogs swaps the process-global slog.Default().
func TestObservationLog_forgetPair_spends_wholeness_without_resetting_deduplication(t *testing.T) {
	logs := captureLogs(t)
	o := newObservationLog(0)
	fp := pairFingerprint([]byte("cert"), []byte("key"))
	obs := []convert.Observation{{
		Kind:   convert.ObsLeafNotFirst,
		Detail: "selected leaf is not the first block",
	}}

	o.note("tls.crt", fp, obs)
	if !o.completedPair("tls.crt") {
		t.Fatal("completedPair after note = false, want true: note is reached only past readPair's success")
	}

	// The vanished-key scan: the grace is spent, so the NEXT missing key is an orphan.
	o.forgetPair("tls.crt")
	if o.completedPair("tls.crt") {
		t.Error("completedPair after forgetPair = true, want false: the grace must be spent, or a key deleted for good stays quiet forever")
	}

	// Same bytes, same observations, one scan later. The de-duplication must hold.
	o.note("tls.crt", fp, obs)
	if got := countObservation(logs, convert.ObsLeafNotFirst); got != 1 {
		t.Errorf("unchanged input re-read after forgetPair logged %d leaf-not-first observations, want exactly 1: spending the vanish grace must not reset the WARN de-duplication",
			got)
	}

	// A COMPLETE walk that no longer sees the path prunes both halves, so a pair that
	// comes back is reported once again.
	o.forget(map[string]struct{}{})
	o.note("tls.crt", fp, obs)
	if got := countObservation(logs, convert.ObsLeafNotFirst); got != 2 {
		t.Errorf("input re-read after forget logged %d leaf-not-first observations in total, want 2: forget prunes the signature as well as the wholeness",
			got)
	}
	if !o.completedPair("tls.crt") {
		t.Error("completedPair after the pair was re-noted = false, want true")
	}
}

// TestScannerRun_reports_an_input_observation_once_while_the_output_stays_unwritable
// pins the once-per-change rule on the OTHER steady-state arm: a bundle whose bytes
// are already correct, whose mode repair was refused, and whose repairing rewrite the
// output directory refused too (statusUnwritable). That condition recurs on every scan
// for as long as the operator leaves /output as it is, so emitting the pair's input
// observations before the write outcome is known re-named the same malformed input on
// every fsnotify event and every fallback tick. The standing condition itself keeps its
// own per-scan WARN (unwritableBundleMsg): the operator must keep being told /output is
// foreign-owned, without the input diagnostic riding along.
//
// Serial: it swaps slog.Default(), the chmod seam and the write seam.
func TestScannerRun_reports_an_input_observation_once_while_the_output_stays_unwritable(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	leafPEM, keyPEM, caPEM, chainPEM := testcerts.GenerateCertChain(t)
	crtPath := filepath.Join(certsRoot, "chain.crt")
	if err := os.WriteFile(crtPath, chainPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "chain.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	})
	if res, err := scanner.Run(t.Context()); err != nil || res.Converted != 1 {
		t.Fatalf("setup: initial Run = %+v, %v, want Converted 1 and nil", res, err)
	}

	// Root-first, same certificates: the bundle on disk stays the right bundle (so the
	// mode is the only reason to rewrite), while the input now carries a WARN-level
	// observation this scan has never reported.
	rootFirst := make([]byte, 0, len(caPEM)+len(leafPEM))
	rootFirst = append(rootFirst, caPEM...)
	rootFirst = append(rootFirst, leafPEM...)
	if err := os.WriteFile(crtPath, rootFirst, 0o644); err != nil {
		t.Fatal(err)
	}
	pfxPath := filepath.Join(outRoot, "chain.pfx")
	if err := os.Chmod(pfxPath, 0o644); err != nil {
		t.Fatalf("setup: Chmod: %v", err)
	}
	prevChmod := chmodInRoot
	chmodInRoot = func(_ *os.Root, name string, _ os.FileMode) error {
		return &fs.PathError{Op: "chmod", Path: name, Err: syscall.EPERM}
	}
	t.Cleanup(func() { chmodInRoot = prevChmod })
	prevWrite := writeFileInRoot
	writeFileInRoot = func(context.Context, *os.Root, string, []byte,
		...atomicfile.Option,
	) (atomicfile.Result, error) {
		return atomicfile.Result{}, &fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EACCES}
	}
	t.Cleanup(func() { writeFileInRoot = prevWrite })

	logs := captureLogs(t)
	res, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(unwritable output) = error %v, want nil", err)
	}
	if res.Unwritable != 1 || res.Failed != 0 {
		t.Fatalf("Run(unwritable output) = %+v, want Unwritable 1 Failed 0: the bundle's bytes are correct,"+
			" so this is the health-neutral arm", res)
	}
	if got := countObservation(logs, convert.ObsLeafNotFirst); got != 1 {
		t.Errorf("Run(unwritable output) logged %d leaf-not-first observations, want exactly 1: a new input"+
			" condition is named once", got)
	}
	if got := logs.CountLevel(slog.LevelWarn, unwritableBundleMsg); got != 1 {
		t.Errorf("Run(unwritable output) logged %q at WARN %d times, want 1", unwritableBundleMsg, got)
	}

	// Steady state: same inputs, same refusal. The condition repeats, the input
	// diagnostic does not.
	res, err = scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(second unwritable scan) = error %v, want nil", err)
	}
	if res.Unwritable != 1 {
		t.Errorf("Run(second unwritable scan) = %+v, want Unwritable 1 unchanged", res)
	}
	if got := countObservation(logs, convert.ObsLeafNotFirst); got != 1 {
		t.Errorf("two unwritable scans logged %d leaf-not-first observations in total, want 1: an"+
			" already-reported input condition must not re-emit while the output stays foreign-owned", got)
	}
	if got := logs.CountLevel(slog.LevelWarn, unwritableBundleMsg); got != 2 {
		t.Errorf("two unwritable scans logged %q at WARN %d times, want 2 (one per scan): the standing"+
			" condition keeps its own diagnostic", unwritableBundleMsg, got)
	}
}

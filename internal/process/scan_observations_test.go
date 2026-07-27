package process

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

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

package process_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// newScanner constructs a Scanner over the given input/output roots with the
// shared test password and the default modern encoder. The scan configuration
// is process-lifetime, so it is injected at construction.
func newScanner(certsRoot, outRoot string) *process.Scanner {
	return process.New(&process.Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	})
}

// newSyncScanner is newScanner with OUTPUT_LIFECYCLE=sync, for tests that must prove a
// reap did NOT happen: under the default warn mode nothing is ever deleted, so such a
// test would pass without exercising the gate it claims to check.
func newSyncScanner(certsRoot, outRoot string) *process.Scanner {
	return process.New(&process.Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
		Lifecycle: outputpolicy.LifecycleSync,
	})
}

// TestScannerRun_skips_a_cert_recreated_after_removal pins a DELIBERATE reversal
// of the previous contract, and the reasoning matters more than the assertion.
//
// This test used to require that a certificate removed and then recreated
// byte-for-byte was RECONVERTED. That was an artefact of how currency was
// decided: an in-memory fingerprint cache, whose entry for the pair was pruned
// when the input vanished, so the recreated pair looked new.
//
// Currency is now derived from the OUTPUT — the existing .pfx is decoded and
// compared against the bundle the current inputs produce. Under that rule the
// recreated pair is legitimately UNCHANGED: the file on disk genuinely is the
// correct bundle for those bytes, so rewriting it would only churn its mtime and
// re-replicate it downstream for no gain. The reversal is the point of the change,
// not a casualty of it.
func TestScannerRun_skips_a_cert_recreated_after_removal(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	anchorCert, anchorKey := testcerts.GenerateSelfSignedCert(t, "anchor.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "anchor.crt"), anchorCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "anchor.key"), anchorKey, 0o600); err != nil {
		t.Fatal(err)
	}

	goneCert, goneKey := testcerts.GenerateSelfSignedCert(t, "gone.example.com", "ecdsa")
	goneCrt := filepath.Join(certsRoot, "gone.crt")
	goneKeyPath := filepath.Join(certsRoot, "gone.key")
	if err := os.WriteFile(goneCrt, goneCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goneKeyPath, goneKey, 0o600); err != nil {
		t.Fatal(err)
	}

	scanner := newScanner(certsRoot, outRoot)

	res1, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("initial Run = %v, want nil", err)
	}
	if res1.Converted != 2 {
		t.Fatalf("initial Run Converted = %d, want 2", res1.Converted)
	}

	pfxPath := filepath.Join(outRoot, "gone.pfx")
	before, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx after the first conversion: %v", err)
	}

	// Remove only the INPUT; the .pfx output stays so the regenerate-on-missing
	// path cannot mask the currency decision.
	if err := os.Remove(goneCrt); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(goneKeyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatalf("post-removal Run = %v, want nil", err)
	}

	// Recreate byte-for-byte.
	if err := os.WriteFile(goneCrt, goneCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goneKeyPath, goneKey, 0o600); err != nil {
		t.Fatal(err)
	}

	res3, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("post-recreate Run = %v, want nil", err)
	}
	if res3.Converted != 0 {
		t.Errorf("post-recreate Run Converted = %d, want 0: the existing pfx is already correct for these bytes", res3.Converted)
	}
	if res3.Unchanged != 2 {
		t.Errorf("post-recreate Run Unchanged = %d, want 2: both pairs' outputs are current", res3.Unchanged)
	}

	// And the bytes on disk must be untouched, which is the operator-visible half:
	// no rewrite means no fresh mtime and nothing re-replicated downstream.
	after, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx after the recreate: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the pfx was rewritten for a byte-identical recreate; want it left alone")
	}
}

// TestScannerRun_regenerates_pfx_when_output_is_not_a_regular_file pins the
// output-TYPE half of the cache-coherence gate: an unchanged input whose prior
// PFX has been replaced by a non-regular file must not be reported as an
// unchanged skip, and the broken output must surface as a conversion failure so
// health reports it. A revert of store.inspect's Lstat+IsRegular check back to
// a bare Stat passes the rest of the suite.
func TestScannerRun_regenerates_pfx_when_output_is_not_a_regular_file(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "probe.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "probe.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "probe.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := newScanner(certsRoot, outRoot)
	res1, err := scanner.Run(t.Context())
	if err != nil || res1.Converted != 1 {
		t.Fatalf("first Run = %+v, %v, want Converted 1 and nil", res1, err)
	}

	// The broken-output case: the prior PFX is replaced by a directory, so no
	// usable PFX exists even though the input fingerprint is unchanged.
	pfxPath := filepath.Join(outRoot, "probe.pfx")
	if err := os.Remove(pfxPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pfxPath, 0o750); err != nil {
		t.Fatal(err)
	}

	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run = %v, want nil (a per-entry failure is not a scan error)", err)
	}
	if res2.Unchanged != 0 {
		t.Errorf("second Run Unchanged = %d, want 0 (a non-regular output must never satisfy the skip gate)", res2.Unchanged)
	}
	if res2.Failed != 1 {
		t.Errorf("second Run Failed = %d, want 1 (a broken output contract must be reported so health goes unhealthy)", res2.Failed)
	}
}

// TestScannerRun_counts_non_regular_key_as_unreadable pins a DELIBERATE reversal of
// this test's previous contract, and the reasoning matters more than the assertion.
//
// It used to require Failed=1 for a sibling key that exists but cannot be read
// (root.Stat succeeds, so the pair is not an orphan, while the confined bounded read
// refuses a non-regular file), which flipped the container unhealthy.
//
// That was wrong by the health philosophy both the README and the steering doc state:
// health answers only "should an orchestrator restart this container?", and a directory
// in a key's place -- like a symlink escaping /input, or a permission denial -- is a
// steady-state layout condition no restart can clear. The old classification made the
// container restart-loop forever on a misconfiguration, and it disagreed with the
// sibling-key STAT failure one line above, which was already health-neutral.
//
// The pair is still not converted, still WARNed with its path, still retried on the
// next scan, and still blocks orphan reaping. Only the health flip is gone.
func TestScannerRun_counts_non_regular_key_as_unreadable(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "badkey.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "badkey.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// A directory in the sibling key's place: it stats fine, so the pair is not
	// an orphan, but it is not a readable PEM file either.
	if err := os.Mkdir(filepath.Join(certsRoot, "badkey.key"), 0o750); err != nil {
		t.Fatal(err)
	}
	scanner := newScanner(certsRoot, outRoot)

	res1, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("first Run(non-regular key) = %v, want nil (a per-cert failure is not a scan error)", err)
	}
	if res1.Unreadable != 1 || res1.Failed != 0 || res1.Orphan != 0 || res1.Converted != 0 {
		t.Fatalf("first Run(non-regular key) = %+v, want Unreadable 1 Failed 0 Orphan 0 Converted 0", res1)
	}
	if _, statErr := os.Stat(filepath.Join(outRoot, "badkey.pfx")); statErr == nil {
		t.Errorf("Run(non-regular key) wrote a pfx; want no output file")
	}

	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run(non-regular key) = %v, want nil", err)
	}
	if res2.Unreadable != 1 || res2.Unchanged != 0 {
		t.Errorf("second Run(non-regular key) = %+v, want Unreadable 1 Unchanged 0 (an unreadable pair must be retried, never cached as a success)", res2)
	}
}

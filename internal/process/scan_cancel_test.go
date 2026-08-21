package process_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestScannerRun_cancelled_context_aborts_and_keeps_prior_output pins the
// shutdown path: a cancelled context aborts the walk with context.Canceled,
// converts nothing, and leaves the bundle already on disk untouched. An aborted
// scan that rewrote or removed output would force a full, timestamp-churning
// reconversion on the next clean cycle (and re-replicate every bundle
// downstream), so the follow-up scan must still report the pair as unchanged.
func TestScannerRun_cancelled_context_aborts_and_keeps_prior_output(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "cancel.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "cancel.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "cancel.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := newScanner(certsRoot, outRoot)

	res1, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("first Run = %v, want nil", err)
	}
	if res1.Converted != 1 {
		t.Fatalf("first Run Converted = %d, want 1", res1.Converted)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	res2, err := scanner.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run(cancelled ctx) error = %v, want context.Canceled", err)
	}
	if res2.Total != 0 || res2.Converted != 0 {
		t.Errorf("Run(cancelled ctx) = %+v, want Total 0 Converted 0 (no entry processed after cancellation)", res2)
	}

	res3, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run after cancellation = %v, want nil", err)
	}
	if res3.Unchanged != 1 || res3.Converted != 0 {
		t.Errorf("Run after a cancelled scan = %+v, want Unchanged 1 Converted 0 (an aborted walk must leave the prior bundle current)", res3)
	}
}

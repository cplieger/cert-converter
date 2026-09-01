package process

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestFlatAllowsRemoval_readsTheFilesystemAtCallTime pins the freshness contract
// of the flat re-check: the verdict comes from an enumeration taken at the
// moment of the call, never from state captured earlier, so a source restored
// between two candidates' unlinks keeps its artifact.
func TestFlatAllowsRemoval_readsTheFilesystemAtCallTime(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	inRoot, err := os.OpenRoot(input)
	if err != nil {
		t.Fatalf("setup: open input root: %v", err)
	}
	defer func() { _ = inRoot.Close() }()
	outRoot, err := os.OpenRoot(output)
	if err != nil {
		t.Fatalf("setup: open output root: %v", err)
	}
	defer func() { _ = outRoot.Close() }()
	rp := &reaper{
		src:        &source{root: inRoot},
		out:        &store{root: outRoot},
		mode:       outputpolicy.LifecycleSync,
		layoutMode: outputpolicy.LayoutFlat,
		formats:    outputpolicy.Formats{PFX: true},
	}

	candidate := "site/site.pfx"
	remove, err := rp.flatAllowsRemoval(t.Context(), candidate)
	if err != nil || !remove {
		t.Fatalf("flatAllowsRemoval(no source) = (%v, %v), want (true, nil)", remove, err)
	}

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "recheck-freshness.example.com", "ecdsa")
	sourceDir := filepath.Join(input, "issuer", "site")
	if err := os.MkdirAll(sourceDir, 0o750); err != nil {
		t.Fatalf("setup: mkdir source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "site.crt"), certPEM, 0o600); err != nil {
		t.Fatalf("setup: write restored certificate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "site.key"), keyPEM, 0o600); err != nil {
		t.Fatalf("setup: write restored key: %v", err)
	}

	remove, err = rp.flatAllowsRemoval(t.Context(), candidate)
	if err != nil {
		t.Fatalf("flatAllowsRemoval(source restored) = %v", err)
	}
	if remove {
		t.Error("flatAllowsRemoval(source restored) = true, want false: the verdict must read the tree at call time, not a snapshot from before the restore")
	}
}

// TestFlatAllowsRemoval_incompleteEnumerationRefusesTheBatch pins the veto
// shape: a re-enumeration that cannot observe the whole tree answers with
// errRecheckIncomplete, which removeConfirmed reads as "stop deleting".
func TestFlatAllowsRemoval_incompleteEnumerationRefusesTheBatch(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	// A directory occupying a source name makes the tree unclassifiable.
	if err := os.MkdirAll(filepath.Join(input, "occupied.crt"), 0o750); err != nil {
		t.Fatalf("setup: mkdir source-shaped directory: %v", err)
	}
	inRoot, err := os.OpenRoot(input)
	if err != nil {
		t.Fatalf("setup: open input root: %v", err)
	}
	defer func() { _ = inRoot.Close() }()
	rp := &reaper{
		src:        &source{root: inRoot},
		mode:       outputpolicy.LifecycleSync,
		layoutMode: outputpolicy.LayoutFlat,
		formats:    outputpolicy.Formats{PFX: true},
	}

	remove, err := rp.flatAllowsRemoval(t.Context(), "site/site.pfx")
	if remove || !errors.Is(err, errRecheckIncomplete) {
		t.Errorf("flatAllowsRemoval(unclassifiable tree) = (%v, %v), want (false, errRecheckIncomplete)", remove, err)
	}
}

// TestProcessFlatSources_cancelledBatchPropagatesCancellation pins the
// shutdown contract for a deferred batch that never reaches processSource: a
// collision-only or empty batch must still report the cancellation, or
// Scanner.Run would log a completed scan during shutdown.
func TestProcessFlatSources_cancelledBatchPropagatesCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sw := &scanWalk{
		pendingSources: []string{"issuer-a/shared/site.pfx", "issuer-b/shared/site.pfx"},
		results:        nil,
	}

	if err := sw.processFlatSources(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("processFlatSources(cancelled collision-only batch) = %v, want context.Canceled", err)
	}
	if len(sw.results) != 0 {
		t.Errorf("processFlatSources(cancelled collision-only batch) recorded %d results, want none before the cancellation check", len(sw.results))
	}
}

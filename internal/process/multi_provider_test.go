package process_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestScannerRun_flatConvertsSourcesFromSeveralProviders pins multi-provider
// input under the default layout: one /input tree holding several issuer
// directories (the shape a proxy's certificate store takes across a CA
// migration) converts every distinctly-named source, and the issuer level does
// not reach /output.
func TestScannerRun_flatConvertsSourcesFromSeveralProviders(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	oldCert, oldKey := testcerts.GenerateSelfSignedCert(t, "old-issuer.example.com", "ecdsa")
	newCert, newKey := testcerts.GenerateSelfSignedCert(t, "new-issuer.example.com", "ecdsa")
	bundleCert, bundleKey := testcerts.GenerateSelfSignedCert(t, "bundle.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "acme-v02.api.example-ca.org-directory", "site-a.example.com"), "site-a.example.com", oldCert, oldKey)
	writePEMSource(t, filepath.Join(input, "acme.other-ca.com-v2-dv90", "site-b.example.com"), "site-b.example.com", newCert, newKey)
	writePFXSource(t, filepath.Join(input, "acme.other-ca.com-v2-dv90", "site-c.example.com"), "site-c.example.com.pfx", bundleCert, bundleKey, "input-password", convert.EncNameModern2023)

	scanner := process.New(&process.Options{
		CertsRoot:          input,
		OutRoot:            output,
		Password:           "output-password",
		InputPassword:      "input-password",
		InputPasswordReady: true,
		Encoder:            convert.EncNameModern2023,
		Formats:            outputpolicy.Formats{PFX: true},
		FormatsExplicit:    true,
		// Layout deliberately unset: multi-provider input must work on the default.
	})

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(multi-provider flat) = %v", err)
	}
	if result.Converted != 3 || result.Collided != 0 || result.Failed != 0 {
		t.Fatalf("Run(multi-provider flat) = %+v, want Converted 3 Collided 0 Failed 0", result)
	}
	for _, artifact := range []string{
		filepath.Join("site-a.example.com", "site-a.example.com.pfx"),
		filepath.Join("site-b.example.com", "site-b.example.com.pfx"),
		filepath.Join("site-c.example.com", "site-c.example.com.pfx"),
	} {
		if _, statErr := os.Stat(filepath.Join(output, artifact)); statErr != nil {
			t.Errorf("expected flat artifact %q missing: %v", artifact, statErr)
		}
	}
	for _, issuerDir := range []string{"acme-v02.api.example-ca.org-directory", "acme.other-ca.com-v2-dv90"} {
		if _, statErr := os.Stat(filepath.Join(output, issuerDir)); !errors.Is(statErr, fs.ErrNotExist) {
			t.Errorf("issuer directory %q reached /output under the flat layout: %v", issuerDir, statErr)
		}
	}
}

// TestScannerRun_defaultLayoutSyncRetainsMirrorLaidArtifacts pins the upgrade
// guard: with OUTPUT_LAYOUT unset, sync must not reconcile away a tree the
// mirror layout wrote — a consumer may still mount those deeper paths. The
// artifacts are reported, never deleted, until the operator explicitly chooses
// a layout.
func TestScannerRun_defaultLayoutSyncRetainsMirrorLaidArtifacts(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "layout-upgrade.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "issuer", "site"), "site", certPEM, keyPEM)

	mirror := process.New(&process.Options{
		CertsRoot: input, OutRoot: output, Password: "output-password",
		Encoder: convert.EncNameModern2023, Layout: outputpolicy.LayoutMirror,
	})
	if result, err := mirror.Run(t.Context()); err != nil || result.Converted != 1 {
		t.Fatalf("Run(mirror before upgrade) = (%+v, %v), want Converted 1 and nil", result, err)
	}

	defaulted := process.New(&process.Options{
		CertsRoot: input, OutRoot: output, Password: "output-password",
		Encoder:   convert.EncNameModern2023,
		Lifecycle: outputpolicy.LifecycleSync,
		// Layout and LayoutExplicit deliberately unset: the post-upgrade state of
		// a deployment that never chose one.
	})
	result, err := defaulted.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(defaulted flat sync over mirror tree) = %v", err)
	}
	if result.Removed != 0 {
		t.Errorf("Run(defaulted flat sync over mirror tree) Removed = %d, want 0: the unset default must not delete the previous layout's tree", result.Removed)
	}
	if _, statErr := os.Stat(filepath.Join(output, "issuer", "site", "site.pfx")); statErr != nil {
		t.Errorf("mirror-laid artifact was deleted under the unset default: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(output, "site", "site.pfx")); statErr != nil {
		t.Errorf("flat artifact was not written alongside the retained mirror tree: %v", statErr)
	}
}

// TestScannerRun_explicitFlatSyncReconcilesMirrorTreeAway pins the migration
// path the retention test above defers to: once the operator EXPLICITLY sets
// OUTPUT_LAYOUT=flat, sync reconciles the mirror-laid duplicates away and the
// flat tree is the one that remains.
func TestScannerRun_explicitFlatSyncReconcilesMirrorTreeAway(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "layout-migrate.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "issuer", "site"), "site", certPEM, keyPEM)

	mirror := process.New(&process.Options{
		CertsRoot: input, OutRoot: output, Password: "output-password",
		Encoder: convert.EncNameModern2023, Layout: outputpolicy.LayoutMirror,
	})
	if result, err := mirror.Run(t.Context()); err != nil || result.Converted != 1 {
		t.Fatalf("Run(mirror before migration) = (%+v, %v), want Converted 1 and nil", result, err)
	}

	explicit := process.New(&process.Options{
		CertsRoot: input, OutRoot: output, Password: "output-password",
		Encoder:        convert.EncNameModern2023,
		Lifecycle:      outputpolicy.LifecycleSync,
		Layout:         outputpolicy.LayoutFlat,
		LayoutExplicit: true,
	})
	result, err := explicit.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(explicit flat sync over mirror tree) = %v", err)
	}
	if result.Removed != 1 {
		t.Errorf("Run(explicit flat sync over mirror tree) Removed = %d, want 1: the explicit layout choice asks for the previous tree to be reconciled away", result.Removed)
	}
	if _, statErr := os.Stat(filepath.Join(output, "issuer", "site", "site.pfx")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(mirror-laid artifact) = %v, want it reconciled away under the explicit flat layout", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(output, "site", "site.pfx")); statErr != nil {
		t.Errorf("flat artifact missing after migration: %v", statErr)
	}
}

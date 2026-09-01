package process_test

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/slogx/capture"
)

// newExcludingScanner is newFormatScanner plus an exclude set, for the sub-tree
// scoping tests.
func newExcludingScanner(input, output string, exclude layout.ExcludeSet, lifecycle outputpolicy.Lifecycle) *process.Scanner {
	return process.New(&process.Options{
		CertsRoot:       input,
		OutRoot:         output,
		Password:        "output-password",
		Encoder:         convert.EncNameModern2023,
		Formats:         outputpolicy.Formats{PFX: true},
		FormatsExplicit: true,
		Layout:          outputpolicy.LayoutFlat,
		LayoutExplicit:  true,
		Lifecycle:       lifecycle,
		Exclude:         exclude,
	})
}

// TestScannerRun_excludedSubtreeIsNotConverted pins the feature's whole point:
// a source under an excluded directory produces no artifact, while every source
// outside it converts normally.
func TestScannerRun_excludedSubtreeIsNotConverted(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	wantedCert, wantedKey := testcerts.GenerateSelfSignedCert(t, "wanted.example.com", "ecdsa")
	skippedCert, skippedKey := testcerts.GenerateSelfSignedCert(t, "client-identity.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "server"), "wanted", wantedCert, wantedKey)
	writePEMSource(t, filepath.Join(input, "clients"), "identity", skippedCert, skippedKey)
	scanner := newExcludingScanner(input, output, layout.NewExcludeSet([]string{"clients"}), outputpolicy.LifecycleWarn)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(excluded subtree) = %v", err)
	}
	if result.Converted != 1 || result.Excluded != 1 || result.Failed != 0 {
		t.Fatalf("Run(excluded subtree) = %+v, want Converted 1 Excluded 1 Failed 0", result)
	}
	assertOnlyRegularFiles(t, output, []string{filepath.Join("server", "wanted.pfx")})
	assertPFXCommonName(t, filepath.Join(output, "server", "wanted.pfx"), "output-password", "wanted.example.com")
}

// TestScannerRun_excludingASourceDoesNotReapItsArtifacts is the safety half, and
// the reason an exclusion is not modelled as absence: a path the operator
// declared out of scope must not have its existing artifacts deleted, because
// nothing guards a mistyped exclusion the way the empty-tree veto guards a
// wrong mount.
func TestScannerRun_excludingASourceDoesNotReapItsArtifacts(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	keptCert, keptKey := testcerts.GenerateSelfSignedCert(t, "still-converted.example.com", "ecdsa")
	laterExcluded, laterExcludedKey := testcerts.GenerateSelfSignedCert(t, "later-excluded.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "server"), "kept", keptCert, keptKey)
	writePEMSource(t, filepath.Join(input, "clients"), "identity", laterExcluded, laterExcludedKey)

	// First scan converts both, so /output holds an artifact for the path the
	// second scan excludes.
	before := newExcludingScanner(input, output, layout.ExcludeSet{}, outputpolicy.LifecycleSync)
	if result, err := before.Run(t.Context()); err != nil || result.Converted != 2 {
		t.Fatalf("Run(before exclusion) = (%+v, %v), want Converted 2 and nil", result, err)
	}
	excludedArtifact := filepath.Join(output, "clients", "identity.pfx")
	if _, statErr := os.Stat(excludedArtifact); statErr != nil {
		t.Fatalf("setup: the artifact to protect was not written: %v", statErr)
	}

	after := newExcludingScanner(input, output, layout.NewExcludeSet([]string{"clients"}), outputpolicy.LifecycleSync)
	logs := capture.Default(t)
	result, err := after.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(after exclusion, sync) = %v", err)
	}
	if result.Removed != 0 {
		t.Errorf("Run(after exclusion, sync) Removed = %d, want 0: excluding a path must never delete what is already there", result.Removed)
	}
	if _, statErr := os.Stat(excludedArtifact); statErr != nil {
		t.Errorf("sync deleted an excluded source's artifact: %v", statErr)
	}
	// The excluded artifact must not even become a CANDIDATE. Removed == 0 alone
	// cannot see that: the post-delay re-check also spares it, because the source
	// is still on disk, so the count stays 0 either way. This is the assertion
	// that fails when an excluded source stops registering its artifacts, and
	// what it protects is real — a candidate costs the whole batch a 30s
	// confirmation deferral on every scan.
	const announced = "possible orphaned output artifacts; re-checking before deleting anything"
	if count := logs.CountLevel(slog.LevelInfo, announced); count != 0 {
		t.Errorf("Run(after exclusion, sync) announced orphan candidates %d times, want 0:"+
			" an excluded source's artifacts must be registered as expected, not merely spared at the re-check", count)
	}
}

// TestScannerRun_excludedPathDoesNotDisableOrphanCleanup pins the difference
// from the permissions workaround this feature replaces: an exclusion is an
// operator assertion, not a coverage hole, so sync keeps reaping the artifacts
// whose sources are genuinely gone.
func TestScannerRun_excludedPathDoesNotDisableOrphanCleanup(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	keptCert, keptKey := testcerts.GenerateSelfSignedCert(t, "anchor.example.com", "ecdsa")
	goneCert, goneKey := testcerts.GenerateSelfSignedCert(t, "gone.example.com", "ecdsa")
	excludedCert, excludedKey := testcerts.GenerateSelfSignedCert(t, "excluded.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "server"), "anchor", keptCert, keptKey)
	writePEMSource(t, filepath.Join(input, "server"), "gone", goneCert, goneKey)
	writePEMSource(t, filepath.Join(input, "clients"), "identity", excludedCert, excludedKey)

	// Convert everything first, so /output holds an artifact for the path the
	// exclusion later covers; otherwise the assertion below would pass on an
	// artifact that was simply never written.
	seed := newExcludingScanner(input, output, layout.ExcludeSet{}, outputpolicy.LifecycleSync)
	if result, err := seed.Run(t.Context()); err != nil || result.Converted != 3 {
		t.Fatalf("Run(seed, no exclusion) = (%+v, %v), want Converted 3 and nil", result, err)
	}
	for _, name := range []string{"gone.crt", "gone.key"} {
		if err := os.Remove(filepath.Join(input, "server", name)); err != nil {
			t.Fatalf("remove %s: %v", name, err)
		}
	}

	scanner := newExcludingScanner(input, output, layout.NewExcludeSet([]string{"clients"}), outputpolicy.LifecycleSync)
	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(with exclusion, sync) = %v", err)
	}
	if result.Excluded != 1 {
		t.Fatalf("Run(with exclusion, sync) = %+v, want Excluded 1", result)
	}
	if result.Removed != 1 {
		t.Errorf("Run(with exclusion, sync) Removed = %d, want 1: an exclusion must not disable orphan cleanup the way an unreadable path does", result.Removed)
	}
	if _, statErr := os.Stat(filepath.Join(output, "server", "gone.pfx")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(gone artifact) = %v, want the genuine orphan reaped", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(output, "clients", "identity.pfx")); statErr != nil {
		t.Errorf("the excluded source's artifact was reaped in the same scan: %v", statErr)
	}
}

// TestScannerRun_excludedCertDoesNotShadowItsSiblingBundle pins precedence
// against the exclude set: shadowing is decided among the sources this app will
// actually convert, so excluding one spelling of a stem must not strand the
// other.
func TestScannerRun_excludedCertDoesNotShadowItsSiblingBundle(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	pairCert, pairKey := testcerts.GenerateSelfSignedCert(t, "excluded-pair.example.com", "ecdsa")
	bundleCert, bundleKey := testcerts.GenerateSelfSignedCert(t, "surviving-bundle.example.com", "ecdsa")
	writePEMSource(t, input, "site", pairCert, pairKey)
	writePFXSource(t, input, "site.pfx", bundleCert, bundleKey, "input-password", convert.EncNameModern2023)
	scanner := process.New(&process.Options{
		CertsRoot:          input,
		OutRoot:            output,
		Password:           "output-password",
		InputPassword:      "input-password",
		InputPasswordReady: true,
		Encoder:            convert.EncNameModern2023,
		Formats:            outputpolicy.Formats{PFX: true},
		FormatsExplicit:    true,
		Layout:             outputpolicy.LayoutFlat,
		LayoutExplicit:     true,
		Exclude:            layout.NewExcludeSet([]string{"site.crt"}),
	})

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(excluded cert beside bundle) = %v", err)
	}
	if result.Converted != 1 || result.Excluded != 1 || result.Collided != 0 {
		t.Fatalf("Run(excluded cert beside bundle) = %+v, want Converted 1 Excluded 1 Collided 0", result)
	}
	assertPFXCommonName(t, filepath.Join(output, "site.pfx"), "output-password", "surviving-bundle.example.com")
}

// TestScannerRun_excludingEverySourceIsReported pins the over-broad-exclusion
// diagnostic: a scan that excludes everything produces nothing while reporting
// no failure, which the summary counts alone cannot distinguish from a healthy
// steady state.
func TestScannerRun_excludingEverySourceIsReported(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "all-excluded.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "clients"), "identity", certPEM, keyPEM)
	scanner := newExcludingScanner(input, output, layout.NewExcludeSet([]string{"clients"}), outputpolicy.LifecycleWarn)
	logs := capture.Default(t)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(everything excluded) = %v", err)
	}
	if result.Excluded != 1 || result.Total != 1 || result.Converted != 0 {
		t.Fatalf("Run(everything excluded) = %+v, want Excluded 1 Total 1 Converted 0", result)
	}
	assertOnlyRegularFiles(t, output, nil)
	const msg = "every certificate source under the input root is excluded"
	if count := logs.CountLevel(slog.LevelWarn, msg); count != 1 {
		t.Errorf("Run(everything excluded) logged %q %d times, want 1: %v", msg, count, logs.Messages())
	}
}

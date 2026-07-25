package process_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// newScanner constructs a Scanner over the given input/output roots with the
// shared test password and the default modern encoder. The scan configuration
// is process-lifetime, so it is injected at construction.
func newScanner(certsRoot, outRoot string) *process.Scanner {
	return process.New(process.Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	})
}

// convertPairToPath converts an already-read cert+key pair to a PFX at destPath
// through PairInRoot, the only PFX-writing entry point convert exposes: it opens
// an *os.Root over destPath's directory and writes the base name inside it.
// Tests that assert on an ambient destination path use this instead of an
// unconfined API, so they exercise exactly the path production takes.
func convertPairToPath(t *testing.T, certPEM, keyPEM []byte, destPath, password string, enc convert.EncoderType) error {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(destPath))
	if err != nil {
		t.Fatalf("setup: os.OpenRoot(%q) = %v", filepath.Dir(destPath), err)
	}
	defer func() { _ = root.Close() }()
	return convert.PairInRoot(t.Context(), certPEM, keyPEM, root, filepath.Base(destPath), password, enc)
}

func TestPairInRoot_rejects_mismatched_cert_and_key(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "cert.example.com", "ecdsa")
	_, keyPEM := testcerts.GenerateSelfSignedCert(t, "other.example.com", "ecdsa")
	destPath := filepath.Join(dir, "mismatch.pfx")

	err := convertPairToPath(t, certPEM, keyPEM, destPath, "pw", convert.EncNameModern2023)
	if err == nil {
		t.Fatal("convert.PairInRoot(mismatched cert/key) = nil, want error")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("convert.PairInRoot(mismatched) error = %q, want it to contain %q", err.Error(), "does not match")
	}
	if _, statErr := os.Stat(destPath); statErr == nil {
		t.Errorf("convert.PairInRoot wrote a pfx at %q for a mismatched pair; want no file written", destPath)
	}
}

func TestScannerRun_regenerates_pfx_when_output_missing(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "regen.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "regen.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "regen.key"), keyPEM, 0o600); err != nil {
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
	pfxPath := filepath.Join(outRoot, "regen.pfx")
	if _, statErr := os.Stat(pfxPath); statErr != nil {
		t.Fatalf("first Run did not write %q: %v", pfxPath, statErr)
	}

	if err := os.Remove(pfxPath); err != nil {
		t.Fatal(err)
	}

	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run = %v, want nil", err)
	}
	if res2.Converted != 1 {
		t.Errorf("second Run Converted = %d, want 1 (unchanged input but output PFX missing must regenerate)", res2.Converted)
	}
	if res2.Unchanged != 0 {
		t.Errorf("second Run Unchanged = %d, want 0 (a missing output must not be reported as an unchanged skip)", res2.Unchanged)
	}
	if _, statErr := os.Stat(pfxPath); statErr != nil {
		t.Errorf("second Run did not regenerate %q: %v", pfxPath, statErr)
	}
}

func TestScannerRun_skips_unchanged_pair_when_output_present(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "skip.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "skip.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "skip.key"), keyPEM, 0o600); err != nil {
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

	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run = %v, want nil", err)
	}
	if res2.Unchanged != 1 {
		t.Errorf("second Run Unchanged = %d, want 1 (unchanged input with output present must skip)", res2.Unchanged)
	}
	if res2.Converted != 0 {
		t.Errorf("second Run Converted = %d, want 0 (nothing changed and output present, must not reconvert)", res2.Converted)
	}
}

func TestScannerRun_returns_error_for_unopenable_input_root(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	scanner := newScanner(missing, t.TempDir())

	res, err := scanner.Run(t.Context())
	if err == nil {
		t.Fatal("Scanner.Run(unopenable input root) = nil error, want a scan error so the container is marked unhealthy")
	}
	if (res != process.ScanResult{}) {
		t.Errorf("Scanner.Run(unopenable input root) result = %+v, want the zero ScanResult", res)
	}
}

func TestScannerRun_failed_conversion_is_counted_and_retried(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "cert.example.com", "ecdsa")
	_, keyPEM := testcerts.GenerateSelfSignedCert(t, "other.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "mismatch.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "mismatch.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := newScanner(certsRoot, outRoot)

	res1, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("first Run = %v, want nil (a per-cert conversion failure is not a scan error)", err)
	}
	if res1.Failed != 1 || res1.Converted != 0 {
		t.Fatalf("first Run = %+v, want Failed 1 Converted 0", res1)
	}
	if _, statErr := os.Stat(filepath.Join(outRoot, "mismatch.pfx")); statErr == nil {
		t.Errorf("a failed conversion wrote a pfx; want no output file")
	}

	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run = %v, want nil", err)
	}
	if res2.Failed != 1 {
		t.Errorf("second Run Failed = %d, want 1 (a failed pair must be retried, never cached as a success)", res2.Failed)
	}
	if res2.Unchanged != 0 {
		t.Errorf("second Run Unchanged = %d, want 0 (a previously-failed pair must not be skipped as unchanged)", res2.Unchanged)
	}
}

func TestScannerRun_records_orphan_crt_without_key(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "orphan.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "orphan.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	scanner := newScanner(certsRoot, outRoot)

	res, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(orphan .crt) = %v, want nil (an orphan is skipped, not an error)", err)
	}
	if res.Orphan != 1 || res.Total != 1 {
		t.Errorf("Run(orphan .crt) = %+v, want Orphan 1 Total 1", res)
	}
	if res.Converted != 0 || res.Failed != 0 {
		t.Errorf("Run(orphan .crt) = %+v, want Converted 0 Failed 0", res)
	}
	if _, statErr := os.Stat(filepath.Join(outRoot, "orphan.pfx")); statErr == nil {
		t.Errorf("an orphan .crt produced a pfx; want no output file")
	}
}

func TestScannerRun_unreadable_subpath_is_health_neutral(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod permission semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 0 does not block directory reads")
	}
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "readable.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "readable.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "readable.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(certsRoot, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	scanner := newScanner(certsRoot, outRoot)

	res, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(unreadable subpath) = %v, want nil", err)
	}
	if res.Unreadable != 1 {
		t.Errorf("Run(unreadable subpath) Unreadable = %d, want 1", res.Unreadable)
	}
	if res.Converted != 1 {
		t.Errorf("Run(unreadable subpath) Converted = %d, want 1 (the readable pair must still convert)", res.Converted)
	}
	if res.Failed != 0 {
		t.Errorf("Run(unreadable subpath) Failed = %d, want 0", res.Failed)
	}
}

func TestScannerRun_classifies_symlink_escape_key_as_orphan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	// A sibling .key that is a symlink escaping the input root: the confined
	// *os.Root refuses to stat it (a non-ENOENT error), so the pair is a
	// health-neutral orphan to surface, never a Failed conversion.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "real.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "escape.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "escape.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "real.key"), filepath.Join(certsRoot, "escape.key")); err != nil {
		t.Fatal(err)
	}
	scanner := newScanner(certsRoot, outRoot)

	res, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(symlink-escape key) = %v, want nil", err)
	}
	if res.Orphan != 1 || res.Total != 1 {
		t.Errorf("Run(symlink-escape key) = %+v, want Orphan 1 Total 1", res)
	}
	if res.Failed != 0 {
		t.Errorf("Run(symlink-escape key) Failed = %d, want 0 (a symlink-escape sibling key must stay health-neutral)", res.Failed)
	}
}

func TestScannerRun_classifies_unreadable_cert_as_failed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	outside := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "unreadable.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(outside, "real.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "real.crt"), filepath.Join(certsRoot, "unreadable.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "unreadable.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := newScanner(certsRoot, outRoot)

	res1, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("first Run(unreadable cert) = %v, want nil", err)
	}
	if res1.Failed != 1 || res1.Converted != 0 {
		t.Fatalf("first Run(unreadable cert) = %+v, want Failed 1 Converted 0", res1)
	}

	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run(unreadable cert) = %v, want nil", err)
	}
	if res2.Failed != 1 {
		t.Errorf("second Run(unreadable cert) Failed = %d, want 1 (an unreadable cert must be retried, never cached as success)", res2.Failed)
	}
}

func TestScannerRun_reconverts_cert_recreated_after_removal(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	// An anchor pair present for the whole test: it must stay an unchanged
	// skip on every rescan, pinning the result counts.
	anchorCert, anchorKey := testcerts.GenerateSelfSignedCert(t, "anchor.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "anchor.crt"), anchorCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "anchor.key"), anchorKey, 0o600); err != nil {
		t.Fatal(err)
	}

	// The pair under test: converted once, its input removed, then recreated
	// byte-for-byte while its earlier .pfx output is left on disk.
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

	// Remove only the gone pair's INPUT; its .pfx OUTPUT stays present so the
	// regenerate-on-missing-output path cannot mask the cache behavior.
	if err := os.Remove(goneCrt); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(goneKeyPath); err != nil {
		t.Fatal(err)
	}

	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("post-removal Run = %v, want nil", err)
	}
	if res2.Total != 1 {
		t.Fatalf("post-removal Run Total = %d, want 1 (only the anchor remains seen)", res2.Total)
	}

	// Recreate the pair with identical bytes; its old .pfx is still present.
	if err := os.WriteFile(goneCrt, goneCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goneKeyPath, goneKey, 0o600); err != nil {
		t.Fatal(err)
	}

	// The completed post-removal scan must have pruned the stale fingerprint,
	// so the recreated pair is now seen as new and reconverted -- even though
	// its bytes are unchanged and its output still exists. If pruning is gated
	// on the wrong walk outcome the fingerprint survives and the pair is
	// wrongly skipped as unchanged.
	res3, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("post-recreate Run = %v, want nil", err)
	}
	if res3.Converted != 1 {
		t.Errorf("post-recreate Run Converted = %d, want 1 (a removed-then-recreated cert must be reconverted, not skipped as unchanged)", res3.Converted)
	}
	if res3.Unchanged != 1 {
		t.Errorf("post-recreate Run Unchanged = %d, want 1 (only the untouched anchor pair stays an unchanged skip)", res3.Unchanged)
	}
}

// TestScannerRun_regenerates_pfx_when_output_is_not_a_regular_file pins the
// output-TYPE half of the cache-coherence gate: an unchanged input whose prior
// PFX has been replaced by a non-regular file must not be reported as an
// unchanged skip, and the broken output must surface as a conversion failure so
// health reports it. A revert of outputIsCurrent's Lstat+IsRegular check back to
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

// TestScannerRun_counts_non_regular_key_as_failed pins the classification of a
// sibling key that exists but cannot be read as PEM: root.Stat succeeds, so the
// pair is not an orphan, while the confined bounded read refuses a non-regular
// file. That must surface as a conversion failure so health reports it, and it
// must be retried on the next scan rather than cached as a success.
func TestScannerRun_counts_non_regular_key_as_failed(t *testing.T) {
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
	if res1.Failed != 1 || res1.Orphan != 0 || res1.Converted != 0 {
		t.Fatalf("first Run(non-regular key) = %+v, want Failed 1 Orphan 0 Converted 0", res1)
	}
	if _, statErr := os.Stat(filepath.Join(outRoot, "badkey.pfx")); statErr == nil {
		t.Errorf("Run(non-regular key) wrote a pfx; want no output file")
	}

	res2, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run(non-regular key) = %v, want nil", err)
	}
	if res2.Failed != 1 || res2.Unchanged != 0 {
		t.Errorf("second Run(non-regular key) = %+v, want Failed 1 Unchanged 0 (a failed pair must be retried, never cached as a success)", res2)
	}
}

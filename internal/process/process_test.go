package process_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cplieger/cert-watcher/internal/convert"
	"github.com/cplieger/cert-watcher/internal/process"
	"github.com/cplieger/cert-watcher/internal/testcerts"
	"software.sslmate.com/src/go-pkcs12"
)

func TestConvertPair_writes_decodable_pfx_for_matched_pair(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "matched.example.com", "ecdsa")
	destPath := filepath.Join(dir, "matched.pfx")

	if err := process.ConvertPair(t.Context(), certPEM, keyPEM, destPath, "pw", pkcs12.Modern2023); err != nil {
		t.Fatalf("process.ConvertPair(matched pair) = %v, want nil", err)
	}

	pfxData, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("process.ConvertPair did not write a readable pfx: %v", err)
	}
	_, leaf, _, decErr := pkcs12.DecodeChain(pfxData, "pw")
	if decErr != nil {
		t.Fatalf("decode pfx written by process.ConvertPair: %v", decErr)
	}
	if leaf.Subject.CommonName != "matched.example.com" {
		t.Errorf("process.ConvertPair wrote leaf CN = %q, want %q", leaf.Subject.CommonName, "matched.example.com")
	}
}

func TestConvertPair_rejects_mismatched_cert_and_key(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "cert.example.com", "ecdsa")
	_, keyPEM := testcerts.GenerateSelfSignedCert(t, "other.example.com", "ecdsa")
	destPath := filepath.Join(dir, "mismatch.pfx")

	err := process.ConvertPair(t.Context(), certPEM, keyPEM, destPath, "pw", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("process.ConvertPair(mismatched cert/key) = nil, want error")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("process.ConvertPair(mismatched) error = %q, want it to contain %q", err.Error(), "does not match")
	}
	if _, statErr := os.Stat(destPath); statErr == nil {
		t.Errorf("process.ConvertPair wrote a pfx at %q for a mismatched pair; want no file written", destPath)
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
	scanner := process.New(convert.NewHashCache())

	res1, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
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

	res2, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
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
	scanner := process.New(convert.NewHashCache())

	res1, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
	if err != nil {
		t.Fatalf("first Run = %v, want nil", err)
	}
	if res1.Converted != 1 {
		t.Fatalf("first Run Converted = %d, want 1", res1.Converted)
	}

	res2, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
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
	scanner := process.New(convert.NewHashCache())
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	res, err := scanner.Run(t.Context(), missing, t.TempDir(), "pw", pkcs12.Modern2023)
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
	scanner := process.New(convert.NewHashCache())

	res1, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
	if err != nil {
		t.Fatalf("first Run = %v, want nil (a per-cert conversion failure is not a scan error)", err)
	}
	if res1.Failed != 1 || res1.Converted != 0 {
		t.Fatalf("first Run = %+v, want Failed 1 Converted 0", res1)
	}
	if _, statErr := os.Stat(filepath.Join(outRoot, "mismatch.pfx")); statErr == nil {
		t.Errorf("a failed conversion wrote a pfx; want no output file")
	}

	res2, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
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
	scanner := process.New(convert.NewHashCache())

	res, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
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

func TestConvertPair_carries_ca_chain_into_pfx(t *testing.T) {
	t.Parallel()
	_, keyPEM, _, chainPEM := testcerts.GenerateCertChain(t)
	destPath := filepath.Join(t.TempDir(), "chain.pfx")

	if err := process.ConvertPair(t.Context(), chainPEM, keyPEM, destPath, "pw", pkcs12.Modern2023); err != nil {
		t.Fatalf("process.ConvertPair(leaf+CA chain) = %v, want nil", err)
	}

	pfxData, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("process.ConvertPair did not write a readable pfx: %v", err)
	}
	_, leaf, caCerts, decErr := pkcs12.DecodeChain(pfxData, "pw")
	if decErr != nil {
		t.Fatalf("decode pfx written by process.ConvertPair: %v", decErr)
	}
	if leaf.Subject.CommonName != "leaf.example.com" {
		t.Errorf("process.ConvertPair leaf CN = %q, want %q", leaf.Subject.CommonName, "leaf.example.com")
	}
	if len(caCerts) != 1 {
		t.Errorf("process.ConvertPair PFX CA count = %d, want 1 (the CA from the chain must be carried into the PFX)", len(caCerts))
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
	scanner := process.New(convert.NewHashCache())

	res, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
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
	scanner := process.New(convert.NewHashCache())

	res, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
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
	scanner := process.New(convert.NewHashCache())

	res1, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
	if err != nil {
		t.Fatalf("first Run(unreadable cert) = %v, want nil", err)
	}
	if res1.Failed != 1 || res1.Converted != 0 {
		t.Fatalf("first Run(unreadable cert) = %+v, want Failed 1 Converted 0", res1)
	}

	res2, err := scanner.Run(t.Context(), certsRoot, outRoot, "pw", pkcs12.Modern2023)
	if err != nil {
		t.Fatalf("second Run(unreadable cert) = %v, want nil", err)
	}
	if res2.Failed != 1 {
		t.Errorf("second Run(unreadable cert) Failed = %d, want 1 (an unreadable cert must be retried, never cached as success)", res2.Failed)
	}
}

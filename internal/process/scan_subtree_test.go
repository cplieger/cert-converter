package process_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
	"software.sslmate.com/src/go-pkcs12"
)

// TestScannerRun_mirrors_input_subdirectories_in_output pins the output path
// derivation for the canonical Caddy layout, where every cert lives in a
// per-domain subdirectory rather than at the root of /input: the .pfx must be
// written at the same relative path under /output (creating the intermediate
// directories), not flattened into the output root.
func TestScannerRun_mirrors_input_subdirectories_in_output(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()
	certDir := filepath.Join(certsRoot, "acme-v02", "example.com")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "nested.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certDir, "example.com.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "example.com.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := newScanner(certsRoot, outRoot)

	res, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(nested cert dir) = %v, want nil", err)
	}
	if res.Converted != 1 {
		t.Fatalf("Run(nested cert dir) = %+v, want Converted 1", res)
	}

	pfxPath := filepath.Join(outRoot, "acme-v02", "example.com", "example.com.pfx")
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("Run(nested cert dir) did not write %q: %v", pfxPath, err)
	}
	_, leaf, _, decErr := pkcs12.DecodeChain(pfxData, "pw")
	if decErr != nil {
		t.Fatalf("decode pfx at %q: %v", pfxPath, decErr)
	}
	if leaf.Subject.CommonName != "nested.example.com" {
		t.Errorf("nested pfx leaf CN = %q, want %q", leaf.Subject.CommonName, "nested.example.com")
	}
	if _, statErr := os.Stat(filepath.Join(outRoot, "example.com.pfx")); statErr == nil {
		t.Error("Run wrote the pfx flattened into the output root; want the input subtree mirrored")
	}
}

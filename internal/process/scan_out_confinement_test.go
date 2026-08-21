package process_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestScannerRun_refuses_symlinked_output_subdirectory pins the /output
// confinement: the scanner resolves every output touch (stat, directory
// creation, atomic write) through an *os.Root, so a symlinked output
// subdirectory cannot redirect the private-key-bearing PFX outside the mounted
// volume. Without this test a revert to the ambient os.Stat/os.MkdirAll/write
// path passes the whole suite.
func TestScannerRun_refuses_symlinked_output_subdirectory(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	certsRoot := filepath.Join(base, "in")
	outRoot := filepath.Join(base, "out")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(certsRoot, "escape"), outRoot, outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "escape.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "escape", "x.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "escape", "x.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// The attacker-controlled step: an output subdirectory replaced by a symlink
	// pointing out of the volume.
	if err := os.Symlink(outside, filepath.Join(outRoot, "escape")); err != nil {
		t.Fatal(err)
	}

	res, err := newScanner(certsRoot, outRoot).Run(t.Context())
	if err != nil {
		t.Fatalf("Run(symlinked output subdir) = %v, want nil (a per-entry failure is not a scan error)", err)
	}
	// Health-NEUTRAL, not a conversion failure. The confinement property this test exists
	// for is the last assertion; the count is incidental to it, and this line said Failed 1
	// from before the /output layout refusals were classified at all. Root.MkdirAll reports
	// EEXIST for a symlink occupying the mirrored directory name, which is the same
	// operator layout as a regular file occupying it
	// (TestScannerRun_when_a_file_blocks_the_mirrored_output_directory), and the settled
	// dir-write-refusal-health-routing decision is that a restart-unclearable /output layout
	// must never reach health: no restart re-reads a different tree, so counting it in
	// Failed removed the health marker on every scan forever.
	if res.Converted != 0 || res.Unwritable != 1 || res.Failed != 0 {
		t.Errorf("Run(symlinked output subdir) = %+v, want Converted 0 Unwritable 1 Failed 0", res)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "x.pfx")); statErr == nil {
		t.Fatalf("the pfx was written outside the output root at %q; the os.Root confinement was bypassed",
			filepath.Join(outside, "x.pfx"))
	}
}

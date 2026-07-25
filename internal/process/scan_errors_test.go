package process_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestScannerRun_reports_an_unopenable_input_root pins the ONE scan outcome that is
// a hard error rather than a per-entry failure: the input tree itself cannot be
// opened. Everything else the scan meets degrades into a counted entry failure and a
// still-completed scan, so this branch is what makes a missing or unmounted /input
// flip the container unhealthy instead of reporting a clean scan of nothing.
//
// It lives here rather than in main's test file (deferred finding l-f13): the
// behaviour is Scanner.Run's, so a change to it must fail a test in this package.
func TestScannerRun_reports_an_unopenable_input_root(t *testing.T) {
	t.Parallel()
	scanner := newScanner(filepath.Join(t.TempDir(), "never-created"), t.TempDir())

	res, err := scanner.Run(t.Context())
	if err == nil {
		t.Fatalf("Run(missing input root) = %+v, nil; want a hard error so health flips", res)
	}
	if !strings.Contains(err.Error(), "open input root") {
		t.Errorf("Run(missing input root) error = %v, want it to name the input root", err)
	}
}

// TestScannerRun_counts_an_unparseable_pair_as_failed pins that a cert whose PEM
// cannot be analysed is a counted entry failure, not a scan-wide error: the rest of
// the tree still converts, and the failure count is what flips health. A pair that
// aborted the whole scan would let one corrupt file stop every other renewal.
func TestScannerRun_counts_an_unparseable_pair_as_failed(t *testing.T) {
	t.Parallel()
	certsRoot, outRoot := t.TempDir(), t.TempDir()

	// One unparseable pair...
	write(t, filepath.Join(certsRoot, "broken.crt"), []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"))
	write(t, filepath.Join(certsRoot, "broken.key"), []byte("garbage"))
	// ...alongside one good pair, to prove the scan continues past the failure.
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "good.example.com", "ecdsa")
	write(t, filepath.Join(certsRoot, "good.crt"), certPEM)
	write(t, filepath.Join(certsRoot, "good.key"), keyPEM)

	res, err := newScanner(certsRoot, outRoot).Run(t.Context())
	if err != nil {
		t.Fatalf("Run = %v, want nil: one unparseable pair must not abort the scan", err)
	}
	if res.Failed != 1 {
		t.Errorf("Failed = %d, want 1 so the container goes unhealthy", res.Failed)
	}
	if res.Converted != 1 {
		t.Errorf("Converted = %d, want 1: the healthy pair beside the broken one must still convert", res.Converted)
	}
}

// write is a fixture-writing helper: a failure here is a broken test, not a finding.
func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

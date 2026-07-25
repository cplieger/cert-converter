package process_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestScannerRun_symlink_escape_is_health_neutral pins the case that motivated the
// classification change (deferred finding h-f9): a certificate whose /input entry is a
// symlink pointing OUT of the mounted subtree.
//
// This is not a hypothetical. The certbot layout — live/<domain>/cert.pem as a symlink
// into archive/<domain>/certN.pem — produces exactly this shape whenever only live/ is
// mounted, and it was previously counted as a conversion failure, so the container
// reported unhealthy forever and an orchestrator restart-looped it over a mount
// configuration no restart can change.
//
// The scan must still refuse the read (that is the confinement guarantee), still report
// the path, and still leave the pair unconverted. Only the health flip is wrong.
func TestScannerRun_symlink_escape_is_health_neutral(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	certsRoot := filepath.Join(base, "live")
	archive := filepath.Join(base, "archive")
	outRoot := t.TempDir()
	for _, d := range []string{certsRoot, archive} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	// The real material lives outside the mounted root...
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "escape.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(archive, "cert1.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archive, "privkey1.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// ...and /input holds only symlinks to it, the certbot live/ shape.
	if err := os.Symlink(filepath.Join(archive, "cert1.pem"), filepath.Join(certsRoot, "escape.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(archive, "privkey1.pem"), filepath.Join(certsRoot, "escape.key")); err != nil {
		t.Fatal(err)
	}

	res, err := newScanner(certsRoot, outRoot).Run(t.Context())
	if err != nil {
		t.Fatalf("Run(escaping symlinks) = %v, want nil: a refused pair is not a scan error", err)
	}
	if res.Failed != 0 {
		t.Errorf("Failed = %d, want 0: an escaping symlink is a layout condition a restart cannot clear, so it must not flip health", res.Failed)
	}
	if res.Unreadable == 0 {
		t.Errorf("Unreadable = %d, want > 0: the refusal must still be reported, not silently ignored", res.Unreadable)
	}
	if res.Converted != 0 {
		t.Errorf("Converted = %d, want 0: the confined root must refuse to read outside the mount", res.Converted)
	}

	// The confinement guarantee itself: nothing was written from material outside the
	// root. A .pfx here would mean the escape succeeded.
	entries, err := os.ReadDir(outRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pfx") {
			t.Errorf("Run wrote %s from material outside the input root; the confinement was bypassed", e.Name())
		}
	}
}

// TestScannerRun_unreadable_pair_does_not_authorise_reaping pins the consequence of
// folding per-entry unreadable into ScanResult.Unreadable: a cert the scan could not
// read is absent from the seen set, so a naive orphan walk would delete its existing
// .pfx on the very scan that failed to read its input — turning an unreadable input
// into a DELETED output.
func TestScannerRun_unreadable_pair_does_not_authorise_reaping(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	certsRoot := filepath.Join(base, "live")
	archive := filepath.Join(base, "archive")
	outRoot := t.TempDir()
	for _, d := range []string{certsRoot, archive} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "escape.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(archive, "cert1.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archive, "privkey1.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(archive, "cert1.pem"), filepath.Join(certsRoot, "escape.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(archive, "privkey1.pem"), filepath.Join(certsRoot, "escape.key")); err != nil {
		t.Fatal(err)
	}

	// A prior output, as if an earlier deployment had converted this pair successfully.
	prior := filepath.Join(outRoot, "escape.pfx")
	if err := os.WriteFile(prior, []byte("prior bundle"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := newSyncScanner(certsRoot, outRoot).Run(t.Context())
	if err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if res.Removed != 0 {
		t.Errorf("Removed = %d, want 0: an input the scan could not read must never authorise deleting its output", res.Removed)
	}
	if _, statErr := os.Stat(prior); statErr != nil {
		t.Errorf("the prior .pfx was deleted (%v); an unreadable input must not become a deleted output", statErr)
	}
}

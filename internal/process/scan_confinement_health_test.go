package process_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestScannerRun_symlink_escape_is_health_neutral pins the case that motivated the
// classification change: a certificate whose /input entry is a
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
// folding per-entry unreadable into ScanResult.Unreadable: an /input tree the scan
// could not fully read cannot prove ANY output orphaned, so reconciliation is
// disabled for the whole scan.
//
// The fixture's prior output is deliberately unrelated to the unreadable cert.
// escape.crt is recorded in `seen` before its read is attempted, so its own
// escape.pfx would be protected by the direct name match even with the veto gone;
// only an output no seen certificate can claim (unrelated.pfx) can distinguish the
// per-entry statusUnreadable veto from that match. Remove the
// result.Unreadable-to-reapContext link and this fixture becomes reapable.
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

	// A prior output no certificate in this tree claims, as if an earlier deployment
	// had converted a pair since removed from /input. Only the scan-wide unreadable
	// veto keeps it: an incomplete enumeration cannot prove it orphaned.
	prior := filepath.Join(outRoot, "unrelated.pfx")
	if err := os.WriteFile(prior, []byte("prior bundle"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := newSyncScanner(certsRoot, outRoot).Run(t.Context())
	if err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if res.Removed != 0 {
		t.Errorf("Removed = %d, want 0: a scan that could not read part of /input must never authorise deleting any output", res.Removed)
	}
	if _, statErr := os.Stat(prior); statErr != nil {
		t.Errorf("the prior .pfx was deleted (%v); an incomplete input enumeration must not become a deleted output", statErr)
	}
}

// TestScannerRun_directory_in_cert_path_does_not_authorise_reaping pins the
// classification of a DIRECTORY occupying a <name>.crt path. The walk cannot read a
// certificate out of it, so it is one unreadable sub-path: health-neutral (no restart
// clears it) but enough to prove the input enumeration is incomplete.
//
// The reaping half is why this matters. A second, valid pair in the same tree means the
// scan otherwise looks complete, so under OUTPUT_LIFECYCLE=sync reconciliation would see
// blocked.pfx with no matching seen certificate and delete a still-live bundle whose
// source path does exist — just in an unusable shape.
//
// The per-path log record for this arm is Debug, pinned by
// TestWalkLogPolicy_per_path_lines_are_debug_only: the counter this test asserts is what
// raises the aggregate WARN, so the operator-visible signal is that aggregate, not the
// per-path line.
func TestScannerRun_directory_in_cert_path_does_not_authorise_reaping(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	// A valid pair, so the scan has something to convert and the tree does not look
	// empty: without it, reconciliation would have no reason to consider itself complete.
	anchorCert, anchorKey := testcerts.GenerateSelfSignedCert(t, "anchor.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "anchor.crt"), anchorCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certsRoot, "anchor.key"), anchorKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(certsRoot, "blocked.crt"), 0o750); err != nil {
		t.Fatal(err)
	}

	// A prior output for the blocked name, as if it had converted before the directory
	// took its place.
	prior := filepath.Join(outRoot, "blocked.pfx")
	if err := os.WriteFile(prior, []byte("prior bundle"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := newSyncScanner(certsRoot, outRoot).Run(t.Context())
	if err != nil {
		t.Fatalf("Run = %v, want nil (a directory in a cert path is not a scan error)", err)
	}
	if res.Unreadable != 1 {
		t.Errorf("Unreadable = %d, want 1: a directory in a <name>.crt path is a cert the scan could not read", res.Unreadable)
	}
	if res.Failed != 0 {
		t.Errorf("Failed = %d, want 0: a layout condition no restart can clear must not flip health", res.Failed)
	}
	if res.Removed != 0 {
		t.Errorf("Removed = %d, want 0: an incomplete input enumeration must never authorise reaping", res.Removed)
	}
	if _, statErr := os.Stat(prior); statErr != nil {
		t.Errorf("blocked.pfx was deleted (%v); a cert path the scan could not read must not become a deleted output", statErr)
	}
	if res.Converted != 1 {
		t.Errorf("Converted = %d, want 1: the unrelated valid pair must still convert", res.Converted)
	}
}

// TestScannerRun_dangling_cert_symlink_stays_an_unreadable_path pins the steady-state
// side of the ENOENT split. A .crt that is a symlink to a target that does not exist
// hands the confined read the SAME ENOENT a renewal race does, but it is not a race:
// the link is still there, so every future scan gets the same answer and that
// certificate produces no PFX until an operator fixes the link. It therefore belongs
// in ScanResult.Unreadable — the count behind the documented unreadable-path alert and
// its /input remediation — and NOT in Vanished, whose Debug-only reporting would leave
// the condition invisible at the default log level forever.
//
// The transient arm (a path that is genuinely gone, or replaced under the read) is
// pinned by TestNoteUnreadableInput_levels, where the filesystem state can be arranged
// exactly; reaching it from Run would need a deletion racing the scan's own read.
//
// Either outcome stays health-neutral and still blocks reaping.
func TestScannerRun_dangling_cert_symlink_stays_an_unreadable_path(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	_, keyPEM := testcerts.GenerateSelfSignedCert(t, "gone.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(certsRoot, "gone.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// The cert entry exists for the walk and its target never will. A RELATIVE target
	// inside the root, so the confined read reaches ENOENT rather than a confinement
	// refusal (which is a different unreadable case, counted the same way).
	if err := os.Symlink("already-renewed.pem", filepath.Join(certsRoot, "gone.crt")); err != nil {
		t.Fatal(err)
	}

	// A prior output nothing in this tree claims: the unreadable cert must not authorise
	// reaping it either, because the scan did not enumerate the whole tree.
	prior := filepath.Join(outRoot, "unrelated.pfx")
	if err := os.WriteFile(prior, []byte("prior bundle"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := newSyncScanner(certsRoot, outRoot).Run(t.Context())
	if err != nil {
		t.Fatalf("Run(dangling cert symlink) = %v, want nil: an unreadable input is not a scan error", err)
	}
	if res.Unreadable != 1 {
		t.Errorf("Unreadable = %d, want 1: a link whose target is missing on every scan is the steady-state condition an operator must hear about", res.Unreadable)
	}
	if res.Vanished != 0 {
		t.Errorf("Vanished = %d, want 0: a symlink that is still there did not vanish, and reporting it as the renewal race hides it at Debug forever", res.Vanished)
	}
	if res.Failed != 0 {
		t.Errorf("Failed = %d, want 0: an unreadable input is health-neutral, because no restart clears it", res.Failed)
	}
	if res.Removed != 0 {
		t.Errorf("Removed = %d, want 0: a scan that missed part of /input cannot prove any output orphaned", res.Removed)
	}
	if _, statErr := os.Stat(prior); statErr != nil {
		t.Errorf("the prior .pfx was deleted (%v); an incomplete input enumeration must not become a deleted output", statErr)
	}
}

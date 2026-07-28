package process

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

// TestStoreReconcile_reports_an_output_tree_it_cannot_enumerate pins the arm that
// fires when the ORPHAN WALK cannot enumerate /output at its ROOT, as opposed to
// under it: the walk error must reach the operator at WARN with the /output
// ownership hint, and it must degrade to "reap nothing" rather than fail the scan,
// because a scan error there would flip health over a condition the WARN already
// names and a restart cannot fix.
//
// Both halves are load-bearing and neither is observable elsewhere. Swallow the
// root-level error and orphans() returns an empty candidate list, so sync mode
// reports nothing to reap and looks exactly like a healthy tree; return it as an
// error instead and a mount whose permissions an operator has to fix pins the
// container unhealthy.
//
// A closed root is the failure injection: it fails at the tree root itself, which
// is the shape a chmod-based test cannot produce when the suite runs as uid 0.
// Runs serially: it swaps slog.Default().
func TestStoreReconcile_reports_an_output_tree_it_cannot_enumerate(t *testing.T) {
	// Spelled out rather than imported from the production const: an operator's log
	// query keys on these words, so a silent rewording must fail here.
	const wantMsg = "could not enumerate output orphans; orphan removal is disabled for this scan"

	dir := t.TempDir()
	orphan := filepath.Join(dir, "orphan.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("setup: root.Close: %v", err)
	}
	s := &store{root: root}
	logs := captureLogs(t)

	// sync over a tree holding one orphan: the mode that would delete, so nothing
	// about the arrangement excuses the refusal except the unwalkable tree.
	deleted, err := s.reconcile(t.Context(), outputpolicy.LifecycleSync, map[string]struct{}{"a.crt": {}},
		&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})
	if err != nil {
		t.Fatalf("reconcile(unwalkable output tree) = error %v, want nil: an unreadable /output is an"+
			" operator condition a restart cannot fix, so it must not fail the scan", err)
	}
	if deleted != 0 {
		t.Errorf("reconcile(unwalkable output tree) deleted = %d, want 0", deleted)
	}
	if got := logs.CountLevel(slog.LevelWarn, wantMsg); got != 1 {
		t.Fatalf("reconcile(unwalkable output tree) logged %q at WARN %d times, want exactly 1: %q",
			wantMsg, got, logs.Messages())
	}
	if _, ok := logs.AttrValue(wantMsg, "error"); !ok {
		t.Errorf("reconcile(unwalkable output tree) logged %q with no error attribute, want the walk"+
			" failure carried so the operator can diagnose it: %q", wantMsg, logs.Messages())
	}
	if got, ok := logs.AttrValue(wantMsg, "remediation"); !ok || got != outputPermRemediation {
		t.Errorf("reconcile(unwalkable output tree) logged remediation %q, want %q", got, outputPermRemediation)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Errorf("a bundle was deleted on a scan that could not enumerate the output tree: %v", statErr)
	}
}

// TestStoreWrite_creates_the_parent_directory pins that a nested output path has its
// parent created rather than failing, so an input tree with domain subdirectories
// mirrors into the output tree.
func TestStoreWrite_creates_the_parent_directory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}

	if err := s.write(t.Context(), filepath.Join("example.com", "cert.pfx"), []byte("pfx")); err != nil {
		t.Fatalf("store.write(nested path) = error %v, want nil", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "example.com", "cert.pfx"))
	if err != nil {
		t.Fatalf("read written pfx: %v", err)
	}
	if string(got) != "pfx" {
		t.Errorf("written content = %q, want %q", got, "pfx")
	}

	info, err := os.Stat(filepath.Join(dir, "example.com", "cert.pfx"))
	if err != nil {
		t.Fatalf("stat written pfx: %v", err)
	}
	// A PFX carries a private key, so the mode is part of the contract.
	if perm := info.Mode().Perm(); perm != pfxFileMode {
		t.Errorf("written mode = %o, want %o", perm, pfxFileMode)
	}
}

// TestStoreWrite_reports_a_parent_it_cannot_create pins the failure branch for an
// output path whose parent cannot exist. A path component that is already a
// regular file cannot become a directory.
//
// The directory creation is atomicfile's (via WithMkdirMode) rather than a
// hand-rolled MkdirAll, so the library's own diagnosis surfaces under this
// package's "write pfx" wrapping. What matters for the operator is that the step
// is named and the offending path appears; the precise inner wording belongs to
// the library.
func TestStoreWrite_reports_a_parent_it_cannot_create(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// "blocked" is a regular file, so MkdirAll("blocked") must fail.
	if err := os.WriteFile(filepath.Join(dir, "blocked"), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}

	err = s.write(t.Context(), filepath.Join("blocked", "cert.pfx"), []byte("pfx"))
	if err == nil {
		t.Fatal("store.write(into a path blocked by a regular file) = nil error, want a failure")
	}
	if !strings.Contains(err.Error(), "write pfx") {
		t.Errorf("error = %q, want it to name the write step", err.Error())
	}
	if !strings.Contains(err.Error(), "blocked/cert.pfx") {
		t.Errorf("error = %q, want it to name the offending path", err.Error())
	}
}

// TestStoreLstat_does_not_follow_a_symlink pins why the prior-output check lstats
// rather than stats: a symlink planted under an output name must not be accepted
// as a usable prior PFX, or unrelated content could satisfy the coherence gate.
func TestStoreLstat_does_not_follow_a_symlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.pfx")
	if err := os.WriteFile(target, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.pfx")); err != nil {
		t.Fatalf("setup: Symlink: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}

	fi, err := s.lstat("link.pfx")
	if err != nil {
		t.Fatalf("store.lstat(symlink) = error %v, want nil", err)
	}
	if fi.Mode().IsRegular() {
		t.Error("store.lstat reported a symlink as a regular file; the prior-output gate would accept it")
	}

	fi, err = s.lstat("real.pfx")
	if err != nil {
		t.Fatalf("store.lstat(regular file) = error %v, want nil", err)
	}
	if !fi.Mode().IsRegular() {
		t.Error("store.lstat did not report a regular file as regular")
	}
}

// TestStoreWrite_wraps_an_atomic_write_failure pins the "write pfx" wrapping.
//
// The error must identify the PFX write rather than parsing, encoding, or parent
// creation, each of which has its own wrapping.
//
// The failure is forced by naming an existing DIRECTORY as the output path, which
// makes the atomic rename fail regardless of the uid the test runs as (a
// permission-based failure would silently pass when running as root).
func TestStoreWrite_wraps_an_atomic_write_failure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "occupied"), 0o750); err != nil {
		t.Fatalf("setup: Mkdir: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}

	err = s.write(t.Context(), "occupied", []byte("pfx"))
	if err == nil {
		t.Fatal("store.write(onto an existing directory) = nil error, want a failure")
	}
	if !strings.Contains(err.Error(), "write pfx") {
		t.Errorf("error = %q, want it to name the pfx write step", err.Error())
	}
}

// TestStoreWrite_refuses_a_bundle_larger_than_the_read_bound pins the write-side
// half of maxPFXSize, which nothing else exercises: a bundle above the cap must be
// refused rather than written.
//
// The cap mirrors the read bound isCurrent uses. Without it, a bundle this app
// wrote could be one its own currency check calls unreadable, so every scan would
// declare it stale and rewrite it -- a permanent write loop with a fresh mtime each
// time, which the documented downstream rsync re-replicates every cycle. The
// refusal happens before the temp is staged, so the previous bundle must survive
// intact and no temp may be left behind.
func TestStoreWrite_refuses_a_bundle_larger_than_the_read_bound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}
	if err := s.write(t.Context(), "out.pfx", []byte("prior bundle")); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	err = s.write(t.Context(), "out.pfx", make([]byte, maxPFXSize+1))
	if err == nil {
		t.Fatal("store.write(over maxPFXSize) = nil error, want a refusal: a bundle this app writes above the cap is one its own currency check would call unreadable")
	}
	if !strings.Contains(err.Error(), "write pfx") || !strings.Contains(err.Error(), "too large") {
		t.Errorf("store.write(over maxPFXSize) error = %q, want it to name the write step and the size refusal", err.Error())
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "out.pfx"))
	if readErr != nil {
		t.Fatalf("read the prior bundle after the refused write: %v", readErr)
	}
	if string(got) != "prior bundle" {
		t.Errorf("prior bundle = %q, want %q: the cap is checked before the temp is staged, so a refusal must leave the previous bundle intact", got, "prior bundle")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the output directory holds %d entries, want 1: a refused write must stage no temp file", len(entries))
	}
}

// TestStoreIsCurrent_names_a_non_regular_prior_output pins the WARN on the arm
// that refuses a prior output which is not a regular file. Nothing else records it:
// the verdict is "stale, regenerate", and for the two shapes covered here the
// rewrite that follows FAILS (atomicfile refuses a symlink target outright, and a
// directory cannot be renamed over), so this line is what names the occupied output
// path before the bare conversion error arrives. A device node, FIFO or socket IS
// replaced by the rename instead, which makes this line that case's only trace.
// Runs serially: it swaps slog.Default().
func TestStoreIsCurrent_names_a_non_regular_prior_output(t *testing.T) {
	const wantMsg = "prior output path is not a regular file; regenerating"
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, dir string)
	}{
		{"a symlink is refused without being followed", func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "elsewhere.pfx")
			if err := os.WriteFile(target, []byte("unrelated"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "out.pfx")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a directory is refused", func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "out.pfx"), 0o750); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.plant(t, dir)
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			defer root.Close()
			s := &store{root: root}
			logs := captureLogs(t)

			// want is never dereferenced on this arm: the verdict is reached from the
			// lstat alone, before any bundle is read.
			current, err := s.isCurrent(t.Context(), "out.pfx", nil, convert.EncNameModern2023, "pw")

			if err != nil || current {
				t.Fatalf("isCurrent(non-regular) = %v, %v, want false, nil: an occupied output path is never a usable prior bundle", current, err)
			}
			if got := logs.CountLevel(slog.LevelWarn, wantMsg); got != 1 {
				t.Fatalf("isCurrent(non-regular) logged %q, want %q once at WARN", logs.Messages(), wantMsg)
			}
			if !logs.HasAttr(wantMsg, "path", "out.pfx") {
				t.Errorf("isCurrent(non-regular) logged %q, want path=out.pfx so the operator can identify the occupied output", logs.Messages())
			}
			if _, ok := logs.AttrValue(wantMsg, "mode"); !ok {
				t.Errorf("isCurrent(non-regular) logged %q, want the mode named so the operator knows what occupies the path", logs.Messages())
			}
			if _, ok := logs.AttrValue(wantMsg, "remediation"); !ok {
				t.Errorf("isCurrent(non-regular) logged %q, want a remediation hint", logs.Messages())
			}
		})
	}
}

// TestStoreIsCurrent_reports_a_bundle_that_vanishes_mid_inspection pins the two arms
// isCurrent takes when the prior bundle disappears after the lstat that classified it
// as a usable regular file: the tightening whose RESULT cannot be observed, and the
// read that then finds nothing.
//
// Both are reachable on a co-mounted /output -- a second writer, or a restore that
// replaces the tree while a scan runs -- and neither is named anywhere else. The
// tightening arm is the one a plausible simplification silently inverts: drop
// chmodAndObserve's re-stat error and the zero FileMode it returns is not laxer than
// policy, so the switch takes its DEFAULT arm and reports "tightened the file mode of
// a prior pfx" at INFO, telling an operator that private-key permissions were repaired
// on a bundle this app can no longer see at all. The read arm must stay a WARN plus a
// stale verdict rather than an error: an error here fails the pair and pins the
// container unhealthy over a condition the rewrite itself fixes.
//
// want is never dereferenced: both verdicts are reached before any bundle is decoded.
// The chmod seam stands in for the timing, exactly as the untightenable-mode test uses
// it for a filesystem that stores no permission bits; neither is stageable in a temp
// directory. Runs serially: it swaps slog.Default() and the chmod seam.
func TestStoreIsCurrent_reports_a_bundle_that_vanishes_mid_inspection(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}
	if err := s.write(t.Context(), "out.pfx", []byte("prior bundle")); err != nil {
		t.Fatalf("setup: write: %v", err)
	}
	// Lax enough that tightenMode acts at all; the vanishing happens inside it.
	if err := os.Chmod(filepath.Join(dir, "out.pfx"), 0o644); err != nil {
		t.Fatalf("setup: Chmod: %v", err)
	}
	prev := chmodInRoot
	chmodInRoot = func(r *os.Root, name string, mode os.FileMode) error {
		if err := r.Chmod(name, mode); err != nil {
			return err
		}
		return r.Remove(name)
	}
	t.Cleanup(func() { chmodInRoot = prev })

	// Spelled out rather than imported from the production consts: an operator's log
	// query keys on these words, so a silent rename must fail here.
	const notTightenedMsg = "prior pfx is more permissive than policy and could not be tightened"
	const tightenedMsg = "tightened the file mode of a prior pfx"
	const unreadableMsg = "cannot read prior pfx; regenerating"

	logs := captureLogs(t)
	current, err := s.isCurrent(t.Context(), "out.pfx", nil, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("isCurrent(bundle removed mid-inspection) = error %v, want nil: an unreadable prior bundle is"+
			" something this app fixes by rewriting, not a failure that flips health", err)
	}
	if current {
		t.Error("isCurrent(bundle removed mid-inspection) = true, want false: a bundle that is not there cannot be the current one")
	}
	if got := logs.CountLevel(slog.LevelWarn, notTightenedMsg); got != 1 {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q at WARN %d times, want exactly 1: %q",
			notTightenedMsg, got, logs.Messages())
	}
	if _, ok := logs.AttrValue(notTightenedMsg, "error"); !ok {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q without an error attribute, want the re-stat"+
			" failure carried so the operator learns the mode was never observed: %q", notTightenedMsg, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelInfo, tightenedMsg); got != 0 {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q %d times, want 0: the chmod's result was never"+
			" observed, so claiming the repair tells the operator the opposite of the truth: %q", tightenedMsg, got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelWarn, unreadableMsg); got != 1 {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q at WARN %d times, want exactly 1: %q",
			unreadableMsg, got, logs.Messages())
	}
	if !logs.HasAttr(unreadableMsg, "path", "out.pfx") {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q, want path=out.pfx so the operator can identify"+
			" the bundle: %q", unreadableMsg, logs.Messages())
	}
	if _, ok := logs.AttrValue(unreadableMsg, "remediation"); !ok {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q without a remediation hint: %q", unreadableMsg, logs.Messages())
	}
}

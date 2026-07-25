package process

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStoreWrite_creates_the_parent_directory pins the half of store.write that
// used to sit in scanWalk.convertEntry as an inline MkdirAll: a nested output path
// must have its directory created rather than failing the entry, so an input tree
// with domain subdirectories mirrors into the output tree.
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

// TestStoreWrite_reports_a_directory_it_cannot_create pins the failure branch.
// This replaces an equivalent assertion that lived against convert's retired
// write helper: the write half moved to this package, so its error path is tested
// here. A path component that already exists as a regular file cannot become a
// directory, and the operator needs the reason named rather than a bare EEXIST.
func TestStoreWrite_reports_a_directory_it_cannot_create(t *testing.T) {
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
	if !strings.Contains(err.Error(), "create output directory") {
		t.Errorf("error = %q, want it to name the directory creation step", err.Error())
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
// This assertion used to live against convert's retired write helper. The write
// moved here, so its error contract did too: a caller reading the log needs to
// know the failure was the PFX write rather than the parse, the encode, or the
// directory creation, each of which has its own wrapping.
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

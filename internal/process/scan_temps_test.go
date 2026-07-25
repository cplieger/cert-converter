package process_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestScannerRun_reaps_only_stale_output_temps pins the stale-temp sweep Run
// performs across the whole output tree: a temp orphaned by an interrupted
// atomic write (older than the one-hour cutoff) is reclaimed at the top level
// and in nested output directories alike, while a temp from a concurrent
// in-flight write and any caller-owned file in /output are left alone. A sweep
// that widened its match or its age window would delete live output.
func TestScannerRun_reaps_only_stale_output_temps(t *testing.T) {
	t.Parallel()
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	stale := filepath.Join(outRoot, ".atomicfile-123456.tmp")
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	// atomicfile stages its temp in the TARGET directory, so a nested cert
	// (input/example.com/cert.crt) orphans its temp in the matching nested
	// output directory; the sweep must recurse to reclaim it.
	nestedDir := filepath.Join(outRoot, "acme-v02", "example.com")
	if err := os.MkdirAll(nestedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	nestedStale := filepath.Join(nestedDir, ".atomicfile-654321.tmp")
	if err := os.WriteFile(nestedStale, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(nestedStale, old, old); err != nil {
		t.Fatal(err)
	}

	fresh := filepath.Join(outRoot, ".atomicfile-999999.tmp")
	if err := os.WriteFile(fresh, []byte("in flight"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(outRoot, "existing.pfx")
	if err := os.WriteFile(keep, []byte("owned by the operator"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keep, old, old); err != nil {
		t.Fatal(err)
	}

	scanner := newScanner(certsRoot, outRoot)
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}

	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("os.Stat(stale temp) error = %v, want fs.ErrNotExist (an orphaned temp must be reaped)", err)
	}
	if _, err := os.Stat(nestedStale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("os.Stat(nested stale temp) error = %v, want fs.ErrNotExist (the sweep must recurse into output subdirectories)", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("os.Stat(fresh temp) = %v, want nil (a temp from an in-flight write must survive)", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("os.Stat(%q) = %v, want nil (a caller-owned output file must never be reaped)", keep, err)
	}
}

// TestScannerRun_temp_sweep_stays_inside_the_output_root pins the confinement of
// the recursive stale-temp sweep: the walk, the stat and the unlink are all
// root-relative, so an output subdirectory replaced by a symlink pointing out of
// the volume cannot redirect a deletion outside it, while a genuinely nested
// orphaned temp is still reclaimed.
func TestScannerRun_temp_sweep_stays_inside_the_output_root(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	certsRoot := filepath.Join(base, "in")
	outRoot := filepath.Join(base, "out")
	outside := filepath.Join(base, "outside")
	nestedDir := filepath.Join(outRoot, "real", "nested")
	for _, dir := range []string{certsRoot, nestedDir, outside} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)

	// A stale-looking temp outside the volume, reachable only by following the
	// symlink below. It must survive.
	outsideTemp := filepath.Join(outside, ".atomicfile-111111.tmp")
	if err := os.WriteFile(outsideTemp, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(outsideTemp, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(outRoot, "escape")); err != nil {
		t.Fatal(err)
	}

	nestedTemp := filepath.Join(nestedDir, ".atomicfile-222222.tmp")
	if err := os.WriteFile(nestedTemp, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(nestedTemp, old, old); err != nil {
		t.Fatal(err)
	}

	if _, err := newScanner(certsRoot, outRoot).Run(t.Context()); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}

	if _, err := os.Stat(outsideTemp); err != nil {
		t.Errorf("os.Stat(%q) = %v, want nil (the sweep must not delete through a symlinked output subdirectory)", outsideTemp, err)
	}
	if _, err := os.Stat(nestedTemp); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("os.Stat(nested stale temp) error = %v, want fs.ErrNotExist (a real nested orphan must still be reaped)", err)
	}
}

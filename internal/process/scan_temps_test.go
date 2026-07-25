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
// performs on the output directory: a temp orphaned by an interrupted atomic
// write (older than the one-hour cutoff) is reclaimed, while a temp from a
// concurrent in-flight write and any caller-owned file in /output are left
// alone. A sweep that widened its match or its age window would delete live
// output.
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
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("os.Stat(fresh temp) = %v, want nil (a temp from an in-flight write must survive)", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("os.Stat(%q) = %v, want nil (a caller-owned output file must never be reaped)", keep, err)
	}
}

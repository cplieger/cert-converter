package process

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

func newVerdictScanner(certsRoot, outRoot string, opts Options) *Scanner {
	opts.CertsRoot, opts.OutRoot = certsRoot, outRoot
	opts.Password, opts.Encoder = "pw", convert.EncNameModern2023
	return New(&opts)
}

// TestScannerRun_reports_each_verdict pins the verdicts Run derives beside the
// counts. The end-of-scan record and the log rules read each one, so a verdict
// that stays false while its WARN fires leaves the condition with no alert.
func TestScannerRun_reports_each_verdict(t *testing.T) {
	t.Run("a clean scan reports nothing", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, in, "live")
		res, err := newVerdictScanner(in, out, Options{Lifecycle: outputpolicy.LifecycleSync}).Run(t.Context())
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
		if res.Outcome != OutcomeComplete || res.NoSources || res.AllExcluded ||
			res.OrphanRemovalDisabled || res.PreviousLayoutRetained || res.CleanupDegraded {
			t.Errorf("Run(clean tree) = %+v, want outcome complete and every verdict false", res)
		}
	})
	t.Run("an empty tree has no sources", func(t *testing.T) {
		res, err := newVerdictScanner(t.TempDir(), t.TempDir(), Options{}).Run(t.Context())
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
		if !res.NoSources {
			t.Errorf("Run(empty /input) NoSources = false, want true")
		}
	})
	t.Run("certificates without keys are no sources", func(t *testing.T) {
		in := t.TempDir()
		writeSelfSignedPair(t, in, "lone")
		if err := os.Remove(filepath.Join(in, "lone.key")); err != nil {
			t.Fatal(err)
		}
		res, err := newVerdictScanner(in, t.TempDir(), Options{}).Run(t.Context())
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
		if !res.NoSources {
			t.Errorf("Run(every .crt without its .key) = %+v, want NoSources", res)
		}
	})
	t.Run("an unreadable path keeps the whole-tree verdicts unclaimed", func(t *testing.T) {
		in := t.TempDir()
		if err := os.Mkdir(filepath.Join(in, "dir.crt"), 0o750); err != nil {
			t.Fatal(err)
		}
		res, err := newVerdictScanner(in, t.TempDir(), Options{Lifecycle: outputpolicy.LifecycleSync}).Run(t.Context())
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
		if res.NoSources {
			t.Errorf("Run(unreadable source path) NoSources = true, want false: a partial walk proves nothing about the tree")
		}
		if !res.OrphanRemovalDisabled {
			t.Errorf("Run(unreadable source path, sync) OrphanRemovalDisabled = false, want true")
		}
	})
	t.Run("every source excluded", func(t *testing.T) {
		in := t.TempDir()
		writeSelfSignedPair(t, in, "skip")
		exclude := layout.NewExcludeSet([]string{"skip.crt"})
		res, err := newVerdictScanner(in, t.TempDir(), Options{Exclude: exclude}).Run(t.Context())
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
		if !res.AllExcluded || res.NoSources {
			t.Errorf("Run(every source excluded) = %+v, want AllExcluded and not NoSources", res)
		}
	})
	t.Run("a budget stop", func(t *testing.T) {
		in := t.TempDir()
		for _, stem := range []string{"a", "b", "c"} {
			writeSelfSignedPair(t, in, stem)
		}
		res, err := newVerdictScanner(in, t.TempDir(), Options{MaxScanEntries: 2}).Run(t.Context())
		if err != nil {
			t.Fatalf("Run(budget stop) = %v, want nil: the stop is reported, not failed", err)
		}
		if res.Outcome != OutcomeBudgetStopped || res.NoSources {
			t.Errorf("Run(budget stop) = %+v, want outcome budget_stopped and no whole-tree verdict", res)
		}
	})
	t.Run("sync keeps the previous layout's tree", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, in, "live")
		deep := filepath.Join(out, "issuer", "site")
		if err := os.MkdirAll(deep, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(deep, "old.pfx"), []byte("pfx"), 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := newVerdictScanner(in, out, Options{
			Lifecycle: outputpolicy.LifecycleSync, Layout: outputpolicy.LayoutFlat,
		}).Run(t.Context())
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
		if !res.PreviousLayoutRetained {
			t.Errorf("Run(mirror-laid orphan, flat by default, sync) PreviousLayoutRetained = false, want true")
		}
	})
	t.Run("the last sweep's verdict carries to scans that do not sweep", func(t *testing.T) {
		in := t.TempDir()
		writeSelfSignedPair(t, in, "live")
		s := newVerdictScanner(in, t.TempDir(), Options{})
		s.cleanupDegraded = true
		s.lastSweep = sweepClock()
		res, err := s.Run(t.Context())
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
		if !res.CleanupDegraded {
			t.Errorf("Run(no sweep due, last sweep degraded) CleanupDegraded = false, want true")
		}
	})
}

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

// hideInput moves /input away, so the next Run cannot open its root, and
// returns the function that puts it back.
func hideInput(t *testing.T, in string) (restore func()) {
	t.Helper()
	away := in + ".away"
	if err := os.Rename(in, away); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.Rename(away, in); err != nil {
			t.Fatal(err)
		}
	}
}

// abortedRun runs s with /input hidden and requires the scan to abort.
func abortedRun(t *testing.T, s *Scanner, in string) ScanResult {
	t.Helper()
	restore := hideInput(t, in)
	defer restore()
	res, err := s.Run(t.Context())
	if err == nil || res.Outcome != OutcomeAborted {
		t.Fatalf("Run(/input missing) = (%+v, %v), want outcome aborted and the open error", res, err)
	}
	return res
}

// TestScannerRun_keeps_unproven_conditions_on_an_incomplete_scan pins that a
// scan which did not enumerate the whole tree still reports what the last
// enumeration found, raised by what it saw itself: the record's rules read the
// latest scan, so a zero here would resolve an alert while its problem holds.
func TestScannerRun_keeps_unproven_conditions_on_an_incomplete_scan(t *testing.T) {
	t.Run("a failed conversion holds through an unopenable root and clears at the next complete scan", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, in, "blocked")
		blocker := filepath.Join(out, "blocked.pfx")
		if err := os.Mkdir(blocker, 0o750); err != nil {
			t.Fatal(err)
		}
		s := newVerdictScanner(in, out, Options{Lifecycle: outputpolicy.LifecycleKeep})
		first, err := s.Run(t.Context())
		if err != nil || first.Failed != 1 {
			t.Fatalf("Run(write blocked) = (%+v, %v), want Failed 1", first, err)
		}
		if res := abortedRun(t, s, in); res.Failed != 1 {
			t.Errorf("Run(/input missing after a failed conversion) Failed = %d, want 1", res.Failed)
		}
		if err := os.Remove(blocker); err != nil {
			t.Fatal(err)
		}
		res, err := s.Run(t.Context())
		if err != nil || res.Failed != 0 || res.Outcome != OutcomeComplete {
			t.Errorf("Run(blocker removed) = (%+v, %v), want a complete scan with Failed 0", res, err)
		}
	})
	t.Run("no sources holds through an unopenable root", func(t *testing.T) {
		in := t.TempDir()
		s := newVerdictScanner(in, t.TempDir(), Options{})
		if first, err := s.Run(t.Context()); err != nil || !first.NoSources {
			t.Fatalf("Run(empty /input) = (%+v, %v), want NoSources", first, err)
		}
		if res := abortedRun(t, s, in); !res.NoSources {
			t.Errorf("Run(/input missing after an empty scan) NoSources = false, want true")
		}
	})
	t.Run("a walk with an unreadable path keeps no sources unless it found one", func(t *testing.T) {
		in := t.TempDir()
		s := newVerdictScanner(in, t.TempDir(), Options{})
		if first, err := s.Run(t.Context()); err != nil || !first.NoSources {
			t.Fatalf("Run(empty /input) = (%+v, %v), want NoSources", first, err)
		}
		if err := os.Mkdir(filepath.Join(in, "dir.crt"), 0o750); err != nil {
			t.Fatal(err)
		}
		if res, err := s.Run(t.Context()); err != nil || !res.NoSources {
			t.Errorf("Run(only an unreadable path added) = (%+v, %v), want NoSources kept", res, err)
		}
		writeSelfSignedPair(t, in, "live")
		if res, err := s.Run(t.Context()); err != nil || res.NoSources {
			t.Errorf("Run(a pair beside the unreadable path) = (%+v, %v), want NoSources false: the scan found a source", res, err)
		}
	})
	t.Run("a walk with an unreadable path drops every source excluded once it found one that is not", func(t *testing.T) {
		in := t.TempDir()
		writeSelfSignedPair(t, in, "skip")
		s := newVerdictScanner(in, t.TempDir(), Options{Exclude: layout.NewExcludeSet([]string{"skip.crt"})})
		if first, err := s.Run(t.Context()); err != nil || !first.AllExcluded {
			t.Fatalf("Run(every source excluded) = (%+v, %v), want AllExcluded", first, err)
		}
		if err := os.Mkdir(filepath.Join(in, "dir.crt"), 0o750); err != nil {
			t.Fatal(err)
		}
		if res, err := s.Run(t.Context()); err != nil || !res.AllExcluded {
			t.Errorf("Run(only an unreadable path added) = (%+v, %v), want AllExcluded kept", res, err)
		}
		writeSelfSignedPair(t, in, "live")
		if res, err := s.Run(t.Context()); err != nil || res.AllExcluded {
			t.Errorf("Run(a pair that is not excluded) = (%+v, %v), want AllExcluded false", res, err)
		}
	})
	t.Run("a degraded cleanup holds through an unopenable root", func(t *testing.T) {
		in := t.TempDir()
		writeSelfSignedPair(t, in, "live")
		s := newVerdictScanner(in, t.TempDir(), Options{})
		s.cleanupDegraded = true
		s.lastSweep = sweepClock()
		if res := abortedRun(t, s, in); !res.CleanupDegraded {
			t.Errorf("Run(/input missing, last sweep degraded) CleanupDegraded = false, want true")
		}
	})
	t.Run("removals are this scan's own", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, in, "live")
		if err := os.WriteFile(filepath.Join(out, "gone.pfx"), []byte("pfx"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := newVerdictScanner(in, out, Options{Lifecycle: outputpolicy.LifecycleSync})
		if first, err := s.Run(t.Context()); err != nil || first.Removed != 1 {
			t.Fatalf("Run(one orphan, sync) = (%+v, %v), want Removed 1", first, err)
		}
		if res := abortedRun(t, s, in); res.Removed != 0 {
			t.Errorf("Run(/input missing) Removed = %d, want 0: it removed nothing", res.Removed)
		}
	})
	// a sorts first, so the two-entry budget's prefix holds the a pair; z is past it.
	budgetStopped := func(t *testing.T, s *Scanner) ScanResult {
		t.Helper()
		s.opts.MaxScanEntries = 2
		res, err := s.Run(t.Context())
		if err != nil || res.Outcome != OutcomeBudgetStopped {
			t.Fatalf("Run(budget 2) = (%+v, %v), want a budget stop", res, err)
		}
		return res
	}
	threePairs := func(t *testing.T, blocked string) (in, out string) {
		t.Helper()
		in, out = t.TempDir(), t.TempDir()
		for _, stem := range []string{"a", "b", "z"} {
			writeSelfSignedPair(t, in, stem)
		}
		if blocked != "" {
			if err := os.Mkdir(filepath.Join(out, blocked+".pfx"), 0o750); err != nil {
				t.Fatal(err)
			}
		}
		return in, out
	}
	t.Run("a budget stop keeps a failure past its prefix", func(t *testing.T) {
		in, out := threePairs(t, "z")
		s := newVerdictScanner(in, out, Options{Lifecycle: outputpolicy.LifecycleKeep})
		if first, err := s.Run(t.Context()); err != nil || first.Failed != 1 {
			t.Fatalf("Run(z blocked) = (%+v, %v), want Failed 1", first, err)
		}
		if res := budgetStopped(t, s); res.Failed != 1 {
			t.Errorf("Run(budget stop before z) Failed = %d, want the last enumeration's 1", res.Failed)
		}
	})
	t.Run("a budget stop reports a failure its prefix saw", func(t *testing.T) {
		in, out := threePairs(t, "")
		s := newVerdictScanner(in, out, Options{Lifecycle: outputpolicy.LifecycleKeep})
		if first, err := s.Run(t.Context()); err != nil || first.Failed != 0 {
			t.Fatalf("Run(clean) = (%+v, %v), want Failed 0", first, err)
		}
		blocker := filepath.Join(out, "a.pfx")
		if err := os.Remove(blocker); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(blocker, 0o750); err != nil {
			t.Fatal(err)
		}
		writeSelfSignedPair(t, in, "a")
		if res := budgetStopped(t, s); res.Failed != 1 {
			t.Errorf("Run(budget stop, a blocked in the prefix) Failed = %d, want 1", res.Failed)
		}
	})
	t.Run("an unopenable root keeps every carried condition", func(t *testing.T) {
		in := t.TempDir()
		s := newVerdictScanner(in, t.TempDir(), Options{})
		prev := ScanResult{
			Orphan: 2, Failed: 3, Unreadable: 4, Unresolved: 5, Unwritable: 6, Collided: 7,
			NoSources: true, AllExcluded: true,
			OrphanRemovalDisabled: true, PreviousLayoutRetained: true,
		}
		s.lastReported = prev
		res := abortedRun(t, s, in)
		if res.Orphan != prev.Orphan {
			t.Errorf("Run(/input missing) Orphan = %d, want %d", res.Orphan, prev.Orphan)
		}
		if res.Failed != prev.Failed {
			t.Errorf("Run(/input missing) Failed = %d, want %d", res.Failed, prev.Failed)
		}
		if res.Unreadable != prev.Unreadable {
			t.Errorf("Run(/input missing) Unreadable = %d, want %d", res.Unreadable, prev.Unreadable)
		}
		if res.Unresolved != prev.Unresolved {
			t.Errorf("Run(/input missing) Unresolved = %d, want %d", res.Unresolved, prev.Unresolved)
		}
		if res.Unwritable != prev.Unwritable {
			t.Errorf("Run(/input missing) Unwritable = %d, want %d", res.Unwritable, prev.Unwritable)
		}
		if res.Collided != prev.Collided {
			t.Errorf("Run(/input missing) Collided = %d, want %d", res.Collided, prev.Collided)
		}
		if !res.NoSources {
			t.Errorf("Run(/input missing) NoSources = false, want true")
		}
		if !res.AllExcluded {
			t.Errorf("Run(/input missing) AllExcluded = false, want true")
		}
		if !res.OrphanRemovalDisabled {
			t.Errorf("Run(/input missing) OrphanRemovalDisabled = false, want true")
		}
		if !res.PreviousLayoutRetained {
			t.Errorf("Run(/input missing) PreviousLayoutRetained = false, want true")
		}
	})
}

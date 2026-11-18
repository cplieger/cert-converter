package process

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/go/filesafe"
)

// sourcesClock is the conversion time every test in this file pins.
var sourcesClock = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func pinConversionClock(t *testing.T, at *time.Time) {
	t.Helper()
	prev := conversionClock
	conversionClock = func() time.Time { return *at }
	t.Cleanup(func() { conversionClock = prev })
}

func newSourcesScanner(inDir, outDir string, adjust func(*Options)) *Scanner {
	opts := &Options{CertsRoot: inDir, OutRoot: outDir, Password: "pw", Encoder: convert.EncNameModern2023}
	if adjust != nil {
		adjust(opts)
	}
	return New(opts)
}

// scanSources runs s, requires its Sources sorted by Path, and returns them by path.
func scanSources(t *testing.T, s *Scanner) map[string]SourceState {
	t.Helper()
	result, _ := s.Run(t.Context())
	if !slices.IsSortedFunc(result.Sources, func(a, b SourceState) int { return strings.Compare(a.Path, b.Path) }) {
		t.Errorf("Run().Sources = %+v, want sorted by Path", result.Sources)
	}
	byPath := make(map[string]SourceState, len(result.Sources))
	for _, st := range result.Sources {
		byPath[st.Path] = st
	}
	return byPath
}

func writeInput(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("setup: MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("setup: WriteFile(%s): %v", path, err)
	}
}

func wantSource(t *testing.T, got map[string]SourceState, rel string, outcome SourceOutcome, converted time.Time) {
	t.Helper()
	st, ok := got[rel]
	if !ok {
		t.Errorf("Sources holds no %q, want outcome %v; got %+v", rel, outcome, got)
		return
	}
	if st.Outcome != outcome || !st.LastConverted.Equal(converted) {
		t.Errorf("Sources[%q] = {%v, %v}, want {%v, %v}", rel, st.Outcome, st.LastConverted, outcome, converted)
	}
}

func TestScanSources_names_each_source_outcome(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)

	t.Run("converted then unchanged", func(t *testing.T) {
		now = sourcesClock
		inDir, outDir := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, inDir, "site")
		s := newSourcesScanner(inDir, outDir, nil)
		wantSource(t, scanSources(t, s), "site.crt", SourceConverted, sourcesClock)
		now = sourcesClock.Add(time.Hour)
		wantSource(t, scanSources(t, s), "site.crt", SourceUnchanged, sourcesClock)
	})
	t.Run("failed", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		writeInput(t, filepath.Join(inDir, "bad.crt"), []byte("not a certificate"))
		writeInput(t, filepath.Join(inDir, "bad.key"), []byte("not a certificate"))
		wantSource(t, scanSources(t, newSourcesScanner(inDir, outDir, nil)), "bad.crt", SourceFailed, time.Time{})
	})
	t.Run("orphan", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		writeInput(t, filepath.Join(inDir, "lone.crt"), []byte("not a certificate"))
		wantSource(t, scanSources(t, newSourcesScanner(inDir, outDir, nil)), "lone.crt", SourceOrphan, time.Time{})
	})
	t.Run("unreadable", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		if err := os.Mkdir(filepath.Join(inDir, "x.crt"), 0o750); err != nil {
			t.Fatalf("setup: Mkdir: %v", err)
		}
		wantSource(t, scanSources(t, newSourcesScanner(inDir, outDir, nil)), "x.crt", SourceUnreadable, time.Time{})
	})
	t.Run("excluded", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, inDir, "site")
		s := newSourcesScanner(inDir, outDir, func(o *Options) { o.Exclude = layout.NewExcludeSet([]string{"site.crt"}) })
		wantSource(t, scanSources(t, s), "site.crt", SourceExcluded, time.Time{})
	})
	t.Run("collided", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		for _, dir := range []string{"x/shared", "y/shared"} {
			if err := os.MkdirAll(filepath.Join(inDir, dir), 0o750); err != nil {
				t.Fatalf("setup: MkdirAll: %v", err)
			}
			writeSelfSignedPair(t, filepath.Join(inDir, dir), "site")
		}
		got := scanSources(t, newSourcesScanner(inDir, outDir, func(o *Options) { o.Layout = outputpolicy.LayoutFlat }))
		wantSource(t, got, "x/shared/site.crt", SourceCollided, time.Time{})
		wantSource(t, got, "y/shared/site.crt", SourceCollided, time.Time{})
	})
	t.Run("unwritable", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, inDir, "site")
		stageOversizedBundle(t, filepath.Join(outDir, "site.pfx"))
		// The prior artifact is the only record of a conversion this process did not make.
		prior := time.Date(2029, 2, 1, 0, 0, 0, 0, time.UTC)
		if err := os.Chtimes(filepath.Join(outDir, "site.pfx"), prior, prior); err != nil {
			t.Fatalf("setup: Chtimes: %v", err)
		}
		stubWriteRefusal(t, &fs.PathError{Op: "openat", Path: "site.pfx", Err: syscall.EROFS})
		wantSource(t, scanSources(t, newSourcesScanner(inDir, outDir, nil)), "site.crt", SourceUnwritable, prior)
	})
}

func TestScanSources_partial_publication_fails_the_source(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)
	inDir, outDir := t.TempDir(), t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "partial.example.com", "ecdsa")
	writePair(t, inDir, "site", certPEM, keyPEM)
	if err := os.WriteFile(filepath.Join(outDir, "site.key"), bytes.Repeat([]byte{'x'}, len(keyPEM)), outputFileMode); err != nil {
		t.Fatalf("setup: write prior key artifact: %v", err)
	}
	// Older than any write the scan makes, so only the prior artifact dates it.
	prior := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(outDir, "site.key"), prior, prior); err != nil {
		t.Fatalf("setup: Chtimes: %v", err)
	}
	priorRead := readBoundedInRoot
	readBoundedInRoot = func(ctx context.Context, root *os.Root, name string, maxBytes int64) ([]byte, error) {
		if name == "site.key" {
			return nil, &fs.PathError{Op: "read", Path: name, Err: syscall.EACCES}
		}
		return priorRead(ctx, root, name, maxBytes)
	}
	t.Cleanup(func() { readBoundedInRoot = priorRead })
	priorWrite := writeFileInRoot
	writeFileInRoot = func(ctx context.Context, root *os.Root, name string, data []byte, opts ...filesafe.WriteOption) (filesafe.Result, error) {
		if name == "site.key" {
			return filesafe.Result{}, &fs.PathError{Op: "rename", Path: name, Err: syscall.EROFS}
		}
		return priorWrite(ctx, root, name, data, opts...)
	}
	t.Cleanup(func() { writeFileInRoot = priorWrite })

	// A new Scanner is a restart: its first scan dates the source from /output.
	s := newSourcesScanner(inDir, outDir, func(o *Options) { o.Formats = outputpolicy.Formats{PFX: true, PEM: true} })
	got := scanSources(t, s)["site.crt"]
	if got.Outcome != SourceFailed {
		t.Errorf("Sources[site.crt].Outcome = %v after one artifact was written and its sibling refused, want %v", got.Outcome, SourceFailed)
	}
	if !got.LastConverted.Equal(prior) {
		t.Errorf("Sources[site.crt].LastConverted = %v after a restart, want %v, the artifact the failed scan did not write", got.LastConverted, prior)
	}
}

// A scan that stops at MAX_SCAN_ENTRIES proves a failure fixed only for a source
// it converted, and keeps every other failure it did not reach. The root, a/, b/
// and a/site.crt fit, so the walk converts a/site.crt and stops before b/.
func TestScanSources_a_stopped_scan_counts_failures_from_the_facts(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)
	for _, c := range []struct {
		name, failing string
		fixed         bool
		wantFailed    int
		want          SourceOutcome
	}{
		{name: "fixed before the stop", failing: "a", fixed: true, wantFailed: 0, want: SourceConverted},
		{name: "past the stop", failing: "b", wantFailed: 1, want: SourceFailed},
	} {
		t.Run(c.name, func(t *testing.T) {
			inDir, outDir := t.TempDir(), t.TempDir()
			for _, dir := range []string{"a", "b"} {
				if err := os.Mkdir(filepath.Join(inDir, dir), 0o750); err != nil {
					t.Fatalf("setup: Mkdir: %v", err)
				}
				writeSelfSignedPair(t, filepath.Join(inDir, dir), "site")
			}
			bad := filepath.Join(inDir, c.failing)
			writeInput(t, filepath.Join(bad, "site.crt"), []byte("not a certificate"))
			s := newSourcesScanner(inDir, outDir, nil)
			if first, _ := s.Run(t.Context()); first.Failed != 1 {
				t.Fatalf("setup: first scan Failed = %d, want 1", first.Failed)
			}
			if c.fixed {
				writeSelfSignedPair(t, bad, "site")
			}

			s.opts.MaxScanEntries = 4
			result, err := s.Run(t.Context())
			if err != nil || result.Outcome != OutcomeBudgetStopped {
				t.Fatalf("Run(over budget) = %v, %v, want a budget stop with no error", result.Outcome, err)
			}
			// healthyAfterScan and CertConverterConversionFailed read these counts.
			if result.Failed != c.wantFailed || result.Collided != 0 {
				t.Errorf("Run(over budget) Failed, Collided = %d, %d, want %d, 0", result.Failed, result.Collided, c.wantFailed)
			}
			got := make(map[string]SourceState)
			for _, st := range result.Sources {
				got[st.Path] = st
			}
			if st := got[c.failing+"/site.crt"]; st.Outcome != c.want {
				t.Errorf("Sources[%s/site.crt].Outcome = %v, want %v", c.failing, st.Outcome, c.want)
			}
		})
	}
}

// A failed source whose key turns into a folder cannot be read, so its failure
// keeps counting, and its row keeps saying so, until a scan reaches it.
func TestScanSources_an_unread_failed_source_stays_failed(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)
	inDir, outDir := t.TempDir(), t.TempDir()
	writeInput(t, filepath.Join(inDir, "bad.crt"), []byte("not a certificate"))
	writeInput(t, filepath.Join(inDir, "bad.key"), []byte("not a key"))
	s := newSourcesScanner(inDir, outDir, nil)
	if first, _ := s.Run(t.Context()); first.Failed != 1 {
		t.Fatalf("setup: first scan Failed = %d, want 1", first.Failed)
	}
	if err := os.Remove(filepath.Join(inDir, "bad.key")); err != nil {
		t.Fatalf("setup: Remove: %v", err)
	}
	if err := os.Mkdir(filepath.Join(inDir, "bad.key"), 0o750); err != nil {
		t.Fatalf("setup: Mkdir: %v", err)
	}

	result, _ := s.Run(t.Context())
	if result.Failed != 1 {
		t.Errorf("Run(key unreadable).Failed = %d, want 1", result.Failed)
	}
	if len(result.Sources) != 1 || result.Sources[0].Outcome != SourceFailed {
		t.Errorf("Run(key unreadable).Sources = %+v, want bad.crt failed", result.Sources)
	}
}

// A walk that finishes without reading a folder cannot prove the problems under
// it gone, so their certificates keep counting in the problem counts the alert
// rules read, as their rows keep saying.
func TestScanSources_a_folder_the_walk_cannot_read_keeps_its_counts(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)
	inDir, outDir, outside := t.TempDir(), t.TempDir(), t.TempDir()
	writeInput(t, filepath.Join(inDir, "d", "lone.crt"), []byte("not a certificate"))
	writeSelfSignedPair(t, inDir, "site")
	s := newSourcesScanner(inDir, outDir, nil)
	if first, _ := s.Run(t.Context()); first.Orphan != 1 {
		t.Fatalf("setup: first scan Orphan = %d, want 1", first.Orphan)
	}
	hideBehindLink(t, inDir, outside, "d")

	result, err := s.Run(t.Context())
	if err != nil || result.Outcome != OutcomeComplete || result.Unresolved != 1 {
		t.Fatalf("Run(d/ behind a link) = %v, %v, Unresolved %d, want a finished walk with one unresolved link", result.Outcome, err, result.Unresolved)
	}
	if result.Orphan != 1 {
		t.Errorf("Run(d/ behind a link).Orphan = %d, want 1", result.Orphan)
	}
	got := make(map[string]SourceState)
	for _, st := range result.Sources {
		got[st.Path] = st
	}
	if st, ok := got["d/lone.crt"]; !ok || st.Outcome != SourceOrphan {
		t.Errorf("Sources[d/lone.crt] = %+v, %v, want orphan", st, ok)
	}
}

// A write refused for a source the scan then cannot read stays refused: the
// write-refused alert reads that count, and the table must agree with it.
func TestScanSources_an_unread_unwritable_source_stays_unwritable(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)
	inDir, outDir := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, inDir, "site")
	writeInput(t, filepath.Join(inDir, "z", "notes.txt"), []byte("not an input"))
	stageOversizedBundle(t, filepath.Join(outDir, "site.pfx"))
	stubWriteRefusal(t, &fs.PathError{Op: "openat", Path: "site.pfx", Err: syscall.EROFS})
	s := newSourcesScanner(inDir, outDir, nil)
	if first, _ := s.Run(t.Context()); first.Unwritable != 1 {
		t.Fatalf("setup: first scan Unwritable = %d, want 1", first.Unwritable)
	}
	cert := filepath.Join(inDir, "site.crt")
	if err := os.Remove(cert); err != nil {
		t.Fatalf("setup: Remove: %v", err)
	}
	if err := os.Mkdir(cert, 0o750); err != nil {
		t.Fatalf("setup: Mkdir: %v", err)
	}

	// The root, site.crt/, site.key and z/ fit; the walk stops at z/notes.txt.
	s.opts.MaxScanEntries = 4
	result, err := s.Run(t.Context())
	if err != nil || result.Outcome != OutcomeBudgetStopped {
		t.Fatalf("Run(over budget) = %v, %v, want a budget stop with no error", result.Outcome, err)
	}
	if result.Unwritable != 1 {
		t.Errorf("Run(over budget).Unwritable = %d, want 1", result.Unwritable)
	}
	if len(result.Sources) != 1 || result.Sources[0].Outcome != SourceUnwritable {
		t.Errorf("Run(over budget).Sources = %+v, want site.crt unwritable", result.Sources)
	}
}

// stoppedScan runs s under an entry budget of limit, requires a budget stop, and
// returns the result with its Sources by path.
func stoppedScan(t *testing.T, s *Scanner, limit int) (ScanResult, map[string]SourceState) {
	t.Helper()
	s.opts.MaxScanEntries = limit
	result, err := s.Run(t.Context())
	if err != nil || result.Outcome != OutcomeBudgetStopped {
		t.Fatalf("Run(over budget) = %v, %v, want a budget stop with no error", result.Outcome, err)
	}
	got := make(map[string]SourceState)
	for _, st := range result.Sources {
		got[st.Path] = st
	}
	return result, got
}

func removeInputs(t *testing.T, inDir string, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := os.Remove(filepath.Join(inDir, name)); err != nil {
			t.Fatalf("setup: Remove: %v", err)
		}
	}
}

// A scan stopped at MAX_SCAN_ENTRIES proves a source gone where it listed the
// source's folder in full, or where the source's file is gone from the folder it
// stopped in, so facts cannot pile up while the tree stays over the limit. A
// source in the stop folder that still exists keeps its fact.
func TestScanSources_a_stopped_scan_drops_a_source_gone_before_the_stop(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)

	t.Run("listed folders", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, inDir, "a")
		for _, dir := range []string{"b", "m", "z"} {
			if err := os.Mkdir(filepath.Join(inDir, dir), 0o750); err != nil {
				t.Fatalf("setup: Mkdir: %v", err)
			}
			writeSelfSignedPair(t, filepath.Join(inDir, dir), "site")
		}
		writeInput(t, filepath.Join(inDir, "b", "notes.txt"), []byte("not an input"))
		s := newSourcesScanner(inDir, outDir, nil)
		if first := scanSources(t, s); len(first) != 4 {
			t.Fatalf("setup: first scan Sources = %+v, want 4", first)
		}
		removeInputs(t, inDir, "a.crt", "a.key", "b/site.crt", "b/site.key")
		if err := os.RemoveAll(filepath.Join(inDir, "z")); err != nil {
			t.Fatalf("setup: RemoveAll: %v", err)
		}

		// The root, b/, m/, b/notes.txt and m/site.crt fit; the walk stops at
		// m/site.key, after it listed the root and b/ in full.
		_, got := stoppedScan(t, s, 5)
		for _, rel := range []string{"a.crt", "b/site.crt", "z/site.crt"} {
			if st, ok := got[rel]; ok {
				t.Errorf("Sources[%s] = %+v, want no entry: the walk listed its folder in full", rel, st)
			}
		}
		wantSource(t, got, "m/site.crt", SourceUnchanged, sourcesClock)
	})
	t.Run("stop folder, deleted failure", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		m := filepath.Join(inDir, "m")
		writeInput(t, filepath.Join(m, "early.crt"), []byte("not a certificate"))
		writeInput(t, filepath.Join(m, "early.key"), []byte("not a key"))
		writeSelfSignedPair(t, m, "late")
		s := newSourcesScanner(inDir, outDir, nil)
		if first, _ := s.Run(t.Context()); first.Failed != 1 {
			t.Fatalf("setup: first scan Failed = %d, want 1", first.Failed)
		}
		removeInputs(t, inDir, "m/early.crt", "m/early.key")

		// The root, m/ and m/late.crt fit; the walk stops at m/late.key.
		result, got := stoppedScan(t, s, 3)
		if st, ok := got["m/early.crt"]; ok {
			t.Errorf("Sources[m/early.crt] = %+v, want no entry: it is gone from the stop folder", st)
		}
		// healthyAfterScan and CertConverterConversionFailed read this count.
		if result.Failed != 0 {
			t.Errorf("Run(over budget).Failed = %d, want 0", result.Failed)
		}
	})
	t.Run("stop folder, unread source present", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		m := filepath.Join(inDir, "m")
		if err := os.Mkdir(m, 0o750); err != nil {
			t.Fatalf("setup: Mkdir: %v", err)
		}
		writeSelfSignedPair(t, m, "early")
		writeSelfSignedPair(t, m, "late")
		s := newSourcesScanner(inDir, outDir, nil)
		scanSources(t, s)

		// The root, m/ and m/early.crt fit; the walk stops at m/early.key and
		// never reaches m/late.crt.
		_, got := stoppedScan(t, s, 3)
		wantSource(t, got, "m/late.crt", SourceConverted, sourcesClock)
	})
}

func TestScanSources_a_source_that_goes_is_dropped(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)
	inDir, outDir := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, inDir, "gone")
	writeSelfSignedPair(t, inDir, "kept")
	s := newSourcesScanner(inDir, outDir, nil)
	scanSources(t, s)
	for _, name := range []string{"gone.crt", "gone.key"} {
		if err := os.Remove(filepath.Join(inDir, name)); err != nil {
			t.Fatalf("setup: Remove: %v", err)
		}
	}
	got := scanSources(t, s)
	if st, ok := got["gone.crt"]; ok {
		t.Errorf("Sources[gone.crt] = %+v after a complete scan no longer found it, want no entry", st)
	}
	wantSource(t, got, "kept.crt", SourceUnchanged, sourcesClock)
}

func TestScanSources_an_unreached_source_keeps_its_fact(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)

	t.Run("budget", func(t *testing.T) {
		inDir, outDir := t.TempDir(), t.TempDir()
		for _, dir := range []string{"a", "b", "c"} {
			if err := os.Mkdir(filepath.Join(inDir, dir), 0o750); err != nil {
				t.Fatalf("setup: Mkdir: %v", err)
			}
			writeSelfSignedPair(t, filepath.Join(inDir, dir), "site")
		}
		s := newSourcesScanner(inDir, outDir, nil)
		scanSources(t, s)
		removeInputs(t, inDir, "c/site.crt", "c/site.key")
		// The root, a/, b/ and c/ fit: the walk lists the root in full and stops
		// at a/site.crt, so it enumerated c/ and never read it.
		s.opts.MaxScanEntries = 4
		wantSource(t, scanSources(t, s), "c/site.crt", SourceConverted, sourcesClock)
	})
	t.Run("aborted", func(t *testing.T) {
		base := t.TempDir()
		inDir, outDir := filepath.Join(base, "in"), t.TempDir()
		if err := os.Mkdir(inDir, 0o750); err != nil {
			t.Fatalf("setup: Mkdir: %v", err)
		}
		writeSelfSignedPair(t, inDir, "site")
		s := newSourcesScanner(inDir, outDir, nil)
		before, err := s.Run(t.Context())
		if err != nil {
			t.Fatalf("Run(first scan) = %v", err)
		}
		if err := os.Rename(inDir, filepath.Join(base, "away")); err != nil {
			t.Fatalf("setup: Rename: %v", err)
		}
		after, err := s.Run(t.Context())
		if err == nil {
			t.Fatal("Run(input root gone) = nil error, want the open failure")
		}
		if !slices.Equal(after.Sources, before.Sources) {
			t.Errorf("Run(input root gone).Sources = %+v, want the previous scan's %+v", after.Sources, before.Sources)
		}
	})
}

func TestScanSources_restart_reads_the_newest_artifact_time(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)
	for _, mode := range []outputpolicy.Layout{outputpolicy.LayoutMirror, outputpolicy.LayoutFlat} {
		t.Run(string(mode), func(t *testing.T) {
			inDir, outDir := t.TempDir(), t.TempDir()
			writeSelfSignedPair(t, inDir, "site")
			// An excluded bundle beside the pair derives the pair's artifact names,
			// none of them its own output.
			writeInput(t, filepath.Join(inDir, "site.pfx"), []byte("never converted"))
			adjust := func(o *Options) {
				o.Layout = mode
				o.Formats = outputpolicy.Formats{PFX: true, PEM: true}
				o.Exclude = layout.NewExcludeSet([]string{"site.pfx"})
			}
			scanSources(t, newSourcesScanner(inDir, outDir, adjust))

			m0 := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
			m1 := time.Date(2029, 6, 1, 0, 0, 0, 0, time.UTC)
			m2 := time.Date(2029, 7, 1, 0, 0, 0, 0, time.UTC)
			for name, at := range map[string]time.Time{"site.key": m0, "site.pfx": m1, "site.crt": m2} {
				if err := os.Chtimes(filepath.Join(outDir, name), at, at); err != nil {
					t.Fatalf("setup: Chtimes(%s): %v", name, err)
				}
			}

			got := scanSources(t, newSourcesScanner(inDir, outDir, adjust))
			wantSource(t, got, "site.crt", SourceUnchanged, m2)
			wantSource(t, got, "site.pfx", SourceExcluded, time.Time{})
		})
	}
}

func TestScanSources_a_flat_collision_claimant_shows_no_winner_time(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)
	inDir, outDir := t.TempDir(), t.TempDir()
	flat := func(o *Options) { o.Layout = outputpolicy.LayoutFlat }
	for _, dir := range []string{"x/shared", "y/shared"} {
		if err := os.MkdirAll(filepath.Join(inDir, dir), 0o750); err != nil {
			t.Fatalf("setup: MkdirAll: %v", err)
		}
	}
	writeSelfSignedPair(t, filepath.Join(inDir, "x/shared"), "site")
	scanSources(t, newSourcesScanner(inDir, outDir, flat))
	owned := time.Date(2029, 3, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(outDir, "shared/site.pfx"), owned, owned); err != nil {
		t.Fatalf("setup: Chtimes: %v", err)
	}
	writeSelfSignedPair(t, filepath.Join(inDir, "y/shared"), "site")

	got := scanSources(t, newSourcesScanner(inDir, outDir, flat))
	wantSource(t, got, "x/shared/site.crt", SourceCollided, owned)
	wantSource(t, got, "y/shared/site.crt", SourceCollided, time.Time{})
}

// After a restart the ownership record is the only evidence of a claimant the
// scan cannot reach, and the table must hold every claimant the collided count
// counts.
func TestScanSources_an_unreached_collision_claimant_stays_collided(t *testing.T) {
	now := sourcesClock
	pinConversionClock(t, &now)
	inDir, outDir := t.TempDir(), t.TempDir()
	for _, dir := range []string{"x/shared", "y/shared"} {
		if err := os.MkdirAll(filepath.Join(inDir, dir), 0o750); err != nil {
			t.Fatalf("setup: MkdirAll: %v", err)
		}
		writeSelfSignedPair(t, filepath.Join(inDir, dir), "site")
	}
	flat := func(o *Options) { o.Layout = outputpolicy.LayoutFlat }
	scanSources(t, newSourcesScanner(inDir, outDir, flat))

	// The root, x/, y/, x/shared/ and its pair fit; the walk stops at y/shared/.
	restarted := newSourcesScanner(inDir, outDir, func(o *Options) { flat(o); o.MaxScanEntries = 6 })
	result, err := restarted.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(budget stop after a restart) = %v", err)
	}
	if result.Collided != 2 {
		t.Fatalf("Run(budget stop after a restart).Collided = %d, want 2: the fixture must leave y/ unreached", result.Collided)
	}
	collided := 0
	for _, st := range result.Sources {
		if st.Outcome == SourceCollided {
			collided++
		}
	}
	if collided != result.Collided {
		t.Errorf("Sources holds %d collided rows, want the %d Collided counts: %+v", collided, result.Collided, result.Sources)
	}
}

// TestOutcomeOfStatus_maps_each_status_to_its_named_outcome pins the outcome
// each per-source status gives and the label it is served under, and that every
// name is a documented last_scan_sources outcome.
func TestOutcomeOfStatus_maps_each_status_to_its_named_outcome(t *testing.T) {
	t.Parallel()
	spec := []struct {
		status  conversionStatus
		outcome SourceOutcome
		name    string
	}{
		{statusConverted, SourceConverted, "converted"},
		{statusUnchanged, SourceUnchanged, "unchanged"},
		{statusFailed, SourceFailed, "failed"},
		{statusOrphan, SourceOrphan, "orphan"},
		{statusUnreadable, SourceUnreadable, "unreadable"},
		{statusUnwritable, SourceUnwritable, "unwritable"},
		{statusCollided, SourceCollided, "collided"},
		{statusExcluded, SourceExcluded, "excluded"},
		{statusVanished, SourceVanished, "vanished"},
	}
	if len(spec) != int(statusCount)-1 {
		t.Errorf("the spec covers %d statuses, want every per-source status (%d)", len(spec), int(statusCount)-1)
	}
	for _, c := range spec {
		outcome, ok := outcomeOfStatus(c.status)
		if !ok || outcome != c.outcome {
			t.Errorf("outcomeOfStatus(%d) = %d, %v, want %d (%s), true", c.status, outcome, ok, c.outcome, c.name)
		}
		if got := c.outcome.String(); got != c.name {
			t.Errorf("outcome %d String() = %q, want %q", c.outcome, got, c.name)
		}
	}
	if _, ok := outcomeOfStatus(statusUnset); ok {
		t.Error("outcomeOfStatus(statusUnset) = _, true, want no outcome")
	}

	doc, err := os.ReadFile("../../docs/monitoring.md")
	if err != nil {
		t.Fatalf("read docs/monitoring.md: %v", err)
	}
	row := regexp.MustCompile("(?m)^\\| `cert_converter_last_scan_sources` \\|.*$").Find(doc)
	if row == nil {
		t.Fatal("docs/monitoring.md has no cert_converter_last_scan_sources row")
	}
	documented := make(map[string]bool)
	for _, m := range regexp.MustCompile("`([a-z_]+)`").FindAllSubmatch(row, -1) {
		documented[string(m[1])] = true
	}
	for i, name := range SourceOutcomeNames() {
		if !documented[name] {
			t.Errorf("SourceOutcomeNames()[%d] = %q, not a documented last_scan_sources outcome", i, name)
		}
	}
}

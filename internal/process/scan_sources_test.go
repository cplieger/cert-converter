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

	s := newSourcesScanner(inDir, outDir, func(o *Options) { o.Formats = outputpolicy.Formats{PFX: true, PEM: true} })
	if got := scanSources(t, s)["site.crt"]; got.Outcome != SourceFailed {
		t.Errorf("Sources[site.crt].Outcome = %v after one artifact was written and its sibling refused, want %v", got.Outcome, SourceFailed)
	}
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
		if err := os.RemoveAll(filepath.Join(inDir, "c")); err != nil {
			t.Fatalf("setup: RemoveAll: %v", err)
		}
		// The root, a/, b/ and a/site.crt fit: the walk has listed the root in full
		// and stops inside a/, so only the stop proves nothing about c/.
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

func TestOutcomeOfStatus_covers_every_source_status(t *testing.T) {
	t.Parallel()
	seen := make(map[SourceOutcome]conversionStatus)
	for status := statusUnset + 1; status < statusCount; status++ {
		outcome, ok := outcomeOfStatus(status)
		if !ok {
			t.Errorf("outcomeOfStatus(%d) = _, false, want an outcome for every per-source status", status)
			continue
		}
		if prev, dup := seen[outcome]; dup {
			t.Errorf("outcomeOfStatus(%d) = %v, the outcome of status %d too, want distinct outcomes", status, outcome, prev)
		}
		seen[outcome] = status
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
	names := SourceOutcomeNames()
	if len(names) != int(sourceOutcomeCount) {
		t.Fatalf("SourceOutcomeNames() holds %d names, want %d", len(names), sourceOutcomeCount)
	}
	for i, name := range names {
		if !documented[name] {
			t.Errorf("SourceOutcomeNames()[%d] = %q, not a documented last_scan_sources outcome", i, name)
		}
		if got := SourceOutcome(i).String(); got != name {
			t.Errorf("SourceOutcome(%d).String() = %q, want %q", i, got, name)
		}
	}
}

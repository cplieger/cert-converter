package process

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/slogx/capture"
)

// captureLogs installs slogx/capture's Recorder as slog.Default() for the test and
// restores the previous default on cleanup. Assertions then read structured
// slog.Records rather than one rendered line, so a check cannot pass because the
// sought text happened to appear in an unrelated attribute. Tests using it must run
// serially: slog.Default is process-global.
func captureLogs(t *testing.T) *capture.Recorder {
	t.Helper()
	return capture.Default(t)
}

// TestWalkLogPolicy_per_path_lines_are_debug_only pins the app's two-level walk
// logging contract, decided deliberately after the input walk and the /output sweep
// were found surfacing the SAME condition at different levels (deferred finding
// l-f28).
//
// The rule: an individual path is named at DEBUG, and the default level carries ONE
// aggregate line with a count. Both walks tolerate an unreadable sub-path — it is a
// steady-state permissions/UID misconfiguration a restart cannot fix and neither feeds
// health — but they run on EVERY scan, each debounced fsnotify event and each fallback
// tick. Naming every path at the default level therefore put N warnings plus an
// aggregate into the log forever for a condition the operator had already been told
// about once.
//
// Asserted per walk, because these are four separate call sites that have drifted
// apart before.
func TestWalkLogPolicy_per_path_lines_are_debug_only(t *testing.T) {
	t.Run("input walk unreadable sub-path", func(t *testing.T) {
		logs := captureLogs(t)
		sw := &scanWalk{seen: map[string]struct{}{}}

		if err := sw.visit(t.Context(), "locked", nil, errors.New("permission denied")); err != nil {
			t.Fatalf("visit(unreadable sub-path) = %v, want nil so the rest of the tree is still walked", err)
		}

		assertDebugOnly(t, logs, "skipping unreadable path", "locked")
		if sw.unreadable != 1 {
			t.Errorf("unreadable = %d, want 1 so the aggregate in scanAndSetHealth fires", sw.unreadable)
		}
	})

	// A DIRECTORY occupying a <name>.crt path is the same shape of steady-state layout
	// mistake as the arm above — it recurs on every scan until an operator moves it —
	// and it feeds the SAME unreadable counter, so the aggregate WARN in
	// scanAndSetHealth already fires on this scan. Naming the path at the default level
	// as well made one condition produce two WARN records per scan, which is the exact
	// double-report this policy exists to prevent.
	//
	// The counter assertion here is what makes that argument true rather than assumed:
	// demoting the line is only safe while the aggregate still fires. The reaping veto
	// the same counter drives is pinned end-to-end by
	// TestScannerRun_directory_in_cert_path_does_not_authorise_reaping.
	t.Run("input walk directory in a cert path", func(t *testing.T) {
		logs := captureLogs(t)
		sw := &scanWalk{seen: map[string]struct{}{}}

		if err := sw.visit(t.Context(), "blocked.crt", dirEntryOf(t, t.TempDir()), nil); err != nil {
			t.Fatalf("visit(directory in a cert path) = %v, want nil so the rest of the tree is still walked", err)
		}

		assertDebugOnly(t, logs, "skipping cert: certificate path is a directory", "blocked.crt")
		if sw.unreadable != 1 {
			t.Errorf("unreadable = %d, want 1 so the aggregate in scanAndSetHealth fires and reaping stays vetoed", sw.unreadable)
		}
		if len(sw.seen) != 0 || len(sw.results) != 0 {
			t.Errorf("seen/results = %d/%d, want 0/0: an unreadable cert path is not a pair outcome",
				len(sw.seen), len(sw.results))
		}
	})

	t.Run("orphan walk unreadable output path", func(t *testing.T) {
		dir := t.TempDir()
		blocked := filepath.Join(dir, "blocked")
		if err := os.Mkdir(blocked, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o750) })
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}

		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })

		logs := captureLogs(t)
		s := &store{root: root}
		_, safe, err := s.orphans(context.Background(), map[string]struct{}{})
		if err != nil {
			t.Fatalf("orphans = %v, want nil: one unreadable sub-path must not abort the walk", err)
		}
		if safe {
			t.Error("safe = true, want false: an incomplete output enumeration must not authorise deletions")
		}

		assertDebugOnly(t, logs, "skipping unreadable output path", "blocked")
		assertOneAggregateWarn(t, logs, "could not be read while looking for orphans", "1")
	})

	t.Run("orphan walk symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(dir, filepath.Join(dir, "loop")); err != nil {
			t.Skipf("symlink unsupported here: %v", err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })

		logs := captureLogs(t)
		s := &store{root: root}
		_, safe, err := s.orphans(context.Background(), map[string]struct{}{})
		if err != nil {
			t.Fatalf("orphans = %v, want nil", err)
		}
		if safe {
			t.Error("safe = true, want false: writes and this walk resolve a symlink differently")
		}

		assertDebugOnly(t, logs, "output tree contains a symlink", "loop")
		assertOneAggregateWarn(t, logs, "orphan removal is disabled for this scan", "1")
	})
}

// dirEntryOf builds the fs.DirEntry the walk would hand visit for path, so a test can
// exercise the directory arm directly instead of through a real WalkDir.
func dirEntryOf(t *testing.T, path string) fs.DirEntry {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fs.FileInfoToDirEntry(fi)
}

// assertDebugOnly requires that the record carrying msg is at Debug and that the path
// is named in its `path` attribute — the path must remain discoverable under
// LOG_LEVEL=debug, which is the whole justification for demoting it. Asserting on the
// attribute rather than on the rendered line means a path that only appears in some
// other attribute (an error string, a remediation hint) cannot satisfy it.
func assertDebugOnly(t *testing.T, logs *capture.Recorder, msg, wantPath string) {
	t.Helper()
	if !logs.Contains(msg) {
		t.Fatalf("logged %q, want a record containing %q", logs.Messages(), msg)
	}
	if got := logs.CountLevel(slog.LevelDebug, msg); got != 1 {
		t.Errorf("%q logged at DEBUG %d times, want exactly 1; per-path lines must not reach the default level", msg, got)
	}
	if got := logs.CountLevel(slog.LevelWarn, msg); got != 0 {
		t.Errorf("%q logged at WARN %d times, want 0; per-path lines must not reach the default level", msg, got)
	}
	if !logs.HasAttr(msg, "path", wantPath) {
		t.Errorf("record %q does not name path=%q; demoting it must not make it undiscoverable", msg, wantPath)
	}
}

// assertOneAggregateWarn requires exactly one WARN record, carrying msg and the given
// count. Exactly one is the point of the policy: the default level reports the
// condition once per scan regardless of how many paths are affected.
func assertOneAggregateWarn(t *testing.T, logs *capture.Recorder, msg, wantCount string) {
	t.Helper()
	if got := logs.CountLevel(slog.LevelWarn, ""); got != 1 {
		t.Fatalf("got %d WARN records, want exactly 1 aggregate: %q", got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelWarn, msg); got != 1 {
		t.Errorf("aggregate WARN = %q, want it to contain %q", logs.Messages(), msg)
	}
	if !logs.HasAttr(msg, "count", wantCount) {
		got, _ := logs.AttrValue(msg, "count")
		t.Errorf("aggregate WARN count = %q, want %q", got, wantCount)
	}
	if _, ok := logs.AttrValue(msg, "remediation"); !ok {
		t.Errorf("aggregate WARN %q has no remediation hint: it is the only line the operator sees", msg)
	}
}

// TestWalkLogPolicy_quiet_when_nothing_is_wrong pins the steady state: a readable
// output tree with no symlinks emits no aggregate at all. A guard that also fired on
// zero would put a "count=0" warning with a remediation hint into the log on every
// scan of a perfectly healthy /output.
func TestWalkLogPolicy_quiet_when_nothing_is_wrong(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	logs := captureLogs(t)
	s := &store{root: root}
	if _, safe, orphanErr := s.orphans(context.Background(), map[string]struct{}{}); orphanErr != nil || !safe {
		t.Fatalf("orphans(clean tree) = safe %v, err %v; want true, nil", safe, orphanErr)
	}
	if logs.Len() != 0 {
		t.Errorf("orphans(clean tree) logged %q, want no output at all", logs.Messages())
	}
}

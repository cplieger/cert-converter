package process

import (
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
// were found surfacing the SAME condition at different levels.
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
			t.Errorf("unreadable = %d, want 1 so the aggregate in logInputCoverageWarnings fires", sw.unreadable)
		}
	})

	// A DIRECTORY occupying a <name>.crt path is the same shape of steady-state layout
	// mistake as the arm above — it recurs on every scan until an operator moves it —
	// and it feeds the SAME unreadable counter, so the aggregate WARN in
	// logInputCoverageWarnings already fires on this scan. Naming the path at the default level
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
			t.Errorf("unreadable = %d, want 1 so the aggregate in logInputCoverageWarnings fires and reaping stays vetoed", sw.unreadable)
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
		_, safe, err := s.listOutputs(t.Context())
		if err != nil {
			t.Fatalf("listOutputs = %v, want nil: one unreadable sub-path must not abort the walk", err)
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
		_, safe, err := s.listOutputs(t.Context())
		if err != nil {
			t.Fatalf("listOutputs = %v, want nil", err)
		}
		if safe {
			t.Error("safe = true, want false: writes and this walk resolve a symlink differently")
		}

		assertDebugOnly(t, logs, "output tree contains a symlink", "loop")
		assertOneAggregateWarn(t, logs, "output tree contains symlinks", "1")
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
	assertWarnRecords(t, logs, 1)
	assertAggregateWarnCount(t, logs, msg, wantCount)
}

// assertWarnRecords requires exactly want WARN records in the batch, whatever they
// say. The count is the policy: the default level reports each condition once per
// scan, so an extra record means one condition was reported twice and a missing one
// means it was not reported at all.
func assertWarnRecords(t *testing.T, logs *capture.Recorder, want int) {
	t.Helper()
	if got := logs.CountLevel(slog.LevelWarn, ""); got != want {
		t.Fatalf("got %d WARN records, want exactly %d: %q", got, want, logs.Messages())
	}
}

// assertAggregateWarnCount requires one WARN record carrying msg, with wantCount in
// its count attribute and a remediation hint. Unlike assertOneAggregateWarn it does
// not require msg to be the batch's only WARN, because the orphan walk's two
// disabling conditions are independent and one scan can report both.
func assertAggregateWarnCount(t *testing.T, logs *capture.Recorder, msg, wantCount string) {
	t.Helper()
	if got := logs.CountLevel(slog.LevelWarn, msg); got != 1 {
		t.Errorf("%q logged at WARN %d times, want exactly 1: %q", msg, got, logs.Messages())
	}
	if !logs.HasAttr(msg, "count", wantCount) {
		got, _ := logs.AttrValue(msg, "count")
		t.Errorf("aggregate WARN %q count = %q, want %q", msg, got, wantCount)
	}
	if _, ok := logs.AttrValue(msg, "remediation"); !ok {
		t.Errorf("aggregate WARN %q has no remediation hint: it is the only line the operator sees", msg)
	}
}

// TestStoreLogOrphanWalkOutcome_reports_each_disabling_condition pins both aggregate
// WARNs of the orphan walk by calling the reporter directly, so the contract holds
// whatever uid the suite runs as: the walk-level subtest above can only produce an
// unreadable output path with a chmod, which does nothing under uid 0. It also pins
// that the two conditions are reported INDEPENDENTLY -- a scan can hit both, and
// collapsing them would hide one behind the other.
func TestStoreLogOrphanWalkOutcome_reports_each_disabling_condition(t *testing.T) {
	const unreadableMsg = "some output paths could not be read while looking for orphans; orphan removal is disabled for this scan"
	const symlinkMsg = "output tree contains symlinks; orphan removal is disabled for this scan because writes and the orphan walk resolve paths differently"

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	s := &store{root: root}

	t.Run("unreadable output paths are reported with their count", func(t *testing.T) {
		logs := captureLogs(t)
		s.logOrphanWalkOutcome(2, 0)
		assertWarnRecords(t, logs, 1)
		assertAggregateWarnCount(t, logs, unreadableMsg, "2")
	})

	t.Run("symlinked output paths are reported with their count", func(t *testing.T) {
		logs := captureLogs(t)
		s.logOrphanWalkOutcome(0, 3)
		assertWarnRecords(t, logs, 1)
		assertAggregateWarnCount(t, logs, symlinkMsg, "3")
	})

	t.Run("both conditions are reported independently", func(t *testing.T) {
		logs := captureLogs(t)
		s.logOrphanWalkOutcome(1, 4)
		assertWarnRecords(t, logs, 2)
		assertAggregateWarnCount(t, logs, unreadableMsg, "1")
		assertAggregateWarnCount(t, logs, symlinkMsg, "4")
	})
}

// TestWalkLogPolicy_quiet_when_nothing_is_wrong pins the steady state: a readable
// output tree with no symlinks emits no aggregate at all. A guard that also fired on
// zero would put a "count=0" warning with a remediation hint into the log on every
// scan of a perfectly healthy /output.
func TestWalkLogPolicy_quiet_when_nothing_is_wrong(t *testing.T) {
	dir := t.TempDir()
	// listOutputs applies the write-permission verdict to every directory it
	// enumerates, so "nothing is wrong" has to include the root's own mode: a
	// group-writable /output is a condition the walk is REQUIRED to report, and some
	// hosts hand t.TempDir a group-writable directory (an inherited default ACL).
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	logs := captureLogs(t)
	s := &store{root: root}
	if _, safe, orphanErr := s.listOutputs(t.Context()); orphanErr != nil || !safe {
		t.Fatalf("listOutputs(clean tree) = safe %v, err %v; want true, nil", safe, orphanErr)
	}
	if logs.Len() != 0 {
		t.Errorf("listOutputs(clean tree) logged %q, want no output at all", logs.Messages())
	}
}

// TestLogIncompleteInputEnumeration_quiet_arms pins which reasons for skipping
// orphan reconciliation reach the operator and which stay at DEBUG.
//
// The default-level line here is an alert-worthy WARN whose remediation points at
// the /input mount, so the two arms that must NOT reach it are the contract: a
// shutdown (every graceful container stop lands mid-scan sooner or later) and a
// clean walk that simply found no pair yet (a deployment whose first certificate has
// not been issued, on every scan). Lose either arm and the alert fires with a
// diagnosis the operator cannot act on. The third case is the converse: a genuinely
// incomplete enumeration must still reach WARN with its hint.
//
// Runs serially: it swaps slog.Default().
func TestLogIncompleteInputEnumeration_quiet_arms(t *testing.T) {
	const mountWarn = "orphan removal is disabled for this scan: the scan did not fully enumerate the input tree, so no output can be proven orphaned"

	t.Run("a shutdown is not an operator-actionable incomplete enumeration", func(t *testing.T) {
		logs := captureLogs(t)
		logIncompleteInputEnumeration(&reapContext{shutdown: true})
		const dbg = "skipping orphan reconciliation; scan cancelled during shutdown"
		if got := logs.CountLevel(slog.LevelWarn, ""); got != 0 {
			t.Fatalf("logIncompleteInputEnumeration(shutdown) logged %d WARN records, want 0: a container"+
				" stop must not raise the /input-mount warning: %q", got, logs.Messages())
		}
		if got := logs.CountLevel(slog.LevelDebug, dbg); got != 1 {
			t.Errorf("logIncompleteInputEnumeration(shutdown) logged %q at DEBUG %d times, want exactly 1: %q",
				dbg, got, logs.Messages())
		}
	})

	t.Run("a clean walk that found no pair is not a mount problem", func(t *testing.T) {
		logs := captureLogs(t)
		logIncompleteInputEnumeration(&reapContext{walkCompleted: true})
		const dbg = "skipping orphan reconciliation; the scan found no certificate pairs to compare the output tree against"
		if got := logs.CountLevel(slog.LevelWarn, ""); got != 0 {
			t.Fatalf("logIncompleteInputEnumeration(empty clean tree) logged %d WARN records, want 0: an"+
				" empty /input is already reported once by the input-coverage warning: %q", got, logs.Messages())
		}
		if got := logs.CountLevel(slog.LevelDebug, dbg); got != 1 {
			t.Errorf("logIncompleteInputEnumeration(empty clean tree) logged %q at DEBUG %d times, want exactly 1: %q",
				dbg, got, logs.Messages())
		}
	})

	t.Run("a genuinely incomplete walk warns with the mount remediation", func(t *testing.T) {
		logs := captureLogs(t)
		logIncompleteInputEnumeration(&reapContext{result: ScanResult{Total: 2, Unreadable: 1}, walkCompleted: true})
		if got := logs.CountLevel(slog.LevelWarn, mountWarn); got != 1 {
			t.Fatalf("logIncompleteInputEnumeration(unreadable path) logged %q, want %q once at WARN",
				logs.Messages(), mountWarn)
		}
		if _, ok := logs.AttrValue(mountWarn, "remediation"); !ok {
			t.Errorf("logIncompleteInputEnumeration(unreadable path) logged %q with no remediation hint: it is"+
				" the only line the operator sees", logs.Messages())
		}
	})

	// A renewal during a scan that ALSO hit an unreadable path must not demote the
	// durable condition to the transient arm: vanishedOnly's Vanished term is only
	// half of it, and without this case dropping its durable half leaves the suite
	// green while the /input-mount WARN (and the alert on it) vanishes for as long
	// as any cert is renewing.
	t.Run("a vanished cert does not hide an unreadable path", func(t *testing.T) {
		logs := captureLogs(t)
		logIncompleteInputEnumeration(&reapContext{
			result: ScanResult{Total: 2, Unreadable: 1, Vanished: 1}, walkCompleted: true,
		})
		if got := logs.CountLevel(slog.LevelWarn, mountWarn); got != 1 {
			t.Fatalf("logIncompleteInputEnumeration(unreadable path + vanished cert) logged %q, want %q"+
				" once at WARN: a transient replacement must not silence a durable veto", logs.Messages(), mountWarn)
		}
	})
}

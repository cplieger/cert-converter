package process

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureLogs swaps slog.Default() for a Debug-level text handler and returns the
// buffer. Tests using it must run serially: slog.Default is process-global.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
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
// Asserted per walk, because these are three separate call sites that have drifted
// apart before.
func TestWalkLogPolicy_per_path_lines_are_debug_only(t *testing.T) {
	t.Run("input walk unreadable sub-path", func(t *testing.T) {
		buf := captureLogs(t)
		sw := &scanWalk{seen: map[string]struct{}{}}

		if err := sw.visit(t.Context(), "locked", nil, errors.New("permission denied")); err != nil {
			t.Fatalf("visit(unreadable sub-path) = %v, want nil so the rest of the tree is still walked", err)
		}

		out := buf.String()
		assertDebugOnly(t, out, "skipping unreadable path", "locked")
		if sw.unreadable != 1 {
			t.Errorf("unreadable = %d, want 1 so the aggregate in scanAndSetHealth fires", sw.unreadable)
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

		buf := captureLogs(t)
		s := &store{root: root}
		_, safe, err := s.orphans(context.Background(), map[string]struct{}{})
		if err != nil {
			t.Fatalf("orphans = %v, want nil: one unreadable sub-path must not abort the walk", err)
		}
		if safe {
			t.Error("safe = true, want false: an incomplete output enumeration must not authorise deletions")
		}

		out := buf.String()
		assertDebugOnly(t, out, "skipping unreadable output path", "blocked")
		assertOneAggregateWarn(t, out, "could not be read while looking for orphans", "count=1")
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

		buf := captureLogs(t)
		s := &store{root: root}
		_, safe, err := s.orphans(context.Background(), map[string]struct{}{})
		if err != nil {
			t.Fatalf("orphans = %v, want nil", err)
		}
		if safe {
			t.Error("safe = true, want false: writes and this walk resolve a symlink differently")
		}

		out := buf.String()
		assertDebugOnly(t, out, "output tree contains a symlink", "loop")
		assertOneAggregateWarn(t, out, "orphan removal is disabled for this scan", "count=1")
	})
}

// assertDebugOnly requires that the record carrying msg is at Debug and that the path
// is named there — the path must remain discoverable under LOG_LEVEL=debug, which is
// the whole justification for demoting it.
func assertDebugOnly(t *testing.T, out, msg, wantPath string) {
	t.Helper()
	line := recordWith(out, msg)
	if line == "" {
		t.Fatalf("logged %q, want a record containing %q", out, msg)
	}
	if !strings.Contains(line, "level=DEBUG") {
		t.Errorf("record %q is not at DEBUG; per-path lines must not reach the default level", line)
	}
	if !strings.Contains(line, wantPath) {
		t.Errorf("record %q does not name the path %q; demoting it must not make it undiscoverable", line, wantPath)
	}
}

// assertOneAggregateWarn requires exactly one WARN record, carrying msg and a count.
// Exactly one is the point of the policy: the default level reports the condition once
// per scan regardless of how many paths are affected.
func assertOneAggregateWarn(t *testing.T, out, msg, wantAttr string) {
	t.Helper()
	var warns []string
	for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
		if strings.Contains(line, "level=WARN") {
			warns = append(warns, line)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("got %d WARN records, want exactly 1 aggregate: %q", len(warns), out)
	}
	if !strings.Contains(warns[0], msg) {
		t.Errorf("aggregate WARN = %q, want it to contain %q", warns[0], msg)
	}
	if !strings.Contains(warns[0], wantAttr) {
		t.Errorf("aggregate WARN = %q, want the count attribute %q", warns[0], wantAttr)
	}
	if !strings.Contains(warns[0], "remediation=") {
		t.Errorf("aggregate WARN = %q, want a remediation hint: it is the only line the operator sees", warns[0])
	}
}

// recordWith returns the first log line containing msg, or "".
func recordWith(out, msg string) string {
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, msg) {
			return line
		}
	}
	return ""
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

	buf := captureLogs(t)
	s := &store{root: root}
	if _, safe, orphanErr := s.orphans(context.Background(), map[string]struct{}{}); orphanErr != nil || !safe {
		t.Fatalf("orphans(clean tree) = safe %v, err %v; want true, nil", safe, orphanErr)
	}
	if out := buf.String(); out != "" {
		t.Errorf("orphans(clean tree) logged %q, want no output at all", out)
	}
}

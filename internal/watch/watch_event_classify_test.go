package watch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
	"github.com/fsnotify/fsnotify"
)

// TestHandleFsEvent_classifies_a_create_it_cannot_stat pins both halves of the
// Create-branch Lstat failure, which now answer the unclassifiable-path
// question exactly as the Remove/Rename and Chmod arms do. A vanished path
// (fs.ErrNotExist) is known to hold nothing rather than being unclassifiable,
// so it stays silent and is still classified by extension. Any other stat
// error means the created path could not be classified at all: it must
// schedule a rescan rather than guess from the suffix -- a created domain-named
// directory such as "example.com" reads as an unrelated file to the suffix-only
// classifier, so guessing means a pair already inside it waits for the periodic
// fallback re-sync, and never with the fallback disabled -- AND it must still
// WARN, because the rescan does not re-attach the subtree's watches. An ENOTDIR
// path (a component of the path is a regular file) is the portable way to
// produce that second case without depending on permissions, which is
// untestable as uid 0.
// Not parallel: it swaps the process-global slog default.
func TestHandleFsEvent_classifies_a_create_it_cannot_stat(t *testing.T) {
	watcher := newTestWatcher(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {})

	notADir := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		path     string
		want     bool
		wantWarn bool
	}{
		{"a vanished cert still rescans, silently", filepath.Join(root, "gone.crt"), true, false},
		{"a vanished unrelated file is ignored, silently", filepath.Join(root, "gone.txt"), false, false},
		{"an unclassifiable cert path rescans and warns", filepath.Join(notADir, "tls.crt"), true, true},
		{"an unclassifiable unrelated path rescans and warns", filepath.Join(notADir, "notes.txt"), true, true},
		{"an unclassifiable domain-named path rescans and warns", filepath.Join(notADir, "example.com"), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: tc.path, Op: fsnotify.Create})

			if got != tc.want {
				t.Errorf("handleFsEvent(Create %s) = %v, want %v", tc.path, got, tc.want)
			}
			warned := logs.CountLevel(slog.LevelWarn, "cannot classify a created path") > 0
			if warned != tc.wantWarn {
				t.Errorf("handleFsEvent(Create %s) warned = %v, want %v; log = %v", tc.path, warned, tc.wantWarn, logs.Messages())
			}
		})
	}
}

// TestHandleFsEvent_classifies_a_chmod_it_cannot_stat pins both halves of the
// Chmod-branch Lstat failure. Chmod is the documented recovery path for a
// permission repair, so a path that cannot be classified at all must be treated
// as a possible unwatched directory: rescan and WARN, rather than fall through
// to the suffix-only classifier that would silently drop a repaired
// domain-named directory. A vanished path is the one quiet case — the chmod
// target is already gone, so there is nothing left to re-attach. An ENOTDIR
// path (a component of the path is a regular file) produces the
// unclassifiable case without depending on permissions, which is untestable as
// uid 0.
// Not parallel: it swaps the process-global slog default.
func TestHandleFsEvent_classifies_a_chmod_it_cannot_stat(t *testing.T) {
	watcher := newTestWatcher(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {})

	notADir := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		path     string
		want     bool
		wantWarn bool
	}{
		{"a vanished cert still rescans, silently", filepath.Join(root, "gone.crt"), true, false},
		{"a vanished unrelated file is ignored, silently", filepath.Join(root, "gone.txt"), false, false},
		{"an unclassifiable cert path rescans and warns", filepath.Join(notADir, "tls.crt"), true, true},
		{"an unclassifiable unrelated path rescans and warns", filepath.Join(notADir, "notes.txt"), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: tc.path, Op: fsnotify.Chmod})

			if got != tc.want {
				t.Errorf("handleFsEvent(Chmod %s) = %v, want %v", tc.path, got, tc.want)
			}
			warned := logs.CountLevel(slog.LevelWarn, "cannot classify a path whose permissions changed") > 0
			if warned != tc.wantWarn {
				t.Errorf("handleFsEvent(Chmod %s) warned = %v, want %v; log = %v", tc.path, warned, tc.wantWarn, logs.Messages())
			}
		})
	}
}

// TestFallbackStatus_tells_the_operator_whether_anything_will_rescan pins the
// fallback_scan attribute every degraded-path WARN carries. The existing
// classify tests assert only that the WARN fires, so the attribute's value --
// the operator's single statement of when (or whether) the reported path is
// re-scanned -- is unverified, and the boundary that produces "disabled" can
// invert without any test noticing. The disabled case is the load-bearing one:
// nothing re-scans that path for the life of the process, so rendering it as a
// duration would read as a promise the process cannot keep.
// Not parallel: it swaps the process-global slog default.
func TestFallbackStatus_tells_the_operator_whether_anything_will_rescan(t *testing.T) {
	const msg = "cannot classify a path whose permissions changed"

	watcher := newTestWatcher(t)
	root := t.TempDir()
	notADir := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		fallback time.Duration
		want     string
	}{
		{"a disabled fallback is named outright", 0, "disabled"},
		{"a negative interval is disabled too", -time.Second, "disabled"},
		{"an enabled fallback states its cadence", 6 * time.Hour, "6h0m0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)
			w := New(root, func(context.Context) {}, WithFallback(tc.fallback))

			w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: filepath.Join(notADir, "tls.crt"), Op: fsnotify.Chmod})

			got, ok := logs.AttrValue(msg, "fallback_scan")
			if !ok {
				t.Fatalf("no fallback_scan attribute on the degraded-path WARN; log = %v", logs.Messages())
			}
			if got != tc.want {
				t.Errorf("fallback_scan = %q with WithFallback(%v), want %q", got, tc.fallback, tc.want)
			}
		})
	}
}

// TestHandleFsEvent_does_not_watch_through_a_symlinked_directory pins the
// containment invariant both the Create and the Chmod arm rely on: they Lstat
// (never Stat), so a symlink to a directory takes the FILE arm and
// addWatchDirs/watcher.Add never runs on it. Neither addWatchDirs nor the
// scanner's root-confined walk descends a symlinked directory, so watching
// through one would register inotify watches on a tree outside /input whose
// certs can never be converted, silently burning the watch quota. Both Create and
// Chmod must use Lstat so a symlinked directory never enters addWatchDirs.
func TestHandleFsEvent_does_not_watch_through_a_symlinked_directory(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "escaped"), 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "example.com")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable on this filesystem: %v", err)
	}
	w := New(root, func(context.Context) {})

	for _, op := range []fsnotify.Op{fsnotify.Create, fsnotify.Chmod} {
		if got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: link, Op: op}); got {
			t.Errorf("handleFsEvent(%v on a symlinked dir) = true, want false (the link name is not a cert or key)", op)
		}
	}
	for _, watched := range watcher.WatchList() {
		if watched == link || strings.HasPrefix(watched, outside) {
			t.Errorf("watch registered through a symlink: %q; watch list = %v", watched, watcher.WatchList())
		}
	}
}

// TestHandleFsEvent_refuses_to_extend_the_watch_set_outside_root pins the
// containment guard the symlink test above cannot reach: a REAL directory whose
// event-derived name is lexically outside the watched root. fsnotify hands back
// the path a watch was registered with, so a registration that once escaped the
// root would otherwise keep walking and registering further outside it, one
// event at a time. The event must still request the conservative in-root rescan
// (content inside the root is unaffected by the refusal) and must say so at WARN
// with the path, the root and whether anything will revisit what stays
// unwatched.
// Not parallel: it swaps the process-global slog default.
func TestHandleFsEvent_refuses_to_extend_the_watch_set_outside_root(t *testing.T) {
	logs := capture.Default(t)
	watcher := newTestWatcher(t)
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "escaped")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})

	if got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: outside, Op: fsnotify.Create}); !got {
		t.Error("handleFsEvent(Create dir outside root) = false, want true: the in-root rescan must still cover content after refusing the watch extension")
	}
	if watched := watcher.WatchList(); slices.Contains(watched, outside) {
		t.Errorf("watch list after an outside-root event = %v, want %q refused", watched, outside)
	}
	const msg = "refusing to extend the watch set outside the watched root"
	if n := logs.CountLevel(slog.LevelWarn, msg); n != 1 {
		t.Fatalf("WARN %q logged %d times, want exactly 1; log = %v", msg, n, logs.Messages())
	}
	if got, ok := logs.AttrValue(msg, "path"); !ok || got != outside {
		t.Errorf("WARN %q path = %q (present %v), want %q", msg, got, ok, outside)
	}
	if got, ok := logs.AttrValue(msg, "root"); !ok || got != root {
		t.Errorf("WARN %q root = %q (present %v), want %q", msg, got, ok, root)
	}
	if got, ok := logs.AttrValue(msg, "fallback_scan"); !ok || got != "disabled" {
		t.Errorf("WARN %q fallback_scan = %q (present %v), want disabled", msg, got, ok)
	}
}

// TestHandleFsEvent_skips_the_rewalk_for_an_already_watched_directory pins the
// half of the membership guard that bounds per-event work: a Create for a
// directory already in the watch set must NOT re-walk its subtree. The oracle is
// a child that appeared without an event of its own — it can only reach the watch
// list if the guard failed to skip the walk.
func TestHandleFsEvent_skips_the_rewalk_for_an_already_watched_directory(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	dir := filepath.Join(root, "example.com")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs(%q) = %v, want nil", root, err)
	}
	child := filepath.Join(dir, "nested")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatal(err)
	}

	if got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: dir, Op: fsnotify.Create}); !got {
		t.Error("handleFsEvent(Create of an already-watched dir) = false, want true: the debounced rescan still covers content")
	}
	if watched := watcher.WatchList(); slices.Contains(watched, child) {
		t.Errorf("a Create for the already-watched %q re-walked its subtree and registered %q; the membership guard must skip the walk (watch list = %v)",
			dir, child, watched)
	}
}

// TestHandleRootWatchLoss_reattaches_the_watch_set_when_the_fallback_is_enabled
// pins the recoverable half of the root-watch-loss contract. The terminal half is
// pinned by TestWatchLoop_reports_lost_change_detection_when_the_root_watch_
// disappears, which builds its Watcher with no WithFallback. With the fallback
// enabled the arm must report true (change detection is still live, so the process
// must not exit) AND re-attach the watch set, because the root's removal took every
// descendant watch with it and waiting for the next tick means up to six hours with
// no real-time detection on the documented cadence.
func TestHandleRootWatchLoss_reattaches_the_watch_set_when_the_fallback_is_enabled(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	child := filepath.Join(root, "example.com")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatal(err)
	}
	watcher := newTestWatcher(t)
	w := New(root, func(context.Context) {}, WithFallback(time.Hour))

	if !w.handleRootWatchLoss(t.Context(), watcher, fsnotify.Event{Name: root, Op: fsnotify.Remove}) {
		t.Fatal("handleRootWatchLoss(root Remove, fallback enabled) = false, want true: the periodic rescan still covers renewals, so the process must not exit for a restart")
	}
	for _, want := range []string{root, child} {
		if !slices.Contains(watcher.WatchList(), want) {
			t.Errorf("watch list after the root watch was lost = %v, want %q re-attached", watcher.WatchList(), want)
		}
	}
}

// TestHandleRootWatchLoss_only_the_root_being_taken_away_ends_change_detection
// pins the two guards that decide whether an event is a root-watch LOSS at all.
// Both are load-bearing and neither is otherwise exercised: the whole table runs
// with the periodic rescan disabled, the one configuration in which a loss is
// terminal, so every "still live" answer here comes from a guard rather than
// from the fallback.
//
// A chmod on the root is the documented permission-repair recovery event, and a
// Remove or Rename BELOW the root is an ordinary certificate deletion. If either
// guard stopped classifying, that benign event would report lost change
// detection, main would exit non-zero, and the critical
// CertConverterChangeDetectionDead alert would fire on a cert deletion or a
// chmod of /input. The terminal rows are what keep the live rows honest: without
// them a function that always reported "live" would satisfy the table.
func TestHandleRootWatchLoss_only_the_root_being_taken_away_ends_change_detection(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		op       fsnotify.Op
		atRoot   bool
		wantLive bool
	}{
		{"a chmod on the root is a permission repair, not a loss", fsnotify.Chmod, true, true},
		{"a write on the root is not a loss", fsnotify.Write, true, true},
		{"a create in the root is not a loss", fsnotify.Create, true, true},
		{"removing a cert below the root is not a loss", fsnotify.Remove, false, true},
		{"renaming a directory below the root is not a loss", fsnotify.Rename, false, true},
		{"the root itself being removed is terminal", fsnotify.Remove, true, false},
		{"the root itself being renamed is terminal", fsnotify.Rename, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			watcher := newTestWatcher(t)
			root := t.TempDir()
			path := filepath.Join(root, "example.com")
			if tc.atRoot {
				path = root
			}
			// No WithFallback: the periodic rescan is disabled, so a loss is terminal.
			w := New(root, func(context.Context) {})

			got := w.handleRootWatchLoss(t.Context(), watcher, fsnotify.Event{Name: path, Op: tc.op})

			if got != tc.wantLive {
				t.Errorf("handleRootWatchLoss(%s on %s) = %v, want %v", tc.op, path, got, tc.wantLive)
			}
		})
	}
}

// TestHandleRootWatchLoss_stays_live_when_the_reattach_fails pins the liveness
// half of the recoverable branch, the same contract its sibling arms carry
// (handleErrorRecv on an overflow, handleFallbackTick on a failed re-sync): with
// the periodic rescan enabled, a re-attach that fails must be WARNed about and
// still report change detection live. Reporting a loss there would restart the
// container over a condition the rescan already covers.
//
// The WARN is the only signal an operator gets that real-time detection is off
// until a later re-sync, so it must name the root and the rescan cadence.
// Not parallel: it swaps the process-global slog default.
func TestHandleRootWatchLoss_stays_live_when_the_reattach_fails(t *testing.T) {
	const msg = "failed to re-attach the watch set after the root watch was lost"

	logs := capture.Default(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {}, WithFallback(6*time.Hour))

	if !w.handleRootWatchLoss(t.Context(), newClosedTestWatcher(t), fsnotify.Event{Name: root, Op: fsnotify.Remove}) {
		t.Fatal("handleRootWatchLoss(re-attach failing, fallback enabled) = false, want true: the periodic rescan still covers renewals, so a failed repair must not restart the container")
	}
	if n := logs.CountLevel(slog.LevelWarn, msg); n != 1 {
		t.Fatalf("WARN %q logged %d times, want exactly 1; log = %v", msg, n, logs.Messages())
	}
	for key, want := range map[string]string{"root": root, "fallback_scan": "6h0m0s"} {
		got, ok := logs.AttrValue(msg, key)
		if !ok {
			t.Errorf("WARN %q carries no %q attribute; an operator cannot tell which tree lost real-time detection or when it is re-scanned", msg, key)
			continue
		}
		if got != want {
			t.Errorf("WARN %q %s = %q, want %q", msg, key, got, want)
		}
	}
}

// TestHandleFsEvent_refuses_a_directory_whose_name_only_prefixes_the_root pins
// the containment guard against the prefix-match bypass class. The existing
// outside-root test uses a path in an unrelated directory, which a naive
// strings.HasPrefix(path, root) containment check also refuses, so nothing
// distinguished the lexical Rel-based guard from that bypassable form: a real
// sibling named "<root>-evil" shares the root's textual prefix while lying
// outside it, and accepting it lets one event extend inotify registrations into
// a tree this app must not watch (and, one event at a time, further outside it).
// The control case keeps the guard honest: a function that refused everything
// would satisfy the refusal half alone.
// Not parallel: it swaps the process-global slog default.
func TestHandleFsEvent_refuses_a_directory_whose_name_only_prefixes_the_root(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "input")
	inside := filepath.Join(root, "example.com")
	sibling := root + "-evil" // shares root's textual prefix, is NOT under it
	for _, dir := range []string{inside, sibling} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	logs := capture.Default(t)
	watcher := newTestWatcher(t)
	w := New(root, func(context.Context) {})
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("setup: addWatchDirs(%q) = %v, want nil", root, err)
	}

	const msg = "refusing to extend the watch set outside the watched root"
	if got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: sibling, Op: fsnotify.Create}); !got {
		t.Error("handleFsEvent(Create of a prefix-sibling dir) = false, want true: content inside the root is unaffected by the refusal, so the rescan must still run")
	}
	if watched := watcher.WatchList(); slices.Contains(watched, sibling) {
		t.Errorf("watch list = %v, want %q refused: it only shares the root's textual prefix", watched, sibling)
	}
	if n := logs.CountLevel(slog.LevelWarn, msg); n != 1 {
		t.Errorf("WARN %q logged %d times, want exactly 1; log = %v", msg, n, logs.Messages())
	}

	// Control: a directory genuinely under the root is still accepted.
	nested := filepath.Join(inside, "nested")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	if got := w.handleFsEvent(t.Context(), watcher, fsnotify.Event{Name: nested, Op: fsnotify.Create}); !got {
		t.Error("handleFsEvent(Create of a dir under the root) = false, want true")
	}
	if watched := watcher.WatchList(); !slices.Contains(watched, nested) {
		t.Errorf("watch list = %v, want %q watched: the guard must not refuse a path inside the root", watched, nested)
	}
}

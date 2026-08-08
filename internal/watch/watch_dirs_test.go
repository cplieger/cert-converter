package watch

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
)

// TestAddWatchDirs_watches_whole_subtree_and_fails_on_missing_root pins the
// watch-set construction: every directory below the root is watched (a
// per-domain Caddy layout nests two levels deep, and an unwatched subdirectory
// means renewals there are only picked up by the fallback rescan), files are
// not watched individually, and a root that cannot be walked is a hard error --
// the signal Run uses to fall back to polling instead of running blind.
func TestAddWatchDirs_watches_whole_subtree_and_fails_on_missing_root(t *testing.T) {
	t.Parallel()

	watcher := newTestWatcher(t)

	root := t.TempDir()
	nested := filepath.Join(root, "acme-v02", "example.com")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(nested, "example.com.crt")
	if err := os.WriteFile(certFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})

	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("addWatchDirs(%q) = %v, want nil", root, err)
	}

	got := watcher.WatchList()
	for _, dir := range []string{root, filepath.Join(root, "acme-v02"), nested} {
		if !slices.Contains(got, dir) {
			t.Errorf("addWatchDirs did not watch %q; watch list = %v", dir, got)
		}
	}
	if slices.Contains(got, certFile) {
		t.Errorf("addWatchDirs added the file %q to the watch list; only directories should be watched", certFile)
	}

	if err := w.addWatchDirs(t.Context(), watcher, filepath.Join(root, "does-not-exist")); err == nil {
		t.Error("addWatchDirs(missing root) = nil, want an error so Run falls back to polling")
	}
}

// TestAddWatchDirs_fails_when_the_root_watch_cannot_be_added pins the second
// fatal case of the watch-set build: the root directory walks fine but the
// watch itself is refused (a closed or exhausted watcher). That must propagate
// as an error, because it is the signal Run uses to fall back to polling; a
// swallowed failure would leave Run believing fsnotify is active while no watch
// exists, so renewals would be detected only by the fallback rescan (or not at
// all when it is disabled).
func TestAddWatchDirs_fails_when_the_root_watch_cannot_be_added(t *testing.T) {
	t.Parallel()
	watcher := newClosedTestWatcher(t)
	root := t.TempDir()

	if err := New(root, func(context.Context) {}).addWatchDirs(t.Context(), watcher, root); err == nil {
		t.Error("addWatchDirs(closed watcher) = nil, want an error so Run falls back to polling instead of watching nothing")
	}
}

func TestAddWatchDirs_reports_shutdown_instead_of_a_watch_failure(t *testing.T) {
	t.Parallel()
	watcher := newTestWatcher(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := New(root, func(context.Context) {}).addWatchDirs(ctx, watcher, root)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("addWatchDirs(cancelled ctx) = %v, want context.Canceled so Run treats it as shutdown rather than falling back to polling", err)
	}
	if watched := watcher.WatchList(); len(watched) != 0 {
		t.Errorf("addWatchDirs(cancelled ctx) registered %v, want no watches once shutdown has started", watched)
	}
}

// The two degraded-path WARN messages of the watch-set build, matched as
// substrings so the assertions below scope to the right log site without
// pinning the whole sentence.
const (
	warnUnwatchablePath = "skipping unwatchable path"
	warnUnwatchableDir  = "skipping unwatchable directory"
)

// assertSkipWarn pins one degraded-path WARN by its ATTRIBUTES rather than by
// its rendered text: what the operator needs off these lines is WHICH path was
// dropped from the watch set, whether the periodic rescan will ever revisit it
// (fallback_scan -- "disabled" means never, for the life of the process), and
// the underlying error. Re-wording the sentence therefore stays free; dropping
// one of those three diagnostics fails.
func assertSkipWarn(t *testing.T, logs *capture.Recorder, msg, wantPath, wantFallback string, wantErr error) {
	t.Helper()
	if n := logs.CountLevel(slog.LevelWarn, msg); n != 1 {
		t.Fatalf("WARN %q logged %d times, want exactly 1; log = %v", msg, n, logs.Messages())
	}
	for key, want := range map[string]string{
		"path":          wantPath,
		"fallback_scan": wantFallback,
		"error":         wantErr.Error(),
	} {
		got, ok := logs.AttrValue(msg, key)
		if !ok {
			t.Errorf("WARN %q carries no %q attribute; an operator cannot act on the skip without it", msg, key)
			continue
		}
		if got != want {
			t.Errorf("WARN %q %s = %q, want %q", msg, key, got, want)
		}
	}
}

// assertNoSkipWarn pins the silence of the two FATAL cases: a root failure is
// returned to Run, which reports the degradation itself, so warning here too
// would double-log one condition as if two paths had been lost.
func assertNoSkipWarn(t *testing.T, logs *capture.Recorder, msg string) {
	t.Helper()
	if n := logs.CountLevel(slog.LevelWarn, msg); n != 0 {
		t.Errorf("WARN %q logged %d times for a ROOT failure, want 0: the error is returned to Run, which reports the fallback to polling once; log = %v", msg, n, logs.Messages())
	}
}

// TestVisitWatchPath_applies_the_walk_error_policy pins the per-entry half of
// addWatchDirs' walk-error contract, at the level where the walk error is an
// ARGUMENT rather than something a test has to provoke from the filesystem: the
// helper accepts the failure as an argument so the policy is deterministic even
// when tests run as uid 0.
//
// The rule: only the root failing is fatal, because that is the signal Run uses
// to fall back to polling; a child that cannot be walked is warned about and
// skipped, so one mis-permissioned certificate directory cannot cost the whole
// tree its real-time watch. The skip WARN must name the fallback cadence,
// covered here for BOTH configurations: with the rescan enabled the subtree is
// still picked up every interval, while "disabled" means the renewals under it
// will not be noticed at all until a restart -- the difference between a
// cosmetic and an actionable log line.
//
// The nil watcher is deliberate: neither branch may register a watch, so a
// change that started touching the watcher here panics instead of passing.
// Not parallel: it swaps the process-global slog default.
func TestVisitWatchPath_applies_the_walk_error_policy(t *testing.T) {
	walkErr := errors.New("permission denied")

	for _, tc := range []struct {
		name         string
		fallback     time.Duration
		atRoot       bool
		wantFatal    bool
		wantFallback string
	}{
		{"a child that cannot be walked is skipped, naming the rescan cadence", 6 * time.Hour, false, false, "6h0m0s"},
		{"a child skip reports a disabled rescan as disabled", 0, false, false, "disabled"},
		{"the root failing to walk is fatal and warns nothing", 6 * time.Hour, true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)
			root := t.TempDir()
			path := filepath.Join(root, "example.com")
			if tc.atRoot {
				path = root
			}
			w := New(root, func(context.Context) {}, WithFallback(tc.fallback))

			err := w.visitWatchPath(t.Context(), nil, &watchSetBudget{max: fallbackWatchEntries, root: root}, path, nil, walkErr)

			if tc.wantFatal {
				if !errors.Is(err, walkErr) {
					t.Errorf("visitWatchPath(root, walkErr) = %v, want the walk error unchanged so Run falls back to polling", err)
				}
				assertNoSkipWarn(t, logs, warnUnwatchablePath)
				return
			}
			if err != nil {
				t.Errorf("visitWatchPath(child, walkErr) = %v, want nil so the rest of the tree is still watched", err)
			}
			assertSkipWarn(t, logs, warnUnwatchablePath, path, tc.wantFallback, walkErr)
		})
	}
}

// TestVisitWatchPath_reports_shutdown_ahead_of_a_walk_error pins the ordering
// inside visitWatchPath: cancellation is checked BEFORE the walk error. That
// ordering is a real contract, not an accident of layout -- callers must treat a
// ctx error as shutdown (no WARN, no fallback to polling, no follow-up scan),
// and a shutdown arriving while the walk is already failing on some sub-path
// would otherwise be reported as a watch degradation and send Run into polling
// on its way out.
// Not parallel: it swaps the process-global slog default.
func TestVisitWatchPath_reports_shutdown_ahead_of_a_walk_error(t *testing.T) {
	logs := capture.Default(t)
	root := t.TempDir()
	w := New(root, func(context.Context) {}, WithFallback(6*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := w.visitWatchPath(ctx, nil, &watchSetBudget{max: fallbackWatchEntries, root: root}, filepath.Join(root, "example.com"), nil, errors.New("permission denied"))

	if !errors.Is(err, context.Canceled) {
		t.Errorf("visitWatchPath(cancelled ctx, walkErr) = %v, want context.Canceled: shutdown outranks the walk error so Run treats it as a clean stop", err)
	}
	assertNoSkipWarn(t, logs, warnUnwatchablePath)
}

// TestHandleWatchAddError_classifies_root_and_child_registration_failures pins
// the watch-registration half of the same policy, again at the level where the
// failure is an argument: the helper accepts the failure as an argument so the
// policy is deterministic even when tests run as uid 0.
//
// A refused root watch is fatal -- Run needs it to fall back to polling, and a
// swallowed failure would leave Run reporting "fsnotify active" over an empty
// watch set. A refused child watch is warned about and skipped, with the same
// fallback_scan cue covered for both cadence configurations.
// Not parallel: it swaps the process-global slog default.
func TestHandleWatchAddError_classifies_root_and_child_registration_failures(t *testing.T) {
	addErr := errors.New("no space left on device")

	for _, tc := range []struct {
		name         string
		fallback     time.Duration
		atRoot       bool
		wantFatal    bool
		wantFallback string
	}{
		{"a child whose watch is refused is skipped, naming the rescan cadence", 6 * time.Hour, false, false, "6h0m0s"},
		{"a child skip reports a disabled rescan as disabled", 0, false, false, "disabled"},
		{"the root watch being refused is fatal and warns nothing", 6 * time.Hour, true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)
			root := t.TempDir()
			path := filepath.Join(root, "example.com")
			if tc.atRoot {
				path = root
			}
			w := New(root, func(context.Context) {}, WithFallback(tc.fallback))

			err := w.handleWatchAddError(root, path, addErr)

			if tc.wantFatal {
				if !errors.Is(err, addErr) {
					t.Errorf("handleWatchAddError(root) = %v, want the add error unchanged so Run falls back to polling", err)
				}
				assertNoSkipWarn(t, logs, warnUnwatchableDir)
				return
			}
			if err != nil {
				t.Errorf("handleWatchAddError(child) = %v, want nil so one unwatchable directory does not cost the tree its watch", err)
			}
			assertSkipWarn(t, logs, warnUnwatchableDir, path, tc.wantFallback, addErr)
		})
	}
}

// TestResyncWatchSet_stays_silent_when_shutdown_cut_the_walk_short pins the
// shutdown half of resyncWatchSet's contract, the single home of that rule for all
// three re-sync sites (the periodic safety-net tick, the event-queue-overflow
// recovery, and the root-watch re-attach): a walk that failed only because
// cancellation stopped it is a clean stop, not a watch degradation, so it must warn
// nothing. Without the guard every graceful shutdown that lands on one of those
// sites logs "failed to re-sync the watch set", telling an operator that renewals
// are uncovered on a container that is merely stopping.
//
// The live-ctx half is pinned at its own sites (handleSafetyNetTick still scans, the
// root-loss re-attach WARN carries root and fallback_scan); only the silence was
// unpinned.
// Not parallel: it swaps the process-global slog default.
func TestResyncWatchSet_stays_silent_when_shutdown_cut_the_walk_short(t *testing.T) {
	logs := capture.Default(t)
	watcher := newTestWatcher(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {}, WithFallback(6*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w.resyncWatchSet(ctx, watcher, "failed to re-sync the watch set")

	if n := logs.CountLevel(slog.LevelWarn, "failed to re-sync the watch set"); n != 0 {
		t.Errorf("resyncWatchSet(cancelled ctx) logged %d WARNs %v, want 0: a walk cut short by shutdown is a clean stop, not a watch degradation",
			n, logs.Messages())
	}
}

// TestAddWatchDirs_stops_at_the_entry_budget pins the watch-set walk's entry
// ceiling, the one behaviour this cycle ADDED to addWatchDirs and the only
// uncovered non-defensive pair of statements left in the package. Three separate
// contracts ride on it and none was pinned: the walk STOPS at the budget rather
// than failing (fs.SkipAll makes WalkDir return nil, which is what keeps Run in
// watch mode instead of degrading it to polling), the entries up to the budget stay
// registered (the root above all, or nothing is watched at all), and the refusal is
// ONE record per walk rather than one per skipped directory, carrying the phrase the
// CertConverterInputTreeTooLarge alert rule matches (README.md). Deleting the
// ceiling, inverting the comparison, or returning the error instead of fs.SkipAll all
// left the suite green.
//
// Budget 2 is the whole tree minus one: the root is charged first, then
// a.example.com (WalkDir enumerates lexically), so b.example.com is the entry past
// the ceiling.
// Not parallel: it swaps the process-global slog default.
func TestAddWatchDirs_stops_at_the_entry_budget(t *testing.T) {
	watcher := newTestWatcher(t)
	root := t.TempDir()
	watched := filepath.Join(root, "a.example.com")
	refused := filepath.Join(root, "b.example.com")
	for _, dir := range []string{watched, refused} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	logs := capture.Default(t)
	w := New(root, func(context.Context) {}, WithMaxEntries(2))

	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("addWatchDirs over a tree past the budget = %v, want nil: a too-large tree degrades to a PARTIAL watch set, and reporting it as a root failure would drop the process into poll mode", err)
	}

	list := watcher.WatchList()
	for _, want := range []string{root, watched} {
		if !slices.Contains(list, want) {
			t.Errorf("watch list = %v, want %q registered: the entries up to the budget must still be watched", list, want)
		}
	}
	if slices.Contains(list, refused) {
		t.Errorf("watch list = %v, want %q refused: the walk must stop at max_entries", list, refused)
	}
	if n := logs.CountLevel(slog.LevelWarn, watchBudgetMsg); n != 1 {
		t.Errorf("budget WARN logged %d times, want exactly 1 per walk (the remainder is unbounded and the operator action is the same for all of it); log = %v",
			n, logs.Messages())
	}
}

// TestResyncWatchSet_prunes_a_directory_the_tree_no_longer_has pins the
// membership mirror's only full rebuild: resyncWatchSet re-walks the whole root,
// so the mirror it leaves behind must be exactly the set that walk established.
// The mirror otherwise shrinks only on a DELIVERED Remove/Rename, and the
// event-queue overflow that drops those deliveries is one of the conditions that
// routes here, so an append-only re-sync accumulates one path string per deleted
// directory for the life of the process.
// Not parallel: it swaps the process-global slog default via the walk's WARNs.
func TestResyncWatchSet_prunes_a_directory_the_tree_no_longer_has(t *testing.T) {
	watcher := newTestWatcher(t)
	root := t.TempDir()
	gone := filepath.Join(root, "example.com")
	if err := os.MkdirAll(gone, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {})

	w.resyncWatchSet(t.Context(), watcher, "failed to re-sync the watch set")
	if !w.watchSetHas(gone) {
		t.Fatalf("setup: %q is not in the membership mirror after the first re-sync", gone)
	}

	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}

	w.resyncWatchSet(t.Context(), watcher, "failed to re-sync the watch set")

	if w.watchSetHas(gone) {
		t.Errorf("the membership mirror still claims %q is watched after a re-sync of a tree that no longer has it: the map grows with directory churn otherwise",
			gone)
	}
}

// TestResyncWatchSet_unregisters_a_directory_the_rebuild_no_longer_reaches pins the
// KERNEL side of the rebuild, which the mirror-side test above cannot see: the
// membership mirror is the only thing the LIVE-set ceiling is read from
// (visitWatchPath's watchSetSize test), so a rebuild that resets the mirror without
// unregistering what it no longer re-establishes leaves the app holding more inotify
// registrations than MAX_SCAN_ENTRIES while reporting fewer -- and that ceiling is a
// share of the per-UID fs.inotify.max_user_watches quota, so overrunning it is paid by
// unrelated same-UID consumers.
//
// The driver is a tree larger than the budget, which is the reachable producer: the
// first walk registers the lexically-first directories, a new early-sorting domain
// then pushes the tail out of the next walk, and the tail still EXISTS on disk, so
// only an explicit Remove can reclaim its descriptor.
// Not parallel: the walk's budget WARN goes to the process-global slog default.
func TestResyncWatchSet_unregisters_a_directory_the_rebuild_no_longer_reaches(t *testing.T) {
	watcher := newTestWatcher(t)
	root := t.TempDir()
	tail := filepath.Join(root, "z.example.com")
	if err := os.MkdirAll(tail, 0o750); err != nil {
		t.Fatal(err)
	}
	w := New(root, func(context.Context) {}, WithMaxEntries(2))

	w.resyncWatchSet(t.Context(), watcher, "failed to re-sync the watch set")
	if !slices.Contains(watcher.WatchList(), tail) {
		t.Fatalf("setup: watch list = %v, want %q registered by the first walk", watcher.WatchList(), tail)
	}

	// A new early-sorting directory pushes the tail out of the budget-truncated walk
	// while it still exists on disk.
	early := filepath.Join(root, "a.example.com")
	if err := os.MkdirAll(early, 0o750); err != nil {
		t.Fatal(err)
	}

	w.resyncWatchSet(t.Context(), watcher, "failed to re-sync the watch set")

	if !slices.Contains(watcher.WatchList(), early) {
		t.Errorf("watch list = %v, want %q registered by the rebuild", watcher.WatchList(), early)
	}
	if watched := watcher.WatchList(); slices.Contains(watched, tail) {
		t.Errorf("watch list = %v, want %q unregistered: the rebuild no longer reaches it, so leaving the kernel registration live puts the LIVE set above the ceiling watchSetSize reports",
			watched, tail)
	}
	if got, want := len(watcher.WatchList()), 2; got != want {
		t.Errorf("the live registration set holds %d watches, want %d (the budget): %v", got, want, watcher.WatchList())
	}
}

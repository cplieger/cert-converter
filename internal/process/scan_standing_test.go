package process

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

const unreadablePathsMsg = "some /input paths were unreadable and were skipped; health is unaffected"

// TestScannerRun_logs_a_standing_unreadable_path_when_it_changes pins that a
// standing condition is logged when it appears, changes and clears: three scans
// with one standing unreadable path log one WARN, the clearing scan logs one INFO with how
// long it lasted, a restart logs the condition once again, and every scan's result
// still carries the count the end-of-scan record reports.
// Serial: it swaps slog.Default().
func TestScannerRun_logs_a_standing_unreadable_path_when_it_changes(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, in, "live")
	// A directory where a source should be is unreadable as a source, as root too.
	blocker := filepath.Join(in, "blocked.crt")
	if err := os.Mkdir(blocker, 0o750); err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{})

	for scan := range 3 {
		res, err := scanner.Run(t.Context())
		if err != nil {
			t.Fatalf("scan %d: Run = %v", scan+1, err)
		}
		if res.Unreadable != 1 {
			t.Errorf("scan %d: Unreadable = %d, want 1 on every scan: the end-of-scan record carries it", scan+1, res.Unreadable)
		}
	}
	if got := logs.CountLevel(slog.LevelWarn, unreadablePathsMsg); got != 1 {
		t.Errorf("three scans with one standing unreadable path logged %d WARNs, want 1", got)
	}

	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatalf("clearing scan: Run = %v", err)
	}
	if got := logs.CountLevel(slog.LevelInfo, standingClearedMsg); got != 1 {
		t.Errorf("the clearing scan logged %d clear records, want 1; log = %q", got, logs.Messages())
	}
	if !logs.HasAttr(standingClearedMsg, "condition", condUnreadablePaths) {
		t.Errorf("the clear record does not name %q", condUnreadablePaths)
	}
	if _, ok := logs.AttrValue(standingClearedMsg, "lasted"); !ok {
		t.Errorf("the clear record does not say how long the condition lasted")
	}

	if err := os.Mkdir(blocker, 0o750); err != nil {
		t.Fatal(err)
	}
	restarted := newVerdictScanner(in, out, Options{})
	for range 2 {
		if _, err := restarted.Run(t.Context()); err != nil {
			t.Fatalf("after restart: Run = %v", err)
		}
	}
	if got := logs.CountLevel(slog.LevelWarn, unreadablePathsMsg); got != 2 {
		t.Errorf("a restart with the path still unreadable logged the condition %d times in total, want 2: the new process reports it once", got)
	}
}

// TestScannerRun_relogs_a_standing_condition_when_its_count_changes pins that a
// changed count is logged again: the count is part of what the reader is told.
// Serial: it swaps slog.Default().
func TestScannerRun_relogs_a_standing_condition_when_its_count_changes(t *testing.T) {
	in := t.TempDir()
	writeSelfSignedPair(t, in, "live")
	if err := os.Mkdir(filepath.Join(in, "one.crt"), 0o750); err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, t.TempDir(), Options{})
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(in, "two.crt"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := logs.CountLevel(slog.LevelWarn, unreadablePathsMsg); got != 2 {
		t.Errorf("a count change from 1 to 2 logged %d WARNs in total, want 2", got)
	}
	if !logs.HasAttr(unreadablePathsMsg, "unreadable", "2") {
		t.Errorf("no WARN carries the new count 2; log = %q", logs.Messages())
	}
}

// TestScannerRun_logs_a_standing_collision_when_it_changes pins the same on the
// flat output-name collision: the ERROR is logged when the collision appears and
// the INFO, under the same output_stem, when it is resolved, not on every scan in
// between.
// Serial: it swaps slog.Default().
func TestScannerRun_logs_a_standing_collision_when_it_changes(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	for _, dir := range []string{"a/site", "b/site"} {
		if err := os.MkdirAll(filepath.Join(in, dir), 0o750); err != nil {
			t.Fatal(err)
		}
		writeSelfSignedPair(t, filepath.Join(in, dir), "cert")
	}
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	for range 2 {
		res, err := scanner.Run(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if res.Collided != 2 {
			t.Fatalf("Run(two sources, one flat name) Collided = %d, want 2", res.Collided)
		}
	}
	if got := logs.CountLevel(slog.LevelError, collisionMsg); got != 1 {
		t.Errorf("two scans with one standing collision logged %d ERRORs, want 1", got)
	}
	if err := os.RemoveAll(filepath.Join(in, "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !logs.HasAttr(standingClearedMsg, "condition", condCollision) {
		t.Errorf("resolving the collision logged no clear record; log = %q", logs.Messages())
	}
	onset, _ := logs.AttrValueExact(collisionMsg, "output_stem")
	if cleared, ok := logs.AttrValueExact(standingClearedMsg, "output_stem"); !ok || cleared != onset {
		t.Errorf("the clear record's output_stem = %q (present %v), want the onset's %q", cleared, ok, onset)
	}
	if _, ok := logs.AttrValueExact(standingClearedMsg, "path"); ok {
		t.Errorf("the collision's clear record carries `path`, want its subject under output_stem only")
	}
}

// TestScannerRun_pairs_an_unresolved_symlink_onset_with_its_clear pins that both
// records name the condition and the link the same way, so a reader can match them.
// Serial: it swaps slog.Default().
func TestScannerRun_pairs_an_unresolved_symlink_onset_with_its_clear(t *testing.T) {
	base := t.TempDir()
	in, outside := filepath.Join(base, "input"), filepath.Join(base, "outside")
	for _, dir := range []string{in, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeSelfSignedPair(t, in, "live")
	link := filepath.Join(in, "linked-dir")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, t.TempDir(), Options{})
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	const onsetMsg = "skipping symlink that could not be resolved through the input root"
	if !logs.HasAttr(onsetMsg, "condition", condUnresolvedSymlink) {
		t.Errorf("the unresolved-symlink WARN does not carry condition=%s; log = %q", condUnresolvedSymlink, logs.Messages())
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !logs.HasAttr(standingClearedMsg, "condition", condUnresolvedSymlink) || !logs.HasAttr(standingClearedMsg, "path", "linked-dir") {
		t.Errorf("removing the link logged no clear record naming %s and path linked-dir; log = %q", condUnresolvedSymlink, logs.Messages())
	}
}

package process

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/scanbudget"
)

// collidingTree builds two flat claimants of the stem site/cert under in, a/site
// and b/site, and returns the base directory a test hides a claimant under.
func collidingTree(t *testing.T) (in, outside string) {
	t.Helper()
	base := t.TempDir()
	in, outside = filepath.Join(base, "input"), filepath.Join(base, "outside")
	for _, dir := range []string{in, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"a/site", "b/site"} {
		if err := os.MkdirAll(filepath.Join(in, dir), 0o750); err != nil {
			t.Fatal(err)
		}
		writeSelfSignedPair(t, filepath.Join(in, dir), "cert")
	}
	return in, outside
}

// hideBehindLink moves in/name outside the input root and leaves an
// unresolvable link in its place; the returned func puts it back.
func hideBehindLink(t *testing.T, in, outside, name string) (restore func()) {
	t.Helper()
	at, hidden := filepath.Join(in, name), filepath.Join(outside, name)
	if err := os.Rename(at, hidden); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hidden, at); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(at); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(hidden, at); err != nil {
			t.Fatal(err)
		}
	}
}

// TestScannerRun_keeps_a_collision_whose_claimant_is_hidden pins that a claimant
// the scan cannot reach still contests its stem: the visible claimant is not
// published, health stays unhealthy, and the collision neither clears nor
// reports a second onset.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_a_collision_whose_claimant_is_hidden(t *testing.T) {
	in, outside := collidingTree(t)
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	if res := runScans(t, scanner, 1); res.Collided != 2 {
		t.Fatalf("setup: Collided = %d, want 2", res.Collided)
	}

	restore := hideBehindLink(t, in, outside, "b")
	res := runScans(t, scanner, 1)
	if res.Unresolved != 1 {
		t.Fatalf("setup: Unresolved = %d, want 1: b must be hidden behind the link", res.Unresolved)
	}
	if res.Collided != 2 || res.conversionsClean() {
		t.Errorf("a scan that could not reach b = %+v, want Collided 2 and conversions not clean", res)
	}
	if _, err := os.Lstat(filepath.Join(out, "site", "cert.pfx")); !os.IsNotExist(err) {
		t.Errorf("the visible claimant was published while b was hidden: Lstat(site/cert.pfx) = %v", err)
	}
	if got := countClears(logs, condCollision); got != 0 {
		t.Errorf("a scan that could not reach b logged %d collision clears, want 0; log = %q", got, logs.Messages())
	}

	restore()
	if res := runScans(t, scanner, 1); res.Collided != 2 {
		t.Errorf("the restored tree: Collided = %d, want 2", res.Collided)
	}
	if got := logs.CountLevel(slog.LevelError, collisionMsg); got != 1 {
		t.Errorf("the collision was reported at ERROR %d times in total, want 1: it held throughout", got)
	}
	if got := countClears(logs, condCollision); got != 0 {
		t.Errorf("the collision logged %d clears, want 0", got)
	}
}

// TestScannerRun_keeps_a_collision_whose_claimants_are_both_hidden pins the
// same when the scan reaches neither claimant.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_a_collision_whose_claimants_are_both_hidden(t *testing.T) {
	in, outside := collidingTree(t)
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, t.TempDir(), Options{Layout: outputpolicy.LayoutFlat})
	runScans(t, scanner, 1)

	restoreA := hideBehindLink(t, in, outside, "a")
	restoreB := hideBehindLink(t, in, outside, "b")
	if res := runScans(t, scanner, 1); res.Unresolved != 2 || res.Collided != 2 {
		t.Errorf("a scan that reached neither claimant = %+v, want Unresolved 2 and Collided 2", res)
	}
	restoreA()
	restoreB()
	runScans(t, scanner, 1)
	if got := countClears(logs, condCollision); got != 0 {
		t.Errorf("the collision logged %d clears, want 0; log = %q", got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelError, collisionMsg); got != 1 {
		t.Errorf("the collision was reported at ERROR %d times in total, want 1", got)
	}
}

// TestScannerRun_clears_a_collision_whose_claimant_left_a_listed_directory pins
// that a claimant deleted from a directory the scan listed ends the collision,
// even while an unrelated link keeps the scan short of the whole tree.
// Serial: it swaps slog.Default().
func TestScannerRun_clears_a_collision_whose_claimant_left_a_listed_directory(t *testing.T) {
	in, outside := collidingTree(t)
	if err := os.Symlink(outside, filepath.Join(in, "linked")); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	runScans(t, scanner, 1)

	for _, name := range []string{"cert.crt", "cert.key"} {
		if err := os.Remove(filepath.Join(in, "b", "site", name)); err != nil {
			t.Fatal(err)
		}
	}
	res := runScans(t, scanner, 1)
	if res.Collided != 0 || res.Unresolved != 1 {
		t.Errorf("the scan after b's claimant left = %+v, want Collided 0 and the link still unresolved", res)
	}
	if got := countClears(logs, condCollision); got != 1 {
		t.Errorf("the resolved collision logged %d clears, want 1; log = %q", got, logs.Messages())
	}
	if _, err := os.Stat(filepath.Join(out, "site", "cert.pfx")); err != nil {
		t.Errorf("the now-unique claimant was not published: %v", err)
	}
}

// TestScanWalkVisit_withdraws_a_directory_whose_listing_failed pins that a
// directory the walk entered and then could not list reaches none of its paths.
func TestScanWalkVisit_withdraws_a_directory_whose_listing_failed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	entry := fs.FileInfoToDirEntry(info)
	sw := &scanWalk{budget: scanbudget.NewCounter(0)}
	for _, step := range []struct {
		rel string
		err error
	}{{".", nil}, {"site", nil}, {"site", fs.ErrPermission}} {
		if got := sw.visit(t.Context(), step.rel, entry, step.err); got != nil {
			t.Fatalf("visit(%q, %v) = %v, want nil", step.rel, step.err, got)
		}
	}
	if sw.reach.input("site/a.crt") {
		t.Errorf("reach.input(site/a.crt) = true, want false: site could not be listed")
	}
	if !sw.reach.input("other.crt") {
		t.Errorf("reach.input(other.crt) = false, want true: the root was listed")
	}
}

// TestScannerRun_clears_an_unwritable_output_whose_source_left_a_listed_directory
// pins that the refusal ends when its source is gone, even while an unrelated
// link keeps the scan short of the whole tree, so the source's return is news.
// Serial: it swaps slog.Default() and the write seam.
func TestScannerRun_clears_an_unwritable_output_whose_source_left_a_listed_directory(t *testing.T) {
	base := t.TempDir()
	in, outside, out := filepath.Join(base, "input"), filepath.Join(base, "outside"), t.TempDir()
	for _, dir := range []string{in, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(in, "linked")); err != nil {
		t.Fatal(err)
	}
	writeSelfSignedPair(t, in, "chain")
	stageOversizedBundle(t, filepath.Join(out, "chain.pfx"))
	stubWriteRefusal(t, &fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EROFS})
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{})
	if res := runScans(t, scanner, 1); res.Unwritable != 1 || res.Unresolved != 1 {
		t.Fatalf("setup: first scan = %+v, want Unwritable 1 and the link unresolved", res)
	}

	held := t.TempDir()
	for _, name := range []string{"chain.crt", "chain.key"} {
		if err := os.Rename(filepath.Join(in, name), filepath.Join(held, name)); err != nil {
			t.Fatal(err)
		}
	}
	runScans(t, scanner, 1)
	if got := countClears(logs, condUnwritable); got != 1 {
		t.Errorf("the scan after the source left logged %d unwritable_output clears, want 1; log = %q", got, logs.Messages())
	}

	for _, name := range []string{"chain.crt", "chain.key"} {
		if err := os.Rename(filepath.Join(held, name), filepath.Join(in, name)); err != nil {
			t.Fatal(err)
		}
	}
	if res := runScans(t, scanner, 1); res.Unwritable != 1 {
		t.Fatalf("setup: the returned source's scan = %+v, want Unwritable 1", res)
	}
	if got := logs.CountLevel(slog.LevelWarn, unreplaceableArtifactMsg); got != 2 {
		t.Errorf("the refusal was reported at WARN %d times in total, want 2: the returned source's refusal is news", got)
	}
}

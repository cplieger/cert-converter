package process

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/scanbudget"
	"github.com/cplieger/go/slogx/capture"
)

// collidingTree builds two flat claimants of the stem site/cert under in, a/site
// and b/site, and returns the base directory a test hides a claimant under.
func collidingTree(t *testing.T) (in, outside string) {
	t.Helper()
	return claimantTree(t, "a", "b")
}

// claimantTree builds a flat claimant of the stem site/cert under in/<name>/site
// for each name, and returns the base directory a test hides a claimant under.
func claimantTree(t *testing.T, names ...string) (in, outside string) {
	t.Helper()
	base := t.TempDir()
	in, outside = filepath.Join(base, "input"), filepath.Join(base, "outside")
	for _, dir := range []string{in, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range names {
		addClaimant(t, in, name)
	}
	return in, outside
}

// addClaimant writes a pair claiming the flat stem site/cert under in/name/site.
func addClaimant(t *testing.T, in, name string) {
	t.Helper()
	dir := filepath.Join(in, name, "site")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeSelfSignedPair(t, dir, "cert")
}

// removePair deletes the pair under in/name/site and leaves the directory.
func removePair(t *testing.T, in, name string) {
	t.Helper()
	for _, file := range []string{"cert.crt", "cert.key"} {
		if err := os.Remove(filepath.Join(in, name, "site", file)); err != nil {
			t.Fatal(err)
		}
	}
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

// TestScannerRun_keeps_a_collision_whose_claimant_is_hidden_behind_an_input_named_link
// pins that an unresolvable link named like a certificate or key hides what is
// under it as any other unresolvable link does, on a scan an unrelated link
// keeps short of the whole tree.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_a_collision_whose_claimant_is_hidden_behind_an_input_named_link(t *testing.T) {
	for _, name := range []string{"b.crt", "b.key"} {
		t.Run(name, func(t *testing.T) {
			in, outside := claimantTree(t, "a", name)
			if err := os.Symlink(outside, filepath.Join(in, "linked")); err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			logs := captureLogs(t)
			scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
			if res := runScans(t, scanner, 1); res.Collided != 2 {
				t.Fatalf("setup: Collided = %d, want 2", res.Collided)
			}

			hideBehindLink(t, in, outside, name)
			if res := runScans(t, scanner, 1); res.Collided != 2 || res.conversionsClean() {
				t.Errorf("a scan that could not reach %s = %+v, want Collided 2 and conversions not clean", name, res)
			}
			if _, err := os.Lstat(filepath.Join(out, "site", "cert.pfx")); !os.IsNotExist(err) {
				t.Errorf("a was published while %s was hidden: Lstat(site/cert.pfx) = %v", name, err)
			}
			if got := countClears(logs, condCollision); got != 0 {
				t.Errorf("a scan that could not reach %s logged %d collision clears, want 0; log = %q", name, got, logs.Messages())
			}
		})
	}
}

// replaceAClaimantWhileOneIsHidden runs three flat scans over collidingTree's
// claimants of site/cert: a and b collide; b goes behind an unresolvable link
// while c joins; c's pair is deleted with b still hidden. It returns each scan's
// result and the func that puts b back.
func replaceAClaimantWhileOneIsHidden(t *testing.T, scanner *Scanner, in, outside string) ([]ScanResult, func()) {
	t.Helper()
	results := []ScanResult{runScans(t, scanner, 1)}
	restore := hideBehindLink(t, in, outside, "b")
	addClaimant(t, in, "c")
	results = append(results, runScans(t, scanner, 1))
	removePair(t, in, "c")
	results = append(results, runScans(t, scanner, 1))
	if results[1].Unresolved != 1 || results[2].Unresolved != 1 {
		t.Fatalf("setup: Unresolved = %d then %d, want 1 on both: b must stay hidden behind the link", results[1].Unresolved, results[2].Unresolved)
	}
	return results, restore
}

// collisionErrorCounts returns the count of every collision record logged at
// ERROR, in order.
func collisionErrorCounts(logs *capture.Recorder) []int64 {
	var counts []int64
	for _, r := range logs.Records() {
		if r.Level != slog.LevelError || r.Message != collisionMsg {
			continue
		}
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "count" {
				counts = append(counts, a.Value.Int64())
			}
			return true
		})
	}
	return counts
}

// TestScannerRun_keeps_a_hidden_claimant_when_the_other_claimants_change pins
// that a claimant out of reach stays in its stem's collision while visible
// claimants come and go: the collision counts it, never clears, publishes
// nothing, and reports each change of its claimant count once.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_a_hidden_claimant_when_the_other_claimants_change(t *testing.T) {
	in, outside := collidingTree(t)
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	results, _ := replaceAClaimantWhileOneIsHidden(t, scanner, in, outside)

	if results[1].Collided != 3 {
		t.Errorf("the scan with b hidden and c added: Collided = %d, want 3 (a, b and c)", results[1].Collided)
	}
	if results[2].Collided != 2 || results[2].conversionsClean() {
		t.Errorf("the scan after c left = %+v, want Collided 2 (a and the hidden b) and conversions not clean", results[2])
	}
	if _, err := os.Lstat(filepath.Join(out, "site", "cert.pfx")); !os.IsNotExist(err) {
		t.Errorf("a was published while the hidden b still claims its stem: Lstat(site/cert.pfx) = %v", err)
	}
	if got := countClears(logs, condCollision); got != 0 {
		t.Errorf("the collision logged %d clears, want 0; log = %q", got, logs.Messages())
	}
	if got, want := collisionErrorCounts(logs), []int64{2, 3, 2}; !slices.Equal(got, want) {
		t.Errorf("collision ERROR counts = %v, want %v: the onset, then each change of the claimant count", got, want)
	}
}

// TestScannerRun_clears_a_collision_once_its_hidden_claimant_is_reached_and_gone
// continues the sequence above: b back in reach keeps the collision, and b's pair
// deleted from a listed directory clears it and publishes a.
// Serial: it swaps slog.Default().
func TestScannerRun_clears_a_collision_once_its_hidden_claimant_is_reached_and_gone(t *testing.T) {
	in, outside := collidingTree(t)
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	_, restore := replaceAClaimantWhileOneIsHidden(t, scanner, in, outside)
	pfx := filepath.Join(out, "site", "cert.pfx")

	restore()
	if res := runScans(t, scanner, 1); res.Collided != 2 || res.Unresolved != 0 {
		t.Errorf("the scan with b back = %+v, want Collided 2 and nothing unresolved", res)
	}
	if _, err := os.Lstat(pfx); !os.IsNotExist(err) {
		t.Errorf("a was published while b is back and still claims its stem: Lstat(site/cert.pfx) = %v", err)
	}
	if got := countClears(logs, condCollision); got != 0 {
		t.Errorf("the scan with b back logged %d collision clears, want 0", got)
	}

	removePair(t, in, "b")
	res := runScans(t, scanner, 1)
	if res.Collided != 0 || !res.conversionsClean() {
		t.Errorf("the scan after b's pair left = %+v, want Collided 0 and conversions clean", res)
	}
	if got := countClears(logs, condCollision); got != 1 {
		t.Errorf("the resolved collision logged %d clears, want 1; log = %q", got, logs.Messages())
	}
	if _, err := os.Stat(pfx); err != nil {
		t.Errorf("a, now the only claimant, was not published: %v", err)
	}
	if got, want := collisionErrorCounts(logs), []int64{2, 3, 2}; !slices.Equal(got, want) {
		t.Errorf("collision ERROR counts = %v, want %v: b coming back into reach is not news", got, want)
	}
}

// clearWithLastClaimantHidden runs a and b to a collision, then deletes a's pair
// with b behind an unresolvable link, so the collision is left with b out of
// reach. It returns that scan's result and the func that puts b back.
func clearWithLastClaimantHidden(t *testing.T, scanner *Scanner, in, outside string) (ScanResult, func()) {
	t.Helper()
	runScans(t, scanner, 1)
	restore := hideBehindLink(t, in, outside, "b")
	removePair(t, in, "a")
	return runScans(t, scanner, 1), restore
}

// TestScannerRun_clears_a_collision_whose_last_claimant_is_hidden pins that
// a collision ends once one claimant is left, even while that claimant is out of
// reach: the collision clears and Collided is 0, while the hidden claimant stays
// stored as the stem's claimant.
// Serial: it swaps slog.Default().
func TestScannerRun_clears_a_collision_whose_last_claimant_is_hidden(t *testing.T) {
	in, outside := collidingTree(t)
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, t.TempDir(), Options{Layout: outputpolicy.LayoutFlat})
	res, _ := clearWithLastClaimantHidden(t, scanner, in, outside)
	if res.Collided != 0 || res.Unresolved != 1 {
		t.Errorf("the scan after a left with b hidden = %+v, want Collided 0 and b unresolved", res)
	}
	if got := countClears(logs, condCollision); got != 1 {
		t.Errorf("the collision logged %d clears, want 1; log = %q", got, logs.Messages())
	}
}

// TestScannerRun_holds_a_newcomer_against_a_hidden_last_claimant pins that the
// last claimant of a cleared collision still claims its stem while out of reach:
// a new claimant of the stem starts a fresh collision instead of being published.
// Serial: it swaps slog.Default().
func TestScannerRun_holds_a_newcomer_against_a_hidden_last_claimant(t *testing.T) {
	in, outside := collidingTree(t)
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	if res, _ := clearWithLastClaimantHidden(t, scanner, in, outside); res.Collided != 0 {
		t.Fatalf("setup: the scan after a left with b hidden = %+v, want Collided 0", res)
	}

	addClaimant(t, in, "c")
	res := runScans(t, scanner, 1)
	if res.Collided != 2 || res.conversionsClean() {
		t.Errorf("the scan that added c with b hidden = %+v, want Collided 2 (the hidden b and c) and conversions not clean", res)
	}
	if _, err := os.Lstat(filepath.Join(out, "site", "cert.pfx")); !os.IsNotExist(err) {
		t.Errorf("c was published while the hidden b still claims its stem: Lstat(site/cert.pfx) = %v", err)
	}
	if got := countClears(logs, condCollision); got != 1 {
		t.Errorf("the collision logged %d clears, want 1; log = %q", got, logs.Messages())
	}
	if got, want := collisionErrorCounts(logs), []int64{2, 2}; !slices.Equal(got, want) {
		t.Errorf("collision ERROR counts = %v, want %v: the first onset, then the onset with c", got, want)
	}
}

// TestScannerRun_releases_a_hidden_last_claimant_once_reached pins the two ways
// that claimant leaves its stem: reached and present it converts, and reached
// and gone it no longer holds the stem against a newcomer. An unrelated link
// keeps every scan short of the whole tree.
// Serial: it swaps slog.Default().
func TestScannerRun_releases_a_hidden_last_claimant_once_reached(t *testing.T) {
	in, outside := collidingTree(t)
	if err := os.Symlink(outside, filepath.Join(in, "linked")); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	_, restore := clearWithLastClaimantHidden(t, scanner, in, outside)

	restore()
	if res := runScans(t, scanner, 1); res.Collided != 0 || res.Converted != 1 {
		t.Errorf("the scan with b back = %+v, want Collided 0 and b converted", res)
	}
	if _, err := os.Stat(filepath.Join(out, "site", "cert.pfx")); err != nil {
		t.Errorf("b, the only claimant and back in reach, was not published: %v", err)
	}

	removePair(t, in, "b")
	runScans(t, scanner, 1)
	addClaimant(t, in, "c")
	if res := runScans(t, scanner, 1); res.Collided != 0 || res.Converted != 1 {
		t.Errorf("the scan that added c after b left = %+v, want Collided 0 and c converted", res)
	}
	if got, want := collisionErrorCounts(logs), []int64{2}; !slices.Equal(got, want) {
		t.Errorf("collision ERROR counts = %v, want %v: only the first onset", got, want)
	}
}

// TestScannerRun_holds_a_newcomer_against_a_hidden_published_claimant pins that
// a claimant out of reach claims its stem whether or not it ever collided: a new
// claimant of the stem collides with it and the hidden claimant's artifact stays.
// Serial: it swaps slog.Default().
func TestScannerRun_holds_a_newcomer_against_a_hidden_published_claimant(t *testing.T) {
	in, outside := claimantTree(t, "a")
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	if res := runScans(t, scanner, 1); res.Converted != 1 {
		t.Fatalf("setup: the scan of a alone = %+v, want a converted", res)
	}
	pfx := filepath.Join(out, "site", "cert.pfx")
	published, err := os.ReadFile(pfx)
	if err != nil {
		t.Fatal(err)
	}

	hideBehindLink(t, in, outside, "a")
	addClaimant(t, in, "c")
	res := runScans(t, scanner, 1)
	if res.Collided != 2 || res.conversionsClean() {
		t.Errorf("the scan that added c with a hidden = %+v, want Collided 2 (the hidden a and c) and conversions not clean", res)
	}
	if got, err := os.ReadFile(pfx); err != nil || !bytes.Equal(got, published) {
		t.Errorf("site/cert.pfx after c joined = %d bytes, %v, want a's artifact unchanged: c must not replace it", len(got), err)
	}
	if got, want := collisionErrorCounts(logs), []int64{2}; !slices.Equal(got, want) {
		t.Errorf("collision ERROR counts = %v, want %v", got, want)
	}
}

// TestScannerRun_clears_a_collision_whose_claimant_directory_left pins that a
// claimant whose directory was removed, renamed or replaced by a link the scan
// resolved (to a directory it walks directly, or to nothing) is gone once the
// scan listed the directory that held it, even while an unrelated link keeps
// the scan short of the whole tree.
// Serial: it swaps slog.Default().
func TestScannerRun_clears_a_collision_whose_claimant_directory_left(t *testing.T) {
	replaceWithLink := func(target string) func(in string) error {
		return func(in string) error {
			if err := os.RemoveAll(filepath.Join(in, "b")); err != nil {
				return err
			}
			return os.Symlink(target, filepath.Join(in, "b"))
		}
	}
	for _, tc := range []struct {
		leave func(in string) error
		name  string
	}{
		{name: "removed", leave: func(in string) error { return os.RemoveAll(filepath.Join(in, "b")) }},
		{name: "renamed", leave: func(in string) error {
			return os.Rename(filepath.Join(in, "b", "site"), filepath.Join(in, "b", "other"))
		}},
		{name: "linked_to_a_walked_directory", leave: replaceWithLink("a")},
		{name: "linked_to_nothing", leave: replaceWithLink("does-not-exist")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, outside := collidingTree(t)
			if err := os.Symlink(outside, filepath.Join(in, "linked")); err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			logs := captureLogs(t)
			scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
			runScans(t, scanner, 1)

			if err := tc.leave(in); err != nil {
				t.Fatal(err)
			}
			if res := runScans(t, scanner, 1); res.Collided != 0 || res.Unresolved != 1 {
				t.Errorf("the scan after b's directory left = %+v, want Collided 0 and the link still unresolved", res)
			}
			if got := countClears(logs, condCollision); got != 1 {
				t.Errorf("the resolved collision logged %d clears, want 1; log = %q", got, logs.Messages())
			}
			if _, err := os.Stat(filepath.Join(out, "site", "cert.pfx")); err != nil {
				t.Errorf("a, now the only claimant, was not published: %v", err)
			}
		})
	}
}

// TestScannerRun_keeps_a_collision_whose_claimant_directory_a_budget_stop_left_unlisted
// pins that a directory the walk enumerated but had not listed when the entry
// budget stopped it reaches none of its paths.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_a_collision_whose_claimant_directory_a_budget_stop_left_unlisted(t *testing.T) {
	in, _ := collidingTree(t)
	if err := os.Mkdir(filepath.Join(in, "b", "aaa"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "b", "aaa", "notes.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	runScans(t, scanner, 1)

	// Eight entries are ".", a, b, a/site, its pair, b/aaa and b/site: the stop
	// lands inside b/aaa, which the walk lists before b/site.
	scanner.opts.MaxScanEntries = 8
	res, err := scanner.Run(t.Context())
	if res.Outcome != OutcomeBudgetStopped {
		t.Fatalf("setup: Run = %+v, %v, want a budget stop inside b/aaa", res, err)
	}
	if res.Collided != 2 {
		t.Errorf("the budget-stopped scan: Collided = %d, want 2 (a and the unreached b)", res.Collided)
	}
	if _, err := os.Lstat(filepath.Join(out, "site", "cert.pfx")); !os.IsNotExist(err) {
		t.Errorf("a was published while the scan stopped before listing b/site: Lstat(site/cert.pfx) = %v", err)
	}
	if got := countClears(logs, condCollision); got != 0 {
		t.Errorf("the budget-stopped scan logged %d collision clears, want 0; log = %q", got, logs.Messages())
	}
}

// TestScannerRun_clears_a_collision_whose_claimant_directory_left_before_a_budget_stop
// pins that a directory holding the entry the budget stopped at was listed in
// full, so a claimant directory gone from it is gone.
// Serial: it swaps slog.Default().
func TestScannerRun_clears_a_collision_whose_claimant_directory_left_before_a_budget_stop(t *testing.T) {
	in, _ := collidingTree(t)
	zz := filepath.Join(in, "b", "zz")
	if err := os.Mkdir(zz, 0o750); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		if err := os.WriteFile(filepath.Join(zz, fmt.Sprintf("f%02d.txt", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	runScans(t, scanner, 1)

	if err := os.RemoveAll(filepath.Join(in, "b", "site")); err != nil {
		t.Fatal(err)
	}
	// Eight entries are ".", a, b, a/site, its pair, b/zz and one of its files:
	// the stop lands inside b/zz, after the walk listed b in full.
	scanner.opts.MaxScanEntries = 8
	res, err := scanner.Run(t.Context())
	if res.Outcome != OutcomeBudgetStopped {
		t.Fatalf("setup: Run = %+v, %v, want a budget stop inside b/zz", res, err)
	}
	if res.Collided != 0 {
		t.Errorf("the budget-stopped scan after b/site left: Collided = %d, want 0", res.Collided)
	}
	if got := countClears(logs, condCollision); got != 1 {
		t.Errorf("the resolved collision logged %d clears, want 1; log = %q", got, logs.Messages())
	}
	if _, err := os.Stat(filepath.Join(out, "site", "cert.pfx")); err != nil {
		t.Errorf("a, now the only claimant, was not published: %v", err)
	}
}

// TestScannerRun_counts_the_ledger_on_a_budget_stopped_scan pins that a scan the
// entry budget stopped after every claimant counts its own claimants, so the
// count follows each claimant that leaves and health recovers once the
// collision clears.
// Serial: it swaps slog.Default().
func TestScannerRun_counts_the_ledger_on_a_budget_stopped_scan(t *testing.T) {
	in, _ := claimantTree(t, "a", "b", "c")
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat, MaxScanEntries: 20})
	if res := runScans(t, scanner, 1); res.Collided != 3 {
		t.Fatalf("setup: the first scan = %+v, want Collided 3", res)
	}
	// z sorts after every claimant and holds more entries than the budget leaves.
	z := filepath.Join(in, "z")
	if err := os.Mkdir(z, 0o750); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if err := os.WriteFile(filepath.Join(z, fmt.Sprintf("f%02d.txt", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	removePair(t, in, "c")
	res := runScans(t, scanner, 1)
	if res.Outcome != OutcomeBudgetStopped {
		t.Fatalf("setup: the scan after c left = %+v, want a budget stop inside z", res)
	}
	if res.Collided != 2 {
		t.Errorf("the budget-stopped scan after c left: Collided = %d, want 2 (a and b)", res.Collided)
	}
	if err := os.RemoveAll(filepath.Join(in, "b")); err != nil {
		t.Fatal(err)
	}
	res = runScans(t, scanner, 1)
	if res.Outcome != OutcomeBudgetStopped || res.Collided != 0 || !res.conversionsClean() {
		t.Errorf("the scan after b's directory left = %+v, want a budget stop, Collided 0 and conversions clean", res)
	}
	if _, err := os.Stat(filepath.Join(out, "site", "cert.pfx")); err != nil {
		t.Errorf("a, now the only claimant, was not published: %v", err)
	}
	if got, want := collisionErrorCounts(logs), []int64{3, 2}; !slices.Equal(got, want) {
		t.Errorf("collision ERROR counts = %v, want %v", got, want)
	}
}

// TestScannerRun_keeps_a_collision_whose_claimant_a_budget_stop_did_not_reach pins
// that a directory the walk entered but stopped inside reaches none of its paths,
// so a claimant after the stop still holds its stem.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_a_collision_whose_claimant_a_budget_stop_did_not_reach(t *testing.T) {
	in, _ := collidingTree(t)
	out := t.TempDir()
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	runScans(t, scanner, 1)

	// Seven entries are ".", a, b, a/site, its pair and b/site: the stop lands on b's certificate.
	scanner.opts.MaxScanEntries = 7
	res, err := scanner.Run(t.Context())
	if res.Outcome != OutcomeBudgetStopped {
		t.Fatalf("setup: Run = %+v, %v, want a budget stop inside b/site", res, err)
	}
	if res.Collided != 2 {
		t.Errorf("the budget-stopped scan: Collided = %d, want 2 (a and the unreached b)", res.Collided)
	}
	if _, err := os.Lstat(filepath.Join(out, "site", "cert.pfx")); !os.IsNotExist(err) {
		t.Errorf("a was published while the scan stopped before b: Lstat(site/cert.pfx) = %v", err)
	}
	if got := countClears(logs, condCollision); got != 0 {
		t.Errorf("the budget-stopped scan logged %d collision clears, want 0; log = %q", got, logs.Messages())
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

	removePair(t, in, "b")
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

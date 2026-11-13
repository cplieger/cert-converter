package process

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/go/slogx/capture"
)

const unreadablePathsMsg = "some /input paths were unreadable and were skipped; health is unaffected unless a skipped path had a standing conversion failure"

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

const (
	conversionFailedLine = "conversion failed"
	permissiveDirLine    = "the /output directory holding generated artifacts is more permissive than policy"
	permissiveFileLine   = "prior output is more permissive than policy; leaving its mode as found"
)

// writeBrokenPair writes a pair whose certificate does not parse, with body as the
// undecodable PEM payload, so the error text follows body.
func writeBrokenPair(t *testing.T, dir, stem, body string) {
	t.Helper()
	writePair(t, dir, stem,
		[]byte("-----BEGIN CERTIFICATE-----\n"+body+"\n-----END CERTIFICATE-----\n"), []byte("garbage"))
}

// runScans runs n complete scans and fails the test on any scan error.
func runScans(t *testing.T, scanner *Scanner, n int) ScanResult {
	t.Helper()
	var res ScanResult
	for scan := range n {
		var err error
		if res, err = scanner.Run(t.Context()); err != nil {
			t.Fatalf("scan %d: Run = %v", scan+1, err)
		}
	}
	return res
}

// TestScannerRun_logs_a_standing_conversion_failure_when_it_changes pins the
// failure record's lifecycle: one ERROR when a source starts failing, Debug while
// it keeps failing the same way, one ERROR again after a restart or when the cause
// changes, and one clear record when the source converts, while every scan's
// result still counts the failure.
// Serial: it swaps slog.Default().
func TestScannerRun_logs_a_standing_conversion_failure_when_it_changes(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, in, "live")
	writeBrokenPair(t, in, "broken", "not base64")
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{})

	for scan := range 3 {
		if res := runScans(t, scanner, 1); res.Failed != 1 {
			t.Errorf("scan %d: Failed = %d, want 1 on every scan: the end-of-scan record carries it", scan+1, res.Failed)
		}
	}
	if got := logs.CountLevel(slog.LevelError, conversionFailedLine); got != 1 {
		t.Errorf("three scans with one failing source logged %d ERRORs, want 1; log = %q", got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelDebug, conversionFailedLine); got != 2 {
		t.Errorf("the two repeat scans logged %d Debug failure records, want 2", got)
	}
	if !logs.HasAttr(conversionFailedLine, "condition", "conversion_failed") || !logs.HasAttr(conversionFailedLine, "path", "broken.crt") {
		t.Errorf("the failure record does not carry condition=conversion_failed and path=broken.crt; log = %q", logs.Messages())
	}

	restarted := newVerdictScanner(in, out, Options{})
	runScans(t, restarted, 2)
	if got := logs.CountLevel(slog.LevelError, conversionFailedLine); got != 2 {
		t.Errorf("a restart with the source still failing logged the failure %d times in total, want 2: the new process reports it once", got)
	}

	writeBrokenPair(t, in, "broken", "")
	runScans(t, restarted, 2)
	if got := logs.CountLevel(slog.LevelError, conversionFailedLine); got != 3 {
		t.Errorf("a changed cause logged the failure %d times in total, want 3: the new cause is news", got)
	}
	if got := logs.CountLevel(slog.LevelInfo, standingClearedMsg); got != 0 {
		t.Errorf("a source that kept failing logged %d clear records, want 0", got)
	}

	writeSelfSignedPair(t, in, "broken")
	if res := runScans(t, restarted, 1); res.Failed != 0 {
		t.Fatalf("the fixed source still fails: %+v", res)
	}
	if !logs.HasAttr(standingClearedMsg, "condition", "conversion_failed") || !logs.HasAttr(standingClearedMsg, "path", "broken.crt") {
		t.Errorf("fixing the source logged no clear record naming conversion_failed and broken.crt; log = %q", logs.Messages())
	}
	if _, ok := logs.AttrValue(standingClearedMsg, "lasted"); !ok {
		t.Errorf("the clear record does not say how long the failure lasted")
	}
}

// TestScannerRun_keeps_a_conversion_failure_through_an_incomplete_scan pins that
// a scan which did not see the whole tree cannot clear a failure it did not reach.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_a_conversion_failure_through_an_incomplete_scan(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeBrokenPair(t, in, "a-broken", "not base64")
	writeSelfSignedPair(t, in, "b-live")
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{})
	runScans(t, scanner, 1)

	if err := os.Rename(filepath.Join(in, "a-broken.crt"), filepath.Join(in, "z-broken.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(in, "a-broken.key"), filepath.Join(in, "z-broken.key")); err != nil {
		t.Fatal(err)
	}
	budgeted := newVerdictScanner(in, out, Options{MaxScanEntries: 3})
	budgeted.standing = scanner.standing
	if res, _ := budgeted.Run(t.Context()); res.Outcome != OutcomeBudgetStopped {
		t.Fatalf("setup: Outcome = %v, want a budget stop before the renamed source", res.Outcome)
	}
	if logs.HasAttr(standingClearedMsg, "condition", "conversion_failed") {
		t.Errorf("a budget-stopped scan cleared a failure it never reached; log = %q", logs.Messages())
	}
}

// countClears counts the clear records naming condition kind.
func countClears(logs *capture.Recorder, kind string) int {
	n := 0
	for _, got := range logs.AttrValuesExact(standingClearedMsg, "condition") {
		if got == kind {
			n++
		}
	}
	return n
}

// TestScannerRun_keeps_per_path_conditions_through_a_hidden_subtree pins the
// incomplete scan that ends without an error: a subtree behind an unresolvable
// symlink keeps its failure and its permissive artifact, and the scan that sees
// it again clears only what is gone.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_per_path_conditions_through_a_hidden_subtree(t *testing.T) {
	base := t.TempDir()
	in, outside, out := filepath.Join(base, "input"), filepath.Join(base, "outside"), t.TempDir()
	site := filepath.Join(in, "site")
	for _, dir := range []string{in, outside, site} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeSelfSignedPair(t, in, "live")
	writeSelfSignedPair(t, site, "cert")
	writeBrokenPair(t, site, "broken", "not base64")
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{})
	runScans(t, scanner, 1)
	chmodOrSkip(t, filepath.Join(out, "site", "cert.pfx"), 0o640)
	runScans(t, scanner, 1)
	if !logs.HasAttr(permissiveFileLine, "path", "site/cert.pfx") || !logs.HasAttr(conversionFailedLine, "path", "site/broken.crt") {
		t.Fatalf("setup: the failure and the permissive artifact were not both reported; log = %q", logs.Messages())
	}

	hidden := filepath.Join(outside, "site")
	if err := os.Rename(site, hidden); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hidden, site); err != nil {
		t.Fatal(err)
	}
	if res := runScans(t, scanner, 1); res.Unresolved != 1 {
		t.Fatalf("setup: Unresolved = %d, want 1: the subtree must be hidden behind the link", res.Unresolved)
	}
	for _, kind := range []string{condConversionFailed, condPermissiveFile} {
		if got := countClears(logs, kind); got != 0 {
			t.Errorf("a scan that could not reach the subtree logged %d %s clears, want 0; log = %q", got, kind, logs.Messages())
		}
	}

	if err := os.Remove(site); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(hidden, site); err != nil {
		t.Fatal(err)
	}
	writeSelfSignedPair(t, site, "broken")
	if res := runScans(t, scanner, 1); res.Failed != 0 || res.Unresolved != 0 {
		t.Fatalf("setup: the restored tree scan = %+v, want no failure and nothing unresolved", res)
	}
	if got := countClears(logs, condConversionFailed); got != 1 {
		t.Errorf("the fixed source logged %d conversion_failed clears, want 1", got)
	}
	if got := countClears(logs, condPermissiveFile); got != 0 {
		t.Errorf("the still-permissive artifact logged %d clears, want 0", got)
	}
	if got := logs.CountLevel(slog.LevelWarn, permissiveFileLine); got != 1 {
		t.Errorf("the permissive artifact was reported %d times in total, want 1: it held throughout", got)
	}
}

// countRecords counts the records at level whose message contains msgSub and
// whose key attribute renders as value.
func countRecords(logs *capture.Recorder, level slog.Level, msgSub, key, value string) int {
	n := 0
	for _, r := range logs.Records() {
		if r.Level != level || !strings.Contains(r.Message, msgSub) {
			continue
		}
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key && a.Value.String() == value {
				n++
				return false
			}
			return true
		})
	}
	return n
}

// TestScannerRun_clears_a_fixed_failure_beside_a_durable_unresolved_link pins
// that a link the scan cannot follow holds back only what it hides: a source the
// scan reached and converted logs its clear, so its next failure is news again.
// Serial: it swaps slog.Default().
func TestScannerRun_clears_a_fixed_failure_beside_a_durable_unresolved_link(t *testing.T) {
	base := t.TempDir()
	in, outside := filepath.Join(base, "input"), filepath.Join(base, "outside")
	for _, dir := range []string{in, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(in, "linked")); err != nil {
		t.Fatal(err)
	}
	writeBrokenPair(t, in, "broken", "not base64")
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, t.TempDir(), Options{})
	if res := runScans(t, scanner, 1); res.Failed != 1 || res.Unresolved != 1 {
		t.Fatalf("setup: first scan = %+v, want one failure and one unresolved link", res)
	}

	writeSelfSignedPair(t, in, "broken")
	if res := runScans(t, scanner, 1); res.Failed != 0 || res.Unresolved != 1 {
		t.Fatalf("setup: fixed scan = %+v, want no failure and the link still unresolved", res)
	}
	if got := countClears(logs, condConversionFailed); got != 1 {
		t.Errorf("the fixed source logged %d conversion_failed clears, want 1; log = %q", got, logs.Messages())
	}

	writeBrokenPair(t, in, "broken", "not base64")
	runScans(t, scanner, 1)
	if got := logs.CountLevel(slog.LevelError, conversionFailedLine); got != 2 {
		t.Errorf("the source that failed again logged %d ERRORs in total, want 2: the new failure is news", got)
	}
}

// TestScannerRun_keeps_a_nested_unresolved_link_through_a_hidden_subtree pins
// that a link inside a subtree the scan could not enter stays reported: no clear
// while the subtree is hidden, and no second onset when it returns.
// Serial: it swaps slog.Default().
func TestScannerRun_keeps_a_nested_unresolved_link_through_a_hidden_subtree(t *testing.T) {
	base := t.TempDir()
	in, outside := filepath.Join(base, "input"), filepath.Join(base, "outside")
	site, target := filepath.Join(in, "site"), filepath.Join(outside, "target")
	for _, dir := range []string{in, outside, site, target} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeSelfSignedPair(t, in, "live")
	if err := os.Symlink(target, filepath.Join(site, "link")); err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, t.TempDir(), Options{})
	if res := runScans(t, scanner, 1); res.Unresolved != 1 {
		t.Fatalf("setup: Unresolved = %d, want 1 for site/link", res.Unresolved)
	}

	hidden := filepath.Join(outside, "site")
	if err := os.Rename(site, hidden); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hidden, site); err != nil {
		t.Fatal(err)
	}
	runScans(t, scanner, 1)
	if logs.HasAttr(standingClearedMsg, "path", "site/link") {
		t.Errorf("a scan that could not enter site cleared site/link; log = %q", logs.Messages())
	}

	if err := os.Remove(site); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(hidden, site); err != nil {
		t.Fatal(err)
	}
	runScans(t, scanner, 1)
	const onsetMsg = "skipping symlink that could not be resolved through the input root"
	if got := countRecords(logs, slog.LevelWarn, onsetMsg, "path", "site/link"); got != 1 {
		t.Errorf("site/link was reported at WARN %d times, want 1: it held throughout", got)
	}
}

// TestScannerRun_logs_an_unstattable_sibling_key_once pins that a key the
// confined root refuses is a standing unreadable path, not a WARN on every scan.
// Serial: it swaps slog.Default().
func TestScannerRun_logs_an_unstattable_sibling_key_once(t *testing.T) {
	base := t.TempDir()
	in, outside := filepath.Join(base, "input"), filepath.Join(base, "outside")
	for _, dir := range []string{in, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeSelfSignedPair(t, in, "live")
	writeSelfSignedPair(t, outside, "escape")
	if err := os.Rename(filepath.Join(outside, "escape.crt"), filepath.Join(in, "escape.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "escape.key"), filepath.Join(in, "escape.key")); err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, t.TempDir(), Options{})
	if res := runScans(t, scanner, 3); res.Unreadable != 1 {
		t.Fatalf("setup: Unreadable = %d, want 1 for the escaping key", res.Unreadable)
	}
	const statMsg = "skipping cert: cannot stat sibling key"
	if got := logs.CountLevel(slog.LevelWarn, statMsg); got != 1 {
		t.Errorf("three scans with one unstattable key logged %d WARNs, want 1", got)
	}
	if got := logs.CountLevel(slog.LevelDebug, statMsg); got != 2 {
		t.Errorf("the two repeat scans logged %d Debug records, want 2", got)
	}
	if got := countRecords(logs, slog.LevelWarn, statMsg, "condition", condUnreadablePath); got != 1 ||
		!logs.HasAttr(statMsg, "path", "escape.key") || !logs.HasAttr(statMsg, "source", "escape.crt") {
		t.Errorf("the WARN does not carry condition %s, path escape.key and source escape.crt; log = %q", condUnreadablePath, logs.Messages())
	}
}

// TestReportVerdict_clears_unreached_per_path_conditions_only_after_a_whole_tree_scan
// pins the gate for every per-path condition a skipped /input path can hide, on a
// scan that reached none of the held subjects.
// Serial: it swaps slog.Default().
func TestReportVerdict_clears_unreached_per_path_conditions_only_after_a_whole_tree_scan(t *testing.T) {
	held := []standingKey{
		{kind: condConversionFailed, subject: "site/a.crt"},
		{kind: condUnwritable, subject: "site/a.pfx"},
		{kind: condPermissiveFile, subject: "site/b.pfx"},
		{kind: condPermissiveDir, subject: "site"},
	}
	// Only the whole-tree walk listed the root and found no site in it.
	for name, tc := range map[string]struct {
		result      ScanResult
		wantCleared bool
	}{
		"an unresolved symlink hid part of the tree": {result: ScanResult{Unresolved: 1}},
		"an unreadable path hid part of the tree":    {result: ScanResult{Unreadable: 1}},
		"an entry vanished during the walk":          {result: ScanResult{Vanished: 1}},
		"the scan saw the whole tree":                {wantCleared: true},
	} {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)
			s := newVerdictScanner(t.TempDir(), t.TempDir(), Options{})
			for _, key := range held {
				s.standing.report(key, 1)
			}
			s.standing.beginScan()
			result := tc.result
			sw := &scanWalk{expected: map[string]struct{}{}}
			if tc.wantCleared {
				sw.reach.enterDir(".")
			}
			s.reportVerdict(&result, &store{standing: s.standing}, sw, nil)
			for _, key := range held {
				if cleared := countClears(logs, key.kind) == 1; cleared != tc.wantCleared {
					t.Errorf("%s cleared = %v, want %v; log = %q", key.kind, cleared, tc.wantCleared, logs.Messages())
				}
			}
		})
	}
}

// TestScannerRun_names_a_failing_sources_observations_once pins that a source
// failing on every scan does not repeat its input observations on every scan.
// Serial: it swaps slog.Default() and the write seam.
func TestScannerRun_names_a_failing_sources_observations_once(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	leafPEM, keyPEM, caPEM, _ := testcerts.GenerateCertChain(t)
	rootFirst := append(append([]byte{}, caPEM...), leafPEM...)
	writePair(t, in, "chain", rootFirst, keyPEM)
	stubWriteRefusal(t, &fs.PathError{Op: "openat", Path: "chain.pfx", Err: syscall.EACCES})
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{})

	if res := runScans(t, scanner, 2); res.Failed != 1 {
		t.Fatalf("setup: Failed = %d, want 1: no prior bundle, so the refused write is a failure", res.Failed)
	}
	if got := logs.CountLevel(slog.LevelError, conversionFailedLine); got != 1 {
		t.Errorf("two scans refused the same write and logged %d ERRORs, want 1", got)
	}
	if got := countObservation(logs, convert.ObsLeafNotFirst); got != 1 {
		t.Errorf("two scans of one failing source named its leaf-not-first observation %d times, want 1", got)
	}
}

// chmodOrSkip sets path to mode and skips when the filesystem stores another one.
func chmodOrSkip(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if got := storedPerm(t, path); got != mode {
		t.Skipf("this filesystem stored %v for a chmod to %v", got, mode)
	}
}

// TestScannerRun_logs_a_standing_permissive_output_dir_when_it_changes pins the
// directory WARN's lifecycle: once when the mode is found, again when the mode
// changes or the process restarts, and one clear record when the mode is tightened.
// Serial: it swaps slog.Default().
func TestScannerRun_logs_a_standing_permissive_output_dir_when_it_changes(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, in, "live")
	chmodOrSkip(t, out, 0o770)
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{})

	runScans(t, scanner, 3)
	if got := logs.CountLevel(slog.LevelWarn, permissiveDirLine); got != 1 {
		t.Errorf("three scans over one permissive directory logged %d WARNs, want 1; log = %q", got, logs.Messages())
	}
	if !logs.HasAttr(permissiveDirLine, "condition", "permissive_output_dir") || !logs.HasAttr(permissiveDirLine, "path", ".") {
		t.Errorf("the WARN does not carry condition=permissive_output_dir and path=.; log = %q", logs.Messages())
	}

	chmodOrSkip(t, out, 0o777)
	runScans(t, scanner, 2)
	if got := logs.CountLevel(slog.LevelWarn, permissiveDirLine); got != 2 {
		t.Errorf("a mode change logged %d WARNs in total, want 2", got)
	}
	if !logs.HasAttr(permissiveDirLine, "mode", os.FileMode(0o777).String()) {
		t.Errorf("no WARN carries the new mode; log = %q", logs.Messages())
	}

	restarted := newVerdictScanner(in, out, Options{})
	runScans(t, restarted, 2)
	if got := logs.CountLevel(slog.LevelWarn, permissiveDirLine); got != 3 {
		t.Errorf("a restart over the same mode logged %d WARNs in total, want 3: the new process reports it once", got)
	}

	chmodOrSkip(t, out, 0o750)
	runScans(t, restarted, 1)
	if !logs.HasAttr(standingClearedMsg, "condition", "permissive_output_dir") || !logs.HasAttr(standingClearedMsg, "path", ".") {
		t.Errorf("tightening the directory logged no clear record; log = %q", logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelWarn, permissiveDirLine); got != 3 {
		t.Errorf("the tightened directory was still reported: %d WARNs in total, want 3", got)
	}
}

// TestScannerRun_clears_a_permissive_output_dir_that_holds_no_artifact pins the
// other clear: a complete scan whose sources no longer place an artifact under
// the directory stops reporting it, even with the directory left as it was.
// Serial: it swaps slog.Default().
func TestScannerRun_clears_a_permissive_output_dir_that_holds_no_artifact(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, in, "live")
	site := filepath.Join(in, "site")
	if err := os.Mkdir(site, 0o750); err != nil {
		t.Fatal(err)
	}
	writeSelfSignedPair(t, site, "cert")
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{})
	runScans(t, scanner, 1)
	chmodOrSkip(t, filepath.Join(out, "site"), 0o770)
	runScans(t, scanner, 1)
	if !logs.HasAttr(permissiveDirLine, "path", "site") {
		t.Fatalf("setup: the permissive site directory was not reported; log = %q", logs.Messages())
	}

	if err := os.RemoveAll(site); err != nil {
		t.Fatal(err)
	}
	runScans(t, scanner, 1)
	if !logs.HasAttr(standingClearedMsg, "condition", "permissive_output_dir") || !logs.HasAttr(standingClearedMsg, "path", "site") {
		t.Errorf("a directory no source writes to any more logged no clear record; log = %q", logs.Messages())
	}
}

// TestScannerRun_logs_a_standing_permissive_output_file_when_it_changes pins the
// same lifecycle on a prior artifact: once when found, again on a mode change,
// and one clear record when the mode is tightened.
// Serial: it swaps slog.Default().
func TestScannerRun_logs_a_standing_permissive_output_file_when_it_changes(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, in, "live")
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{})
	runScans(t, scanner, 1)
	pfx := filepath.Join(out, "live.pfx")

	chmodOrSkip(t, pfx, 0o640)
	runScans(t, scanner, 3)
	if got := logs.CountLevel(slog.LevelWarn, permissiveFileLine); got != 1 {
		t.Errorf("three scans over one permissive file logged %d WARNs, want 1; log = %q", got, logs.Messages())
	}
	if !logs.HasAttr(permissiveFileLine, "condition", "permissive_output_file") || !logs.HasAttr(permissiveFileLine, "path", "live.pfx") {
		t.Errorf("the WARN does not carry condition=permissive_output_file and path=live.pfx; log = %q", logs.Messages())
	}

	chmodOrSkip(t, pfx, 0o644)
	runScans(t, scanner, 2)
	if got := logs.CountLevel(slog.LevelWarn, permissiveFileLine); got != 2 {
		t.Errorf("a mode change logged %d WARNs in total, want 2", got)
	}

	chmodOrSkip(t, pfx, 0o600)
	runScans(t, scanner, 1)
	if !logs.HasAttr(standingClearedMsg, "condition", "permissive_output_file") || !logs.HasAttr(standingClearedMsg, "path", "live.pfx") {
		t.Errorf("tightening the file logged no clear record; log = %q", logs.Messages())
	}
}

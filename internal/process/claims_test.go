package process

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/go/filesafe"
	"github.com/cplieger/go/slogx/capture"
)

// claimsName is the flat ownership record's name at the root of /output.
const claimsName = ".cert-converter-claims.json"

// recordedClaims is the ownership record as it is stored.
type recordedClaims struct {
	Stems   map[string]recordedStem `json:"stems"`
	Version int                     `json:"version"`
}

// recordedStem is one output stem's entry in the ownership record.
type recordedStem struct {
	Owner   string   `json:"owner"`
	Members []string `json:"members"`
}

// readClaims decodes the ownership record under out and fails the test when it
// is missing or is not version 1.
func readClaims(t *testing.T, out string) recordedClaims {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(out, claimsName))
	if err != nil {
		t.Fatalf("the ownership record: %v", err)
	}
	var claims recordedClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		t.Fatalf("the ownership record does not decode: %v; record = %q", err, data)
	}
	if claims.Version != 1 {
		t.Fatalf("the ownership record's version = %d, want 1", claims.Version)
	}
	return claims
}

// stubClaimsWrites routes every write of the ownership record through refuse,
// which returns the write's error or nil to let it through, and counts the
// writes; every other write goes through unchanged.
func stubClaimsWrites(t *testing.T, refuse func() error) *int {
	t.Helper()
	prev := writeFileInRoot
	writes := new(int)
	writeFileInRoot = func(ctx context.Context, root *os.Root, name string, data []byte, opts ...filesafe.WriteOption) (filesafe.Result, error) {
		if filepath.Base(name) == claimsName {
			*writes++
			if err := refuse(); err != nil {
				return filesafe.Result{}, err
			}
		}
		return prev(ctx, root, name, data, opts...)
	}
	t.Cleanup(func() { writeFileInRoot = prev })
	return writes
}

// claimsRecords counts every record, at any level, whose condition is one of
// the ownership record's own.
func claimsRecords(logs *capture.Recorder) int {
	n := 0
	for _, r := range logs.Records() {
		for _, kind := range []string{"claims_rebuilt", "claims_unreadable", "claims_unwritable"} {
			if attrIs(&r, "condition", kind) {
				n++
			}
		}
	}
	return n
}

// mentions reports whether some attribute of r renders with sub in it.
func mentions(r *slog.Record, sub string) bool {
	found := false
	r.Attrs(func(a slog.Attr) bool {
		found = strings.Contains(a.Value.String(), sub)
		return !found
	})
	return found
}

// TestScannerRun_flat_restart_keeps_the_artifact_behind_an_input_named_link pins
// that under OUTPUT_LIFECYCLE=sync a new process keeps the flat artifact of a
// claimant behind an unresolvable link named like an input, and names the link.
// Serial: it swaps slog.Default().
func TestScannerRun_flat_restart_keeps_the_artifact_behind_an_input_named_link(t *testing.T) {
	for _, name := range []string{"site.key", "site.crt"} {
		t.Run(name, func(t *testing.T) {
			in, outside := inputAndOutside(t)
			addClaimant(t, filepath.Join(in, name), "a")
			writeSelfSignedPair(t, in, "other")
			out := t.TempDir()
			logs := captureLogs(t)
			opts := Options{Layout: outputpolicy.LayoutFlat, Lifecycle: outputpolicy.LifecycleSync}
			if res := runScans(t, newVerdictScanner(in, out, opts), 1); res.Converted != 2 {
				t.Fatalf("setup: the first scan = %+v, want a and other converted", res)
			}

			hideBehindLink(t, in, outside, name)
			if res := runScans(t, newVerdictScanner(in, out, opts), 1); res.Removed != 0 {
				t.Errorf("the restarted scan that could not reach %s = %+v, want nothing removed", name, res)
			}
			if _, err := os.Stat(filepath.Join(out, "site", "cert.pfx")); err != nil {
				t.Errorf("a's artifact did not survive the restart: %v", err)
			}
			if got := conditionCount(logs, slog.LevelWarn, condUnresolvedSymlink, name); got != 1 {
				t.Errorf("the restarted scan logged %d unresolved_symlink WARNs for %s, want 1", got, name)
			}
		})
	}
}

// TestScannerRun_flat_restart_keeps_a_hidden_claimants_collision pins that a new
// process still counts a claimant behind an unresolvable link named like an
// input: the collision holds, nothing converts, and a new claimant of the stem
// does not replace the hidden claimant's artifact.
// Serial: it swaps slog.Default().
func TestScannerRun_flat_restart_keeps_a_hidden_claimants_collision(t *testing.T) {
	keep := Options{Layout: outputpolicy.LayoutFlat, Lifecycle: outputpolicy.LifecycleKeep}
	t.Run("collision_holds", func(t *testing.T) {
		in, outside := claimantTree(t, "a", "b.key")
		out := t.TempDir()
		captureLogs(t)
		if res := runScans(t, newVerdictScanner(in, out, keep), 1); res.Collided != 2 {
			t.Fatalf("setup: Collided = %d, want 2", res.Collided)
		}

		hideBehindLink(t, in, outside, "b.key")
		res := runScans(t, newVerdictScanner(in, out, keep), 1)
		if res.Collided != 2 || res.conversionsClean() {
			t.Errorf("the restarted scan that could not reach b.key = %+v, want Collided 2 and conversions not clean", res)
		}
		if _, err := os.Lstat(filepath.Join(out, "site", "cert.pfx")); !os.IsNotExist(err) {
			t.Errorf("a was published while the hidden b.key still claims its stem: Lstat(site/cert.pfx) = %v", err)
		}
	})
	t.Run("no_overwrite", func(t *testing.T) {
		in, outside := claimantTree(t, "b.key")
		out := t.TempDir()
		captureLogs(t)
		runScans(t, newVerdictScanner(in, out, keep), 1)
		pfx := filepath.Join(out, "site", "cert.pfx")
		published, err := os.ReadFile(pfx)
		if err != nil {
			t.Fatal(err)
		}

		hideBehindLink(t, in, outside, "b.key")
		addClaimant(t, in, "a")
		if res := runScans(t, newVerdictScanner(in, out, keep), 1); res.Collided != 2 {
			t.Errorf("the restarted scan that added a = %+v, want Collided 2", res)
		}
		if got, err := os.ReadFile(pfx); err != nil || !bytes.Equal(got, published) {
			t.Errorf("site/cert.pfx after a joined = %d bytes, %v, want b.key's artifact unchanged", len(got), err)
		}
	})
}

// TestClaims_rebuilds_a_missing_record_beside_existing_artifacts pins that a
// flat start with artifacts in /output and no ownership record says so once,
// whatever the lifecycle and whether or not the scan may reap, and writes the
// record from what the scan saw.
// Serial: it swaps slog.Default().
func TestClaims_rebuilds_a_missing_record_beside_existing_artifacts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lifecycle outputpolicy.Lifecycle
		closeGate bool
	}{
		{name: "under_warn", lifecycle: outputpolicy.LifecycleWarn},
		{name: "under_keep", lifecycle: outputpolicy.LifecycleKeep},
		// An unresolvable link stops every reap, so the output walk never runs.
		{name: "reap_gate_closed_on_the_first_scan", lifecycle: outputpolicy.LifecycleSync, closeGate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, outside := inputAndOutside(t)
			writeSelfSignedPair(t, in, "x")
			out := t.TempDir()
			captureLogs(t)
			runScans(t, newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat}), 1)
			if err := os.Remove(filepath.Join(out, claimsName)); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if tc.closeGate {
				if err := os.Symlink(outside, filepath.Join(in, "linked")); err != nil {
					t.Fatal(err)
				}
			}

			logs := captureLogs(t)
			runScans(t, newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat, Lifecycle: tc.lifecycle}), 1)
			warns := conditionRecords(logs, slog.LevelWarn, "claims_rebuilt", "")
			if len(warns) != 1 {
				t.Fatalf("the start without a record logged %d claims_rebuilt WARNs, want 1; log = %q", len(warns), logs.Messages())
			}
			if !mentions(&warns[0], claimsName) {
				t.Errorf("the claims_rebuilt WARN does not name %s", claimsName)
			}
			if got := readClaims(t, out).Stems["x"].Owner; got != "x.crt" {
				t.Errorf("the rebuilt record's owner of x = %q, want x.crt", got)
			}
		})
	}
}

// TestClaims_starts_empty_from_a_record_it_cannot_use pins that a record the app
// cannot use is reported once and replaced, and never fails the scan or health.
// Serial: it swaps slog.Default().
func TestClaims_starts_empty_from_a_record_it_cannot_use(t *testing.T) {
	plant := func(data string) func(t *testing.T, out string) {
		return func(t *testing.T, out string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(out, claimsName), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		plant func(t *testing.T, out string)
		name  string
	}{
		{name: "corrupt", plant: plant("{not json")},
		{name: "unknown_version", plant: plant(`{"version":99,"stems":{}}`)},
		{name: "oversized", plant: plant(`{"version":1,"stems":{}}` + strings.Repeat(" ", 16<<20))},
		{name: "invalid_member_path", plant: plant(`{"version":1,"stems":{"x":{"owner":"../x.crt","members":["../x.crt"]}}}`)},
		{name: "not_a_regular_file", plant: func(t *testing.T, out string) {
			t.Helper()
			valid := `{"version":1,"stems":{"x":{"owner":"x.crt","members":["x.crt"]}}}`
			if err := os.WriteFile(filepath.Join(out, "elsewhere.json"), []byte(valid), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("elsewhere.json", filepath.Join(out, claimsName)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out := t.TempDir(), t.TempDir()
			writeSelfSignedPair(t, in, "x")
			tc.plant(t, out)
			logs := captureLogs(t)

			res := runScans(t, newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat, MaxScanEntries: 8}), 1)
			if res.Converted != 1 || !res.conversionsClean() {
				t.Errorf("the scan beside an unusable record = %+v, want x converted and conversions clean", res)
			}
			if got := conditionCount(logs, slog.LevelWarn, "claims_unreadable", ""); got != 1 {
				t.Errorf("the unusable record logged %d claims_unreadable WARNs, want 1; log = %q", got, logs.Messages())
			}
			fi, err := os.Lstat(filepath.Join(out, claimsName))
			if err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("the record after the scan: Lstat = %v, %v, want a regular file", fi, err)
			}
			if got := readClaims(t, out).Stems["x"].Owner; got != "x.crt" {
				t.Errorf("the rewritten record's owner of x = %q, want x.crt", got)
			}
		})
	}
}

// TestClaims_record_is_never_an_output pins that the ownership record is not an
// artifact: a reap under OUTPUT_LIFECYCLE=sync leaves it, counts it nowhere and
// names it in no output condition.
// Serial: it swaps slog.Default().
func TestClaims_record_is_never_an_output(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, in, "other")
	writeSelfSignedPair(t, in, "gone")
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat, Lifecycle: outputpolicy.LifecycleSync})
	runScans(t, scanner, 1)
	for _, name := range []string{"gone.crt", "gone.key"} {
		if err := os.Remove(filepath.Join(in, name)); err != nil {
			t.Fatal(err)
		}
	}

	if res := runScans(t, scanner, 1); res.Removed != 1 {
		t.Errorf("the scan after gone's pair left = %+v, want Removed 1", res)
	}
	if fi, err := os.Lstat(filepath.Join(out, claimsName)); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("the ownership record after the reap: Lstat = %v, %v, want it kept", fi, err)
	}
	for _, r := range logs.Records() {
		if mentions(&r, claimsName) && !attrIs(&r, "condition", "claims_rebuilt") {
			t.Errorf("the record %q names the ownership record", r.Message)
		}
	}
}

// TestClaims_writes_only_on_an_ownership_change pins that the record is written
// on a scan that changed an owner or a member set and on no other, and that the
// change is on disk before the reap's confirmation wait, which a shutdown can cut.
// Serial: it swaps slog.Default(), the write seam and the reap wait.
func TestClaims_writes_only_on_an_ownership_change(t *testing.T) {
	t.Run("counts", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, in, "x")
		writes := stubClaimsWrites(t, func() error { return nil })
		captureLogs(t)
		scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
		for _, step := range []struct {
			change func()
			name   string
			want   int
		}{
			{name: "the first scan", want: 1},
			{name: "an unchanged scan", want: 1},
			{name: "a new member", want: 2, change: func() { writeSelfSignedPair(t, in, "y") }},
			{name: "a renewal of the same owner", want: 2, change: func() { writeSelfSignedPair(t, in, "x") }},
		} {
			if step.change != nil {
				step.change()
			}
			runScans(t, scanner, 1)
			if *writes != step.want {
				t.Errorf("after %s the record was written %d times in total, want %d", step.name, *writes, step.want)
			}
		}
	})
	t.Run("cancelled_wait", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, in, "other")
		writeSelfSignedPair(t, in, "gone")
		captureLogs(t)
		scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat, Lifecycle: outputpolicy.LifecycleSync})
		runScans(t, scanner, 1)
		for _, name := range []string{"gone.crt", "gone.key"} {
			if err := os.Remove(filepath.Join(in, name)); err != nil {
				t.Fatal(err)
			}
		}
		writeSelfSignedPair(t, in, "fresh")
		stubReapWait(t, func(context.Context) error { return context.Canceled })

		if _, err := scanner.Run(t.Context()); err == nil {
			t.Fatalf("setup: Run = nil, want the cancelled wait's error")
		}
		claims := readClaims(t, out)
		if got := claims.Stems["fresh"].Members; !slices.Equal(got, []string{"fresh.crt"}) {
			t.Errorf("the record's members of fresh = %v, want [fresh.crt]", got)
		}
		if _, held := claims.Stems["gone"]; held {
			t.Errorf("the record still holds gone, which left the ledger before the wait")
		}
	})
}

// TestClaims_moves_ownership_only_after_the_owner_leaves pins that a stem's owner
// stays its owner while out of reach, and that ownership moves to the remaining
// claimant only once the owner is gone.
// Serial: it swaps slog.Default() and the write seam.
func TestClaims_moves_ownership_only_after_the_owner_leaves(t *testing.T) {
	in, outside := claimantTree(t, "a")
	out := t.TempDir()
	writes := stubClaimsWrites(t, func() error { return nil })
	captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	runScans(t, scanner, 1)
	if got := readClaims(t, out).Stems["site/cert"]; got.Owner != "a/site/cert.crt" || *writes != 1 {
		t.Fatalf("setup: the record = %+v after %d writes, want a as owner after 1", got, *writes)
	}

	hideBehindLink(t, in, outside, "a")
	addClaimant(t, in, "b")
	if res := runScans(t, scanner, 1); res.Collided != 2 {
		t.Errorf("the scan with a hidden and b added = %+v, want Collided 2", res)
	}
	got := readClaims(t, out).Stems["site/cert"]
	if want := []string{"a/site/cert.crt", "b/site/cert.crt"}; got.Owner != "a/site/cert.crt" || !slices.Equal(got.Members, want) || *writes != 2 {
		t.Errorf("the record = %+v after %d writes, want owner a, members %v, after 2", got, *writes, want)
	}

	if err := os.Remove(filepath.Join(in, "a")); err != nil {
		t.Fatal(err)
	}
	if res := runScans(t, scanner, 1); res.Collided != 0 || res.Converted != 1 {
		t.Errorf("the scan after a's link left = %+v, want Collided 0 and b converted", res)
	}
	got = readClaims(t, out).Stems["site/cert"]
	if want := []string{"b/site/cert.crt"}; got.Owner != "b/site/cert.crt" || !slices.Equal(got.Members, want) || *writes != 3 {
		t.Errorf("the record = %+v after %d writes, want owner b, members %v, after 3", got, *writes, want)
	}
}

// TestClaims_reports_a_failed_write_and_keeps_the_record_in_memory pins that a
// record the app cannot write is one standing warning, costs no health, and
// leaves this process's record in charge until a write succeeds.
// Serial: it swaps slog.Default() and the write seam.
func TestClaims_reports_a_failed_write_and_keeps_the_record_in_memory(t *testing.T) {
	in, outside := claimantTree(t, "a", "b.key")
	out := t.TempDir()
	refused := true
	stubClaimsWrites(t, func() error {
		if refused {
			return &fs.PathError{Op: "openat", Path: claimsName, Err: syscall.EROFS}
		}
		return nil
	})
	logs := captureLogs(t)
	scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
	if res := runScans(t, scanner, 1); res.Collided != 2 || res.Failed != 0 {
		t.Errorf("the scan whose record write failed = %+v, want Collided 2 and Failed 0", res)
	}
	if got := conditionCount(logs, slog.LevelWarn, "claims_unwritable", ""); got != 1 {
		t.Errorf("the failed write logged %d claims_unwritable WARNs, want 1; log = %q", got, logs.Messages())
	}

	hideBehindLink(t, in, outside, "b.key")
	if res := runScans(t, scanner, 1); res.Collided != 2 {
		t.Errorf("the scan that could not reach b.key = %+v, want Collided 2 from the record in memory", res)
	}

	refused = false
	addClaimant(t, in, "c")
	runScans(t, scanner, 1)
	if got := clearCount(logs, "claims_unwritable", ""); got != 1 {
		t.Errorf("the write that succeeded logged %d claims_unwritable clears, want 1", got)
	}
	if got := conditionCount(logs, slog.LevelWarn, "claims_unwritable", ""); got != 1 {
		t.Errorf("the failing scans logged %d claims_unwritable WARNs in total, want 1", got)
	}
	if got := readClaims(t, out).Stems["site/cert"].Members; !slices.Contains(got, "b.key/site/cert.crt") {
		t.Errorf("the written record's members = %v, want the hidden b.key/site/cert.crt among them", got)
	}
}

// TestClaims_clears_a_failed_write_when_nothing_is_left_to_write pins that a
// ledger returning to what /output already holds clears claims_unwritable, so
// the next failed write warns again.
// Serial: it swaps slog.Default() and the write seam.
func TestClaims_clears_a_failed_write_when_nothing_is_left_to_write(t *testing.T) {
	t.Run("ledger_empties_before_any_write", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		stubClaimsWrites(t, func() error { return &fs.PathError{Op: "openat", Path: claimsName, Err: syscall.EROFS} })
		logs := captureLogs(t)
		scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
		writeSelfSignedPair(t, in, "x")
		runScans(t, scanner, 1)
		for _, name := range []string{"x.crt", "x.key"} {
			if err := os.Remove(filepath.Join(in, name)); err != nil {
				t.Fatal(err)
			}
		}
		runScans(t, scanner, 1)
		if got := clearCount(logs, "claims_unwritable", ""); got != 1 {
			t.Errorf("the scan that left nothing to write logged %d claims_unwritable clears, want 1", got)
		}
		writeSelfSignedPair(t, in, "x")
		runScans(t, scanner, 1)
		if got := conditionCount(logs, slog.LevelWarn, "claims_unwritable", ""); got != 2 {
			t.Errorf("the two failed writes logged %d claims_unwritable WARNs, want 2", got)
		}
	})
	t.Run("ledger_returns_to_the_written_record", func(t *testing.T) {
		in, _ := claimantTree(t, "a", "b")
		out := t.TempDir()
		refused := false
		stubClaimsWrites(t, func() error {
			if refused {
				return &fs.PathError{Op: "openat", Path: claimsName, Err: syscall.EROFS}
			}
			return nil
		})
		logs := captureLogs(t)
		scanner := newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutFlat})
		runScans(t, scanner, 1)
		refused = true
		addClaimant(t, in, "c")
		runScans(t, scanner, 1)
		removePair(t, in, "c")
		runScans(t, scanner, 1)
		if got := clearCount(logs, "claims_unwritable", ""); got != 1 {
			t.Errorf("the scan back at the written record logged %d claims_unwritable clears, want 1", got)
		}
		addClaimant(t, in, "c")
		runScans(t, scanner, 1)
		if got := conditionCount(logs, slog.LevelWarn, "claims_unwritable", ""); got != 2 {
			t.Errorf("the two failed writes logged %d claims_unwritable WARNs, want 2", got)
		}
	})
}

// TestClaims_owner_gate_guards_only_absence_reaps pins that the recorded owner
// keeps only the artifacts whose removal rests on the source being gone: an
// excluded owner's artifact, a switched-off format's and the other layout's are
// removed as before.
// Serial: it swaps slog.Default().
func TestClaims_owner_gate_guards_only_absence_reaps(t *testing.T) {
	sync := Options{Layout: outputpolicy.LayoutFlat, Lifecycle: outputpolicy.LifecycleSync}
	t.Run("excluded_owner", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		if err := os.Mkdir(filepath.Join(in, "x"), 0o750); err != nil {
			t.Fatal(err)
		}
		writeSelfSignedPair(t, filepath.Join(in, "x"), "cert")
		writeSelfSignedPair(t, in, "other")
		captureLogs(t)
		runScans(t, newVerdictScanner(in, out, sync), 1)

		excluded := sync
		excluded.Exclude = layout.NewExcludeSet([]string{"x"})
		if res := runScans(t, newVerdictScanner(in, out, excluded), 1); res.Removed != 1 {
			t.Errorf("the scan with x excluded = %+v, want Removed 1", res)
		}
		if _, err := os.Lstat(filepath.Join(out, "x", "cert.pfx")); !os.IsNotExist(err) {
			t.Errorf("the excluded owner's x/cert.pfx was kept: Lstat = %v", err)
		}
		if got, held := readClaims(t, out).Stems["x/cert"]; held {
			t.Errorf("the record still holds x/cert = %+v after its owner was excluded", got)
		}
	})
	t.Run("format_switched_off", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		writeSelfSignedPair(t, in, "x")
		writeSelfSignedPair(t, in, "other")
		captureLogs(t)
		both := sync
		both.Formats, both.FormatsExplicit = outputpolicy.Formats{PFX: true, PEM: true}, true
		runScans(t, newVerdictScanner(in, out, both), 1)

		pfxOnly := both
		pfxOnly.Formats = outputpolicy.Formats{PFX: true}
		runScans(t, newVerdictScanner(in, out, pfxOnly), 1)
		for _, name := range []string{"x.crt", "x.key"} {
			if _, err := os.Lstat(filepath.Join(out, name)); !os.IsNotExist(err) {
				t.Errorf("the switched-off format's %s was kept: Lstat = %v", name, err)
			}
		}
		if _, err := os.Stat(filepath.Join(out, "x.pfx")); err != nil {
			t.Errorf("the enabled format's x.pfx was removed: %v", err)
		}
		if got := readClaims(t, out).Stems["x"].Owner; got != "x.crt" {
			t.Errorf("the record's owner of x = %q, want x.crt", got)
		}
	})
	t.Run("layout_changed", func(t *testing.T) {
		in, out := t.TempDir(), t.TempDir()
		addClaimant(t, filepath.Join(in, "a"), "b")
		writeSelfSignedPair(t, in, "other")
		captureLogs(t)
		runScans(t, newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutMirror}), 1)

		flat := sync
		flat.LayoutExplicit = true
		runScans(t, newVerdictScanner(in, out, flat), 1)
		if _, err := os.Lstat(filepath.Join(out, "a", "b", "site", "cert.pfx")); !os.IsNotExist(err) {
			t.Errorf("the mirror layout's a/b/site/cert.pfx was kept: Lstat = %v", err)
		}
		if got := readClaims(t, out).Stems["site/cert"].Owner; got != "a/b/site/cert.crt" {
			t.Errorf("the record's owner of site/cert = %q, want a/b/site/cert.crt", got)
		}
	})
}

// TestClaims_an_excluded_member_behind_an_unproven_link_leaves_the_ledger pins
// that INPUT_EXCLUDE_PATHS removes a member from the ledger at once, reachable or
// not: the setting says the path is not an input.
// Serial: it swaps slog.Default().
func TestClaims_an_excluded_member_behind_an_unproven_link_leaves_the_ledger(t *testing.T) {
	sync := Options{Layout: outputpolicy.LayoutFlat, Lifecycle: outputpolicy.LifecycleSync}
	for _, restart := range []bool{false, true} {
		name := "member_in_a_collision"
		if restart {
			name += "_after_a_restart"
		}
		t.Run(name, func(t *testing.T) {
			in, outside := collidingTree(t)
			writeSelfSignedPair(t, in, "other")
			out := t.TempDir()
			captureLogs(t)
			scanner := newVerdictScanner(in, out, sync)
			if res := runScans(t, scanner, 1); res.Collided != 2 {
				t.Fatalf("setup: Collided = %d, want 2", res.Collided)
			}

			hideBehindLink(t, in, outside, "b")
			excluded := layout.NewExcludeSet([]string{"b"})
			if restart {
				opts := sync
				opts.Exclude = excluded
				scanner = newVerdictScanner(in, out, opts)
			} else {
				scanner.opts.Exclude = excluded
			}
			if res := runScans(t, scanner, 1); res.Collided != 0 {
				t.Errorf("the scan with the hidden b excluded = %+v, want Collided 0", res)
			}
			if _, err := os.Stat(filepath.Join(out, "site", "cert.pfx")); err != nil {
				t.Errorf("a, the only claimant left, was not published: %v", err)
			}
		})
	}
	t.Run("sole_owner", func(t *testing.T) {
		in, outside := inputAndOutside(t)
		addClaimant(t, filepath.Join(in, "site.key"), "a")
		writeSelfSignedPair(t, in, "other")
		out := t.TempDir()
		captureLogs(t)
		runScans(t, newVerdictScanner(in, out, sync), 1)

		hideBehindLink(t, in, outside, "site.key")
		excluded := sync
		excluded.Exclude = layout.NewExcludeSet([]string{"site.key"})
		if res := runScans(t, newVerdictScanner(in, out, excluded), 1); res.Removed != 1 {
			t.Errorf("the scan with the hidden owner excluded = %+v, want Removed 1", res)
		}
		if _, err := os.Lstat(filepath.Join(out, "site", "cert.pfx")); !os.IsNotExist(err) {
			t.Errorf("the excluded owner's site/cert.pfx was kept: Lstat = %v", err)
		}
		if got, held := readClaims(t, out).Stems["site/cert"]; held {
			t.Errorf("the record still holds site/cert = %+v after its owner was excluded", got)
		}
	})
}

// TestClaims_mirror_scan_leaves_the_record_alone pins that the mirror layout
// neither reads, reports on nor rewrites a flat ownership record left in /output.
// Serial: it swaps slog.Default().
func TestClaims_mirror_scan_leaves_the_record_alone(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeSelfSignedPair(t, in, "x")
	valid := []byte(`{"version":1,"stems":{"x":{"owner":"x.crt","members":["x.crt"]}}}`)
	if err := os.WriteFile(filepath.Join(out, claimsName), valid, 0o600); err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)
	runScans(t, newVerdictScanner(in, out, Options{Layout: outputpolicy.LayoutMirror, Lifecycle: outputpolicy.LifecycleSync}), 1)
	if got, err := os.ReadFile(filepath.Join(out, claimsName)); err != nil || !bytes.Equal(got, valid) {
		t.Errorf("the record after a mirror scan = %q, %v, want it unchanged", got, err)
	}
	if got := claimsRecords(logs); got != 0 {
		t.Errorf("the mirror scan logged %d records about the ownership record, want 0", got)
	}
}

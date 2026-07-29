package process

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

// newOutputStore opens dir as a confined output root and returns the store under test,
// closing the root when the test ends. The mirror of newInputSource: the four-line
// open/check/close/construct preamble is otherwise spelled once per test, in two
// different shapes.
func newOutputStore(t *testing.T, dir string) *store {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return &store{root: root}
}

// TestStoreReconcile_reports_an_output_tree_it_cannot_enumerate pins the arm that
// fires when the ORPHAN WALK cannot enumerate /output at its ROOT, as opposed to
// under it: the walk error must reach the operator at WARN with the /output
// ownership hint, and it must degrade to "reap nothing" rather than fail the scan,
// because a scan error there would flip health over a condition the WARN already
// names and a restart cannot fix.
//
// Both halves are load-bearing and neither is observable elsewhere. Swallow the
// root-level error and orphans() returns an empty candidate list, so sync mode
// reports nothing to reap and looks exactly like a healthy tree; return it as an
// error instead and a mount whose permissions an operator has to fix pins the
// container unhealthy.
//
// A closed root is the failure injection: it fails at the tree root itself, which
// is the shape a chmod-based test cannot produce when the suite runs as uid 0.
// Runs serially: it swaps slog.Default().
func TestStoreReconcile_reports_an_output_tree_it_cannot_enumerate(t *testing.T) {
	// Spelled out rather than imported from the production const: an operator's log
	// query keys on these words, so a silent rewording must fail here.
	const wantMsg = "could not enumerate output orphans; orphan removal is disabled for this scan"

	dir := t.TempDir()
	orphan := filepath.Join(dir, "orphan.pfx")
	if err := os.WriteFile(orphan, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("setup: root.Close: %v", err)
	}
	// Deliberately NOT newOutputStore: the closed root IS this test's failure
	// injection, so the store must outlive its root handle here.
	s := &store{root: root}
	logs := captureLogs(t)

	// sync over a tree holding one orphan: the mode that would delete, so nothing
	// about the arrangement excuses the refusal except the unwalkable tree.
	deleted, err := newReaper(s, newInputSource(t, t.TempDir()), outputpolicy.LifecycleSync).
		reconcile(t.Context(), map[string]struct{}{"a.crt": {}},
			&reapContext{result: ScanResult{Total: 1}, walkCompleted: true})
	if err != nil {
		t.Fatalf("reconcile(unwalkable output tree) = error %v, want nil: an unreadable /output is an"+
			" operator condition a restart cannot fix, so it must not fail the scan", err)
	}
	if deleted != 0 {
		t.Errorf("reconcile(unwalkable output tree) deleted = %d, want 0", deleted)
	}
	if got := logs.CountLevel(slog.LevelWarn, wantMsg); got != 1 {
		t.Fatalf("reconcile(unwalkable output tree) logged %q at WARN %d times, want exactly 1: %q",
			wantMsg, got, logs.Messages())
	}
	if _, ok := logs.AttrValue(wantMsg, "error"); !ok {
		t.Errorf("reconcile(unwalkable output tree) logged %q with no error attribute, want the walk"+
			" failure carried so the operator can diagnose it: %q", wantMsg, logs.Messages())
	}
	if got, ok := logs.AttrValue(wantMsg, "remediation"); !ok || got != outputPermRemediation {
		t.Errorf("reconcile(unwalkable output tree) logged remediation %q, want %q", got, outputPermRemediation)
	}
	if _, statErr := os.Stat(orphan); statErr != nil {
		t.Errorf("a bundle was deleted on a scan that could not enumerate the output tree: %v", statErr)
	}
}

// TestStoreOrphanReportRemediation_advice_matches_the_mode pins that the orphan
// report never advises a setting that is already in effect, and that it names the
// condition actually holding the reap back. In sync mode the report branch is
// reachable two ways (reconcile returns early unless the input enumeration is
// complete, so !reapable there means conversionsClean() is false): a failed
// conversion, or a refused permission repair, which logs no conversion failure at all
// and is cleared by chowning /output.
func TestStoreOrphanReportRemediation_advice_matches_the_mode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		mode        outputpolicy.Lifecycle
		walkSafe    bool
		refusalOnly bool
		wantHas     string
		wantLacks   string
	}{
		{
			name: "sync names the conversion failure, not the mode it is already in",
			mode: outputpolicy.LifecycleSync, walkSafe: true,
			wantHas:   "fix the conversion failure reported above",
			wantLacks: "OUTPUT_LIFECYCLE=sync",
		},
		{
			name: "sync names the refused permission repair, not a conversion failure",
			mode: outputpolicy.LifecycleSync, walkSafe: true, refusalOnly: true,
			wantHas:   "no refused permission repair",
			wantLacks: "fix the conversion failure reported above",
		},
		{
			name: "warn offers sync",
			mode: outputpolicy.LifecycleWarn, walkSafe: true,
			wantHas: "OUTPUT_LIFECYCLE=sync",
		},
		{
			name: "an unwalkable output tree withholds removal advice in every mode",
			mode: outputpolicy.LifecycleSync, walkSafe: false,
			wantHas:   "do not remove anything from this list yet",
			wantLacks: "OUTPUT_LIFECYCLE=sync",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := orphanReportRemediation(tc.mode, tc.walkSafe, tc.refusalOnly)
			if !strings.Contains(got, tc.wantHas) {
				t.Errorf("orphanReportRemediation(%v, %v) = %q, want it to contain %q",
					tc.mode, tc.walkSafe, got, tc.wantHas)
			}
			if tc.wantLacks != "" && strings.Contains(got, tc.wantLacks) {
				t.Errorf("orphanReportRemediation(%v, %v) = %q, want it NOT to advise %q",
					tc.mode, tc.walkSafe, got, tc.wantLacks)
			}
		})
	}
}

// TestStoreWrite_creates_the_parent_directory pins that a nested output path has its
// parent created rather than failing, so an input tree with domain subdirectories
// mirrors into the output tree.
func TestStoreWrite_creates_the_parent_directory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := newOutputStore(t, dir)

	if err := s.write(t.Context(), filepath.Join("example.com", "cert.pfx"), []byte("pfx")); err != nil {
		t.Fatalf("store.write(nested path) = error %v, want nil", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "example.com", "cert.pfx"))
	if err != nil {
		t.Fatalf("read written pfx: %v", err)
	}
	if string(got) != "pfx" {
		t.Errorf("written content = %q, want %q", got, "pfx")
	}

	info, err := os.Stat(filepath.Join(dir, "example.com", "cert.pfx"))
	if err != nil {
		t.Fatalf("stat written pfx: %v", err)
	}
	// A PFX carries a private key, so the mode is part of the contract.
	if perm := info.Mode().Perm(); perm != pfxFileMode {
		t.Errorf("written mode = %o, want %o", perm, pfxFileMode)
	}
}

// TestStoreWrite_reports_a_parent_it_cannot_create pins the failure branch for an
// output path whose parent cannot exist. A path component that is already a
// regular file cannot become a directory.
//
// The directory creation is atomicfile's (via WithMkdirMode) rather than a
// hand-rolled MkdirAll, so the library's own diagnosis surfaces under this
// package's "write pfx" wrapping. What matters for the operator is that the step
// is named and the offending path appears; the precise inner wording belongs to
// the library.
func TestStoreWrite_reports_a_parent_it_cannot_create(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// "blocked" is a regular file, so MkdirAll("blocked") must fail.
	if err := os.WriteFile(filepath.Join(dir, "blocked"), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	s := newOutputStore(t, dir)

	err := s.write(t.Context(), filepath.Join("blocked", "cert.pfx"), []byte("pfx"))
	if err == nil {
		t.Fatal("store.write(into a path blocked by a regular file) = nil error, want a failure")
	}
	if !strings.Contains(err.Error(), "write pfx") {
		t.Errorf("error = %q, want it to name the write step", err.Error())
	}
	if !strings.Contains(err.Error(), "blocked/cert.pfx") {
		t.Errorf("error = %q, want it to name the offending path", err.Error())
	}
}

// TestStoreWrite_wraps_an_atomic_write_failure pins the "write pfx" wrapping.
//
// The error must identify the PFX write rather than parsing, encoding, or parent
// creation, each of which has its own wrapping.
//
// The failure is forced by naming an existing DIRECTORY as the output path, which
// makes the atomic rename fail regardless of the uid the test runs as (a
// permission-based failure would silently pass when running as root).
func TestStoreWrite_wraps_an_atomic_write_failure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "occupied"), 0o750); err != nil {
		t.Fatalf("setup: Mkdir: %v", err)
	}
	s := newOutputStore(t, dir)

	err := s.write(t.Context(), "occupied", []byte("pfx"))
	if err == nil {
		t.Fatal("store.write(onto an existing directory) = nil error, want a failure")
	}
	if !strings.Contains(err.Error(), "write pfx") {
		t.Errorf("error = %q, want it to name the pfx write step", err.Error())
	}
}

// TestStoreWrite_refuses_a_bundle_larger_than_the_read_bound pins the write-side
// half of maxPFXSize, which nothing else exercises: a bundle above the cap must be
// refused rather than written.
//
// The cap mirrors the read bound isCurrent uses. Without it, a bundle this app
// wrote could be one its own currency check calls unreadable, so every scan would
// declare it stale and rewrite it -- a permanent write loop with a fresh mtime each
// time, which the documented downstream rsync re-replicates every cycle. The
// refusal happens before the temp is staged, so the previous bundle must survive
// intact and no temp may be left behind.
func TestStoreWrite_refuses_a_bundle_larger_than_the_read_bound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := newOutputStore(t, dir)
	if err := s.write(t.Context(), "out.pfx", []byte("prior bundle")); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	err := s.write(t.Context(), "out.pfx", make([]byte, maxPFXSize+1))
	if err == nil {
		t.Fatal("store.write(over maxPFXSize) = nil error, want a refusal: a bundle this app writes above the cap is one its own currency check would call unreadable")
	}
	if !strings.Contains(err.Error(), "write pfx") || !strings.Contains(err.Error(), "too large") {
		t.Errorf("store.write(over maxPFXSize) error = %q, want it to name the write step and the size refusal", err.Error())
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "out.pfx"))
	if readErr != nil {
		t.Fatalf("read the prior bundle after the refused write: %v", readErr)
	}
	if string(got) != "prior bundle" {
		t.Errorf("prior bundle = %q, want %q: the cap is checked before the temp is staged, so a refusal must leave the previous bundle intact", got, "prior bundle")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the output directory holds %d entries, want 1: a refused write must stage no temp file", len(entries))
	}
}

// TestStoreIsCurrent_names_a_non_regular_prior_output pins the WARN on the arm
// that refuses a prior output which is not a regular file. Nothing else records it:
// the verdict is "stale, regenerate", and for the two shapes covered here the
// rewrite that follows FAILS (atomicfile refuses a symlink target outright, and a
// directory cannot be renamed over), so this line is what names the occupied output
// path before the bare conversion error arrives. A device node, FIFO or socket IS
// replaced by the rename instead, which makes this line that case's only trace.
// Runs serially: it swaps slog.Default().
func TestStoreIsCurrent_names_a_non_regular_prior_output(t *testing.T) {
	const wantMsg = "prior output path is not a regular file; regenerating"
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, dir string)
	}{
		{"a symlink is refused without being followed", func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "elsewhere.pfx")
			if err := os.WriteFile(target, []byte("unrelated"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "out.pfx")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a directory is refused", func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "out.pfx"), 0o750); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.plant(t, dir)
			s := newOutputStore(t, dir)
			logs := captureLogs(t)

			// want is never dereferenced on this arm: the verdict is reached from the
			// lstat alone, before any bundle is read.
			current, _, err := s.isCurrent(t.Context(), "out.pfx", nil, convert.EncNameModern2023, "pw")

			if err != nil || current {
				t.Fatalf("isCurrent(non-regular) = %v, %v, want false, nil: an occupied output path is never a usable prior bundle", current, err)
			}
			if got := logs.CountLevel(slog.LevelWarn, wantMsg); got != 1 {
				t.Fatalf("isCurrent(non-regular) logged %q, want %q once at WARN", logs.Messages(), wantMsg)
			}
			if !logs.HasAttr(wantMsg, "path", "out.pfx") {
				t.Errorf("isCurrent(non-regular) logged %q, want path=out.pfx so the operator can identify the occupied output", logs.Messages())
			}
			if _, ok := logs.AttrValue(wantMsg, "mode"); !ok {
				t.Errorf("isCurrent(non-regular) logged %q, want the mode named so the operator knows what occupies the path", logs.Messages())
			}
			if _, ok := logs.AttrValue(wantMsg, "remediation"); !ok {
				t.Errorf("isCurrent(non-regular) logged %q, want a remediation hint", logs.Messages())
			}
		})
	}
}

// TestStoreIsCurrent_reports_a_bundle_that_vanishes_mid_inspection pins the two arms
// isCurrent takes when the prior bundle disappears after the lstat that classified it
// as a usable regular file: the tightening whose RESULT cannot be observed, and the
// read that then finds nothing.
//
// Both are reachable on a co-mounted /output -- a second writer, or a restore that
// replaces the tree while a scan runs -- and neither is named anywhere else. The
// tightening arm is the one a plausible simplification silently inverts: drop
// chmodAndObserve's re-stat error and the zero FileMode it returns is not laxer than
// policy, so the switch takes its DEFAULT arm and reports "tightened the file mode of
// a prior pfx" at INFO, telling an operator that private-key permissions were repaired
// on a bundle this app can no longer see at all. The read arm must stay a WARN plus a
// stale verdict rather than an error: an error here fails the pair and pins the
// container unhealthy over a condition the rewrite itself fixes.
//
// want is never dereferenced: both verdicts are reached before any bundle is decoded.
// The chmod seam stands in for the timing, exactly as the untightenable-mode test uses
// it for a filesystem that stores no permission bits; neither is stageable in a temp
// directory. Runs serially: it swaps slog.Default() and the chmod seam.
func TestStoreIsCurrent_reports_a_bundle_that_vanishes_mid_inspection(t *testing.T) {
	dir := t.TempDir()
	s := newOutputStore(t, dir)
	if err := s.write(t.Context(), "out.pfx", []byte("prior bundle")); err != nil {
		t.Fatalf("setup: write: %v", err)
	}
	// Lax enough that tightenMode acts at all; the vanishing happens inside it.
	if err := os.Chmod(filepath.Join(dir, "out.pfx"), 0o644); err != nil {
		t.Fatalf("setup: Chmod: %v", err)
	}
	prev := chmodInRoot
	chmodInRoot = func(r *os.Root, name string, mode os.FileMode) error {
		if err := r.Chmod(name, mode); err != nil {
			return err
		}
		return r.Remove(name)
	}
	t.Cleanup(func() { chmodInRoot = prev })

	// Spelled out rather than imported from the production consts: an operator's log
	// query keys on these words, so a silent rename must fail here.
	const notTightenedMsg = "prior pfx is more permissive than policy and could not be tightened"
	const tightenedMsg = "tightened the file mode of a prior pfx"
	const unreadableMsg = "cannot read prior pfx; regenerating"

	logs := captureLogs(t)
	current, _, err := s.isCurrent(t.Context(), "out.pfx", nil, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("isCurrent(bundle removed mid-inspection) = error %v, want nil: an unreadable prior bundle is"+
			" something this app fixes by rewriting, not a failure that flips health", err)
	}
	if current {
		t.Error("isCurrent(bundle removed mid-inspection) = true, want false: a bundle that is not there cannot be the current one")
	}
	if got := logs.CountLevel(slog.LevelWarn, notTightenedMsg); got != 1 {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q at WARN %d times, want exactly 1: %q",
			notTightenedMsg, got, logs.Messages())
	}
	if _, ok := logs.AttrValue(notTightenedMsg, "error"); !ok {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q without an error attribute, want the re-stat"+
			" failure carried so the operator learns the mode was never observed: %q", notTightenedMsg, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelInfo, tightenedMsg); got != 0 {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q %d times, want 0: the chmod's result was never"+
			" observed, so claiming the repair tells the operator the opposite of the truth: %q", tightenedMsg, got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelWarn, unreadableMsg); got != 1 {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q at WARN %d times, want exactly 1: %q",
			unreadableMsg, got, logs.Messages())
	}
	if !logs.HasAttr(unreadableMsg, "path", "out.pfx") {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q, want path=out.pfx so the operator can identify"+
			" the bundle: %q", unreadableMsg, logs.Messages())
	}
	if _, ok := logs.AttrValue(unreadableMsg, "remediation"); !ok {
		t.Errorf("isCurrent(bundle removed mid-inspection) logged %q without a remediation hint: %q", unreadableMsg, logs.Messages())
	}
}

// TestStoreIsCurrent_reports_a_lax_output_directory pins the /output DIRECTORY
// permission record — and that it is REPORT-ONLY, which is the whole contract after
// the 2026-07 user decision ("if it can write to output but not chmod that is fine.
// that is a user choice. you can throw a warning but dont make the container
// unhealthy").
//
// The app creates the directory at pfxDirMode once, through
// atomicfile.WithMkdirMode, and MkdirAll is a no-op on a directory that already
// exists — so a directory an operator (or the README's own `mkdir -p`, which yields
// 0755 under the default umask and 0775 under a umask of 0002) left group- or
// world-accessible is named nowhere else, while this app polices the private-key
// bundle's own mode to 0600 on every scan.
//
// What "report-only" has to mean, and what a re-introduced enforcement rule would
// break here: ANY bit beyond pfxDirMode is warned about once (the write bits included,
// since they are the most consequential), the mode on disk is left exactly as found,
// the currency verdict carries no error, and TestStoreWrite_publishes_into_a_lax_
// directory below pins that the bundle is still published and the reap is not vetoed.
// A previous cycle chmod-ed the ancestors and refused to publish when it could not;
// on CIFS/NFS/vfat (the Synology shares this app serves) the chmod can never succeed,
// so the container published nothing and restart-looped. A mode at or stricter than
// policy (a deliberately tighter 0700) is neither touched nor nagged about, and every
// record is emitted ONCE per directory per scan — isCurrent runs for every .crt, so a
// flat /output holding twenty bundles must not produce twenty identical records on
// every tick.
// Runs serially: it swaps slog.Default().
func TestStoreIsCurrent_reports_a_lax_output_directory(t *testing.T) {
	// Spelled out rather than imported from the production const: an operator's log
	// query keys on these words, so a silent rewording must fail here.
	const wantMsg = "the /output directory holding a pfx is more permissive than policy"

	for _, tc := range []struct {
		name     string
		mode     os.FileMode
		wantWarn bool
	}{
		{name: "the policy mode is not reported", mode: pfxDirMode},
		{name: "an owner-only directory is not reported", mode: 0o700},
		{name: "a world-traversable directory is reported and left alone", mode: 0o755, wantWarn: true},
		{name: "a group-writable directory is reported and left alone", mode: 0o770, wantWarn: true},
		{name: "a group-writable world-traversable directory is reported and left alone", mode: 0o775, wantWarn: true},
		{name: "a world-writable directory is reported and left alone", mode: 0o777, wantWarn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// Chmod explicitly: what t.TempDir creates depends on the host (an inherited
			// ACL widens it), so the fixture cannot inherit tc.mode.
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatalf("setup: Chmod(dir): %v", err)
			}
			s := newOutputStore(t, dir)
			logs := captureLogs(t)

			// No bundle is planted: the check is asked before the bundle's own lstat, so
			// the absent-bundle arm must carry it too — a lax directory is lax whether or
			// not a prior bundle sits in it. want is never dereferenced on that arm.
			current, _, err := s.isCurrent(t.Context(), "out.pfx", nil, convert.EncNameModern2023, "pw")
			if err != nil || current {
				t.Fatalf("isCurrent(no prior bundle) = %v, %v, want false, nil: a directory mode may never"+
					" fail the pair, whatever its permissions", current, err)
			}

			want := 0
			if tc.wantWarn {
				want = 1
			}
			if got := logs.CountLevel(slog.LevelWarn, wantMsg); got != want {
				t.Errorf("isCurrent(directory mode %o) logged %q at WARN %d times, want %d: %q",
					tc.mode, wantMsg, got, want, logs.Messages())
			}
			if fi, statErr := os.Stat(dir); statErr != nil {
				t.Fatalf("Stat(dir): %v", statErr)
			} else if got := fi.Mode().Perm(); got != tc.mode {
				t.Errorf("isCurrent(directory mode %o) left the directory at %o, want it untouched: the mode of"+
					" the operator's own directory is theirs to choose, and repairing it breaks every mount"+
					" that forces directory modes", tc.mode, got)
			}
			if !tc.wantWarn {
				return
			}
			for _, key := range []string{"path", "mode", "want", "remediation"} {
				if _, ok := logs.AttrValue(wantMsg, key); !ok {
					t.Errorf("isCurrent(directory mode %o) logged %q without a %s attribute, want the"+
						" directory, the mode found, the mode wanted and what to do: %q",
						tc.mode, wantMsg, key, logs.Messages())
				}
			}
			if !logs.HasAttr(wantMsg, "mode", tc.mode.String()) {
				t.Errorf("isCurrent(directory mode %o) logged %q without the mode it found, want %s: %q",
					tc.mode, wantMsg, tc.mode.String(), logs.Messages())
			}
		})
	}

	t.Run("one record per directory per scan, not one per bundle", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
			t.Fatalf("setup: Mkdir: %v", err)
		}
		// Both directories are chmod-ed explicitly: what the host creates depends on it
		// (an inherited default ACL widens a fresh directory).
		if err := os.Chmod(filepath.Join(dir, "nested"), 0o755); err != nil {
			t.Fatalf("setup: Chmod(nested): %v", err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatalf("setup: Chmod(dir): %v", err)
		}
		s := newOutputStore(t, dir)
		logs := captureLogs(t)

		// Three bundles in the flat root plus one in a nested directory: the flat ones
		// share a directory and must report once between them, while the nested one is a
		// different directory and reports on its own.
		for _, rel := range []string{"a.pfx", "b.pfx", "c.pfx", "nested/d.pfx"} {
			if _, _, err := s.isCurrent(t.Context(), rel, nil, convert.EncNameModern2023, "pw"); err != nil {
				t.Fatalf("isCurrent(%s) = error %v, want nil", rel, err)
			}
		}

		if got := logs.CountLevel(slog.LevelWarn, wantMsg); got != 2 {
			t.Errorf("isCurrent over three bundles in one lax directory plus one in a second logged %q %d"+
				" times, want exactly 2: the fact is a property of the DIRECTORY, and a per-bundle record"+
				" would repeat on every scan for as long as the mode stands: %q", wantMsg, got, logs.Messages())
		}
		if !logs.HasAttr(wantMsg, "path", "nested") {
			t.Errorf("isCurrent(nested/d.pfx) logged %q without path=nested, want each directory named"+
				" separately: %q", wantMsg, logs.Messages())
		}
	})
}

// TestStoreWrite_publishes_into_a_lax_directory_and_still_reaps pins the OTHER half of
// the report-only decision, the half that decides whether the container works at all:
// a group- and world-writable /output whose mode this app cannot change must still get
// its bundle published, and must not disable orphan reaping.
//
// This is the case a previous cycle got wrong by design: it chmod-ed the ancestors,
// refused the write when the chmod did not take, routed that refusal through failEntry
// (so it counted in ScanResult.Failed and flipped the health marker) and vetoed the
// reap. On a mount that forces directory modes — CIFS, NFS, vfat, i.e. the Synology
// shares this app exists to serve — the chmod can NEVER succeed, so the container
// published nothing and restart-looped forever. No chmod seam is needed: after the
// removal of enforcement neither store.write nor store.listOutputs touches a
// directory mode at all, which is the property under test.
func TestStoreWrite_publishes_into_a_lax_directory_and_still_reaps(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("setup: Chmod(dir): %v", err)
	}
	s := newOutputStore(t, dir)

	if err := s.write(t.Context(), "out.pfx", []byte("pfx")); err != nil {
		t.Fatalf("write(world-writable directory) = %v, want nil: a directory mode the operator chose must"+
			" not stop the bundle being published", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "out.pfx")); err != nil {
		t.Errorf("os.Stat(out.pfx) = %v, want the bundle published", err)
	}
	if fi, err := os.Stat(dir); err != nil {
		t.Fatalf("Stat(dir): %v", err)
	} else if got := fi.Mode().Perm(); got != 0o777 {
		t.Errorf("write left the output directory at %o, want 0777 untouched: this app does not chmod the"+
			" operator's directories", got)
	}
	if _, safe, err := s.listOutputs(t.Context()); err != nil {
		t.Fatalf("listOutputs = error %v, want nil", err)
	} else if !safe {
		t.Error("listOutputs reported the walk unsafe under a world-writable directory, want safe: directory" +
			" permissiveness is a reported condition, not a reap veto")
	}
}

// TestStoreRemoveOrphans_reports_vanished_candidate_and_continues pins removeOrphans'
// dedicated pre-unlink RACE arm: a candidate that no longer exists when the unlink is
// attempted is a transient producer transaction, not an operator-facing permission
// problem, so it is DEBUG and must not raise the re-check WARN — and it must not stop
// the loop. Deleting the errors.Is(statErr, fs.ErrNotExist) arm routes the vanished
// candidate through the generic WARN, which is what these two log assertions catch;
// the deletion count alone would still pass. Serial: captureLogs swaps the
// process-global slog.Default.
func TestStoreRemoveOrphans_reports_vanished_candidate_and_continues(t *testing.T) {
	const vanishedMsg = "orphaned output vanished before removal"
	const recheckWarn = "could not re-check an orphaned output before removing it; leaving it in place"

	dir := t.TempDir()
	reapable := filepath.Join(dir, "reapable.pfx")
	if err := os.WriteFile(reapable, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	s := newOutputStore(t, dir)
	logs := captureLogs(t)

	deleted, err := s.removeOrphans(t.Context(), []string{"vanished.pfx", "reapable.pfx"})
	if err != nil {
		t.Fatalf("removeOrphans(missing candidate followed by regular file) = %v, want nil", err)
	}
	if deleted != 1 {
		t.Errorf("removeOrphans(missing candidate followed by regular file) deleted = %d, want 1", deleted)
	}
	if _, statErr := os.Stat(reapable); !os.IsNotExist(statErr) {
		t.Errorf("os.Stat(reapable.pfx) = %v, want a not-exist error: the vanished first candidate must not stop the loop", statErr)
	}
	if got := logs.CountLevel(slog.LevelDebug, vanishedMsg); got != 1 {
		t.Errorf("removeOrphans(missing candidate) logged %q at DEBUG %d times, want exactly 1: %q", vanishedMsg, got, logs.Messages())
	}
	if !logs.HasAttr(vanishedMsg, "path", "vanished.pfx") {
		t.Errorf("removeOrphans(missing candidate) logged %q without path=vanished.pfx: %q", vanishedMsg, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelWarn, recheckWarn); got != 0 {
		t.Errorf("removeOrphans(missing candidate) logged %q at WARN %d times, want 0: disappearance is a transient race, not an operator permission problem: %q", recheckWarn, got, logs.Messages())
	}
}

// TestStoreRemoveOrphans_leaves_a_candidate_it_cannot_recheck pins removeOrphan's
// OTHER pre-unlink arm: a candidate whose re-check fails for any reason that is not
// "it is gone" must be left in place, at WARN, with the /output ownership hint.
//
// It is the fail-safe half of the vanished-race arm above, and the two are one line
// apart: fold the ENOENT test into a bare statErr != nil and every unrecheckable
// candidate is reported as a transient race at DEBUG instead, so an operator whose
// /output the reap cannot inspect gets no default-level record at all. The whole
// suite stays green through that change without this test.
//
// A closed root is the failure injection, the same one
// TestStoreReconcile_reports_an_output_tree_it_cannot_enumerate uses: it produces a
// non-ENOENT Lstat failure whatever uid the suite runs as, where a chmod-based
// fixture does nothing under uid 0. Deliberately NOT newOutputStore: the closed root
// IS the injection, so the store must outlive its root handle.
// Runs serially: it swaps slog.Default().
func TestStoreRemoveOrphans_leaves_a_candidate_it_cannot_recheck(t *testing.T) {
	// Spelled out rather than imported from the production call sites: an operator's
	// log query keys on these words, so a silent rewording must fail here.
	const recheckWarn = "could not re-check an orphaned output before removing it; leaving it in place"
	const vanishedMsg = "orphaned output vanished before removal"

	dir := t.TempDir()
	bundle := filepath.Join(dir, "a.pfx")
	if err := os.WriteFile(bundle, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("setup: root.Close: %v", err)
	}
	s := &store{root: root}
	logs := captureLogs(t)

	deleted, err := s.removeOrphans(t.Context(), []string{"a.pfx"})
	if err != nil {
		t.Fatalf("removeOrphans(uninspectable candidate) = %v, want nil: a candidate this app cannot"+
			" re-check is skipped, not a scan failure", err)
	}
	if deleted != 0 {
		t.Errorf("removeOrphans(uninspectable candidate) deleted = %d, want 0", deleted)
	}
	if _, statErr := os.Stat(bundle); statErr != nil {
		t.Errorf("the bundle was deleted after a re-check this app could not make: %v: doubt about the"+
			" state of a private-key bundle must keep it", statErr)
	}
	if got := logs.CountLevel(slog.LevelWarn, recheckWarn); got != 1 {
		t.Errorf("removeOrphans(uninspectable candidate) logged %q at WARN %d times, want exactly 1: %q",
			recheckWarn, got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelDebug, vanishedMsg); got != 0 {
		t.Errorf("removeOrphans(uninspectable candidate) logged %q %d times, want 0: an /output the reap"+
			" cannot inspect is an operator condition, not the transient renewal race: %q",
			vanishedMsg, got, logs.Messages())
	}
	if _, ok := logs.AttrValue(recheckWarn, "error"); !ok {
		t.Errorf("removeOrphans(uninspectable candidate) logged %q with no error attribute, want the"+
			" re-check failure carried so the operator can diagnose it: %q", recheckWarn, logs.Messages())
	}
	if got, ok := logs.AttrValue(recheckWarn, "remediation"); !ok || got != outputPermRemediation {
		t.Errorf("removeOrphans(uninspectable candidate) logged remediation %q, want %q",
			got, outputPermRemediation)
	}
}

// TestStoreRemoveOrphans_reports_a_vanished_nested_candidate_as_a_race pins the same
// DEBUG-not-WARN contract for the NESTED layout, which reaches the disappearance
// through a different call.
//
// A flat candidate answers ENOENT from removeOrphan's own Lstat, but a nested one is
// pinned parent-component by parent-component first, so an ancestor removed during the
// reap deferral fails the PIN instead — and the pin's WARN carries a symlink
// remediation ("mount the real output directory instead of linking to it") for an
// ordinary disappearance that is neither a symlink nor an identity swap. Serial:
// captureLogs swaps the process-global slog.Default.
func TestStoreRemoveOrphans_reports_a_vanished_nested_candidate_as_a_race(t *testing.T) {
	const (
		vanishedMsg = "orphaned output vanished before removal"
		pinMsg      = pinRedirectedMsg
	)

	dir := t.TempDir()
	nested := filepath.Join(dir, "ca1")
	if err := os.Mkdir(nested, 0o750); err != nil {
		t.Fatalf("setup: Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "gone.pfx"), []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	s := newOutputStore(t, dir)
	// The whole directory goes, exactly as a producer replacing a CA folder mid-scan
	// would take it: the candidate was enumerated, its ancestor is gone by unlink time.
	if err := os.RemoveAll(nested); err != nil {
		t.Fatalf("setup: RemoveAll: %v", err)
	}
	logs := captureLogs(t)

	deleted, err := s.removeOrphans(t.Context(), []string{"ca1/gone.pfx"})
	if err != nil {
		t.Fatalf("removeOrphans(vanished nested candidate) = %v, want nil", err)
	}
	if deleted != 0 {
		t.Errorf("removeOrphans(vanished nested candidate) deleted = %d, want 0", deleted)
	}
	if got := logs.CountLevel(slog.LevelDebug, vanishedMsg); got != 1 {
		t.Errorf("removeOrphans(vanished nested candidate) logged %q at DEBUG %d times, want exactly 1: %q",
			vanishedMsg, got, logs.Messages())
	}
	if got := logs.CountLevel(slog.LevelWarn, pinMsg); got != 0 {
		t.Errorf("removeOrphans(vanished nested candidate) logged %q at WARN %d times, want 0: a disappearance is a"+
			" transient race, and that WARN's remediation points at a symlink misconfiguration that is not there: %q",
			pinMsg, got, logs.Messages())
	}
}

// TestStoreListOutputs_enumerates_a_nested_tree pins the enumeration contract the
// /output walk owes the reap: every bundle this app could have written, at any depth,
// reaches the candidate list, and nothing else does.
//
// It is the /output half of the shared walker's contract (walkRoot, which both mounts
// now go through): the reap's whole claim is that a candidate it cannot match to an
// input is an orphan, so a bundle the walk never reported would be retained forever
// while a non-bundle it wrongly reported could be deleted. Order is deliberately NOT
// asserted — the streaming walk visits directory order, sorted within a batch only,
// and every consumer (orphansOf's set membership, sampleOrphanPaths' bounded sample)
// is order-independent.
func TestStoreListOutputs_enumerates_a_nested_tree(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub", "deeper"), 0o750); err != nil {
		t.Fatalf("setup: MkdirAll: %v", err)
	}
	for _, rel := range []string{
		"top.pfx",
		filepath.Join("sub", "mid.pfx"),
		filepath.Join("sub", "deeper", "leaf.pfx"),
		"notes.txt",
		filepath.Join("sub", "chain.pem"),
	} {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte("x"), 0o600); err != nil {
			t.Fatalf("setup: WriteFile(%s): %v", rel, err)
		}
	}

	s := newOutputStore(t, dir)
	found, safe, err := s.listOutputs(t.Context())
	if err != nil {
		t.Fatalf("listOutputs(nested tree) = %v, want nil", err)
	}
	if !safe {
		t.Error("safe = false, want true: a fully readable tree with no symlink is a complete enumeration")
	}

	want := []string{"sub/deeper/leaf.pfx", "sub/mid.pfx", "top.pfx"}
	got := slices.Clone(found)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("listOutputs(nested tree) = %v, want %v (any order): every bundle at every depth is a"+
			" candidate, and a file this app would never have written is never one", got, want)
	}
}

// TestOwnedByThisProcess_answers_the_chmod_authorization_question pins the
// discriminator the untightenable-mode arms branch on, which every chmod-refusal test
// reaches through the fileOwnedByProcess seam and therefore never executes.
//
// Both halves matter. A file this process just created is OWNED, which is what routes
// a mode-forcing filesystem's EPERM onto the WARN-only arm instead of scheduling a
// rewrite that would land with the same forced mode. And a FileInfo carrying no
// *syscall.Stat_t answers false, which keeps the documented deployment shape (a
// root-owned bundle left by an earlier PUID mapping) on the arm that repairs it —
// failing OPEN toward repair rather than assuming ownership it could not read.
func TestOwnedByThisProcess_answers_the_chmod_authorization_question(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("setup: Lstat: %v", err)
	}
	if !ownedByThisProcess(fi) {
		t.Errorf("ownedByThisProcess(a file this process created) = false, want true: the euid that"+
			" owns a file may always chmod it, which is the premise the WARN-only refusal arm rests on"+
			" (file uid vs euid %d)", os.Geteuid())
	}
	if ownedByThisProcess(statlessFileInfo{fi}) {
		t.Error("ownedByThisProcess(a FileInfo with no *syscall.Stat_t) = true, want false: an" +
			" unreadable ownership must route the refusal to the arm that regenerates")
	}
}

// statlessFileInfo is an os.FileInfo whose Sys() carries no *syscall.Stat_t, the
// shape a non-POSIX or synthetic filesystem hands back.
type statlessFileInfo struct{ os.FileInfo }

func (statlessFileInfo) Sys() any { return nil }

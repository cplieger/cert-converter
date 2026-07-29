package process

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
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

// TestStoreLstat_does_not_follow_a_symlink pins why the prior-output check lstats
// rather than stats: a symlink planted under an output name must not be accepted
// as a usable prior PFX, or unrelated content could satisfy the coherence gate.
func TestStoreLstat_does_not_follow_a_symlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.pfx")
	if err := os.WriteFile(target, []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.pfx")); err != nil {
		t.Fatalf("setup: Symlink: %v", err)
	}
	s := newOutputStore(t, dir)

	fi, err := s.lstat("link.pfx")
	if err != nil {
		t.Fatalf("store.lstat(symlink) = error %v, want nil", err)
	}
	if fi.Mode().IsRegular() {
		t.Error("store.lstat reported a symlink as a regular file; the prior-output gate would accept it")
	}

	fi, err = s.lstat("real.pfx")
	if err != nil {
		t.Fatalf("store.lstat(regular file) = error %v, want nil", err)
	}
	if !fi.Mode().IsRegular() {
		t.Error("store.lstat did not report a regular file as regular")
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
// permission verdict, the precondition every other output touch is confined against —
// and the SPLIT in that verdict, which is the whole point of the check.
//
// The app creates the directory at pfxDirMode once, through
// atomicfile.WithMkdirMode, and MkdirAll is a no-op on a directory that already
// exists — so a directory an operator (or the README's own `mkdir -p`, which yields
// 0755 under the default umask and 0775 under a umask of 0002) left group- or
// world-accessible is corrected and named nowhere else, while this app polices the
// private-key bundle's own mode to 0600 on every scan.
//
// The split, by consequence: a group- or world-WRITE bit grants unlink and rename
// authority over a published owner-only bundle, so it is REPAIRED with a confined
// chmod (0770 -> 0750, 0775 -> 0755, 0777 -> 0755) and, when the repair cannot be
// made, refuses the write outright. Every other extra bit exposes names and traversal
// only (0755), so it stays report-only: tightening a directory the operator may have
// widened deliberately is their call, and the mode on disk must be left exactly as
// found. A mode at or stricter than policy (a deliberately tighter 0700) is neither
// touched nor nagged about, and every record is emitted ONCE per directory per scan —
// isCurrent runs for every .crt, so a flat /output holding twenty bundles must not
// produce twenty identical records on every tick.
// Runs serially: it swaps slog.Default().
func TestStoreIsCurrent_reports_a_lax_output_directory(t *testing.T) {
	// Spelled out rather than imported from the production const: an operator's log
	// query keys on these words, so a silent rewording must fail here.
	const wantMsg = "the /output directory holding a pfx is more permissive than policy"
	const tightenedMsg = "tightened a group- or world-writable /output directory"

	for _, tc := range []struct {
		name          string
		mode          os.FileMode
		wantMode      os.FileMode
		wantWarn      bool
		wantTightened bool
	}{
		{name: "the policy mode is not reported", mode: pfxDirMode, wantMode: pfxDirMode},
		{name: "an owner-only directory is not reported", mode: 0o700, wantMode: 0o700},
		{name: "a world-traversable directory is reported and left alone", mode: 0o755, wantMode: 0o755, wantWarn: true},
		{name: "a group-writable directory is tightened", mode: 0o770, wantMode: 0o750, wantTightened: true},
		{name: "a group-writable world-traversable directory is tightened", mode: 0o775, wantMode: 0o755, wantTightened: true},
		{name: "a world-writable directory is tightened", mode: 0o777, wantMode: 0o755, wantTightened: true},
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
				t.Fatalf("isCurrent(no prior bundle) = %v, %v, want false, nil", current, err)
			}

			want := 0
			if tc.wantWarn {
				want = 1
			}
			if got := logs.CountLevel(slog.LevelWarn, wantMsg); got != want {
				t.Errorf("isCurrent(directory mode %o) logged %q at WARN %d times, want %d: %q",
					tc.mode, wantMsg, got, want, logs.Messages())
			}
			wantTightenRecords := 0
			if tc.wantTightened {
				wantTightenRecords = 1
			}
			if got := logs.CountLevel(slog.LevelInfo, tightenedMsg); got != wantTightenRecords {
				t.Errorf("isCurrent(directory mode %o) logged %q at INFO %d times, want %d: a repair this app"+
					" makes to the operator's volume must be named, and only a real repair may be: %q",
					tc.mode, tightenedMsg, got, wantTightenRecords, logs.Messages())
			}
			if fi, statErr := os.Stat(dir); statErr != nil {
				t.Fatalf("Stat(dir): %v", statErr)
			} else if got := fi.Mode().Perm(); got != tc.wantMode {
				t.Errorf("isCurrent(directory mode %o) left the directory at %o, want %o: the group/other WRITE"+
					" bits are repaired because they let another UID replace a published bundle, and every"+
					" other bit is the operator's call", tc.mode, got, tc.wantMode)
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

	// The two ways the repair does not happen, neither of which this suite can produce
	// for real: it runs as uid 0, so no chmod is refused, and no mount-forced-mode
	// filesystem is available. Both must refuse the write rather than warn and continue,
	// because a bundle published into a directory another UID can rewrite can be
	// replaced with attacker-chosen key material after this app publishes it.
	for _, tc := range []struct {
		name  string
		chmod func(*os.Root, string, os.FileMode) error
	}{
		{
			name:  "a refused repair refuses the write",
			chmod: func(*os.Root, string, os.FileMode) error { return fs.ErrPermission },
		},
		{
			// Accepted and stored nowhere: CIFS/vfat with mount-forced modes, some NFS
			// squash configs. The chmod reports success and the write bit is still there.
			name:  "a chmod the filesystem does not store refuses the write",
			chmod: func(*os.Root, string, os.FileMode) error { return nil },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const refusedMsg = "the /output directory holding a pfx is group- or world-writable and could not be tightened; refusing to write there"

			dir := t.TempDir()
			if err := os.Chmod(dir, 0o775); err != nil {
				t.Fatalf("setup: Chmod(dir): %v", err)
			}
			prev := chmodInRoot
			chmodInRoot = tc.chmod
			t.Cleanup(func() { chmodInRoot = prev })
			s := newOutputStore(t, dir)
			logs := captureLogs(t)

			current, _, err := s.isCurrent(t.Context(), "out.pfx", nil, convert.EncNameModern2023, "pw")
			if err == nil {
				t.Fatalf("isCurrent(unrepairable writable directory) = %v, nil, want an error: no private key may"+
					" be published into a namespace another UID can rewrite", current)
			}
			if got := logs.CountLevel(slog.LevelWarn, refusedMsg); got != 1 {
				t.Errorf("isCurrent(unrepairable writable directory) logged %q at WARN %d times, want exactly 1: %q",
					refusedMsg, got, logs.Messages())
			}
			if writeErr := s.write(t.Context(), "out.pfx", []byte("pfx")); writeErr == nil {
				t.Errorf("write(unrepairable writable directory) = nil, want an error")
			} else if _, statErr := os.Stat(filepath.Join(dir, "out.pfx")); statErr == nil {
				t.Errorf("write(unrepairable writable directory) published the bundle anyway")
			}
			// The same failure must also stop the reap: a candidate under a directory
			// another process can write can be swapped between the walk and the unlink.
			if _, safe, listErr := s.listOutputs(t.Context()); listErr != nil {
				t.Fatalf("listOutputs = error %v, want nil", listErr)
			} else if safe {
				t.Errorf("listOutputs reported the walk safe after an unrepairable writable directory, want unsafe")
			}
		})
	}

	t.Run("one record per directory per scan, not one per bundle", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
			t.Fatalf("setup: Mkdir: %v", err)
		}
		// Both directories are chmod-ed explicitly: what the host creates depends on it
		// (an inherited ACL widens a fresh directory), and the fixture needs the
		// report-only class — a bit beyond policy that grants no write authority — not
		// the repaired one.
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

package mounts

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/slogx/capture"
)

// wantVolumeMissingMsg is the ERROR substring OpenMounts must log for a mount
// that is absent or is not a directory. One copy, matched as a substring of the
// full record (main.go appends "; refusing to start").
const wantVolumeMissingMsg = "required volume is missing or not a directory"

// TestOpenMounts pins the startup volume guard, the one decision in run()
// that decides between a single actionable refusal and an endless
// restart-unhealthy loop: every required mount must already exist AND be a
// directory, EVERY offender is named at ERROR with its role and a
// remediation, and a fully-mounted pair starts silently. Serial: it swaps
// slog.Default().
func TestOpenMounts(t *testing.T) {
	existingDir := t.TempDir()
	regularFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(regularFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "absent")

	for _, tc := range []struct {
		name       string
		dirs       []Mount
		want       bool
		wantRole   string
		wantErrSub string
	}{
		{"both mounted", []Mount{{"input", existingDir}, {"output", existingDir}}, true, "", ""},
		{"missing input", []Mount{{"input", absent}, {"output", existingDir}}, false, "input", "no such file"},
		{"missing output", []Mount{{"input", existingDir}, {"output", absent}}, false, "output", "no such file"},
		{"input is a regular file", []Mount{{"input", regularFile}, {"output", existingDir}}, false, "input", "path exists but is not a directory"},
		{"output is a regular file", []Mount{{"input", existingDir}, {"output", regularFile}}, false, "output", "path exists but is not a directory"},
		{"no volumes required", nil, true, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			open, got := OpenMounts(tc.dirs)
			t.Cleanup(func() { CloseMounts(open) })
			if got != tc.want {
				t.Errorf("OpenMounts(%+v) = %v, want %v", tc.dirs, got, tc.want)
			}
			if tc.want {
				// Every accepted volume comes back with its confined handle open: that
				// handle is what the /output write probe runs against, so a guard that
				// returned the verdict alone would send the probe back to re-resolving
				// the path it just proved openable.
				if len(open) != len(tc.dirs) {
					t.Errorf("OpenMounts(%+v) returned %d handles, want one per required volume (%d)",
						tc.dirs, len(open), len(tc.dirs))
				}
				for i, vol := range open {
					if vol.Root == nil {
						t.Errorf("OpenMounts(%+v) handle %d (role %q) has a nil root", tc.dirs, i, vol.Role)
					}
				}
				if logs.Len() != 0 {
					t.Errorf("OpenMounts(%+v) logged %v, want silence when every volume is mounted", tc.dirs, logs.Messages())
				}
				return
			}
			// A refusal must hand back nothing: run() returns 1 without looking at the
			// slice, so any handle opened before the offender has to be closed here or
			// it is leaked for the life of the process.
			if open != nil {
				t.Errorf("OpenMounts(%+v) returned %d handles on the refusal path, want none", tc.dirs, len(open))
			}
			const msg = wantVolumeMissingMsg
			if n := logs.CountLevel(slog.LevelError, msg); n != 1 {
				t.Fatalf("OpenMounts(%+v) logged %d ERROR records matching %q, want exactly 1 (logs %v)",
					tc.dirs, n, msg, logs.Messages())
			}
			if !logs.AttrContains(msg, "role", tc.wantRole) {
				t.Errorf("OpenMounts(%+v) ERROR does not name role %q (logs %v)", tc.dirs, tc.wantRole, logs.Messages())
			}
			if !logs.AttrContains(msg, "remediation", "mount ") {
				t.Errorf("OpenMounts(%+v) ERROR is missing an actionable remediation attr (logs %v)", tc.dirs, logs.Messages())
			}
			// The two causes need different remedies — a missing mount versus a
			// bind-mounted FILE — so the error attr must distinguish them. It
			// carried error=<nil> for the non-directory case before the
			// substitution in OpenMounts, which is unactionable.
			if !logs.AttrContains(msg, "error", tc.wantErrSub) {
				t.Errorf("OpenMounts(%+v) ERROR attr does not name the cause %q (logs %v)", tc.dirs, tc.wantErrSub, logs.Messages())
			}
		})
	}
}

// TestOpenMounts_names_every_missing_volume pins the whole point of the
// all-offenders sweep: an operator who omitted the volumes block entirely has
// both mounts missing, and a report naming only /input costs a restart to
// discover /output. Serial: it swaps slog.Default().
func TestOpenMounts_names_every_missing_volume(t *testing.T) {
	absentInput := filepath.Join(t.TempDir(), "absent-input")
	absentOutput := filepath.Join(t.TempDir(), "absent-output")

	logs := capture.Default(t)

	if _, ready := OpenMounts([]Mount{{"input", absentInput}, {"output", absentOutput}}); ready {
		t.Fatal("OpenMounts(both absent) = true, want false")
	}
	const msg = wantVolumeMissingMsg
	if n := logs.CountLevel(slog.LevelError, msg); n != 2 {
		t.Fatalf("OpenMounts(both absent) logged %d ERROR records matching %q, want 2 so one start attempt names the whole misconfiguration (logs %v)",
			n, msg, logs.Messages())
	}
	for _, role := range []string{"input", "output"} {
		if !logs.AttrContains(msg, "role", role) {
			t.Errorf("OpenMounts(both absent) ERROR set does not name role %q (logs %v)", role, logs.Messages())
		}
	}
}

// TestOpenMounts_refuses_a_volume_it_cannot_open pins the third refusal leg of
// the startup guard, the one whose remediation differs from the other two: a
// mount that EXISTS as a directory but cannot be opened by the running UID is a
// permissions problem on the host directory, so the operator must be told to
// grant that UID access, not to mount a path they already mounted. The refusal
// also has to hand back no handles, because run() returns 1 without reading the
// slice.
// Serial (no t.Parallel): it swaps the openMountRoot package var and
// slog.Default().
func TestOpenMounts_refuses_a_volume_it_cannot_open(t *testing.T) {
	existing, blocked := t.TempDir(), t.TempDir()

	prev := openMountRoot
	openMountRoot = func(path string) (*os.Root, error) {
		if path == blocked {
			return nil, &fs.PathError{Op: "openat", Path: path, Err: fs.ErrPermission}
		}
		return prev(path)
	}
	t.Cleanup(func() { openMountRoot = prev })

	logs := capture.Default(t)

	open, ready := OpenMounts([]Mount{{"input", existing}, {"output", blocked}})
	t.Cleanup(func() { CloseMounts(open) })

	if ready {
		t.Fatalf("OpenMounts(%q unopenable) = true, want false: starting anyway converts nothing and restart-loops on a condition a restart cannot clear", blocked)
	}
	if open != nil {
		t.Errorf("OpenMounts returned %d handles on the unopenable-volume path, want none: the input handle opened before the offender leaks for the life of the process otherwise",
			len(open))
	}
	const msg = "required volume cannot be opened by this container's user; refusing to start"
	if n := logs.CountLevel(slog.LevelError, msg); n != 1 {
		t.Fatalf("OpenMounts(%q unopenable) logged %d ERROR records matching %q, want exactly 1 (logs %v)",
			blocked, n, msg, logs.Messages())
	}
	if !logs.HasAttr(msg, "role", "output") {
		t.Errorf("the refusal does not name the offending role, so an operator cannot tell which mount to fix (logs %v)", logs.Messages())
	}
	if !logs.HasAttr(msg, "path", blocked) {
		t.Errorf("the refusal does not name the unopenable path (logs %v)", logs.Messages())
	}
	if !logs.AttrContains(msg, "remediation", "grant the UID") {
		t.Errorf("the refusal gives no ownership remediation, so a permission problem reads as a missing mount (logs %v)", logs.Messages())
	}
	const mountMsg = "required volume is missing or not a directory"
	if n := logs.Count(mountMsg); n != 0 {
		t.Errorf("an unopenable mount produced %d %q records, want 0: that wording tells the operator to mount a path they already mounted (logs %v)",
			n, mountMsg, logs.Messages())
	}
}

// TestWarnOutputNotWritable_reports_failed_probe pins the startup probe's only
// output: OpenMounts proves /output is a directory this UID can OPEN, so this
// WARN is the sole immediate signal that it cannot be WRITTEN. A scan whose
// bundles are all current writes nothing and still reports healthy, so without
// this record the misconfiguration surfaces only at the next renewal.
//
// This case runs the REAL library probe, so the app's mapping is pinned against
// atomicfile's actual outcome and not only against the stub below. The probe is
// failed by opening the confined handle and then deleting the directory under it:
// the handle stays valid and every create through it fails ENOENT, which no UID
// bypasses. (That replaces the previous regular-file construction for the same
// reason it replaced a chmod-0500 directory — the suite can run as uid 0 — and a
// regular file is no longer usable at all, since an *os.Root can only be opened
// on a directory.) Not parallel: it swaps the process-global slog default.
func TestWarnOutputNotWritable_reports_failed_probe(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "output-gone")
	if err := os.Mkdir(blocked, 0o750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(blocked)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	logs := capture.Default(t)

	WarnOutputNotWritable(root)

	const msg = wantOutputNotWritableMsg
	if n := logs.CountLevel(slog.LevelWarn, msg); n != 1 {
		t.Fatalf("WarnOutputNotWritable(%q) logged %d WARN records matching %q, want 1 (logs %v)",
			blocked, n, msg, logs.Messages())
	}
	if !logs.HasAttr(msg, "path", blocked) {
		t.Errorf("WarnOutputNotWritable(%q) did not identify the unusable output path (logs %v)",
			blocked, logs.Messages())
	}
	if !logs.AttrContains(msg, "remediation", "chown the host directory") {
		t.Errorf("WarnOutputNotWritable(%q) gave no ownership remediation (logs %v)",
			blocked, logs.Messages())
	}
	// The stage is what tells an operator WHICH refusal they are looking at, now
	// that the probe walks the whole create/write/flush/close/unlink ladder instead
	// of the create alone.
	if !logs.HasAttr(msg, "stage", atomicfile.ProbeStageCreate.String()) {
		t.Errorf("WarnOutputNotWritable(%q) does not name the failing probe stage (logs %v)",
			blocked, logs.Messages())
	}
}

// wantOutputNotWritableMsg is the operator-visible refusal message. It is spelled
// out again rather than imported from main.go for the same reason the case above
// keeps its own copy: the wording is the contract an operator (and the README's
// alerting section) reads, so the tests assert the literal text.
const wantOutputNotWritableMsg = "the output volume is not writable by the running UID, so no PFX can be produced; " +
	"a scan whose bundles are all current still reports healthy, so this would otherwise " +
	"surface only at the next renewal"

// stubOutputProbe substitutes the probe seam for one test and restores it. The
// stub is how the stages a temp directory cannot produce — a volume that accepts
// and flushes the bytes and then refuses the unlink, a deferred write error that
// surfaces only at close — get exercised at all; they are precisely the
// misconfigurations this WARN set exists for.
func stubOutputProbe(t *testing.T, res atomicfile.ProbeResult, err error) {
	t.Helper()
	prev := probeOutputWritable
	probeOutputWritable = func(context.Context, *os.Root, string, ...atomicfile.Option) (atomicfile.ProbeResult, error) {
		return res, err
	}
	t.Cleanup(func() { probeOutputWritable = prev })
}

// TestWarnOutputNotWritable_maps_every_probe_stage_to_its_own_warning pins the
// whole outcome ladder onto the operator's warnings, and the two properties that
// make the probe warn-and-continue:
//
//   - No probe outcome fails startup. WarnOutputNotWritable returns nothing (a
//     compile-time property of its call site in run()), and no leg emits an ERROR
//     record, the level this app reserves for the conditions it refuses to start on.
//   - The refusal and the two teardown failures stay THREE distinguishable
//     records. Folding the close and remove outcomes into the create warning hides
//     a volume that writes bundles fine and only denies cleanup; the stage-to-
//     message mapping below is what such a regression would break.
//
// Serial (no t.Parallel): it swaps the process-global slog default and the seam.
func TestWarnOutputNotWritable_maps_every_probe_stage_to_its_own_warning(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	const leakedName = ".atomicfile-1234567890.tmp"
	leakedPath := filepath.Join(dir, leakedName)

	for _, tc := range []struct {
		probeErr    error
		wantAttrs   map[string]string
		name        string
		wantMsg     string
		wantAbsent  string
		res         atomicfile.ProbeResult
		wantWarns   int
		wantRecords int
	}{
		{
			name: "every stage passed is silent",
			res:  atomicfile.ProbeResult{Dir: dir, Name: leakedName},
		},
		{
			name: "a refused create reports the volume as not writable",
			res: atomicfile.ProbeResult{
				Dir: dir, Stage: atomicfile.ProbeStageCreate, Err: fs.ErrPermission,
			},
			wantMsg:     wantOutputNotWritableMsg,
			wantWarns:   1,
			wantRecords: 1,
			wantAttrs: map[string]string{
				"role": "output", "path": dir,
				"stage": atomicfile.ProbeStageCreate.String(),
			},
			// Nothing was durably written, so there is no probe file to reclaim and the
			// sweep sentence would send an operator after a file that does not exist.
			wantAbsent: "cleanup",
		},
		{
			name: "a refused write that also leaked names the leftover",
			res: atomicfile.ProbeResult{
				Dir: dir, Name: leakedName, Stage: atomicfile.ProbeStageWrite,
				Err: fs.ErrPermission, Leaked: true,
			},
			wantMsg:     wantOutputNotWritableMsg,
			wantWarns:   1,
			wantRecords: 1,
			wantAttrs: map[string]string{
				"stage": atomicfile.ProbeStageWrite.String(), "leaked_probe": leakedPath,
				"cleanup": staleTempRemediation,
			},
		},
		{
			name: "a close failure keeps its own message",
			res: atomicfile.ProbeResult{
				Dir: dir, Name: leakedName, Stage: atomicfile.ProbeStageClose,
				Err: errors.New("input/output error"),
			},
			wantMsg:     "failed to close the output write probe",
			wantWarns:   1,
			wantRecords: 1,
			wantAttrs: map[string]string{
				"path": leakedPath, "stage": atomicfile.ProbeStageClose.String(),
			},
			// The probe file WAS removed here, so the sweep remediation must not fire:
			// it is keyed on ProbeResult.Leaked, not on the stage.
			wantAbsent: "remediation",
		},
		{
			name: "a close failure that leaked keeps the sweep remediation",
			res: atomicfile.ProbeResult{
				Dir: dir, Name: leakedName, Stage: atomicfile.ProbeStageClose,
				Err: errors.New("input/output error"), Leaked: true,
			},
			wantMsg:     "failed to close the output write probe",
			wantWarns:   1,
			wantRecords: 1,
			wantAttrs:   map[string]string{"remediation": staleTempRemediation},
		},
		{
			name: "a refused unlink keeps its own message and the sweep remediation",
			res: atomicfile.ProbeResult{
				Dir: dir, Name: leakedName, Stage: atomicfile.ProbeStageRemove,
				Err: fs.ErrPermission, Leaked: true,
			},
			wantMsg:     "failed to remove the output write probe",
			wantWarns:   1,
			wantRecords: 1,
			wantAttrs: map[string]string{
				"path": leakedPath, "remediation": staleTempRemediation,
			},
		},
		{
			// "The probe was not attempted" says nothing about /output either way, so it
			// must not print the diagnosis an operator would act on — and must not
			// vanish either.
			name:        "a probe that was not attempted is not the not-writable diagnosis",
			probeErr:    errors.New("atomicfile: context canceled"),
			wantRecords: 1,
			wantAttrs:   map[string]string{"path": dir},
			wantAbsent:  "remediation",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubOutputProbe(t, tc.res, tc.probeErr)
			logs := capture.Default(t)

			WarnOutputNotWritable(root)

			if got := logs.Len(); got != tc.wantRecords {
				t.Fatalf("WarnOutputNotWritable logged %d records, want %d (logs %v)",
					got, tc.wantRecords, logs.Messages())
			}
			if got := logs.CountLevel(slog.LevelWarn, ""); got != tc.wantWarns {
				t.Errorf("WarnOutputNotWritable logged %d WARN records, want %d (logs %v)",
					got, tc.wantWarns, logs.Messages())
			}
			if got := logs.CountLevel(slog.LevelError, ""); got != 0 {
				t.Errorf("WarnOutputNotWritable logged %d ERROR records, want 0: a probe outcome must never read as a refusal to start (logs %v)",
					got, logs.Messages())
			}
			if tc.wantMsg != "" && logs.CountLevel(slog.LevelWarn, tc.wantMsg) != 1 {
				t.Fatalf("WarnOutputNotWritable did not emit the %q WARN (logs %v)", tc.wantMsg, logs.Messages())
			}
			for key, want := range tc.wantAttrs {
				if !logs.HasAttr(tc.wantMsg, key, want) {
					t.Errorf("WarnOutputNotWritable %q record: attr %q = %q, want %q (logs %v)",
						tc.wantMsg, key, attrOrMissing(logs, tc.wantMsg, key), want, logs.Messages())
				}
			}
			if tc.wantAbsent != "" {
				if got, ok := logs.AttrValue(tc.wantMsg, tc.wantAbsent); ok {
					t.Errorf("WarnOutputNotWritable %q record carries attr %q = %q, want it absent",
						tc.wantMsg, tc.wantAbsent, got)
				}
			}
		})
	}
}

// TestProbeOutputMounts_probes_only_the_output_volume pins the wiring run()
// performs between the volume guard and the write probe: the probe inspects the
// handle for the OUTPUT role and no other. /input is mounted read-only in
// production, so a probe pointed at it would emit the "output volume is not
// writable" WARN on every start, and dropping the wiring entirely would remove
// the only immediate signal that /output cannot be written.
// Serial (no t.Parallel): it swaps the probeOutputWritable package var.
func TestProbeOutputMounts_probes_only_the_output_volume(t *testing.T) {
	inDir, outDir := t.TempDir(), t.TempDir()

	vols, ready := OpenMounts([]Mount{{"input", inDir}, {"output", outDir}})
	if !ready {
		t.Fatalf("setup: OpenMounts(%q, %q) refused two usable temp dirs", inDir, outDir)
	}
	t.Cleanup(func() { CloseMounts(vols) })

	var probed []string
	prev := probeOutputWritable
	probeOutputWritable = func(_ context.Context, root *os.Root, _ string, _ ...atomicfile.Option) (atomicfile.ProbeResult, error) {
		probed = append(probed, root.Name())
		return atomicfile.ProbeResult{Dir: root.Name(), Name: ".atomicfile-1234567890.tmp"}, nil
	}
	t.Cleanup(func() { probeOutputWritable = prev })

	ProbeOutputMounts(vols)

	if len(probed) != 1 || probed[0] != outDir {
		t.Errorf("ProbeOutputMounts probed %q, want exactly [%q]: the input mount is read-only in production, so probing it reports /output as unwritable on every start",
			probed, outDir)
	}
}

// attrOrMissing renders an attr for a failure message, or reports it as absent.
func attrOrMissing(logs *capture.Recorder, msgSub, key string) string {
	if got, ok := logs.AttrValue(msgSub, key); ok {
		return got
	}
	return "<absent>"
}

// TestOutputWriteProbe_leaves_a_name_the_stale_temp_sweep_reclaims pins the claim
// the leaked-probe remediation makes: a probe file left in /output is reclaimable
// by the app's own stale-temp sweep (process/store.sweepStaleTemps, which runs
// atomicfile.CleanupStaleTempsInRoot).
//
// It replaces the local ".atomicfile-*.tmp" pattern main.go used to carry. That
// constant matched the sweep only because os.CreateTemp happens to substitute
// DIGITS for "*", which its documentation promises merely to be "a random string"
// — an undocumented stdlib detail the app had to rely on to re-derive a
// library-owned convention. The library now owns the name and exports the
// predicate, so the agreement is asserted here instead of assumed.
func TestOutputWriteProbe_leaves_a_name_the_stale_temp_sweep_reclaims(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	// Calls the library directly rather than through the probeOutputWritable seam:
	// the claim under test is atomicfile's naming contract, and reading a package
	// var the serial tests above swap would be a data race under t.Parallel.
	res, err := atomicfile.ProbeWritableInRoot(t.Context(), root, ".")
	if err != nil {
		t.Fatalf("the probe could not be attempted on a writable temp dir: %v", err)
	}
	if !res.OK() {
		t.Fatalf("probe on a writable temp dir: stage %v, err %v; want every stage to pass", res.Stage, res.Err)
	}
	if !atomicfile.IsPackageTemp(res.Name) {
		t.Errorf("the probe file was named %q, which the stale-temp sweep does not reclaim, so a leaked probe would be permanent and the remediation this app logs would be false",
			res.Name)
	}
	// A probe that passed every stage removed its own file: a leftover on the happy
	// path would accumulate one entry per container start.
	if _, statErr := os.Stat(filepath.Join(dir, res.Name)); statErr == nil {
		t.Errorf("the probe file %q survived a fully successful probe", res.Name)
	}
}

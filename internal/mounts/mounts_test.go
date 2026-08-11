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

// wantVolumeMissingMsg is the ERROR substring Verify must log for a mount
// that is absent or is not a directory. One copy, matched as a substring of the
// full record (main.go appends "; refusing to start").
const wantVolumeMissingMsg = "required volume is missing or not a directory"

// TestVerify pins the startup volume guard, the one decision in run()
// that decides between a single actionable refusal and an endless
// restart-unhealthy loop: every required mount must already exist AND be a
// directory, EVERY offender is named at ERROR with its role and a
// remediation, and a fully-mounted pair starts silently. Serial: it swaps
// slog.Default().
func TestVerify(t *testing.T) {
	existingDir := t.TempDir()
	regularFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(regularFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "absent")

	for _, tc := range []struct {
		name       string
		wantRole   string
		wantErrSub string
		wantRemedy string
		dirs       Paths
		want       bool
	}{
		{"both mounted", "", "", "", Paths{Input: existingDir, Output: existingDir}, true},
		{"missing input", "input", "no such file", "mount ", Paths{Input: absent, Output: existingDir}, false},
		{"missing output", "output", "no such file", "mount ", Paths{Input: existingDir, Output: absent}, false},
		{"input is a regular file", "input", "path exists but is not a directory", "point that volume's source at a directory", Paths{Input: regularFile, Output: existingDir}, false},
		{"output is a regular file", "output", "path exists but is not a directory", "point that volume's source at a directory", Paths{Input: existingDir, Output: regularFile}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			got := Verify(tc.dirs)
			if got != tc.want {
				t.Errorf("Verify(%+v) = %v, want %v", tc.dirs, got, tc.want)
			}
			if tc.want {
				if logs.Len() != 0 {
					t.Errorf("Verify(%+v) logged %v, want silence when every volume is mounted", tc.dirs, logs.Messages())
				}
				return
			}
			const msg = wantVolumeMissingMsg
			if n := logs.CountLevel(slog.LevelError, msg); n != 1 {
				t.Fatalf("Verify(%+v) logged %d ERROR records matching %q, want exactly 1 (logs %v)",
					tc.dirs, n, msg, logs.Messages())
			}
			if !logs.AttrContains(msg, "role", tc.wantRole) {
				t.Errorf("Verify(%+v) ERROR does not name role %q (logs %v)", tc.dirs, tc.wantRole, logs.Messages())
			}
			// The two causes need different REMEDIES as well as different causes: an
			// absent path is a missing mount, while a path that exists and is not a
			// directory is a mount whose SOURCE is the wrong kind of object, so repeating
			// the mount-it advice would send the operator to redo what they already did.
			if !logs.AttrContains(msg, "remediation", tc.wantRemedy) {
				t.Errorf("Verify(%+v) ERROR remediation does not name the action this cause calls for (%q) (logs %v)",
					tc.dirs, tc.wantRemedy, logs.Messages())
			}
			// The two causes need different remedies — a missing mount versus a
			// bind-mounted FILE — so the error attr must distinguish them. It
			// carried error=<nil> for the non-directory case before the
			// substitution in openMount, which is unactionable.
			if !logs.AttrContains(msg, "error", tc.wantErrSub) {
				t.Errorf("Verify(%+v) ERROR attr does not name the cause %q (logs %v)", tc.dirs, tc.wantErrSub, logs.Messages())
			}
		})
	}
}

// TestVerify_names_every_missing_volume pins the whole point of the
// all-offenders sweep: an operator who omitted the volumes block entirely has
// both mounts missing, and a report naming only /input costs a restart to
// discover /output. Serial: it swaps slog.Default().
func TestVerify_names_every_missing_volume(t *testing.T) {
	absentInput := filepath.Join(t.TempDir(), "absent-input")
	absentOutput := filepath.Join(t.TempDir(), "absent-output")

	logs := capture.Default(t)

	if ready := Verify(Paths{Input: absentInput, Output: absentOutput}); ready {
		t.Fatal("Verify(both absent) = true, want false")
	}
	const msg = wantVolumeMissingMsg
	if n := logs.CountLevel(slog.LevelError, msg); n != 2 {
		t.Fatalf("Verify(both absent) logged %d ERROR records matching %q, want 2 so one start attempt names the whole misconfiguration (logs %v)",
			n, msg, logs.Messages())
	}
	for _, role := range []string{"input", "output"} {
		if !logs.AttrContains(msg, "role", role) {
			t.Errorf("Verify(both absent) ERROR set does not name role %q (logs %v)", role, logs.Messages())
		}
	}
}

// TestVerify_refuses_a_volume_it_cannot_open pins the third refusal leg of
// the startup guard, the one whose remediation differs from the other two: a
// mount that EXISTS as a directory but cannot be opened by the running UID is a
// permissions problem on the host directory, so the operator must be told to
// grant that UID access, not to mount a path they already mounted.
// Serial (no t.Parallel): it swaps the openMountRoot package var and
// slog.Default().
func TestVerify_refuses_a_volume_it_cannot_open(t *testing.T) {
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

	ready := Verify(Paths{Input: existing, Output: blocked})

	if ready {
		t.Fatalf("Verify(%q unopenable) = true, want false: starting anyway converts nothing and restart-loops on a condition a restart cannot clear", blocked)
	}
	const msg = "required volume cannot be opened by this container's user; refusing to start"
	if n := logs.CountLevel(slog.LevelError, msg); n != 1 {
		t.Fatalf("Verify(%q unopenable) logged %d ERROR records matching %q, want exactly 1 (logs %v)",
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
	if n := logs.Count(wantVolumeMissingMsg); n != 0 {
		t.Errorf("an unopenable mount produced %d %q records, want 0: that wording tells the operator to mount a path they already mounted (logs %v)",
			n, wantVolumeMissingMsg, logs.Messages())
	}
}

// TestVerify_runs_the_output_write_probe pins the wiring the guard's collapse created:
// the write probe used to be a second call main made against the handle Open returned,
// and it is now a statement inside Verify, so no caller can observe that it still
// happens. Without this case, deleting that call leaves the suite green — the success
// row above asserts silence, which is what a Verify that never probes also produces.
// Serial (no t.Parallel): it swaps the probeOutputWritable package var and slog.Default().
func TestVerify_runs_the_output_write_probe(t *testing.T) {
	dir := t.TempDir()
	stubOutputProbe(t, atomicfile.ProbeResult{
		Dir: dir, Stage: atomicfile.ProbeStageCreate, Err: fs.ErrPermission,
	}, nil)
	logs := capture.Default(t)

	if !Verify(Paths{Input: dir, Output: dir}) {
		t.Fatalf("Verify(%q) = false, want true: no probe outcome may fail startup", dir)
	}
	if n := logs.CountLevel(slog.LevelWarn, wantOutputNotWritableMsg); n != 1 {
		t.Errorf("Verify logged %d %q WARN records, want 1: the write probe is no longer wired into the"+
			" startup guard (logs %v)", n, wantOutputNotWritableMsg, logs.Messages())
	}
}

// TestWarnOutputNotWritable_reports_failed_probe pins the startup probe's only
// output: the volume guard proves /output is a directory this UID can OPEN, so this
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

	warnOutputNotWritable(root)

	const msg = wantOutputNotWritableMsg
	if n := logs.CountLevel(slog.LevelWarn, msg); n != 1 {
		t.Fatalf("warnOutputNotWritable(%q) logged %d WARN records matching %q, want 1 (logs %v)",
			blocked, n, msg, logs.Messages())
	}
	if !logs.HasAttr(msg, "path", blocked) {
		t.Errorf("warnOutputNotWritable(%q) did not identify the unusable output path (logs %v)",
			blocked, logs.Messages())
	}
	if !logs.AttrContains(msg, "remediation", "chown the host directory") {
		t.Errorf("warnOutputNotWritable(%q) gave no ownership remediation (logs %v)",
			blocked, logs.Messages())
	}
	// The stage is what tells an operator WHICH refusal they are looking at, now
	// that the probe walks the whole create/write/flush/close/unlink ladder instead
	// of the create alone.
	if !logs.HasAttr(msg, "stage", atomicfile.ProbeStageCreate.String()) {
		t.Errorf("warnOutputNotWritable(%q) does not name the failing probe stage (logs %v)",
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
//   - No probe outcome fails startup. warnOutputNotWritable returns nothing (a
//     compile-time property of its call site in Verify), and no leg emits an ERROR
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
				"remediation": "the directory entry was accepted and the data was not, so this is not an ownership problem: " +
					"check free space and any quota on the filesystem backing " + dir,
			},
		},
		{
			name: "a refused flush is not an ownership problem",
			res: atomicfile.ProbeResult{
				Dir: dir, Name: leakedName, Stage: atomicfile.ProbeStageSync,
				Err: errors.New("disk quota exceeded"),
			},
			wantMsg:     wantOutputNotWritableMsg,
			wantWarns:   1,
			wantRecords: 1,
			wantAttrs: map[string]string{
				"stage": atomicfile.ProbeStageSync.String(),
				"remediation": "the directory entry was accepted and the data was not, so this is not an ownership problem: " +
					"check free space and any quota on the filesystem backing " + dir,
			},
			wantAbsent: "cleanup",
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

			warnOutputNotWritable(root)

			if got := logs.Len(); got != tc.wantRecords {
				t.Fatalf("warnOutputNotWritable logged %d records, want %d (logs %v)",
					got, tc.wantRecords, logs.Messages())
			}
			if got := logs.CountLevel(slog.LevelWarn, ""); got != tc.wantWarns {
				t.Errorf("warnOutputNotWritable logged %d WARN records, want %d (logs %v)",
					got, tc.wantWarns, logs.Messages())
			}
			if got := logs.CountLevel(slog.LevelError, ""); got != 0 {
				t.Errorf("warnOutputNotWritable logged %d ERROR records, want 0: a probe outcome must never read as a refusal to start (logs %v)",
					got, logs.Messages())
			}
			if tc.wantMsg != "" && logs.CountLevel(slog.LevelWarn, tc.wantMsg) != 1 {
				t.Fatalf("warnOutputNotWritable did not emit the %q WARN (logs %v)", tc.wantMsg, logs.Messages())
			}
			for key, want := range tc.wantAttrs {
				if !logs.HasAttr(tc.wantMsg, key, want) {
					t.Errorf("warnOutputNotWritable %q record: attr %q = %q, want %q (logs %v)",
						tc.wantMsg, key, attrOrMissing(logs, tc.wantMsg, key), want, logs.Messages())
				}
			}
			if tc.wantAbsent != "" {
				if got, ok := logs.AttrValue(tc.wantMsg, tc.wantAbsent); ok {
					t.Errorf("warnOutputNotWritable %q record carries attr %q = %q, want it absent",
						tc.wantMsg, tc.wantAbsent, got)
				}
			}
		})
	}
}

// attrOrMissing renders an attr for a failure message, or reports it as absent.
func attrOrMissing(logs *capture.Recorder, msgSub, key string) string {
	if got, ok := logs.AttrValue(msgSub, key); ok {
		return got
	}
	return "<absent>"
}

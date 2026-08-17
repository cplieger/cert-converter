// Package mounts verifies the container's required volumes at startup -- each one
// exists as a directory the running UID can open -- and probes the output volume
// for write access, before any scan runs.
package mounts

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/logtext"
)

// Paths is the required mount set.
type Paths struct {
	Input, Output string
}

// The role names the startup diagnostics carry.
const (
	roleInput  = "input"
	roleOutput = "output"
)

// Verify checks that every required mount already exists as a directory the
// running UID can open, and probes /output for write access through the handle it
// just proved openable.
func Verify(dirs Paths) bool {
	ready := true
	// Both volumes are inspected before any refusal, so one startup attempt
	// names every offender.
	if root, ok := openMount(roleInput, dirs.Input); ok {
		closeRoot(root, roleInput)
	} else {
		ready = false
	}
	output, ok := openMount(roleOutput, dirs.Output)
	if ok {
		// Deferred, so the refusal path below cannot leak a handle opened before the
		// offender was found.
		defer closeRoot(output, roleOutput)
	} else {
		ready = false
	}
	if !ready {
		return false
	}
	// Against the guard's OWN handle, so the probe inspects the object the guard
	// inspected instead of re-resolving the path; keeping the handle inside this
	// function is what makes that the only possible arrangement.
	warnOutputNotWritable(output)
	return true
}

// openMount inspects one required volume and returns its confined handle. The
// os.Stat decides the type BEFORE the open, and must: os.OpenRoot opens the name
// before it fstats it, so a bind-mounted FIFO here blocks in open(2) forever
// instead of failing ENOTDIR (TestVerify_refuses_a_fifo_at_a_required_mount_path).
func openMount(role, path string) (*os.Root, bool) {
	// One sanitized rendering, reused by the attribute and by the remediation that
	// names the same mount: both are log text, and a mount path holding CR/LF or a bidi
	// control must not reach either (logtext.Path).
	logPath := logtext.Path(path)
	fi, statErr := os.Stat(path)
	if statErr == nil && fi.IsDir() {
		root, openErr := openMountRoot(path)
		if openErr == nil {
			return root, true
		}
		// The access the remediation names is the access the VOLUME needs, not the
		// access this open happened to need: an operator acts on it once, and granting
		// /output read-only clears this refusal only to fail the write probe and every
		// bundle on the next start. The README's Volumes table states the same split.
		access := "read access"
		if role == roleOutput {
			access = "read and write access"
		}
		slog.Error("required volume cannot be opened by this container's user; refusing to start",
			"role", role, "path", logPath, "error", logtext.Path(openErr.Error()),
			"remediation", "grant the UID in the container's `user:` "+access+" to "+logPath+
				" (chgrp/chmod the host directory), or run the container as a UID that already has it")
		return nil, false
	}
	// The two causes take two remedies, chosen here beside the cause rather than
	// left to the operator to infer from the error text.
	remediation := "mount " + logPath + " into the container before starting it"
	if statErr == nil {
		// os.Stat succeeded, so the path exists as a file, FIFO or device: the volume
		// IS mounted and its SOURCE is the wrong kind of object, so repeating the
		// missing-mount advice tells the operator to do what they already did.
		statErr = errors.New("path exists but is not a directory")
		remediation = "something is already mounted at " + logPath +
			" and it is not a directory (a bind-mounted file, FIFO or device): point that " +
			"volume's source at a directory on the host"
	}
	slog.Error("required volume is missing or not a directory; refusing to start",
		"role", role, "path", logPath, "error", logtext.Path(statErr.Error()),
		"remediation", remediation)
	return nil, false
}

// closeRoot releases one confined handle. Called only on openMount's ok branch, which
// is the only one that yields a handle.
func closeRoot(root *os.Root, role string) {
	if err := root.Close(); err != nil {
		slog.Debug("failed to close a required volume's handle",
			"role", role, "path", logtext.Path(root.Name()), "error", logtext.Path(err.Error()))
	}
}

// probeOutputWritable is the writability probe warnOutputNotWritable runs, and a
// package-var seam in the same style as main's runProbe and requiredVolumes.
var probeOutputWritable = atomicfile.ProbeWritableInRoot

// staleTempRemediation is the operator action for a probe file left behind.
const staleTempRemediation = "the unlink that would have removed it was just refused, so the per-scan " +
	"stale-temp sweep (the same unlink through the same handle) can only reclaim it once that refusal is gone: " +
	"check that the UID in user: owns the output volume's host directory and that the mount is not read-only"

// warnOutputNotWritable probes output write access under the running UID, through
// the same confined handle the volume guard already proved openable.
func warnOutputNotWritable(root *os.Root) {
	// context.Background rather than a cancellable context: the probe checks ctx
	// once before it creates anything, and its stages are single filesystem calls
	// the OS does not make interruptible, so a context could not shorten a wedged
	// mount. Startup has no context of its own until main's signal handler.
	res, err := probeOutputWritable(context.Background(), root, ".")
	switch {
	case err != nil:
		// A non-nil error means only "the probe was not attempted", which for the
		// fixed arguments above is a programming error rather than an operator
		// condition.
		slog.Debug("the output write probe could not be attempted",
			"role", roleOutput, "path", logtext.Path(root.Name()), "error", logtext.Path(err.Error()))
	case res.OK():
		// Deliberately silent: /output being usable is the expected case, and main's
		// startup line already states the path and the UID.
	case !res.Writable():
		warnOutputRefusedWrite(res)
	default:
		warnOutputProbeTeardown(res)
	}
}

// outputNotWritableMsg is the WARN an operator acts on when /output refused the
// probe's write.
const outputNotWritableMsg = "the output volume is not writable by the running UID, so no PFX can be produced; " +
	"a scan whose bundles are all current still reports healthy, so this would otherwise " +
	"surface only at the next renewal"

// warnOutputRefusedWrite reports a volume that never durably accepted the probe's
// bytes: the create, the first write or the flush failed, so no PFX can be written
// either.
func warnOutputRefusedWrite(res atomicfile.ProbeResult) {
	// One sanitized rendering of the probed volume, reused by the remediation and by both
	// records' path attribute: the remediation is log text like any attribute (logtext.Path).
	logRoot := logtext.Path(res.Dir)
	// Same root cause as internal/process's outputPermRemediation (store.go), stated
	// as the startup action: at this point nothing has been written yet, so the
	// operator is pointed at the host directory rather than at a bundle.
	remediation := "chown the host directory mounted at " + logRoot +
		" to the UID in user: (and check the mount is not read-only)"
	// A create refusal is an ownership/read-only/missing-mount condition, which the
	// chown advice above fits.
	if res.Stage == atomicfile.ProbeStageWrite || res.Stage == atomicfile.ProbeStageSync {
		remediation = "the directory entry was accepted and the data was not, so this is not an ownership problem: " +
			"check free space and any quota on the filesystem backing " + logRoot
	}
	if res.Leaked {
		// Reachable when the write or the flush failed AND the follow-up unlink failed
		// too: the volume is unusable and is still holding the probe file.
		slog.Warn(outputNotWritableMsg,
			"role", roleOutput, "path", logRoot, "stage", res.Stage.String(), "error", logtext.Path(res.Err.Error()),
			"uid", os.Getuid(), "gid", os.Getgid(), "remediation", remediation,
			"leaked_probe", logtext.Path(probePath(res)), "cleanup", staleTempRemediation)
		return
	}
	slog.Warn(outputNotWritableMsg,
		"role", roleOutput, "path", logRoot, "stage", res.Stage.String(), "error", logtext.Path(res.Err.Error()),
		"uid", os.Getuid(), "gid", os.Getgid(), "remediation", remediation)
}

// warnOutputProbeTeardown reports a probe whose data reached disk and whose
// teardown did not.
func warnOutputProbeTeardown(res atomicfile.ProbeResult) {
	msg := "failed to remove the output write probe"
	if res.Stage == atomicfile.ProbeStageClose {
		msg = "failed to close the output write probe"
	}
	if res.Leaked {
		slog.Warn(msg, "path", logtext.Path(probePath(res)), "stage", res.Stage.String(),
			"error", logtext.Path(res.Err.Error()),
			"remediation", staleTempRemediation)
		return
	}
	slog.Warn(msg, "path", logtext.Path(probePath(res)), "stage", res.Stage.String(),
		"error", logtext.Path(res.Err.Error()))
}

// probePath is the probe file's full path for a diagnostic, joined from the directory the
// probe reported probing and the name it left there.
func probePath(res atomicfile.ProbeResult) string {
	return filepath.Join(res.Dir, res.Name)
}

// openMountRoot opens a required mount's confined handle.
var openMountRoot = os.OpenRoot

// Package mounts verifies the container's required volumes at startup -- each one
// exists as a directory the running UID can open -- and probes the output volume
// for write access, before any scan runs. It is startup-only: the handles it opens
// are released by Roots.Close, and internal/process opens its own roots per scan.
package mounts

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cplieger/atomicfile/v2"
)

// Paths is the required mount set. This product mounts exactly two volumes, so
// they are named FIELDS rather than a list keyed by a free-form role string: the
// compiler then holds the contract, and the output volume can no longer be
// renamed out of the write probe's reach by a role literal that still compiles.
type Paths struct {
	Input, Output string
}

// The role names the startup diagnostics carry. Unexported because nothing
// SELECTS a mount by role any more -- a role is a log attribute and nothing else,
// so a renamed literal can no longer stop a check from running.
const (
	roleInput  = "input"
	roleOutput = "output"
)

// Roots holds the confined handles Open opened to prove each required mount
// usable. The handle is what any FURTHER check on that mount runs against, so the
// check inspects the same object the guard inspected instead of re-resolving the
// path and testing whatever it resolves to the second time. The caller owns them
// and releases the set with Close.
type Roots struct {
	Input, Output *os.Root
}

// mountSpec is one required volume's inspection: the role its diagnostics carry,
// the path to inspect, and where its handle lands on success. The table stays
// private so the all-offender sweep is an implementation detail of Open rather
// than a shape a caller can build a third role in.
type mountSpec struct {
	assign func(*os.Root)
	role   string
	path   string
}

// Open verifies every required mount already exists as a directory and can be
// opened by the running UID. It reports every offender in one startup attempt and
// never creates a missing mount in the container's ephemeral layer. Output write
// access is checked separately by WarnOutputNotWritable, which runs against the
// handles returned here.
//
// On success it returns both roots open. On refusal it closes everything it
// opened and returns no handles, so a caller that ignores the returned value on
// the failure path cannot leak one.
func Open(dirs Paths) (Roots, bool) {
	var open Roots
	ready := true
	for _, spec := range []mountSpec{
		{role: roleInput, path: dirs.Input, assign: func(root *os.Root) { open.Input = root }},
		{role: roleOutput, path: dirs.Output, assign: func(root *os.Root) { open.Output = root }},
	} {
		root, ok := openMount(spec)
		if !ok {
			ready = false
			continue
		}
		spec.assign(root)
	}
	if !ready {
		open.Close()
		return Roots{}, false
	}
	return open, true
}

// openMount inspects one required volume and returns its confined handle. On
// refusal it has already logged that offender at ERROR with the remediation its
// cause calls for, so Open can carry on and name the rest of them.
func openMount(spec mountSpec) (*os.Root, bool) {
	fi, statErr := os.Stat(spec.path)
	if statErr == nil && fi.IsDir() {
		root, openErr := openMountRoot(spec.path)
		if openErr == nil {
			return root, true
		}
		slog.Error("required volume cannot be opened by this container's user; refusing to start",
			"role", spec.role, "path", spec.path, "error", openErr,
			"remediation", "grant the UID in the container's `user:` read access to "+spec.path+
				" (chgrp/chmod the host directory), or run the container as a UID that already has it")
		return nil, false
	}
	if statErr == nil {
		// os.Stat succeeded, so the path exists as a file, FIFO or device. The
		// synthesised cause is what separates the two remedies: an absent path is a
		// missing mount, a non-directory is a bind-mounted FILE.
		statErr = errors.New("path exists but is not a directory")
	}
	slog.Error("required volume is missing or not a directory; refusing to start",
		"role", spec.role, "path", spec.path, "error", statErr,
		"remediation", "mount "+spec.path+" into the container before starting it")
	return nil, false
}

// Close releases the confined handles Open returned. It tolerates a zero Roots,
// so the refusal path can defer it unconditionally. A close failure on a handle
// the process is finished with gives an operator nothing to act on, so it goes to
// Debug rather than a WARN they would have to triage.
func (r Roots) Close() {
	for _, vol := range []struct {
		root *os.Root
		role string
	}{{r.Input, roleInput}, {r.Output, roleOutput}} {
		if vol.root == nil {
			continue
		}
		if err := vol.root.Close(); err != nil {
			slog.Debug("failed to close a required volume's handle",
				"role", vol.role, "path", vol.root.Name(), "error", err)
		}
	}
}

// probeOutputWritable is the writability probe WarnOutputNotWritable runs, and a
// package-var seam in the same style as main's runProbe and requiredVolumes. It
// exists because atomicfile reports a stage failure in its ProbeResult rather than
// as an error, and most of those stages cannot be staged on a temp directory: a
// volume that accepts a create and refuses the unlink, or one whose write error
// surfaces only at close, is exactly the misconfiguration this WARN set exists for
// and exactly what a test cannot produce for real.
var probeOutputWritable = atomicfile.ProbeWritableInRoot

// staleTempRemediation is the operator action for a probe file left behind. It
// holds because the probe file carries atomicfile's OWN temp-name shape, so the
// app's per-scan /output stale-temp sweep (internal/process's
// store.sweepStaleTemps, which runs atomicfile.CleanupStaleTempsInRoot) reclaims it
// by construction — this file no longer re-derives that name shape, which it
// previously did by relying on os.CreateTemp happening to substitute digits for "*".
//
// Keyed on ProbeResult.Leaked at every site that can leave one, so the sentence is
// never printed for a probe the volume did remove.
const staleTempRemediation = "the unlink that would have removed it was just refused, so the per-scan " +
	"stale-temp sweep (the same unlink through the same handle) can only reclaim it once that refusal is gone: " +
	"check that the UID in user: owns the output volume's host directory and that the mount is not read-only"

// WarnOutputNotWritable probes output write access under the running UID, through
// the same confined handle the volume guard already proved openable. It warns
// rather than refusing startup because host ownership can be repaired while the
// process runs; later scans retain their normal health semantics. No probe outcome
// can fail startup: this function returns nothing and every leg is a log record.
//
// The probe is atomicfile's, which walks the whole ladder a real bundle write
// walks (create, write, flush, close, unlink) and reports the first stage that
// failed. That is what keeps the two operator conditions apart: a volume that
// refused the write outright is a permissions problem on the mount, while one that
// accepted and flushed the bytes and then failed teardown will write bundles
// fine and has only left a file behind.
func WarnOutputNotWritable(root *os.Root) {
	// context.Background rather than a cancellable context: the probe checks ctx
	// once before it creates anything, and its stages are single filesystem calls
	// the OS does not make interruptible, so a context could not shorten a wedged
	// mount. Startup has no context of its own until main's signal handler.
	res, err := probeOutputWritable(context.Background(), root, ".")
	switch {
	case err != nil:
		// A non-nil error means only "the probe was not attempted", which for the
		// fixed arguments above is a programming error rather than an operator
		// condition. Nothing is known about /output either way, so this must NOT
		// print the not-writable diagnosis an operator would act on.
		slog.Debug("the output write probe could not be attempted",
			"role", roleOutput, "path", root.Name(), "error", err)
	case res.OK():
		// Deliberately silent: /output being usable is the expected case, and main's
		// startup line already states the path and the UID. A record here would print
		// on every container start and dilute the three warnings below.
	case !res.Writable():
		warnOutputRefusedWrite(root, res)
	default:
		warnOutputProbeTeardown(res)
	}
}

// outputNotWritableMsg is the WARN an operator acts on when /output refused the
// probe's write. Named because two legs below emit it, so the two records an
// operator's log query has to match cannot drift apart. No README alert rule keys
// on it today; it is a startup record, and the README's alerting section covers
// per-scan conditions only.
const outputNotWritableMsg = "the output volume is not writable by the running UID, so no PFX can be produced; " +
	"a scan whose bundles are all current still reports healthy, so this would otherwise " +
	"surface only at the next renewal"

// warnOutputRefusedWrite reports a volume that never durably accepted the probe's
// bytes: the create, the first write or the flush failed, so no PFX can be written
// either. Wording, level and remediation are unchanged from the hand-rolled probe;
// the stage name is added because the library distinguishes conditions a create-only
// probe could not see (a quota, a network filesystem's deferred error).
//
// The two legs spell their attrs out instead of sharing a built slice: every other
// diagnostic in this file is an inline slog call, and goconst counts a key repeated
// inside a composite literal while ignoring one passed as a call argument.
func warnOutputRefusedWrite(root *os.Root, res atomicfile.ProbeResult) {
	// Same root cause as internal/process's outputPermRemediation (store.go), stated
	// as the startup action: at this point nothing has been written yet, so the
	// operator is pointed at the host directory rather than at a bundle.
	remediation := "chown the host directory mounted at " + root.Name() +
		" to the UID in user: (and check the mount is not read-only)"
	// A create refusal is an ownership/read-only/missing-mount condition, which the
	// chown advice above fits. A write or sync refusal is not: the directory entry was
	// accepted, so the UID can write the directory and the DATA was refused - the
	// causes atomicfile documents for these two stages are a quota, a full filesystem,
	// or a network mount's deferred error. Sending that operator to chown a directory
	// whose ownership is already correct costs them the whole diagnosis.
	if res.Stage == atomicfile.ProbeStageWrite || res.Stage == atomicfile.ProbeStageSync {
		remediation = "the directory entry was accepted and the data was not, so this is not an ownership problem: " +
			"check free space and any quota on the filesystem backing " + root.Name()
	}
	if res.Leaked {
		// Reachable when the write or the flush failed AND the follow-up unlink failed
		// too: the volume is unusable and is still holding the probe file.
		slog.Warn(outputNotWritableMsg,
			"role", roleOutput, "path", res.Dir, "stage", res.Stage.String(), "error", res.Err,
			"uid", os.Getuid(), "gid", os.Getgid(), "remediation", remediation,
			"leaked_probe", probePath(res), "cleanup", staleTempRemediation)
		return
	}
	slog.Warn(outputNotWritableMsg,
		"role", roleOutput, "path", res.Dir, "stage", res.Stage.String(), "error", res.Err,
		"uid", os.Getuid(), "gid", os.Getgid(), "remediation", remediation)
}

// warnOutputProbeTeardown reports a probe whose data reached disk and whose
// teardown did not. The two messages are the two the hand-rolled probe emitted,
// kept distinct because they are different operator conditions: a close failure is
// a deferred write error on a volume that will still be written to, while a refused
// unlink means the volume denies cleanup and the probe file is still there.
// atomicfile reports only the FIRST failure (a secondary teardown failure goes to
// its logger at Debug), so a volume that fails both emits the close record alone
// rather than the two the hand-rolled probe could produce.
func warnOutputProbeTeardown(res atomicfile.ProbeResult) {
	msg := "failed to remove the output write probe"
	if res.Stage == atomicfile.ProbeStageClose {
		msg = "failed to close the output write probe"
	}
	if res.Leaked {
		slog.Warn(msg, "path", probePath(res), "stage", res.Stage.String(), "error", res.Err,
			"remediation", staleTempRemediation)
		return
	}
	slog.Warn(msg, "path", probePath(res), "stage", res.Stage.String(), "error", res.Err)
}

// probePath is the probe file's full path for a diagnostic, as the hand-rolled
// probe's os.File.Name() reported it. ProbeResult carries the directory and the
// base name separately; Name is "" when the probe never created the file, and
// filepath.Join then reports the directory alone rather than a bogus path.
func probePath(res atomicfile.ProbeResult) string {
	return filepath.Join(res.Dir, res.Name)
}

// openMountRoot opens a required mount's confined handle. It is a seam in the
// same style as probeOutputWritable and main's requiredVolumes: a mount that
// exists as a directory but cannot be OPENED by the running UID is a startup
// refusal with its own remediation, and no suite that may run as uid 0 can
// produce that refusal for real.
var openMountRoot = os.OpenRoot

// Package main watches a PEM certificate directory and converts changed certificates to PFX/PKCS#12 on every renewal.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cplieger/cert-converter/internal/config"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/watch"
	"github.com/cplieger/health"
	"github.com/cplieger/slogx"
)

// Fixed container paths — configured via volume mounts, not env vars.
const (
	certsRootDir = "/input"
	outputDir    = "/output"
)

// watchDebounce is the debounce window for the watcher.
const watchDebounce = 2 * time.Second

// healthyAfterScan reports whether a completed scan should keep the container
// healthy. Only conversion failures clear health; input coverage gaps and
// refused mode-only output repairs are permissions/layout conditions a restart
// cannot fix. The pointer avoids copying ScanResult and is never mutated.
func healthyAfterScan(r *process.ScanResult) bool {
	return r.Failed == 0
}

// scanAndSetHealth runs one scan and updates the marker. Shutdown cancellation
// leaves the prior marker untouched; any other scan error clears it. Scanner
// owns input-coverage diagnostics; this composition root logs terminal errors.
func scanAndSetHealth(ctx context.Context, scanner *process.Scanner, marker *health.Marker) {
	result, err := scanner.Run(ctx)
	if err != nil {
		if process.IsShutdown(err) {
			slog.Info("scan interrupted by shutdown", "reason", err)
			return
		}
		slog.Error("processing failed", "error", err)
		marker.Set(false)
		return
	}
	marker.Set(healthyAfterScan(&result))
}

// --- Entrypoint ---

// volumeDir is a required mount point and the role it plays in the startup log.
type volumeDir struct {
	role, path string
}

// volumesReady verifies every required mount already exists as a directory and
// can be opened by the running UID. It reports every offender in one startup
// attempt and never creates a missing mount in the container's ephemeral layer.
// Output write access is checked separately by warnOutputNotWritable.
func volumesReady(dirs []volumeDir) bool {
	ready := true
	for _, dir := range dirs {
		fi, statErr := os.Stat(dir.path)
		if statErr == nil && fi.IsDir() {
			root, openErr := os.OpenRoot(dir.path)
			if openErr == nil {
				_ = root.Close()
				continue
			}
			slog.Error("required volume cannot be opened by this container's user; refusing to start",
				"role", dir.role, "path", dir.path, "error", openErr,
				"remediation", "grant the UID in the container's `user:` read access to "+dir.path+
					" (chgrp/chmod the host directory), or run the container as a UID that already has it")
			ready = false
			continue
		}
		if statErr == nil {
			// os.Stat succeeded, so the path exists as a file, FIFO or device. The
			// synthesised cause is what separates the two remedies: an absent path is a
			// missing mount, a non-directory is a bind-mounted FILE.
			statErr = errors.New("path exists but is not a directory")
		}
		slog.Error("required volume is missing or not a directory; refusing to start",
			"role", dir.role, "path", dir.path, "error", statErr,
			"remediation", "mount "+dir.path+" into the container before starting it")
		ready = false
	}
	return ready
}

// outputWriteProbePattern matches atomicfile's temp-name convention so a probe
// orphaned by a crash is eligible for the normal stale-temp sweep.
const outputWriteProbePattern = ".atomicfile-*.tmp"

// warnOutputNotWritable probes output write access under the running UID. It
// warns rather than refusing startup because host ownership can be repaired
// while the process runs; later scans retain their normal health semantics.
func warnOutputNotWritable(dir string) {
	f, err := os.CreateTemp(dir, outputWriteProbePattern)
	if err != nil {
		slog.Warn("the output volume is not writable by the running UID, so no PFX can be produced; "+
			"a scan whose bundles are all current still reports healthy, so this would otherwise "+
			"surface only at the next renewal",
			"role", "output", "path", dir, "error", err,
			"uid", os.Getuid(), "gid", os.Getgid(),
			"remediation", "chown the host directory mounted at "+dir+
				" to the UID in user: (and check the mount is not read-only)")
		return
	}
	name := f.Name()
	if closeErr := f.Close(); closeErr != nil {
		slog.Warn("failed to close the output write probe", "path", name, "error", closeErr)
	}
	if rmErr := os.Remove(name); rmErr != nil {
		slog.Warn("failed to remove the output write probe", "path", name, "error", rmErr,
			"remediation", "the stale-temp sweep reclaims it on a later scan; no action is required unless it persists")
	}
}

// runProbe is a seam: health.RunProbe exits the process, so tests replace it.
var runProbe = health.RunProbe

// requiredVolumes is the mount set run() refuses to start without, and the
// second seam in the same style as runProbe: the production value is the two
// fixed container paths, and tests point it at temp directories so the refusal
// itself can be exercised without a /input and /output on the test host.
var requiredVolumes = []volumeDir{{"input", certsRootDir}, {"output", outputDir}}

const healthSubcommand = "health"

// dispatchArgs runs the health probe when argv requests it and REJECTS an
// unrecognized argument. It returns the process exit code, or
// continueToWatcher when argv asks for the watcher. Returning rather than
// calling os.Exit keeps the decision testable and keeps every exit on one path
// through run().
func dispatchArgs(args []string) int {
	if len(args) <= 1 {
		return continueToWatcher
	}
	switch {
	case len(args) == 2 && args[1] == healthSubcommand:
		// The fallback rescan is the marker's guaranteed refresh floor
		// (fs events refresh it sooner), so a marker older than 3 fallback
		// intervals means the watch loop is wedged and a restart fixes it.
		// FALLBACK_SCAN_HOURS=0/false disables the fallback and with it
		// the deadline (WithMaxAge(0) is a no-op): watch-only mode has no
		// guaranteed refresh cadence to hold the marker to.
		// config.FallbackInterval is deliberately silent — a misconfigured or
		// above-ceiling value is diagnosed once at startup by config.Load, not
		// here, where Docker's healthcheck would reprint it every 30s forever.
		// RunProbe exits the process, so this never falls through to the
		// watcher below.
		runProbe(health.DefaultPath,
			health.WithMaxAge(3*config.FallbackInterval()))
		return continueToWatcher // unreachable in production; runProbe exits
	default:
		// Refuse rather than fall through: falling through reaches
		// marker.Set(false) in run(), which UNLINKS the resident watcher's health
		// marker, and then starts a second watcher over the same /input and /output.
		// The ENTRYPOINT takes no arguments, so a mistyped HEALTHCHECK override
		// (`healthz`, `--health`) or a stray `docker exec ... status` is a mistake,
		// and a usage error is the honest response.
		if args[1] != healthSubcommand {
			// Names the unrecognized token even when extra operands follow it: the
			// token IS the mistake, and reporting only the operands hides it.
			fmt.Fprintf(os.Stderr, "cert-watcher: unrecognized argument %q\n", args[1])
		} else {
			fmt.Fprintf(os.Stderr, "cert-watcher: unexpected trailing arguments %q\n", args[2:])
		}
		fmt.Fprintln(os.Stderr, "usage: cert-watcher            start the watcher (no arguments)")
		fmt.Fprintln(os.Stderr, "       cert-watcher health     probe the health marker")
		return exitUsage
	}
}

// dispatchArgs sentinels. continueToWatcher is deliberately negative so it can
// never collide with a real exit code.
const (
	continueToWatcher = -1
	exitUsage         = 2
)

func main() {
	os.Exit(run())
}

// run is the real entrypoint: it returns the process exit code instead of
// calling os.Exit itself, so every deferred cleanup registered below (the
// signal-context stop, the health-marker removal) actually runs on the failure
// paths too.
func run() int {
	slogx.Setup(slogx.Options{Level: config.LogLevel()})

	if code := dispatchArgs(os.Args); code != continueToWatcher {
		return code
	}

	// Diagnosed only on the watcher path, below the argv dispatch: the health
	// subcommand re-reads LOG_LEVEL on every probe (roughly every 30s under the
	// image's HEALTHCHECK), so warning before dispatchArgs turned a
	// once-per-process-start startup line into one on every healthcheck. The
	// wording lives in config, which owns the variable; config.FallbackInterval
	// is silent for the same reason and config.Load owns that setting's WARNs.
	config.WarnInvalidLogLevel()

	// Clear any marker left by a previous run BEFORE the first failure exit:
	// /tmp/.healthy lives in the container's writable layer and survives a
	// restart, so an early return here would leave a stale healthy marker for a
	// process that never validated its configuration. The health subcommand has
	// already exited by this point, so the probe is unaffected.
	marker := health.NewMarker(health.DefaultPath)
	marker.Set(false)
	defer marker.Cleanup()

	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		return 1
	}

	slog.Info("starting cert watcher",
		"input", certsRootDir, "output", outputDir,
		// The whole mount contract is "readable/writable by the UID in user:",
		// and every downstream permission WARN points at that UID without ever
		// naming it. compose resolves it from ${PUID:-1000}, so the compose file
		// may not name it either; the process is the only thing that knows.
		"uid", os.Getuid(), "gid", os.Getgid(),
		"password", string(cfg.PasswordStatus),
		"fallback_scan", watch.FallbackLabel(cfg.FallbackInterval), "encoder", cfg.EncoderName,
		"output_lifecycle", string(cfg.Lifecycle))

	if !volumesReady(requiredVolumes) {
		return 1
	}
	// Same seam as the guard above, deliberately not the outputDir const: a test that
	// substitutes requiredVolumes and lets the guard pass must not have the write probe
	// fall through to the real /output.
	for _, dir := range requiredVolumes {
		if dir.role == "output" {
			warnOutputNotWritable(dir.path)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanner := process.New(&process.Options{
		CertsRoot: certsRootDir,
		OutRoot:   outputDir,
		Password:  cfg.Password,
		Encoder:   cfg.EncoderName,
		Lifecycle: cfg.Lifecycle,
	})

	// runAndSetHealth adapts scanAndSetHealth to the watcher's on-change
	// callback signature.
	runAndSetHealth := func(ctx context.Context) {
		scanAndSetHealth(ctx, scanner, marker)
	}

	// No scan here: w.Run owns the first scan in both modes. In fsnotify mode it
	// must run AFTER the watch set is attached so an event landing during the scan
	// is not missed — a sequencing constraint main cannot honour from outside, and
	// a scan here would double every start's /input scans and marker writes.
	w := watch.New(certsRootDir, runAndSetHealth,
		watch.WithDebounce(watchDebounce),
		watch.WithFallback(cfg.FallbackInterval))
	return reportWatchExit(ctx, w.Run(ctx))
}

// reportWatchExit turns the watcher's single exit into the process's exit code,
// and is the SINGLE place the app announces that change detection is dead.
//
// That announcement is main's to make because main is what ACTS on the
// condition: it exits non-zero so the orchestrator restarts the container.
// internal/watch returns the condition (a *watch.LostError naming which loss
// occurred, plus the operator action where one exists) and logs nothing about
// it, so the wording cannot drift across the package boundary — the
// CertConverterChangeDetectionDead alert matches the message below and nothing
// else. Exactly one ERROR record per dead-detection event.
//
// A nil error is a shutdown: it reports the cause at Info and exits 0, and must
// never mention dead change detection, or a SIGTERM would fire that critical
// alert.
func reportWatchExit(ctx context.Context, runErr error) int {
	if runErr == nil {
		slog.Info("shutting down", "reason", context.Cause(ctx))
		return 0
	}
	// Run reported that change detection ended for a reason other than
	// shutdown: the fsnotify watch is gone and only a restart can recover it.
	// Exit non-zero so restart: on-failure deployments restart too; the
	// deferred marker.Cleanup drops the marker on the way out, so a probe
	// cannot report healthy after this point.
	attrs := []any{"error", runErr}
	var lost *watch.LostError
	if errors.As(runErr, &lost) && lost.Remediation != "" {
		attrs = append(attrs, "remediation", lost.Remediation)
	}
	slog.Error("watcher stopped without a shutdown signal; "+
		"change detection is dead, exiting for a restart", attrs...)
	return 1
}

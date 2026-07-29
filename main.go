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
// healthy. Health answers one operational question — "should an orchestrator
// restart this container?" — so it is driven solely by conversion failures,
// the only outcome a restart could plausibly clear (a transient mount glitch,
// a half-written renewal). Unreadable /input sub-paths are deliberately NOT a
// health input: they are a steady-state permissions/UID misconfiguration or a
// layout mistake that a restart cannot fix, so internal/process surfaces them
// as a once-per-scan WARN (logInputCoverageWarnings, which owns every
// default-level /input-coverage diagnostic) rather than flapping the container
// unhealthy in a restart loop. The same
// reasoning covers ScanResult.Unwritable, the /output-side member of that
// family: a prior bundle whose mode repair AND whose repairing rewrite were
// both refused for a permission reason already holds the right bytes, and no
// restart grants the UID ownership of the volume, so it carries its own
// standing WARN and leaves health alone — while every other failed PFX write is
// still a conversion failure that clears the marker. It is the
// single source of truth for the health boundary so the gate can be
// unit-tested without reimplementing it. The pointer parameter is gocritic's
// hugeParam threshold, not a mutation: the result is read, never modified.
func healthyAfterScan(r *process.ScanResult) bool {
	return r.Failed == 0
}

// scanAndSetHealth runs one scan with the scanner's configured input and output
// roots and flips the health marker via healthyAfterScan (zero conversion
// failures). A shutdown cancellation leaves the marker untouched; any other
// scan error clears it. It renders no /input-coverage diagnostic of its own:
// internal/process owns that whole taxonomy and every default-level warning derived
// from it (including the unreadable-paths aggregate). What it does own is the
// scan-level outcome at the composition root — one Info naming a shutdown, one ERROR
// for a scan that failed for any other reason — because only main knows the failure is
// also a health transition, and internal/process reports the same event at Warn
// ("scan aborted before completion", the message the README's CertConverterScanAborted
// rule matches) without knowing that. Add no further records here: the
// one-record-per-event discipline reportWatchExit documents holds for this boundary
// too.
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

// volumesReady reports whether every required volume is already mounted as a
// directory the running UID can open, logging EVERY offender at ERROR with its
// role, path and remediation: an operator who omitted the volumes block
// entirely has both mounts missing, and naming only the first costs a restart
// per mount to discover the next one.
//
// Both volumes must already exist; nothing in this app creates them. Refusing
// once at startup with a named path is the actionable form of a missing mount:
// a restart cannot create a directory, so the health marker — reserved for
// failures a restart could clear — must never carry this one.
// A mount that exists but cannot be OPENED by the running UID is the same fact
// one step later: the scanner opens both roots on every scan and a refusal
// there is a hard scan error, so leaving it to the scan reproduces exactly the
// restart loop this function exists to prevent for a condition (host-side
// ownership, mode 0700 — the README's own named first-run mistake) that no
// restart can clear either. Openability, not writability: an /output that opens
// but refuses a write is the deliberately health-neutral case
// warnOutputNotWritable reports and process.ScanResult.Unwritable carries, and
// refusing to start on it would contradict that design.
//
// Deliberately NOT MkdirAll: silently creating a missing mount point would put
// certificates in the container's ephemeral layer, where they vanish on the
// next restart, which is worse than refusing to start. A path that exists but
// is not a directory (a file bind-mounted over /input, a stray touch) is the
// same fact and is refused the same way.
func volumesReady(dirs []volumeDir) bool {
	ready := true
	for _, dir := range dirs {
		fi, statErr := os.Stat(dir.path)
		if statErr == nil && fi.IsDir() {
			// The scanner opens BOTH roots with os.OpenRoot on every scan and treats a
			// failure as a hard scan error, so a mount the running UID cannot open
			// otherwise surfaces only as an unhealthy container on every tick — the
			// restart loop this preflight exists to prevent, for a condition no
			// restart can clear. Probing with the same call the scanner uses is what
			// keeps the two verdicts from disagreeing.
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

// outputWriteProbePattern reuses atomicfile's own temp-name shape
// (".atomicfile-<digits>.tmp", which os.CreateTemp produces from this pattern) so a
// probe leaked by a crash in the create/remove window is reclaimed by the per-scan
// stale-temp sweep instead of sitting in the operator's output tree forever (the
// orphan reaper only ever matches this app's .pfx output shape).
const outputWriteProbePattern = ".atomicfile-*.tmp"

// warnOutputNotWritable probes /output for write access under the running UID and
// warns once at startup when it is refused. volumesReady proves only that the mount
// is a directory: a directory this UID can read but not write in (a host path still
// owned by root, a user: changed to a different PUID after the first run, an
// accidental :ro on the output mount) passes that check, and a scan whose bundles are
// all current writes nothing, so the deployment reports HEALTHY and the
// misconfiguration surfaces only at the next renewal — weeks away for the
// set-and-forget deployment this app is built for, and exactly when a fresh bundle is
// needed.
//
// Deliberately a WARN, not a refusal: /output ownership can be repaired on the host
// while the container runs and the next scan picks it up with no restart, so refusing
// to start would remove that recovery. It is also why the probe does not touch health:
// a write refusal a restart cannot clear is health-neutral here for the same reason
// ScanResult.Unwritable is.
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
	warnOutputNotWritable(outputDir)

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

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

// runProbe is a seam: health.RunProbe exits the process, so tests replace it.
var runProbe = health.RunProbe

// requiredVolumes is the mount set run() refuses to start without, and the
// second seam in the same style as runProbe: the production value is the two
// fixed container paths, and tests point it at temp directories so the refusal
// itself can be exercised without a /input and /output on the test host.
var requiredVolumes = []process.Mount{
	{Role: process.RoleInput, Path: certsRootDir},
	{Role: process.RoleOutput, Path: outputDir},
}

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
		"output_lifecycle", string(cfg.Lifecycle), "max_scan_entries", cfg.MaxScanEntries)

	volumes, ready := process.OpenMounts(requiredVolumes)
	// The handles come back OPEN so the write probe below inspects the same object
	// this guard proved openable instead of re-resolving /output. Deferred rather
	// than closed after the probe so a later return cannot skip it; OpenMounts
	// returns none on the refusal path, where CloseMounts is a no-op.
	defer process.CloseMounts(volumes)
	if !ready {
		return 1
	}
	// Same seam as the guard above, deliberately not the outputDir const: a test that
	// substitutes requiredVolumes and lets the guard pass must not have the write probe
	// fall through to the real /output.
	process.ProbeOutputMounts(volumes)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanner := process.New(&process.Options{
		CertsRoot: certsRootDir,
		OutRoot:   outputDir,
		Password:  cfg.Password,
		Encoder:   cfg.EncoderName,
		Lifecycle: cfg.Lifecycle,
		// internal/config owns MAX_SCAN_ENTRIES' name, default, ceiling and every
		// diagnostic for a repaired value; internal/process takes the budget as
		// injected state and deliberately does not import internal/config, so this
		// composition root is the only place the two meet.
		MaxScanEntries: cfg.MaxScanEntries,
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
		watch.WithFallback(cfg.FallbackInterval),
		// Same MAX_SCAN_ENTRIES budget the scanner gets: both walks cross the same
		// /input tree, and watches for directories the scan will never reach can
		// produce no conversion.
		watch.WithMaxEntries(cfg.MaxScanEntries))
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

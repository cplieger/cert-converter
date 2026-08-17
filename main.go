// Package main watches a PEM certificate directory and converts changed certificates to PFX/PKCS#12 on every renewal.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/cplieger/cert-converter/internal/config"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/mounts"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/scancadence"
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
// healthy.
func healthyAfterScan(r *process.ScanResult) bool {
	return r.Failed == 0
}

// scanAndSetHealth runs one scan and updates the marker.
func scanAndSetHealth(ctx context.Context, scanner *process.Scanner, marker *health.Marker) {
	result, err := scanner.Run(ctx)
	if err != nil {
		if process.IsShutdown(err) {
			slog.Info("scan interrupted by shutdown", "reason", err)
			return
		}
		slog.Error("processing failed", "error", logtext.Path(err.Error()))
		marker.Set(false)
		return
	}
	marker.Set(healthyAfterScan(&result))
}

// --- Entrypoint ---

// runProbe is a seam: health.RunProbe exits the process, so tests replace it.
var runProbe = health.RunProbe

// requiredVolumes is the ONE statement of this container's mount set: the paths
// the startup guard proves openable, and the same paths the scanner, the watcher
// and the startup line then use.
var requiredVolumes = mounts.Paths{
	Input:  certsRootDir,
	Output: outputDir,
}

const healthSubcommand = "health"

// dispatchArgs runs the health probe when argv requests it and REJECTS an
// unrecognized argument.
func dispatchArgs(args []string) int {
	if len(args) <= 1 {
		return continueToWatcher
	}
	switch {
	case len(args) == 2 && args[1] == healthSubcommand:
		// The periodic safety-net scan is the marker's guaranteed refresh floor
		// (fs events refresh it sooner), so a marker older than 3 of those
		// intervals means the watch loop is wedged and a restart fixes it.
		runProbe(health.DefaultPath,
			health.WithMaxAge(3*scancadence.Effective(config.FallbackInterval())))
		return continueToWatcher // unreachable in production; runProbe exits
	default:
		// Refuse rather than fall through: falling through reaches
		// marker.Set(false) in run(), which UNLINKS the resident watcher's health
		// marker, and then starts a second watcher over the same /input and /output.
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

// dispatchArgs sentinels.
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
	// once-per-process-start startup line into one on every healthcheck.
	config.WarnInvalidLogLevel()

	// Clear any marker left by a previous run BEFORE the first failure exit:
	// /tmp/.healthy lives in the container's writable layer and survives a
	// restart, so an early return here would leave a stale healthy marker for a
	// process that never validated its configuration.
	marker := health.NewMarker(health.DefaultPath)
	marker.Set(false)
	defer marker.Cleanup()

	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", logtext.Path(err.Error()))
		return 1
	}

	slog.Info("starting cert watcher", slices.Concat(
		[]any{
			// Through the same log-boundary gate every other path attribute in this app
			// uses, so the rule has no exception to remember: one helper for every
			// filesystem-derived attribute, wherever the value came from.
			"input", logtext.Path(requiredVolumes.Input), "output", logtext.Path(requiredVolumes.Output),
			// The whole mount contract is "readable/writable by the UID in user:",
			// and every downstream permission WARN points at that UID without ever
			// naming it.
			"uid", os.Getuid(), "gid", os.Getgid(),
			"password", string(cfg.PasswordStatus),
		},
		// Both cadences, because either alone misreads: fallback_scan is the
		// operator's own rescan interval and reads "disabled" when they switched it
		// off, while scan_floor is the cadence the watcher guarantees regardless —
		// the longest it will go without a full re-assert plus scan, and the value
		// the health probe's staleness deadline is derived from.
		scancadence.CoverageAttrs(cfg.FallbackInterval),
		[]any{
			"encoder", cfg.EncoderName,
			"output_lifecycle", string(cfg.Lifecycle), "max_scan_entries", cfg.MaxScanEntries,
		},
	)...)

	// Verify owns the handles it opens: it proves both volumes openable, probes
	// /output for write access through the handle it just proved, and releases both
	// before returning.
	if !mounts.Verify(requiredVolumes) {
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanner := process.New(&process.Options{
		CertsRoot: requiredVolumes.Input,
		OutRoot:   requiredVolumes.Output,
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

	// No scan here: w.Run owns the first scan in both modes.
	w := watch.New(requiredVolumes.Input, runAndSetHealth,
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
func reportWatchExit(ctx context.Context, runErr error) int {
	if runErr == nil {
		slog.Info("shutting down", "reason", context.Cause(ctx))
		return 0
	}
	// Run reported that change detection ended for a reason other than
	// shutdown: the fsnotify watch is gone and only a restart can recover it.
	attrs := []any{"error", logtext.Path(runErr.Error())}
	var lost *watch.LostError
	if errors.As(runErr, &lost) && lost.Remediation != "" {
		attrs = append(attrs, "remediation", lost.Remediation)
	}
	slog.Error("watcher stopped without a shutdown signal; "+
		"change detection is dead, exiting for a restart", attrs...)
	return 1
}

// Package main watches a PEM certificate directory and converts changed certificates to PFX/PKCS#12 on every renewal.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
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
// health input: they are a steady-state permissions/UID misconfiguration that
// a restart cannot fix, so they are surfaced as a WARN in scanAndSetHealth
// rather than flapping the container unhealthy in a restart loop. It is the
// single source of truth for the health boundary so the gate can be
// unit-tested without reimplementing it.
func healthyAfterScan(r process.ScanResult) bool {
	return r.Failed == 0
}

// scanAndSetHealth runs one scan with the scanner's configured input and output
// roots and flips the health marker via healthyAfterScan (zero conversion
// failures). A shutdown cancellation leaves the marker untouched; any other
// scan error clears it. Unreadable input sub-paths are logged as a WARN but
// never affect health — see healthyAfterScan.
func scanAndSetHealth(ctx context.Context, scanner *process.Scanner, marker *health.Marker) {
	result, err := scanner.Run(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			slog.Info("scan interrupted by shutdown", "reason", err)
			return
		}
		slog.Error("processing failed", "error", err)
		marker.Set(false)
		return
	}
	if result.Unreadable > 0 {
		slog.Warn("some /input paths were unreadable and were skipped; health is unaffected",
			"unreadable", result.Unreadable,
			"remediation", "fix /input permissions or run as a UID that can read it")
	}
	marker.Set(healthyAfterScan(result))
}

// --- Entrypoint ---

// logPasswordStatus emits the appropriate weak-password warning and returns
// the non-secret status used by the startup log. Keeping the warning and the
// status in one decision prevents the two predicate trees from drifting apart.
func logPasswordStatus(password string) string {
	status := config.ClassifyPassword(password)
	switch status {
	case config.PasswordEmpty:
		slog.Warn("PFX_PASSWORD is empty; generated PFX files protect the private key with an empty password",
			"remediation", "set PFX_PASSWORD, or point PFX_PASSWORD_FILE at a mounted secret")
	case config.PasswordWhitespaceOnly:
		slog.Warn("PFX_PASSWORD is whitespace-only; generated PFX files are protected by that whitespace string, which is effectively no protection",
			"remediation", "set PFX_PASSWORD to a real value (check for stray quotes or spaces in the env file)")
	}
	return string(status)
}

// fallbackLogValue renders the fallback rescan cadence for the startup log.
// A non-positive interval means the rescan is switched off, which is reported
// as "disabled" rather than as a bare "0s" duration: the value is the
// operator's confirmation that FALLBACK_SCAN_HOURS=0/false took effect, and
// that the health probe's staleness deadline is off with it.
func fallbackLogValue(d time.Duration) string {
	if d <= 0 {
		return "disabled"
	}
	return d.String()
}

// runProbe is a seam: health.RunProbe exits the process, so tests replace it.
var runProbe = health.RunProbe

// dispatchArgs runs the health probe when argv requests it and warns on an
// unrecognized argument. It returns only when the watcher should start.
func dispatchArgs(args []string) {
	if len(args) <= 1 {
		return
	}
	switch args[1] {
	case "health":
		// The fallback rescan is the marker's guaranteed refresh floor
		// (fs events refresh it sooner), so a marker older than 3 fallback
		// intervals means the watch loop is wedged and a restart fixes it.
		// FALLBACK_SCAN_HOURS=0/false disables the fallback and with it
		// the deadline (WithMaxAge(0) is a no-op): watch-only mode has no
		// guaranteed refresh cadence to hold the marker to.
		// RunProbe exits the process, so this never falls through to the
		// watcher below.
		runProbe(health.DefaultPath,
			health.WithMaxAge(3*config.FallbackInterval()))
	default:
		// Not an error (the watcher takes no arguments), but a mistyped probe
		// invocation would otherwise silently start a second watcher.
		slog.Warn("unrecognized argument, starting the watcher",
			"argument", args[1], "known_subcommands", "health")
	}
}

func main() {
	os.Exit(run())
}

// run is the real entrypoint: it returns the process exit code instead of
// calling os.Exit itself, so every deferred cleanup registered below (the
// signal-context stop, the health-marker removal) actually runs on the failure
// paths too.
func run() int {
	lvl, rawLevel, ok := config.LogLevel()
	slogx.Setup(slogx.Options{Level: lvl})
	if !ok {
		slog.Warn("invalid LOG_LEVEL, using default", "value", rawLevel, "default", strings.ToLower(lvl.String()))
	}

	dispatchArgs(os.Args)

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

	passwordStatus := logPasswordStatus(cfg.Password)
	slog.Info("starting cert watcher",
		"input", certsRootDir, "output", outputDir,
		"password", passwordStatus,
		"fallback_scan", fallbackLogValue(cfg.FallbackInterval), "encoder", cfg.EncoderName)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanner := process.New(&process.Options{
		CertsRoot: certsRootDir,
		OutRoot:   outputDir,
		Password:  cfg.Password,
		Encoder:   cfg.EncoderName,
	})

	// runAndSetHealth adapts scanAndSetHealth to the watcher's on-change
	// callback signature.
	runAndSetHealth := func(ctx context.Context) {
		scanAndSetHealth(ctx, scanner, marker)
	}

	runAndSetHealth(ctx)

	w := watch.New(certsRootDir, runAndSetHealth,
		watch.WithDebounce(watchDebounce),
		watch.WithFallback(cfg.FallbackInterval))
	if runErr := w.Run(ctx); runErr != nil {
		// Run reported that change detection ended for a reason other than
		// shutdown: the fsnotify channels closed, so only a restart can recover
		// it. Exit non-zero so restart: on-failure deployments restart too; the
		// deferred marker.Cleanup drops the marker on the way out, so a probe
		// cannot report healthy after this point.
		slog.Error("watcher stopped without a shutdown signal; "+
			"change detection is dead, exiting for a restart", "error", runErr)
		return 1
	}

	slog.Info("shutting down", "reason", context.Cause(ctx))
	return 0
}

// Package main watches a PEM certificate directory and converts changed certificates to PFX/PKCS#12 on every renewal.
package main

import (
	"context"
	"errors"
	"fmt"
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
		if process.IsShutdown(err) {
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

// volumeDir is a required mount point and the role it plays in the startup log.
type volumeDir struct {
	role, path string
}

// volumesReady reports whether every required volume is already mounted as a
// directory, logging EVERY offender at ERROR with its role, path and
// remediation: an operator who omitted the volumes block entirely has both
// mounts missing, and naming only the first costs a restart per mount to
// discover the next one.
//
// Both volumes must already exist. Nothing in this app creates them, and a
// missing one used to surface as a scan-level error on every tick: the
// container reported unhealthy and the orchestrator restarted it forever,
// because a restart cannot create a directory either. Failing once at startup
// with a named path is the actionable form of the same fact, and it matches the
// health contract — the marker is reserved for failures a restart could clear.
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
			continue
		}
		if statErr == nil {
			// os.Stat succeeded, so the path exists and is a file, symlink to a file,
			// FIFO, or device. Without this the log carried error=<nil> and the two
			// causes were indistinguishable, though their remedies differ: an absent
			// path is a missing mount, a non-directory is a bind-mounted FILE.
			statErr = errors.New("path exists but is not a directory")
		}
		slog.Error("required volume is missing or not a directory; refusing to start",
			"role", dir.role, "path", dir.path, "error", statErr,
			"remediation", "mount "+dir.path+" into the container before starting it")
		ready = false
	}
	return ready
}

// runProbe is a seam: health.RunProbe exits the process, so tests replace it.
var runProbe = health.RunProbe

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
	case len(args) == 2 && args[1] == "health":
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
		return continueToWatcher // unreachable in production; runProbe exits
	default:
		// Refuse rather than fall through. Falling through reached
		// marker.Set(false) below, which UNLINKS the resident watcher's health
		// marker, and then started a second watcher against the same /input and
		// /output with its own unsynchronised view. A mistyped HEALTHCHECK
		// override (`healthz`, `--health`) or a stray `docker exec ... status`
		// therefore made the container report unhealthy until the resident
		// watcher's next clean cycle, up to FALLBACK_SCAN_HOURS away, and could
		// leave two processes writing one output tree.
		//
		// The ENTRYPOINT takes no arguments, so anything here is a mistake and a
		// usage error is the honest response.
		if len(args) == 2 {
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
	lvl, rawLevel, ok := config.LogLevel()
	slogx.Setup(slogx.Options{Level: lvl})
	if !ok {
		slog.Warn("invalid LOG_LEVEL, using default", "value", rawLevel, "default", strings.ToLower(lvl.String()))
	}

	if code := dispatchArgs(os.Args); code != continueToWatcher {
		return code
	}

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

	passwordStatus := string(cfg.PasswordStatus)
	slog.Info("starting cert watcher",
		"input", certsRootDir, "output", outputDir,
		"password", passwordStatus,
		"fallback_scan", watch.FallbackLabel(cfg.FallbackInterval), "encoder", cfg.EncoderName,
		"output_lifecycle", string(cfg.Lifecycle))

	if !volumesReady([]volumeDir{{"input", certsRootDir}, {"output", outputDir}}) {
		return 1
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

	// No scan here: w.Run owns the first scan in both fsnotify and poll mode. In
	// fsnotify mode it must run AFTER the watch set is attached (so an event landing
	// during the scan is not missed), which is a sequencing constraint main cannot
	// honour from outside — scanning here as well meant two full scans of /input and
	// two health-marker writes on every start.
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

// Package main watches PEM and PFX certificate sources and keeps the configured
// PEM/PFX output formats current.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cplieger/cert-converter/internal/config"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/mounts"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/scancadence"
	"github.com/cplieger/cert-converter/internal/scanreport"
	"github.com/cplieger/cert-converter/internal/watch"
	"github.com/cplieger/go/health/v2"
	"github.com/cplieger/go/httpserver"
	"github.com/cplieger/go/measure"
	"github.com/cplieger/go/slogx"
)

// Fixed container paths — configured via volume mounts, not env vars.
const (
	certsRootDir = "/input"
	outputDir    = "/output"
)

// watchDebounce is the debounce window for the watcher.
const watchDebounce = 2 * time.Second

// healthyAfterScan reports whether a completed scan should keep the container
// healthy: no conversion failed, and no output name is contested between two
// inputs (a collision converts nothing for that name until the operator
// resolves it, which no restart does — but a stale artifact a consumer keeps
// reading is exactly what the unhealthy state exists to surface).
func healthyAfterScan(r *process.ScanResult) bool {
	return r.Failed == 0 && r.Collided == 0
}

// scanAndSetHealth runs one scan, reports its verdict to the record and the
// metrics, and updates the health verdict.
func scanAndSetHealth(ctx context.Context, scanner *process.Scanner, reporter *scanreport.Reporter, st *health.Status, polling bool) {
	result, err := scanner.Run(ctx)
	if err != nil && process.IsShutdown(err) {
		slog.Info("scan interrupted by shutdown", "reason", err)
		return
	}
	reporter.Report(ctx, &scanreport.Scan{Result: result, Err: err, Polling: polling})
	if err != nil {
		slog.Error("processing failed", "error", logtext.Path(err.Error()))
		st.Set(false)
		return
	}
	st.Set(healthyAfterScan(&result))
}

// --- Metrics ---

// metricsPrefix names every cert-converter series on the metrics page.
const metricsPrefix = "cert_converter"

// newMetrics builds the registry run serves, with the scan metrics on it.
func newMetrics() (*measure.Registry, *scanreport.Reporter) {
	reg := measure.NewRegistry(metricsPrefix)
	return reg, scanreport.NewReporter(reg)
}

// listenTCP is a seam so a test can see that an unset address opens nothing.
var listenTCP = net.Listen

// Timeouts for the metrics page: a scrape reads one small page, so a slow client
// is cut off rather than held.
const (
	metricsReadTimeout  = 10 * time.Second
	metricsWriteTimeout = 30 * time.Second
)

// startMetrics binds addr and serves reg's page and healthz on it until ctx
// ends; wait blocks until the server has shut down. An empty addr opens no
// listener.
func startMetrics(ctx context.Context, addr string, reg *measure.Registry, healthz http.Handler) (wait func(), err error) {
	if addr == "" {
		return func() {}, nil
	}
	ln, err := listenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", reg.Handler())
	mux.Handle("GET /healthz", healthz)
	srv := httpserver.New(mux)
	srv.ReadTimeout = metricsReadTimeout
	srv.WriteTimeout = metricsWriteTimeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := httpserver.Run(ctx, srv, ln); err != nil {
			slog.Error("metrics listener stopped", "address", logtext.Path(addr), "error", logtext.Path(err.Error()))
		}
	}()
	return func() { <-done }, nil
}

// --- Health ---

// healthLease is how old the last clean scan may grow before the watch loop
// counts as stuck: three effective fallback cadences, the guaranteed refresh
// floor (file events refresh it sooner).
func healthLease(fallback time.Duration) time.Duration {
	return health.Lease{Interval: scancadence.Effective(fallback), Cycles: 3}.Duration()
}

// Reasons /healthz lists. Fixed sentences, because the route answers with no login.
const (
	reasonScanFailed = "the last scan did not finish cleanly, or no scan has finished since the start"
	reasonStuck      = "no scan has finished within three guaranteed recheck cadences, so the watch loop may be stuck"
)

// newHealthz serves st with the lease the health subcommand gives the probe, as
// one check per fault so each names itself.
func newHealthz(st *health.Status, fallback time.Duration) http.Handler {
	return health.CheckHandler(
		health.Check{Signal: st, Reason: reasonScanFailed},
		health.Check{Signal: st.Fresh(healthLease(fallback)), Reason: reasonStuck},
	)
}

// healthMarkerPath is the file the watcher mirrors its verdict to and the health
// subcommand reads.
var healthMarkerPath = health.MarkerPath("cert-converter")

// --- Entrypoint ---

// runProbe is a seam: health.RunProbe exits the process, so tests replace it.
var runProbe = func(path string, maxAge time.Duration) {
	health.RunProbe(path, health.WithMaxAge(maxAge))
}

// requiredVolumes is the ONE statement of this container's mount set: the paths
// the startup guard proves openable, and the same paths the scanner, the watcher
// and the startup line then use.
var requiredVolumes = mounts.Paths{
	Input:  certsRootDir,
	Output: outputDir,
}

// Subcommands. watch is the daemon and is what the image's CMD supplies; health
// is the probe the HEALTHCHECK re-invokes.
const (
	healthSubcommand = "health"
	watchSubcommand  = "watch"
)

// usage writes the invocation summary to stderr. Shared by the no-subcommand
// path and the rejection path so the two cannot describe different binaries.
func usage() {
	fmt.Fprintln(os.Stderr, "usage: cert-watcher watch     start the watcher, which is the image's default command")
	fmt.Fprintln(os.Stderr, "       cert-watcher health    probe the health marker")
}

// dispatchArgs routes argv: watch continues to the watcher, health runs the
// probe, and EVERYTHING else — including a bare argv with no subcommand — is a
// usage error.
//
// A bare argv is rejected on purpose, and it is the reason this dispatcher takes
// a subcommand at all. The image sets CMD ["watch"], so the container's own
// start supplies it; a bare argv therefore means the binary was run by hand, and
// overwhelmingly that means `docker exec <container> /cert-watcher` against a
// container whose watcher is already running. Before, that fell through to the
// watcher: run() builds a health Status, which REMOVES the resident watcher's
// health marker, and then a SECOND watcher attaches over the same
// /input and /output, so two processes convert the same certificates and make
// orphan-reaping decisions about each other's files. Refusing costs the operator
// one word and removes the accident outright. It does not stop a deliberate
// `/cert-watcher watch` in a second process, which no in-process check can.
func dispatchArgs(args []string) int {
	if len(args) <= 1 {
		fmt.Fprintln(os.Stderr, "cert-watcher: no subcommand given")
		usage()
		return exitUsage
	}
	switch {
	case len(args) == 2 && args[1] == watchSubcommand:
		return continueToWatcher
	case len(args) == 2 && args[1] == healthSubcommand:
		runProbe(healthMarkerPath, healthLease(config.FallbackInterval()))
		return continueToWatcher // unreachable in production; runProbe exits
	default:
		switch args[1] {
		case healthSubcommand, watchSubcommand:
			fmt.Fprintf(os.Stderr, "cert-watcher: unexpected trailing arguments %q\n", args[2:])
		default:
			// Names the unrecognized token even when extra operands follow it: the
			// token IS the mistake, and reporting only the operands hides it.
			fmt.Fprintf(os.Stderr, "cert-watcher: unrecognized argument %q\n", args[1])
		}
		usage()
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
// signal-context stop, the health drain) actually runs on the failure paths too.
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

	// Built BEFORE the first failure exit: NewStatus removes a marker an earlier
	// run left, so a process that never validated its configuration cannot read
	// healthy.
	st := health.NewStatus(health.WithMarker(healthMarkerPath))
	defer st.BeginDrain()

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
			"input_password_configured", cfg.InputPasswordReady,
			"output_formats", strings.Join(cfg.Formats.Names(), ","), "output_layout", string(cfg.Layout),
			"output_lifecycle", string(cfg.Lifecycle), "max_scan_entries", cfg.MaxScanEntries,
			"excluded_input_paths", logtext.Path(strings.Join(cfg.Exclude.Paths(), ",")),
			"metrics_listen_addr", logtext.Path(cfg.MetricsListenAddr),
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

	// Bound before the first scan, so a typo stops the container at once instead
	// of leaving it converting with no page.
	reg, reporter := newMetrics()
	metricsCtx, stopMetrics := context.WithCancel(ctx)
	waitMetrics, err := startMetrics(metricsCtx, cfg.MetricsListenAddr, reg, newHealthz(st, cfg.FallbackInterval))
	if err != nil {
		stopMetrics()
		slog.Error("cannot listen on METRICS_LISTEN_ADDR; refusing to start",
			"address", logtext.Path(cfg.MetricsListenAddr), "error", logtext.Path(err.Error()),
			"remediation", "set METRICS_LISTEN_ADDR to a free address such as :9468, or unset it")
		return 1
	}
	defer func() {
		stopMetrics()
		waitMetrics()
	}()

	scanner := process.New(&process.Options{
		CertsRoot: requiredVolumes.Input,
		OutRoot:   requiredVolumes.Output,
		Password:  cfg.Password,
		// The input-bundle decode password is its own channel: an operator's PFX
		// sources need not share the password this app embeds in its outputs.
		InputPassword:      cfg.InputPassword,
		InputPasswordReady: cfg.InputPasswordReady,
		Encoder:            cfg.EncoderName,
		Lifecycle:          cfg.Lifecycle,
		Formats:            cfg.Formats,
		FormatsExplicit:    cfg.FormatsExplicit,
		Layout:             cfg.Layout,
		LayoutExplicit:     cfg.LayoutExplicit,
		// Enumerated but never converted; their artifacts stay protected from the
		// orphan reaper, so a mistyped exclusion cannot become a deletion.
		Exclude: cfg.Exclude,
		// internal/config owns MAX_SCAN_ENTRIES' name, default, ceiling and every
		// diagnostic for a repaired value; internal/process takes the budget as
		// injected state and deliberately does not import internal/config, so this
		// composition root is the only place the two meet.
		MaxScanEntries: cfg.MaxScanEntries,
	})

	// runAndSetHealth adapts scanAndSetHealth to the watcher's on-change
	// callback signature.
	runAndSetHealth := func(ctx context.Context, polling bool) {
		scanAndSetHealth(ctx, scanner, reporter, st, polling)
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

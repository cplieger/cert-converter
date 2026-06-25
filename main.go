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

	"github.com/cplieger/cert-watcher/internal/config"
	"github.com/cplieger/cert-watcher/internal/convert"
	"github.com/cplieger/cert-watcher/internal/process"
	"github.com/cplieger/cert-watcher/internal/watch"
	"github.com/cplieger/health"
)

// Fixed container paths — configured via volume mounts, not env vars.
const (
	certsRootDir = "/input"
	outputDir    = "/output"
)

// healthyAfterScan reports whether a completed scan should keep the container
// healthy. Health answers one operational question — "should an orchestrator
// restart this container?" — so it is driven solely by conversion failures,
// the only outcome a restart could plausibly clear (a transient mount glitch,
// a half-written renewal). Unreadable /input sub-paths are deliberately NOT a
// health input: they are a steady-state permissions/UID misconfiguration that
// a restart cannot fix, so they are surfaced as a WARN in runAndSetHealth
// rather than flapping the container unhealthy in a restart loop. It is the
// single source of truth for the health boundary so the gate can be
// unit-tested without reimplementing it.
func healthyAfterScan(r process.ScanResult) bool {
	return r.Failed == 0
}

// resolveLogLevel maps the LOG_LEVEL env value to an slog.Level. slog accepts
// debug/info/warn/error (case-insensitive) with optional +/- offsets; when the
// variable is set but does not parse, it falls back to slog.LevelInfo and
// reports badLevel=true so the caller can warn. An unset variable uses
// LevelInfo with badLevel=false. Pure (no I/O) so the LOG_LEVEL fallback
// contract is unit-testable without reconstructing it in main.
func resolveLogLevel(raw string, set bool) (level slog.Level, badLevel bool) {
	level = slog.LevelInfo
	if set {
		if err := level.UnmarshalText([]byte(raw)); err != nil {
			return slog.LevelInfo, true
		}
	}
	return level, false
}

// watchDebounce is the debounce window for the watcher.
const watchDebounce = 2 * time.Second

// --- Entrypoint ---

func main() {
	if len(os.Args) > 1 && os.Args[1] == "health" {
		health.RunProbe(health.DefaultPath)
	}

	rawLevel, levelSet := os.LookupEnv("LOG_LEVEL")
	lvl, badLevel := resolveLogLevel(rawLevel, levelSet)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
	if badLevel {
		slog.Warn("invalid LOG_LEVEL, using default", "value", rawLevel, "default", "info")
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	if strings.TrimSpace(cfg.Password) == "" {
		slog.Warn("PFX_PASSWORD is empty; generated PFX files protect the private key with an empty password",
			"remediation", "set PFX_PASSWORD")
	}

	passwordStatus := "empty"
	if strings.TrimSpace(cfg.Password) != "" {
		passwordStatus = "configured"
	}
	fallback := cfg.FallbackInterval.String()
	if cfg.FallbackInterval <= 0 {
		fallback = "disabled"
	}
	slog.Info("starting cert watcher",
		"input", certsRootDir, "output", outputDir,
		"password", passwordStatus,
		"fallback_scan", fallback, "encoder", cfg.EncoderName)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	marker := health.NewMarker(health.DefaultPath)
	marker.Set(false)
	defer marker.Cleanup()

	cache := convert.NewHashCache()
	scanner := process.New(cache)

	// runAndSetHealth runs a scan and flips the health marker via
	// healthyAfterScan (zero conversion failures). Unreadable /input
	// sub-paths are logged as a WARN but never affect health — see
	// healthyAfterScan. Shared by the initial run and the watcher's
	// on-change callback.
	runAndSetHealth := func(ctx context.Context) {
		result, err := scanner.Run(ctx, certsRootDir, outputDir, cfg.Password, cfg.Encoder)
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

	runAndSetHealth(ctx)

	w := watch.New(certsRootDir, runAndSetHealth,
		watch.WithDebounce(watchDebounce),
		watch.WithFallback(cfg.FallbackInterval))
	w.Run(ctx)

	slog.Info("shutting down", "reason", context.Cause(ctx))
}

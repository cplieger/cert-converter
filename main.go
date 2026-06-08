package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
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

// watchDebounce is the debounce window for the watcher. Declared as var so
// tests can shorten it.
var watchDebounce = 2 * time.Second

// --- Entrypoint ---

func main() {
	if len(os.Args) > 1 && os.Args[1] == "health" {
		health.RunProbe(health.DefaultPath)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg := config.Load()

	passwordStatus := "empty"
	if cfg.Password != "" {
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

	// runAndSetHealth runs a scan and flips the health marker: healthy
	// only when the scan completed with zero conversion failures. Shared
	// by the initial run and the watcher's on-change callback.
	runAndSetHealth := func(ctx context.Context) {
		result, err := scanner.Run(ctx, certsRootDir, outputDir, cfg.Password, cfg.Encoder)
		if err != nil {
			slog.Error("processing failed", "error", err)
			marker.Set(false)
			return
		}
		marker.Set(result.Failed == 0)
	}

	runAndSetHealth(ctx)

	w := watch.New(certsRootDir, runAndSetHealth,
		watch.WithDebounce(watchDebounce),
		watch.WithFallback(cfg.FallbackInterval))
	w.Run(ctx)

	slog.Info("shutting down", "reason", ctx.Err())
}

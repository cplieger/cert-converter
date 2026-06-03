package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cert-watcher/internal/config"
	"cert-watcher/internal/convert"
	"github.com/cplieger/health"
	"cert-watcher/internal/process"
	"cert-watcher/internal/watch"
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

	result, err := scanner.Run(ctx, certsRootDir, outputDir, cfg.Password, cfg.Encoder)
	if err != nil {
		slog.Error("initial processing failed", "error", err)
		marker.Set(false)
	} else {
		marker.Set(result.Failed == 0)
	}

	onChange := func(ctx context.Context) {
		result, err := scanner.Run(ctx, certsRootDir, outputDir, cfg.Password, cfg.Encoder)
		if err != nil {
			slog.Error("processing failed", "error", err)
			marker.Set(false)
		} else {
			marker.Set(result.Failed == 0)
		}
	}

	w := watch.New(certsRootDir, onChange,
		watch.WithDebounce(watchDebounce),
		watch.WithFallback(cfg.FallbackInterval))
	w.Run(ctx)

	slog.Info("shutting down", "reason", ctx.Err())
}

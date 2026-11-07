package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/mounts"
	"github.com/cplieger/cert-converter/internal/scanreport"
	"github.com/cplieger/go/slogx/capture"
)

func testReporter() *scanreport.Reporter {
	_, reporter := newMetrics()
	return reporter
}

// TestStartMetrics_unset_opens_no_listener pins the default: with
// METRICS_LISTEN_ADDR unset the image opens no port, as before the setting existed.
// Serial: it swaps the listenTCP seam.
func TestStartMetrics_unset_opens_no_listener(t *testing.T) {
	calls := 0
	prev := listenTCP
	listenTCP = func(network, addr string) (net.Listener, error) {
		calls++
		return prev(network, addr)
	}
	t.Cleanup(func() { listenTCP = prev })

	reg, _ := newMetrics()
	ctx, cancel := context.WithCancel(t.Context())
	wait, err := startMetrics(ctx, "", reg)
	cancel()
	if err != nil {
		t.Fatalf("startMetrics(unset) = %v, want nil", err)
	}
	wait()
	if calls != 0 {
		t.Errorf("startMetrics(unset) bound %d listeners, want 0: an unset address opens no port", calls)
	}
}

// TestStartMetrics_serves_the_page_on_GET pins the route: GET /metrics answers the
// registry's page and any other method is refused.
func TestStartMetrics_serves_the_page_on_GET(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	reg, _ := newMetrics()
	wait, err := startMetrics(ctx, addr, reg)
	if err != nil {
		cancel()
		t.Fatalf("startMetrics(%s) = %v", addr, err)
	}
	t.Cleanup(func() {
		cancel()
		wait()
	})

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "cert_converter_last_scan_outcome") {
		t.Errorf("GET /metrics = %d, body lacks cert_converter_last_scan_outcome:\n%s", resp.StatusCode, body)
	}
	post, err := client.Post("http://"+addr+"/metrics", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /metrics: %v", err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics = %d, want 405", post.StatusCode)
	}
}

// runWithMetricsAddr runs the watcher path with valid volumes and
// METRICS_LISTEN_ADDR=addr, and returns its exit code and stderr. A bind that
// wrongly succeeds starts the watcher, so the run is bounded by a deadline.
func runWithMetricsAddr(t *testing.T, addr string) (code int, out string) {
	t.Helper()
	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("PFX_PASSWORD", "test-password")
	t.Setenv("METRICS_LISTEN_ADDR", addr)
	for _, key := range []string{"PFX_PASSWORD_FILE", "PFX_ALLOW_EMPTY_PASSWORD"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	capture.SwapDefault(t, slog.New(slog.DiscardHandler))
	prevArgs, prevVolumes := os.Args, requiredVolumes
	os.Args = []string{"cert-watcher", watchSubcommand}
	requiredVolumes = mounts.Paths{Input: t.TempDir(), Output: t.TempDir()}
	t.Cleanup(func() {
		os.Args = prevArgs
		requiredVolumes = prevVolumes
	})
	returned := make(chan int, 1)
	out = captureStderr(t, func() {
		go func() { returned <- run() }()
		select {
		case code = <-returned:
		case <-time.After(10 * time.Second):
			// run is past its signal.NotifyContext here, so SIGTERM stops the
			// watcher it wrongly started instead of killing the test binary.
			t.Error("run() did not return: it started the watcher instead of refusing the address")
			if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			code = <-returned
		}
	})
	return code, out
}

// TestRun_refuses_to_start_when_METRICS_LISTEN_ADDR_cannot_be_bound pins the
// tier-3 bind rule: a malformed or taken address exits non-zero before the first
// scan with one error naming the variable, and never falls back to another address.
// Serial: it swaps os.Args, os.Stderr, slog.Default() and requiredVolumes.
func TestRun_refuses_to_start_when_METRICS_LISTEN_ADDR_cannot_be_bound(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = taken.Close() })
	for name, addr := range map[string]string{
		"malformed": "not-an-address",
		"taken":     taken.Addr().String(),
	} {
		t.Run(name, func(t *testing.T) {
			code, out := runWithMetricsAddr(t, addr)
			if code != 1 {
				t.Errorf("run(METRICS_LISTEN_ADDR=%q) = %d, want 1; stderr %q", addr, code, out)
			}
			if n := strings.Count(out, "level=ERROR"); n != 1 || !strings.Contains(out, "METRICS_LISTEN_ADDR") {
				t.Errorf("run(METRICS_LISTEN_ADDR=%q) wrote %d ERROR lines, want one naming METRICS_LISTEN_ADDR; stderr %q", addr, n, out)
			}
		})
	}
}

// bindFailureOutput is the stderr of a refused METRICS_LISTEN_ADDR.
func bindFailureOutput(t *testing.T) string {
	t.Helper()
	_, out := runWithMetricsAddr(t, "not-an-address")
	return out
}

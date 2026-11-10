package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/config"
	"github.com/cplieger/go/health"
)

// healthzBody is the JSON body every cplieger /healthz answers with.
type healthzBody struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

// markerState puts a test marker in a state: written by a clean scan (fresh),
// removed by a failed one (failed), or written age ago (aged).
func markerState(t *testing.T, marker *health.Marker, path, state string, age time.Duration) {
	t.Helper()
	switch state {
	case "fresh":
		marker.Set(true)
	case "failed":
		marker.Set(false)
	case "aged":
		marker.Set(true)
		aged := time.Now().Add(-age)
		if err := os.Chtimes(path, aged, aged); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown marker state %q", state)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestStartMetrics_serves_healthz pins the route on METRICS_LISTEN_ADDR: GET
// and HEAD answer 200 with {"status":"ok"} on a fresh marker, 503 with one
// reason per fault on a failed or a stale marker, and any other method gets 405.
// Serial: it reads FALLBACK_SCAN_HOURS.
func TestStartMetrics_serves_healthz(t *testing.T) {
	t.Setenv("FALLBACK_SCAN_HOURS", "")
	path := filepath.Join(t.TempDir(), ".healthy")
	marker := health.NewMarker(path)
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(t.Context())
	reg, _ := newMetrics()
	wait, err := startMetrics(ctx, addr, reg, newHealthz(marker, config.FallbackInterval()))
	if err != nil {
		cancel()
		t.Fatalf("startMetrics(%s) = %v", addr, err)
	}
	t.Cleanup(func() {
		cancel()
		wait()
	})
	client := &http.Client{Timeout: 5 * time.Second}
	url := "http://" + addr + "/healthz"

	get := func(t *testing.T) (int, http.Header, healthzBody) {
		t.Helper()
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		var body healthzBody
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("GET /healthz body %q is not JSON: %v", raw, err)
		}
		return resp.StatusCode, resp.Header, body
	}

	// The default 6-hour cadence gives an 18-hour lease.
	const pastLease = 19 * time.Hour
	reasons := map[string]string{}
	for _, tc := range []struct {
		name       string
		state      string
		wantCode   int
		wantStatus string
	}{
		{"fresh", "fresh", http.StatusOK, "ok"},
		{"failed", "failed", http.StatusServiceUnavailable, "unhealthy"},
		{"stale", "aged", http.StatusServiceUnavailable, "unhealthy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markerState(t, marker, path, tc.state, pastLease)
			code, header, body := get(t)
			if code != tc.wantCode || body.Status != tc.wantStatus {
				t.Errorf("GET /healthz on a %s marker = %d %q, want %d %q", tc.name, code, body.Status, tc.wantCode, tc.wantStatus)
			}
			for key, want := range map[string]string{
				"Content-Type":           "application/json",
				"Cache-Control":          "no-store",
				"X-Content-Type-Options": "nosniff",
			} {
				if got := header.Get(key); got != want {
					t.Errorf("GET /healthz %s = %q, want %q", key, got, want)
				}
			}
			switch {
			case tc.wantCode == http.StatusOK && body.Reasons != nil:
				t.Errorf("GET /healthz on a fresh marker lists reasons %q, want none", body.Reasons)
			case tc.wantCode != http.StatusOK && len(body.Reasons) != 1:
				t.Errorf("GET /healthz on a %s marker lists reasons %q, want exactly one", tc.name, body.Reasons)
			case tc.wantCode != http.StatusOK:
				reasons[tc.name] = body.Reasons[0]
			}
		})
	}
	if reasons["failed"] == reasons["stale"] {
		t.Errorf("a failed and a stale marker both report %q, want a reason naming each fault", reasons["failed"])
	}

	t.Run("HEAD", func(t *testing.T) {
		markerState(t, marker, path, "fresh", 0)
		resp, err := client.Head(url)
		if err != nil {
			t.Fatalf("HEAD /healthz: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("HEAD /healthz = %d, want 200", resp.StatusCode)
		}
	})
	t.Run("POST", func(t *testing.T) {
		resp, err := client.Post(url, "application/json", nil)
		if err != nil {
			t.Fatalf("POST /healthz: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST /healthz = %d, want 405", resp.StatusCode)
		}
	})
}

// TestHealthz_agrees_with_the_health_subcommand pins one verdict for two
// readers: for a fresh, a failed, a stale and a not yet stale marker, /healthz answers 200
// exactly when `cert-watcher health` exits 0, at the default cadence and when
// FALLBACK_SCAN_HOURS=0 selects the 24-hour floor.
// Serial: it swaps runProbe and sets FALLBACK_SCAN_HOURS.
func TestHealthz_agrees_with_the_health_subcommand(t *testing.T) {
	for _, cadence := range []struct {
		fallbackHours string
		lease         time.Duration
	}{
		{"", 18 * time.Hour},
		{"0", 72 * time.Hour},
	} {
		for _, tc := range []struct {
			state    string
			age      time.Duration
			wantCode int
		}{
			{"fresh", 0, http.StatusOK},
			{"aged", cadence.lease - time.Hour, http.StatusOK},
			{"failed", 0, http.StatusServiceUnavailable},
			{"aged", cadence.lease + time.Hour, http.StatusServiceUnavailable},
		} {
			name := "FALLBACK_SCAN_HOURS=" + cadence.fallbackHours + " " + tc.state + " " + tc.age.String()
			t.Run(name, func(t *testing.T) {
				t.Setenv("FALLBACK_SCAN_HOURS", cadence.fallbackHours)
				var probeOpts []health.ProbeOption
				prev := runProbe
				runProbe = func(_ string, opts ...health.ProbeOption) { probeOpts = opts }
				t.Cleanup(func() { runProbe = prev })
				_ = dispatchArgs([]string{"cert-watcher", healthSubcommand})

				path := filepath.Join(t.TempDir(), ".healthy")
				marker := health.NewMarker(path)
				markerState(t, marker, path, tc.state, tc.age)

				rec := httptest.NewRecorder()
				newHealthz(marker, config.FallbackInterval()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
				probeHealthy := health.Inspect(path, probeOpts...).Healthy()
				if rec.Code != tc.wantCode {
					t.Errorf("/healthz = %d, want %d", rec.Code, tc.wantCode)
				}
				if probeHealthy != (rec.Code == http.StatusOK) {
					t.Errorf("/healthz = %d but cert-watcher health reads healthy = %v: the two readers disagree", rec.Code, probeHealthy)
				}
			})
		}
	}
}

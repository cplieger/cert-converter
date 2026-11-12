package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/cert-converter/internal/config"
	"github.com/cplieger/go/health/v2"
)

// healthzBody is the JSON body every cplieger /healthz answers with.
type healthzBody struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

// markerState puts a test verdict in a state: set by a clean scan (fresh) or
// by a failed one (failed).
func markerState(t *testing.T, st *health.Status, state string) {
	t.Helper()
	switch state {
	case "fresh":
		st.Set(true)
	case "failed":
		st.Set(false)
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
// and HEAD answer 200 with {"status":"ok"} on a fresh verdict, 503 with one
// reason on a failed one, and any other method gets 405. The stale verdict
// needs a fake clock, so TestHealthz_names_each_fault covers it.
// Serial: it reads FALLBACK_SCAN_HOURS.
func TestStartMetrics_serves_healthz(t *testing.T) {
	t.Setenv("FALLBACK_SCAN_HOURS", "")
	marker := health.NewStatus()
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

	for _, tc := range []struct {
		name       string
		state      string
		wantCode   int
		wantStatus string
	}{
		{"fresh", "fresh", http.StatusOK, "ok"},
		{"failed", "failed", http.StatusServiceUnavailable, "unhealthy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markerState(t, marker, tc.state)
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
			}
		})
	}

	t.Run("HEAD", func(t *testing.T) {
		markerState(t, marker, "fresh")
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

// healthzVerdict answers one GET /healthz on h.
func healthzVerdict(t *testing.T, h http.Handler) (int, healthzBody) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var body healthzBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET /healthz body %q is not JSON: %v", rec.Body.Bytes(), err)
	}
	return rec.Code, body
}

// TestHealthz_names_each_fault pins that a failed scan and a watch loop that
// stopped refreshing a healthy verdict each answer 503 with one reason of their
// own. Serial: it reads FALLBACK_SCAN_HOURS.
func TestHealthz_names_each_fault(t *testing.T) {
	t.Setenv("FALLBACK_SCAN_HOURS", "")
	synctest.Test(t, func(t *testing.T) {
		st := health.NewStatus()
		h := newHealthz(st, config.FallbackInterval())

		st.Set(false)
		code, failed := healthzVerdict(t, h)
		if code != http.StatusServiceUnavailable || len(failed.Reasons) != 1 {
			t.Fatalf("GET /healthz after a failed scan = %d %q, want 503 with one reason", code, failed.Reasons)
		}

		st.Set(true)
		// The default 6-hour cadence gives an 18-hour lease.
		time.Sleep(19 * time.Hour)
		code, stale := healthzVerdict(t, h)
		if code != http.StatusServiceUnavailable || len(stale.Reasons) != 1 {
			t.Fatalf("GET /healthz 19h after the last clean scan = %d %q, want 503 with one reason", code, stale.Reasons)
		}
		if failed.Reasons[0] == stale.Reasons[0] {
			t.Errorf("a failed and a stale verdict both report %q, want a reason naming each fault", stale.Reasons[0])
		}
	})
}

// TestHealthz_agrees_with_the_health_subcommand pins one deadline for two
// readers: /healthz turns 503 once the last clean scan is older than the lease
// the health subcommand gives the probe, and not before, at the default cadence
// and when FALLBACK_SCAN_HOURS=0 selects the 24-hour floor.
// Serial: it swaps runProbe and sets FALLBACK_SCAN_HOURS.
func TestHealthz_agrees_with_the_health_subcommand(t *testing.T) {
	for _, fallbackHours := range []string{"", "0"} {
		t.Run("FALLBACK_SCAN_HOURS="+fallbackHours, func(t *testing.T) {
			t.Setenv("FALLBACK_SCAN_HOURS", fallbackHours)
			var probeLease time.Duration
			prev := runProbe
			runProbe = func(_ string, maxAge time.Duration) { probeLease = maxAge }
			t.Cleanup(func() { runProbe = prev })
			_ = dispatchArgs([]string{"cert-watcher", healthSubcommand})
			if probeLease <= 0 {
				t.Fatalf("the health subcommand armed no lease (%v)", probeLease)
			}

			synctest.Test(t, func(t *testing.T) {
				st := health.NewStatus()
				h := newHealthz(st, config.FallbackInterval())
				st.Set(true)
				time.Sleep(probeLease - time.Minute)
				if code, body := healthzVerdict(t, h); code != http.StatusOK {
					t.Errorf("/healthz a minute inside the probe's %v lease = %d %q, want 200", probeLease, code, body.Reasons)
				}
				time.Sleep(2 * time.Minute)
				if code, _ := healthzVerdict(t, h); code != http.StatusServiceUnavailable {
					t.Errorf("/healthz a minute past the probe's %v lease = %d, want 503", probeLease, code)
				}
			})
		})
	}
}

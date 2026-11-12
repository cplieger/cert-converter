package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/mounts"
	"github.com/cplieger/cert-converter/internal/scanreport"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/go/health/v2"
	"github.com/cplieger/go/measure"
	"github.com/cplieger/go/slogx/capture"
)

func testReporter() *scanreport.Reporter {
	_, reporter := newMetrics(0)
	return reporter
}

// TestStartMetrics_logs_strays_but_not_scrapes pins the listener's access log: a
// scrape or a /healthz probe repeats one standing state, so it logs at Debug and
// never fills the INFO log, while a request for any other path is one INFO
// event an operator can see. Serial: it swaps slog.Default().
func TestStartMetrics_logs_strays_but_not_scrapes(t *testing.T) {
	rec := capture.Default(t)
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(t.Context())
	reg, _ := newMetrics(0)
	wait, err := startMetrics(ctx, addr, reg, http.NotFoundHandler())
	if err != nil {
		cancel()
		t.Fatalf("startMetrics(%s) = %v", addr, err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/metrics", "/healthz", "/stray"} {
		resp, err := client.Get("http://" + addr + path)
		if err != nil {
			cancel()
			wait()
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
	}
	// The shutdown waits for every handler, so each access line is written.
	cancel()
	wait()

	lines := map[slog.Level][]string{}
	for _, r := range rec.Records() {
		if r.Message != "http" {
			continue
		}
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "path" {
				lines[r.Level] = append(lines[r.Level], a.Value.String())
			}
			return true
		})
	}
	if got, want := lines[slog.LevelDebug], []string{"/metrics", "/healthz"}; !slices.Equal(got, want) {
		t.Errorf("Debug access lines = %q, want %q", got, want)
	}
	if got, want := lines[slog.LevelInfo], []string{"/stray"}; !slices.Equal(got, want) {
		t.Errorf("INFO access lines = %q, want %q", got, want)
	}
}

// TestStartMetrics_serves_the_page_on_GET pins the route: GET /metrics answers the
// registry's page and any other method is refused.
func TestStartMetrics_serves_the_page_on_GET(t *testing.T) {
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(t.Context())
	reg, _ := newMetrics(0)
	wait, err := startMetrics(ctx, addr, reg, http.NotFoundHandler())
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

// TestNewMetrics_serves_build_info pins the series a query joins on to find the
// release a target runs: one line at 1, labelled with the stamped version.
func TestNewMetrics_serves_build_info(t *testing.T) {
	t.Parallel()
	reg, _ := newMetrics(0)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	var lines []string
	for line := range strings.SplitSeq(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "cert_converter_build_info") {
			lines = append(lines, line)
		}
	}
	if want := `cert_converter_build_info{version="` + version + `"} 1`; !slices.Equal(lines, []string{want}) {
		t.Errorf("build_info lines = %q, want [%q]", lines, want)
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

// TestRun_refuses_to_start_when_METRICS_LISTEN_ADDR_cannot_be_bound pins that an
// address that cannot be bound stops startup: a malformed or taken address exits
// non-zero before the first scan with one error naming the variable, and never
// falls back to another address.
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

// scanDeadline reads the deadline CertConverterScanStalled compares with time().
func scanDeadline(t *testing.T, reg *measure.Registry) time.Time {
	t.Helper()
	families, err := reg.Gather(t.Context())
	if err != nil {
		t.Fatalf("Gather = %v", err)
	}
	for _, f := range families {
		if f.Name == "cert_converter_scan_deadline_timestamp_seconds" && len(f.Samples) == 1 {
			return time.Unix(int64(f.Samples[0].Value), 0)
		}
	}
	t.Fatal("the page has no single cert_converter_scan_deadline_timestamp_seconds sample")
	return time.Time{}
}

// TestScanAndSetHealth_moves_the_deadline_only_on_a_healthy_scan pins the stall
// rule's deadline to the health verdict: it starts one health lease after the
// start, a scan that fails a conversion or cannot open /input leaves it, and a
// healthy scan moves it one lease past its end, so CertConverterScanStalled and
// the stale /healthz check judge the same moment.
func TestScanAndSetHealth_moves_the_deadline_only_on_a_healthy_scan(t *testing.T) {
	capture.SwapDefault(t, slog.New(slog.DiscardHandler))
	synctest.Test(t, func(t *testing.T) {
		const fallback = time.Hour
		lease := 3 * fallback
		start := time.Now()
		reg, reporter := newMetrics(fallback)
		st := health.NewStatus()
		if got, want := scanDeadline(t, reg), start.Add(lease).Truncate(time.Second); !got.Equal(want) {
			t.Errorf("deadline at the start = %v, want the start plus three cadences %v", got, want)
		}

		inDir, outDir := t.TempDir(), t.TempDir()
		writeCertAndKey(t, inDir, "broken", []byte("not a certificate"), []byte("not a private key"))
		time.Sleep(time.Hour)
		scanAndSetHealth(t.Context(), newTestScanner(inDir, outDir, "", convert.EncNameModern2023), reporter, st, false)
		if got, want := scanDeadline(t, reg), start.Add(lease).Truncate(time.Second); !got.Equal(want) {
			t.Errorf("deadline after a failed conversion = %v, want it unchanged at %v", got, want)
		}

		time.Sleep(time.Hour)
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		scanAndSetHealth(t.Context(), newTestScanner(missing, outDir, "", convert.EncNameModern2023), reporter, st, false)
		if got, want := scanDeadline(t, reg), start.Add(lease).Truncate(time.Second); !got.Equal(want) {
			t.Errorf("deadline after an aborted scan = %v, want it unchanged at %v", got, want)
		}

		for _, name := range []string{"broken.crt", "broken.key"} {
			if err := os.Remove(filepath.Join(inDir, name)); err != nil {
				t.Fatal(err)
			}
		}
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "deadline", "ecdsa")
		writeCertAndKey(t, inDir, "good", certPEM, keyPEM)
		time.Sleep(time.Hour)
		end := time.Now()
		scanAndSetHealth(t.Context(), newTestScanner(inDir, outDir, "", convert.EncNameModern2023), reporter, st, false)
		if !st.Healthy() {
			t.Fatal("the scan of one good pair did not report healthy")
		}
		if got, want := scanDeadline(t, reg), end.Add(lease).Truncate(time.Second); !got.Equal(want) {
			t.Errorf("deadline after a healthy scan = %v, want its end plus three cadences %v", got, want)
		}
	})
}

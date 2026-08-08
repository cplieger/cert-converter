package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/mounts"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/cert-converter/internal/watch"
	"github.com/cplieger/health"
	"github.com/cplieger/slogx/capture"
)

// --- Test helpers ---

// newTestScanner creates a scanner (with its own fresh fingerprint cache) over
// the given roots for test isolation. The scan configuration is
// process-lifetime, so it is injected at construction.
func newTestScanner(certsRoot, outRoot, password string, enc convert.EncoderType) *process.Scanner {
	return process.New(&process.Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  password,
		Encoder:   enc,
		// main always passes the parsed cfg.Lifecycle, which ParseLifecycle
		// guarantees is one of the three modes; the zero value is not.
		Lifecycle: outputpolicy.LifecycleWarn,
	})
}

// writeCertAndKey writes a .crt and .key file pair into dir and returns their paths.
func writeCertAndKey(t *testing.T, dir, base string, certPEM, keyPEM []byte) (crtPath, keyPath string) {
	t.Helper()
	crtPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return crtPath, keyPath
}

// --- Tests: scanAndSetHealth ---

// newTestMarker constructs a marker rooted in a fresh TempDir so tests
// don't race on /tmp/.healthy.
func newTestMarker(t *testing.T) (*health.Marker, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".healthy")
	return health.NewMarker(path), path
}

func TestScanAndSetHealth_sets_marker_after_failure_free_scan(t *testing.T) {
	t.Parallel()

	marker, markerPath := newTestMarker(t)

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "health-test", "ecdsa")
	inDir := t.TempDir()
	outDir := t.TempDir()
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)
	writeCertAndKey(t, inDir, "test", certPEM, keyPEM)

	scanAndSetHealth(t.Context(), scanner, marker)

	if _, err := os.Stat(markerPath); err != nil {
		t.Errorf("health marker should exist after a failure-free scan: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "test.pfx")); err != nil {
		t.Errorf("PFX should be created: %v", err)
	}
}

func TestScanAndSetHealth_clears_marker_when_scan_errors(t *testing.T) {
	t.Parallel()

	marker, markerPath := newTestMarker(t)

	// Start healthy so the assertion proves the scan error cleared it.
	marker.Set(true)
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	scanner := newTestScanner(missing, t.TempDir(), "", convert.EncNameModern2023)

	scanAndSetHealth(t.Context(), scanner, marker)

	if _, err := os.Stat(markerPath); err == nil {
		t.Error("health marker should be cleared when the input root cannot be scanned")
	}
}

// TestScanAndSetHealth_unreadable_pair_stays_healthy pins the health-neutral
// half of the unreadable-path contract end to end: an /input path the scan could
// not read is WARNed about but must never flip the marker unhealthy, because no
// restart can clear a permissions/layout misconfiguration.
//
// The WARN itself is rendered by internal/process (logInputCoverageWarnings owns
// every default-level /input-coverage diagnostic); this test asserts it still
// reaches an operator through the composition root, which is the only place the
// scan, the diagnostic and the marker meet. Its remediation must name the LAYOUT
// shapes too, not permissions alone: the count aggregates a directory occupying a
// <name>.crt path and an escaping symlink as well, and permission-only advice
// sent an operator with a layout mistake to re-check permissions that were
// already correct.
//
// The unreadable input is an escaping symlink pair (the certbot live/ ->
// archive/ layout with only live/ mounted), which the confined /input root
// refuses on every Linux UID. The previous chmod(000) construction skipped
// whenever the suite ran as root, which is exactly where this assertion is
// needed: both halves — Unreadable staying healthy and the aggregate WARN —
// could regress unobserved there.
// Serial (no t.Parallel): it swaps the process-global slog default.
func TestScanAndSetHealth_unreadable_pair_stays_healthy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Root symlink-confinement behavior is Linux-specific")
	}

	marker, markerPath := newTestMarker(t)
	marker.Set(false) // start unhealthy; a failure-free scan must restore health

	base := t.TempDir()
	inDir := filepath.Join(base, "live")
	archive := filepath.Join(base, "archive")
	outDir := t.TempDir()
	if err := os.Mkdir(inDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(archive, 0o750); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "unreadable", "ecdsa")
	certPath, keyPath := writeCertAndKey(t, archive, "unreadable", certPEM, keyPEM)
	if err := os.Symlink(certPath, filepath.Join(inDir, "unreadable.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keyPath, filepath.Join(inDir, "unreadable.key")); err != nil {
		t.Fatal(err)
	}

	// The remediation hint is the only observable effect of the Unreadable
	// branch, so capture the default logger to pin it.
	logs := capture.Default(t)
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

	scanAndSetHealth(t.Context(), scanner, marker)

	// CountExact, not Count: README's Alerting section tells operators running at
	// LOG_LEVEL=warn to alert on the prefix "some /input paths were unreadable and
	// were skipped". Pinning the whole message byte-for-byte is the superset of
	// that contract: any reword fails here - loudly, with the message in the
	// failure - rather than in an operator's Loki rule that silently stops
	// matching. Count would pass on a superstring reword.
	const unreadableMsg = "some /input paths were unreadable and were skipped; health is unaffected"
	if n := logs.CountLevel(slog.LevelWarn, unreadableMsg); n != 1 {
		t.Errorf("a scan with one unreadable pair logged %d WARN records with the alerted message %q, want exactly 1; got logs %q",
			n, unreadableMsg, logs.Messages())
	}
	if n := logs.CountExact(unreadableMsg); n != 1 {
		t.Errorf("a scan with one unreadable pair logged %d records exactly matching the alerted message %q, want 1; got logs %q",
			n, unreadableMsg, logs.Messages())
	}
	if !logs.HasAttr(unreadableMsg, "unreadable", "1") {
		t.Errorf("the unreadable aggregate does not report unreadable=1 for one escaping pair; got logs %q", logs.Messages())
	}
	if !logs.AttrContains(unreadableMsg, "remediation", "check /input permissions") {
		t.Errorf("the unreadable aggregate carries no actionable remediation attr; got logs %q", logs.Messages())
	}
	// The layout half of the same hint. The count aggregates shapes that are not
	// permission problems at all (a directory occupying a <name>.crt path, a symlink
	// out of the mount), and their per-path diagnosis is Debug-only, so this attr is
	// the only default-level place that advice exists.
	if !logs.AttrContains(unreadableMsg, "remediation", "not a directory or a symlink out of it") {
		t.Errorf("the unreadable aggregate's remediation covers permissions only, so an operator with a layout mistake"+
			" re-checks permissions that are already correct; got logs %q", logs.Messages())
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("marker must stay healthy when only Unreadable>0 and no conversion failed: %v", err)
	}
}

// TestScanAndSetHealth_clears_marker_after_conversion_failure pins the
// composition scanAndSetHealth performs between Scanner.Run, healthyAfterScan
// and Marker.Set on the result.Failed > 0, err == nil path: malformed
// certificate material converts nothing and must clear the marker. Without it,
// replacing marker.Set(healthyAfterScan(result)) with marker.Set(true) keeps
// every other test in this file green.
func TestScanAndSetHealth_clears_marker_after_conversion_failure(t *testing.T) {
	t.Parallel()

	marker, markerPath := newTestMarker(t)
	marker.Set(true) // start healthy so the assertion proves the failure cleared it
	inDir := t.TempDir()
	outDir := t.TempDir()
	writeCertAndKey(t, inDir, "broken", []byte("not a certificate"), []byte("not a private key"))
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

	scanAndSetHealth(t.Context(), scanner, marker)

	if _, err := os.Stat(markerPath); err == nil {
		t.Error("health marker should be cleared when a certificate conversion fails")
	}
}

// TestScanAndSetHealth_clean_scan_emits_no_unreadable_warning pins the NEGATIVE
// half of the unreadable WARN, which its positive twin above cannot: a scan
// with nothing unreadable must not emit that message at all. README's Alerting
// section tells operators running at LOG_LEVEL=warn to alert on the line "some
// /input paths were unreadable and were skipped" to keep the coverage the
// healthcheck deliberately omits, so a guard that stops discriminating turns
// every clean cycle into that alert. The guard itself now lives in
// internal/process (logInputCoverageWarnings); this is the composition-root
// assertion that a clean cycle is silent all the way through, which no
// package-level test of that function can make.
// Serial (no t.Parallel): it swaps the process-global slog default.
func TestScanAndSetHealth_clean_scan_emits_no_unreadable_warning(t *testing.T) {
	marker, markerPath := newTestMarker(t)

	inDir, outDir := t.TempDir(), t.TempDir()
	// The output directory's own mode is fixture noise here, but the scan reports a
	// /output directory more permissive than 0750, and what t.TempDir creates depends
	// on the host (an inherited ACL widens it). Pinned so the "quiet at warn level"
	// assertion below observes the scan's own conclusions only.
	if err := os.Chmod(outDir, 0o750); err != nil {
		t.Fatalf("setup: Chmod(outDir): %v", err)
	}
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "clean", "ecdsa")
	writeCertAndKey(t, inDir, "clean", certPEM, keyPEM)
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

	logs := capture.Default(t)

	scanAndSetHealth(t.Context(), scanner, marker)

	const unreadableMsg = "some /input paths were unreadable and were skipped; health is unaffected"
	if n := logs.Count(unreadableMsg); n != 0 {
		t.Errorf("a scan with nothing unreadable logged %d records mentioning %q, want 0: operators alert on that message, so it must stay specific to Unreadable > 0; got logs %q",
			n, unreadableMsg, logs.Messages())
	}
	if n := logs.CountLevel(slog.LevelWarn, ""); n != 0 {
		t.Errorf("a clean scan logged %d WARN records %q, want none: a healthy cycle must be quiet at warn level", n, logs.Messages())
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("a clean scan must still set the health marker: %v", err)
	}
}

// TestScanAndSetHealth_cancelled_context_leaves_marker_untouched pins the
// shutdown contract: a cancelled scan is not a conversion failure, so the
// marker keeps whatever value the last completed scan gave it.
func TestScanAndSetHealth_cancelled_context_leaves_marker_untouched(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name             string
		initiallyHealthy bool
	}{
		{name: "healthy marker stays healthy", initiallyHealthy: true},
		{name: "unhealthy marker stays unhealthy", initiallyHealthy: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker, markerPath := newTestMarker(t)
			marker.Set(tc.initiallyHealthy)

			inDir, outDir := t.TempDir(), t.TempDir()
			certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "cancelled", "ecdsa")
			writeCertAndKey(t, inDir, "cancelled", certPEM, keyPEM)
			scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			scanAndSetHealth(ctx, scanner, marker)

			_, statErr := os.Stat(markerPath)
			if gotHealthy := statErr == nil; gotHealthy != tc.initiallyHealthy {
				t.Errorf("marker healthy after cancelled scan = %v, want prior state %v (stat error: %v)",
					gotHealthy, tc.initiallyHealthy, statErr)
			}
		})
	}
}

// TestDispatchArgs pins the argv policy behind the runProbe seam: the health
// subcommand probes the marker at health.DefaultPath, an unrecognized argument
// is a usage error that never probes and never starts a watcher, and a bare
// invocation starts the watcher. The usage error is written to stderr, so argv
// dispatch must emit no log records at all. No t.Parallel: it swaps the
// package-level runProbe var and slog.Default().
func TestDispatchArgs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		wantProbe bool
		wantCode  int
	}{
		{"no argument starts the watcher", []string{"cert-watcher"}, false, continueToWatcher},
		{"health probes the marker", []string{"cert-watcher", "health"}, true, continueToWatcher},
		// A typo used to WARN and fall through, which unlinked the resident
		// watcher's health marker and started a second watcher over the same
		// output tree. It is now a usage error that never reaches the marker.
		{"typo is a usage error and never starts a watcher", []string{"cert-watcher", "helth"}, false, exitUsage},
		// `health` plus a trailing operand used to enter the health case
		// and probe while silently ignoring the extra argument. The subcommand
		// must consume the whole of argv or the invocation is a usage error.
		{"health with a trailing argument is a usage error", []string{"cert-watcher", "health", "typo"}, false, exitUsage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			gotPath, probed := "", false
			prev := runProbe
			runProbe = func(path string, _ ...health.ProbeOption) {
				probed, gotPath = true, path
			}
			t.Cleanup(func() { runProbe = prev })

			gotCode := dispatchArgs(tc.args)

			if probed != tc.wantProbe {
				t.Errorf("dispatchArgs(%q) probed = %v, want %v", tc.args, probed, tc.wantProbe)
			}
			if tc.wantProbe && gotPath != health.DefaultPath {
				t.Errorf("dispatchArgs(%q) probed %q, want %q", tc.args, gotPath, health.DefaultPath)
			}
			if logs.Len() != 0 {
				t.Errorf("dispatchArgs(%q) logged %v, want no log records: the usage error goes to stderr", tc.args, logs.Messages())
			}
			if gotCode != tc.wantCode {
				t.Errorf("dispatchArgs(%q) = %d, want %d", tc.args, gotCode, tc.wantCode)
			}
		})
	}
}

// TestDispatchArgs_arms_the_marker_lease pins the staleness deadline the health
// subcommand hands the probe: three refresh floors — 18h on the default 6h cadence,
// and three reconciliation floors when FALLBACK_SCAN_HOURS switches the routine
// rescan off, because the watcher still reconciles on that floor and every
// reconciliation refreshes the marker. A cadence ABOVE the floor is capped by the
// same rule, so the config package's 10-year ceiling can no longer arm a deadline
// that never expires.
//
// The disabled case is the one that changed: it used to disarm the deadline entirely
// (WithMaxAge(0) is a no-op), which is what let a wedged watcher keep a container
// healthy indefinitely. A marker past the lease must now fail, so both sides of that
// boundary are asserted.
//
// The captured options are applied with health.ProbeCheck to markers whose
// mtimes straddle the deadline, so a wrong multiplier or a dropped option fails
// here rather than in production. No t.Parallel: it swaps runProbe and mutates
// the environment.
func TestDispatchArgs_arms_the_marker_lease(t *testing.T) {
	// Three reconciliation floors: the watcher's own guarantee rather than a
	// configured value, so it is derived from the same function main arms the probe
	// with.
	reconcileLease := 3 * watch.MarkerRefreshFloor(0)

	for _, tc := range []struct {
		name          string
		fallbackHours string
		markerAge     time.Duration
		wantCode      int
	}{
		{"default cadence keeps a marker inside the 18h lease healthy", "", 17 * time.Hour, 0},
		{"default cadence fails a marker past the 18h lease", "", 19 * time.Hour, 1},
		{"a disabled fallback keeps a marker inside the reconciliation lease healthy", "0", reconcileLease - time.Hour, 0},
		{"a disabled fallback fails a marker past the reconciliation lease", "0", reconcileLease + time.Hour, 1},
		{"a cadence above the floor is capped to the reconciliation lease", "87600", reconcileLease + time.Hour, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FALLBACK_SCAN_HOURS", tc.fallbackHours)

			var gotOpts []health.ProbeOption
			probed := false
			prev := runProbe
			runProbe = func(_ string, opts ...health.ProbeOption) {
				probed, gotOpts = true, opts
			}
			t.Cleanup(func() { runProbe = prev })

			_ = dispatchArgs([]string{"cert-watcher", "health"})

			if !probed {
				t.Fatalf("dispatchArgs([health]) did not probe with FALLBACK_SCAN_HOURS=%q", tc.fallbackHours)
			}

			marker := filepath.Join(t.TempDir(), ".healthy")
			if err := os.WriteFile(marker, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			aged := time.Now().Add(-tc.markerAge)
			if err := os.Chtimes(marker, aged, aged); err != nil {
				t.Fatal(err)
			}

			if got := health.ProbeCheck(marker, gotOpts...); got != tc.wantCode {
				t.Errorf("ProbeCheck(marker aged %v, opts from FALLBACK_SCAN_HOURS=%q) = %d, want %d",
					tc.markerAge, tc.fallbackHours, got, tc.wantCode)
			}
		})
	}
}

// TestDispatchArgs_health_probe_emits_no_startup_diagnostics pins the reason the
// FALLBACK_SCAN_HOURS diagnostics live in config.Load rather than in the parser:
// the health subcommand derives its marker lease from config.FallbackInterval on
// EVERY probe, which under Docker's healthcheck is roughly every 30 seconds for
// the life of the container. A misconfigured or above-ceiling value must not turn
// that into a repeating startup-shaped WARN. No t.Parallel: it swaps runProbe,
// slog.Default() and the environment.
func TestDispatchArgs_health_probe_emits_no_startup_diagnostics(t *testing.T) {
	for _, raw := range []string{"abc", "-1", "87601", "999999999999999999999999999999", "0", "12", ""} {
		t.Run("FALLBACK_SCAN_HOURS="+raw, func(t *testing.T) {
			t.Setenv("FALLBACK_SCAN_HOURS", raw)

			prev := runProbe
			runProbe = func(string, ...health.ProbeOption) {}
			t.Cleanup(func() { runProbe = prev })

			logs := capture.Default(t)

			_ = dispatchArgs([]string{"cert-watcher", "health"})

			if logs.Len() != 0 {
				t.Errorf("the health subcommand with FALLBACK_SCAN_HOURS=%q logged %v, want no records: "+
					"config diagnostics belong to startup, and this runs on every healthcheck",
					raw, logs.Messages())
			}
		})
	}
}

// captureStderr redirects os.Stderr to a temp file for the duration of fn and
// returns everything written to it. A temp file rather than an os.Pipe: a pipe
// blocks its writer once the buffer fills, which would deadlock the test.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = prev }()
	fn()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestDispatchArgs_usage_error_names_the_offending_argument pins the usage
// diagnostic, which is the only operator-visible output of the reject path: the
// rejected token is quoted back on stderr and the two usage lines follow it, so
// a mistyped HEALTHCHECK override is diagnosable from the container log instead
// of being a bare exit 2. It also pins that the reject path never probes.
// Serial (no t.Parallel): it swaps the process-global os.Stderr and runProbe.
func TestDispatchArgs_usage_error_names_the_offending_argument(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		wantParts []string
	}{
		{
			name:      "unrecognized argument is quoted back",
			args:      []string{"cert-watcher", "helth"},
			wantParts: []string{`unrecognized argument "helth"`, "usage: cert-watcher", "cert-watcher health"},
		},
		{
			name:      "trailing operands are quoted back",
			args:      []string{"cert-watcher", "health", "typo"},
			wantParts: []string{`unexpected trailing arguments ["typo"]`, "usage: cert-watcher", "cert-watcher health"},
		},
		{
			name:      "an unrecognized argument is named even with trailing operands",
			args:      []string{"cert-watcher", "helth", "now"},
			wantParts: []string{`unrecognized argument "helth"`, "usage: cert-watcher"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := runProbe
			runProbe = func(string, ...health.ProbeOption) {
				t.Error("a usage error must never probe the health marker")
			}
			t.Cleanup(func() { runProbe = prev })

			var code int
			out := captureStderr(t, func() { code = dispatchArgs(tc.args) })

			if code != exitUsage {
				t.Errorf("dispatchArgs(%q) = %d, want %d", tc.args, code, exitUsage)
			}
			for _, want := range tc.wantParts {
				if !strings.Contains(out, want) {
					t.Errorf("dispatchArgs(%q) stderr = %q, want it to contain %q", tc.args, out, want)
				}
			}
		})
	}
}

// TestReportWatchExit_announces_dead_change_detection_exactly_once pins the
// boundary decision this app makes about the loudest thing it ever says: main is
// the ONLY author of the dead-change-detection announcement, because main is
// what acts on it (exit 1 for a restart). internal/watch returns the condition
// and says nothing.
//
// The four contracts, all operator-visible:
//   - Exactly ONE ERROR record per dead-detection event. A second one, here or
//     in internal/watch, double-counts the CertConverterChangeDetectionDead
//     alert and lets the two wordings drift apart again.
//   - The message keeps the exact "change detection is dead" wording that alert
//     matches, and the specific loss travels in the error attr.
//   - The FALLBACK_SCAN_HOURS remediation still reaches the operator on every
//     loss that carries one (both disabled-fallback losses do), and is absent on
//     the paths that have none — a dead fsnotify fd is not something the operator
//     misconfigured.
//   - A shutdown (nil error) says only that it is shutting down, at Info. If it
//     announced dead change detection, every SIGTERM would fire a critical alert.
//
// Serial (no t.Parallel): it swaps the process-global slog default.
func TestReportWatchExit_announces_dead_change_detection_exactly_once(t *testing.T) {
	const deadMsg = "watcher stopped without a shutdown signal; change detection is dead, exiting for a restart"

	for _, tc := range []struct {
		name            string
		runErr          error
		wantCode        int
		wantRemediation string
	}{
		{
			name:            "the disabled-fallback loss carries its remediation",
			runErr:          &watch.LostError{Cause: "no fsnotify watch could be established and the periodic rescan is disabled", Remediation: "unset FALLBACK_SCAN_HOURS (or set it above 0)"},
			wantCode:        1,
			wantRemediation: "FALLBACK_SCAN_HOURS",
		},
		{
			name:     "a dead fsnotify channel has no remediation to give",
			runErr:   &watch.LostError{Cause: "the fsnotify events channel closed"},
			wantCode: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			if got := reportWatchExit(t.Context(), tc.runErr); got != tc.wantCode {
				t.Errorf("reportWatchExit(%v) = %d, want %d", tc.runErr, got, tc.wantCode)
			}

			if n := logs.CountLevel(slog.LevelError, ""); n != 1 {
				t.Fatalf("reportWatchExit(%v) logged %d ERROR records %v, want exactly 1: the alert counts lines, so a second announcement double-counts one event",
					tc.runErr, n, logs.Messages())
			}
			if n := logs.CountExact(deadMsg); n != 1 {
				t.Errorf("reportWatchExit(%v) logged %d records with the exact alerted message %q, want 1 (logs %v)",
					tc.runErr, n, deadMsg, logs.Messages())
			}
			if !logs.AttrContains(deadMsg, "error", "change detection lost") {
				t.Errorf("reportWatchExit(%v) ERROR does not name which loss occurred (logs %v)", tc.runErr, logs.Messages())
			}
			gotRemediation, hasRemediation := logs.AttrValue(deadMsg, "remediation")
			if tc.wantRemediation == "" {
				if hasRemediation {
					t.Errorf("reportWatchExit(%v) attached remediation %q, want none: nothing the operator configured caused this loss",
						tc.runErr, gotRemediation)
				}
				return
			}
			if !strings.Contains(gotRemediation, tc.wantRemediation) {
				t.Errorf("reportWatchExit(%v) remediation = %q, want it to name %q so the operator can fix the state that produced it",
					tc.runErr, gotRemediation, tc.wantRemediation)
			}
		})
	}

	t.Run("an error that is not a LostError still exits non-zero, announced once", func(t *testing.T) {
		logs := capture.Default(t)
		// The half the *LostError cases above cannot pin: reportWatchExit branches on
		// errors.As only to DECORATE the record with a remediation, so every non-nil
		// error must reach the same exit code and the same single announcement. This
		// case replaces the bare-sentinel one the ErrWatchLost removal deleted (l-f12),
		// which was the table's only error of another type — it cannot be a table row,
		// because the shared body asserts the error attr names "change detection lost",
		// which no foreign-typed error carries.
		runErr := errors.New("a loss shape this app does not model")

		if got := reportWatchExit(t.Context(), runErr); got != 1 {
			t.Errorf("reportWatchExit(%v) = %d, want 1: any non-shutdown exit is dead change detection, whatever the error's type", runErr, got)
		}
		if n := logs.CountLevel(slog.LevelError, ""); n != 1 {
			t.Fatalf("reportWatchExit(%v) logged %d ERROR records %v, want exactly 1: the alert counts lines", runErr, n, logs.Messages())
		}
		if n := logs.CountExact(deadMsg); n != 1 {
			t.Errorf("reportWatchExit(%v) logged %d records with the alerted message %q, want 1 (logs %v)", runErr, n, deadMsg, logs.Messages())
		}
		if got, has := logs.AttrValue(deadMsg, "remediation"); has {
			t.Errorf("reportWatchExit(%v) attached remediation %q, want none: only a *LostError carries one", runErr, got)
		}
	})

	t.Run("a shutdown says nothing about dead change detection", func(t *testing.T) {
		logs := capture.Default(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if got := reportWatchExit(ctx, nil); got != 0 {
			t.Errorf("reportWatchExit(nil) = %d, want 0: a clean shutdown is not a failure", got)
		}
		if n := logs.CountLevel(slog.LevelError, ""); n != 0 {
			t.Errorf("reportWatchExit(nil) logged %d ERROR records %v, want 0: a SIGTERM must not fire the critical dead-detection alert", n, logs.Messages())
		}
		if logs.Contains("change detection") {
			t.Errorf("reportWatchExit(nil) mentioned change detection in %v; the alert matcher would fire on a graceful stop", logs.Messages())
		}
		if n := logs.CountLevel(slog.LevelInfo, "shutting down"); n != 1 {
			t.Errorf("reportWatchExit(nil) logged %d INFO shutdown records %v, want 1 so the stop is still visible", n, logs.Messages())
		}
	})
}

// shutdownCause is a distinguishable cancellation cause: for a plain
// cancel(), context.Cause(ctx) and ctx.Err() both render as "context
// canceled", so a test built on cancel() cannot tell the two apart.
type shutdownCause struct{}

func (shutdownCause) Error() string { return "terminated-under-test" }

// TestReportWatchExit_shutdown_names_the_cancellation_cause pins the only
// operator-visible detail of the clean-shutdown path: the reason attr names
// WHICH signal stopped the container. reportWatchExit reports
// context.Cause(ctx), which signal.NotifyContext sets to the signal that was
// received; replacing it with ctx.Err() or dropping the attr turns every stop
// into an indistinguishable "context canceled" and leaves the rest of this
// file green.
// Serial (no t.Parallel): it swaps the process-global slog default.
func TestReportWatchExit_shutdown_names_the_cancellation_cause(t *testing.T) {
	logs := capture.Default(t)

	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(shutdownCause{})

	if got := reportWatchExit(ctx, nil); got != 0 {
		t.Fatalf("reportWatchExit(nil) = %d, want 0: a clean shutdown is not a failure", got)
	}
	if !logs.AttrContains("shutting down", "reason", "terminated-under-test") {
		t.Errorf("the shutdown record carries no cancellation cause in its reason attr, so an operator cannot tell which signal stopped the container; got logs %q", logs.Messages())
	}
}

func TestHealthyAfterScan(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   process.ScanResult
		want bool
	}{
		{"clean scan is healthy", process.ScanResult{Total: 3, Converted: 3}, true},
		{"conversion failure clears health", process.ScanResult{Total: 2, Converted: 1, Failed: 1}, false},
		{"unreadable path alone stays healthy", process.ScanResult{Total: 1, Converted: 1, Unreadable: 1}, true},
		{"failure stays unhealthy even with unreadable", process.ScanResult{Failed: 2, Unreadable: 3}, false},
		{"orphan-only scan stays healthy", process.ScanResult{Total: 1, Orphan: 1}, true},
		// The /output-side member of the health-neutral family: a prior bundle this app
		// could not replace, that it never proved wrong (its bytes matched, or it could not
		// read them at all), where the volume refused the write for a reason no restart
		// clears. No restart grants the UID ownership, frees a full volume or remounts a
		// read-only one, so restarting would loop forever on a condition it cannot clear —
		// the mistake the unreadable case above exists to avoid, in the shapes
		// TestScannerRun_when_the_repairing_rewrite_is_also_refused and
		// TestScannerRun_when_an_unverifiable_bundle_cannot_be_rewritten produce
		// (Unwritable 1, Failed 0). Those tests assert the counts; this one asserts what
		// health does with them.
		{"refused output replacement stays healthy", process.ScanResult{Total: 1, Unwritable: 1}, true},
		{"failure stays unhealthy even with unwritable", process.ScanResult{Total: 2, Failed: 1, Unwritable: 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := healthyAfterScan(&tc.in); got != tc.want {
				t.Errorf("healthyAfterScan(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestRun_argv_dispatch_precedes_the_log_level_diagnostic pins the ORDER of
// run()'s first two steps, which nothing else in this package can see: the
// invalid-LOG_LEVEL WARN sits BELOW the argv dispatch on purpose, because the
// health subcommand re-reads LOG_LEVEL on every probe (roughly every 30s under
// the image's HEALTHCHECK), so a WARN above the dispatch turns one startup line
// into a permanent stream. TestDispatchArgs_health_probe_emits_no_startup_diagnostics
// calls dispatchArgs directly and therefore cannot see the ordering at all:
// moving those three lines up in run() leaves this whole file green without
// this test.
//
// The unrecognized-argument path is the cheap way in: dispatchArgs returns
// exitUsage, so run() returns before it touches the health marker, the config,
// or the /input and /output mounts. Asserting the quoted usage line first is
// the precondition that keeps the absence assertion from passing vacuously.
// Serial (no t.Parallel): it uses t.Setenv and swaps os.Args, os.Stderr and the
// process-global slog default.
func TestRun_argv_dispatch_precedes_the_log_level_diagnostic(t *testing.T) {
	t.Setenv("LOG_LEVEL", "bogus")

	prevArgs, prevLogger := os.Args, slog.Default()
	os.Args = []string{"cert-watcher", "helth"}
	t.Cleanup(func() {
		os.Args = prevArgs
		slog.SetDefault(prevLogger)
	})

	var code int
	out := captureStderr(t, func() { code = run() })

	if code != exitUsage {
		t.Fatalf("run() with an unrecognized argument = %d, want %d; stderr %q", code, exitUsage, out)
	}
	if !strings.Contains(out, `unrecognized argument "helth"`) {
		t.Fatalf("precondition failed: run() never reached the argv dispatch; stderr %q", out)
	}
	if strings.Contains(out, "invalid LOG_LEVEL") {
		t.Errorf("run() diagnosed LOG_LEVEL before dispatching argv, so every health probe would reprint the startup WARN; stderr %q", out)
	}
}

func TestRun_startup_failure_diagnoses_the_configuration_and_exits_nonzero(t *testing.T) {
	t.Setenv("LOG_LEVEL", "bogus")
	// Unset rather than blank: PFX_PASSWORD_FILE="" is SET-but-blank, which is a
	// different documented case with its own WARN. The t.Setenv call first is
	// what registers the restore and marks the test as environment-mutating.
	for _, key := range []string{"PFX_PASSWORD", "PFX_PASSWORD_FILE", "PFX_ALLOW_EMPTY_PASSWORD"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}

	prevArgs, prevLogger := os.Args, slog.Default()
	os.Args = []string{"cert-watcher"}
	t.Cleanup(func() {
		os.Args = prevArgs
		slog.SetDefault(prevLogger)
	})

	var code int
	out := captureStderr(t, func() { code = run() })

	if code != 1 {
		t.Errorf("run() with an unusable PFX password = %d, want 1 so the orchestrator does not read the stop as a clean shutdown; stderr %q", code, out)
	}
	if !strings.Contains(out, "invalid configuration") {
		t.Errorf("run() refused to start without naming the configuration as the cause; stderr %q", out)
	}
	if !strings.Contains(out, "PFX_ALLOW_EMPTY_PASSWORD") {
		t.Errorf("the configuration ERROR does not carry the underlying cause, so an operator cannot tell WHICH setting is wrong; stderr %q", out)
	}
	if !strings.Contains(out, "invalid LOG_LEVEL") {
		t.Errorf("run() started the watcher path without diagnosing the invalid LOG_LEVEL, the only signal the value was misspelled; stderr %q", out)
	}
}

// TestRun_refuses_to_start_when_a_required_volume_is_missing pins the branch that
// ACTS on mounts.OpenMounts' verdict: run() must return 1 before it builds a scanner
// or a watcher, because starting anyway converts nothing and restart-loops
// forever on a condition a restart cannot clear. It also pins the startup INFO
// line, the operator's only statement of the effective configuration.
// Serial (no t.Parallel): it swaps os.Args, os.Stderr, slog.Default() and the
// requiredVolumes seam, and uses t.Setenv.
func TestRun_refuses_to_start_when_a_required_volume_is_missing(t *testing.T) {
	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("PFX_PASSWORD", "test-password")
	for _, key := range []string{"PFX_PASSWORD_FILE", "PFX_ALLOW_EMPTY_PASSWORD"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}

	absentOutput := filepath.Join(t.TempDir(), "absent-output")
	prevArgs, prevLogger, prevVolumes := os.Args, slog.Default(), requiredVolumes
	os.Args = []string{"cert-watcher"}
	requiredVolumes = []mounts.Mount{
		{Role: mounts.RoleInput, Path: t.TempDir()},
		{Role: mounts.RoleOutput, Path: absentOutput},
	}
	t.Cleanup(func() {
		os.Args = prevArgs
		slog.SetDefault(prevLogger)
		requiredVolumes = prevVolumes
	})

	// run() is called on a goroutine with a deadline because the failure mode
	// under test is "it started the watcher anyway": w.Run blocks until a signal
	// arrives, so a dropped guard would hang this test instead of failing it.
	var code int
	returned := make(chan int, 1)
	out := captureStderr(t, func() {
		go func() { returned <- run() }()
		select {
		case code = <-returned:
		case <-time.After(10 * time.Second):
			t.Error("run() did not return with a missing output mount: it started the watcher instead of refusing")
		}
	})

	if code != 1 {
		t.Errorf("run() with a missing output mount = %d, want 1: starting anyway converts nothing and restart-loops forever; stderr %q", code, out)
	}
	if !strings.Contains(out, "required volume is missing or not a directory") {
		t.Fatalf("precondition failed: run() never reached the volume guard; stderr %q", out)
	}
	if !strings.Contains(out, absentOutput) {
		t.Errorf("the refusal does not name the missing path, so the operator cannot fix it; stderr %q", out)
	}
	// The startup line is the operator's only statement of the effective
	// configuration; every attr below is a setting they could have got wrong.
	if !strings.Contains(out, "starting cert watcher") {
		t.Fatalf("precondition failed: run() refused before it loaded the configuration; stderr %q", out)
	}
	for _, attr := range []string{"password", "fallback_scan", "scan_floor", "encoder", "output_lifecycle", "max_scan_entries"} {
		if !strings.Contains(out, attr) {
			t.Errorf("the startup line omits %q, so the effective configuration is not observable; stderr %q", attr, out)
		}
	}
}

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
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

// --- Tests: runAndSetHealth ---

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

func TestScanAndSetHealth_unreadable_subdir_stays_healthy(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("chmod 0 does not block root / differs on Windows")
	}
	marker, markerPath := newTestMarker(t)
	marker.Set(false) // start unhealthy; a failure-free scan must restore health
	inDir, outDir := t.TempDir(), t.TempDir()
	scanner := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "good", "ecdsa")
	writeCertAndKey(t, inDir, "good", certPEM, keyPEM)
	bad := filepath.Join(inDir, "blocked")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o755) })
	// Establish the precondition (the blocked subdir really is unreadable) with a
	// throwaway scanner, then drive the production wiring itself so the WARN branch
	// and the marker decision in scanAndSetHealth are the code under test.
	precheck := newTestScanner(inDir, outDir, "", convert.EncNameModern2023)
	result, err := precheck.Run(context.Background())
	if err != nil {
		t.Fatalf("scan should not error on an unreadable subdir: %v", err)
	}
	if result.Unreadable == 0 {
		t.Fatal("expected Unreadable > 0 from the blocked subdir (test precondition)")
	}
	// The remediation hint is the only observable effect of the Unreadable
	// branch, so capture the default logger to pin it. slog.Default is
	// process-global; this test is deliberately serial (no t.Parallel).
	logs := capture.Default(t)

	scanAndSetHealth(t.Context(), scanner, marker)

	if logs.CountLevel(slog.LevelWarn, "unreadable") == 0 {
		t.Errorf("scanAndSetHealth should WARN about unreadable /input paths; got logs %q", logs.Messages())
	}
	if _, statErr := os.Stat(markerPath); statErr != nil {
		t.Fatalf("marker must stay healthy when only Unreadable>0 and no conversion failed: %v", statErr)
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

// TestFallbackLogValue pins the startup log's rendering of the fallback
// cadence, the one operator-visible decision left in run(): a disabled
// rescan must read "disabled", never a bare "0s".
func TestFallbackLogValue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   time.Duration
		want string
	}{
		{"explicit zero is disabled", 0, "disabled"},
		{"negative is disabled", -1 * time.Hour, "disabled"},
		{"default cadence", 6 * time.Hour, "6h0m0s"},
		{"one hour", 1 * time.Hour, "1h0m0s"},
		{"clamp ceiling", 87600 * time.Hour, "87600h0m0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := fallbackLogValue(tc.in); got != tc.want {
				t.Errorf("fallbackLogValue(%v) = %q, want %q", tc.in, got, tc.want)
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
// subcommand hands the probe: three fallback intervals (18h on the default 6h
// cadence), and no deadline at all when FALLBACK_SCAN_HOURS disables the
// fallback rescan, because watch-only mode has no guaranteed refresh cadence.
// The captured options are applied with health.ProbeCheck to markers whose
// mtimes straddle the deadline, so a wrong multiplier or a dropped option fails
// here rather than in production. No t.Parallel: it swaps runProbe and mutates
// the environment.
func TestDispatchArgs_arms_the_marker_lease(t *testing.T) {
	for _, tc := range []struct {
		name          string
		fallbackHours string
		markerAge     time.Duration
		wantCode      int
	}{
		{"default cadence keeps a marker inside the 18h lease healthy", "", 17 * time.Hour, 0},
		{"default cadence fails a marker past the 18h lease", "", 19 * time.Hour, 1},
		{"a disabled fallback disarms the lease entirely", "0", 100 * time.Hour, 0},
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := healthyAfterScan(tc.in); got != tc.want {
				t.Errorf("healthyAfterScan(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestVolumesReady pins the startup volume guard, the one decision in run()
// that decides between a single actionable refusal and an endless
// restart-unhealthy loop: every required mount must already exist AND be a
// directory, the first offender is named at ERROR with its role and a
// remediation, and a fully-mounted pair starts silently. Serial: it swaps
// slog.Default().
func TestVolumesReady(t *testing.T) {
	existingDir := t.TempDir()
	regularFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(regularFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "absent")

	for _, tc := range []struct {
		name     string
		dirs     []volumeDir
		want     bool
		wantRole string
	}{
		{"both mounted", []volumeDir{{"input", existingDir}, {"output", existingDir}}, true, ""},
		{"missing input", []volumeDir{{"input", absent}, {"output", existingDir}}, false, "input"},
		{"missing output", []volumeDir{{"input", existingDir}, {"output", absent}}, false, "output"},
		{"input is a regular file", []volumeDir{{"input", regularFile}, {"output", existingDir}}, false, "input"},
		{"output is a regular file", []volumeDir{{"input", existingDir}, {"output", regularFile}}, false, "output"},
		{"no volumes required", nil, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)

			if got := volumesReady(tc.dirs); got != tc.want {
				t.Errorf("volumesReady(%+v) = %v, want %v", tc.dirs, got, tc.want)
			}
			if tc.want {
				if logs.Len() != 0 {
					t.Errorf("volumesReady(%+v) logged %v, want silence when every volume is mounted", tc.dirs, logs.Messages())
				}
				return
			}
			const msg = "required volume is missing or not a directory"
			if n := logs.CountLevel(slog.LevelError, msg); n != 1 {
				t.Fatalf("volumesReady(%+v) logged %d ERROR records matching %q, want exactly 1 (logs %v)",
					tc.dirs, n, msg, logs.Messages())
			}
			if !logs.AttrContains(msg, "role", tc.wantRole) {
				t.Errorf("volumesReady(%+v) ERROR does not name role %q (logs %v)", tc.dirs, tc.wantRole, logs.Messages())
			}
			if !logs.AttrContains(msg, "remediation", "mount ") {
				t.Errorf("volumesReady(%+v) ERROR is missing an actionable remediation attr (logs %v)", tc.dirs, logs.Messages())
			}
		})
	}
}

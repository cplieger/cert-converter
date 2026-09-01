package process_test

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/slogx/capture"
)

// newExcludingScanner is newFormatScanner plus an exclude set, for the sub-tree
// scoping tests.
func newExcludingScanner(input, output string, exclude layout.ExcludeSet, lifecycle outputpolicy.Lifecycle) *process.Scanner {
	return process.New(&process.Options{
		CertsRoot:       input,
		OutRoot:         output,
		Password:        "output-password",
		Encoder:         convert.EncNameModern2023,
		Formats:         outputpolicy.Formats{PFX: true},
		FormatsExplicit: true,
		Layout:          outputpolicy.LayoutFlat,
		LayoutExplicit:  true,
		Lifecycle:       lifecycle,
		Exclude:         exclude,
	})
}

// TestScannerRun_excludedSubtreeIsNotConverted pins the feature's whole point:
// a source under an excluded directory produces no artifact, while every source
// outside it converts normally.
func TestScannerRun_excludedSubtreeIsNotConverted(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	wantedCert, wantedKey := testcerts.GenerateSelfSignedCert(t, "wanted.example.com", "ecdsa")
	skippedCert, skippedKey := testcerts.GenerateSelfSignedCert(t, "client-identity.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "server"), "wanted", wantedCert, wantedKey)
	writePEMSource(t, filepath.Join(input, "clients"), "identity", skippedCert, skippedKey)
	scanner := newExcludingScanner(input, output, layout.NewExcludeSet([]string{"clients"}), outputpolicy.LifecycleWarn)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(excluded subtree) = %v", err)
	}
	if result.Converted != 1 || result.Excluded != 1 || result.Failed != 0 {
		t.Fatalf("Run(excluded subtree) = %+v, want Converted 1 Excluded 1 Failed 0", result)
	}
	assertOnlyRegularFiles(t, output, []string{filepath.Join("server", "wanted.pfx")})
	assertPFXCommonName(t, filepath.Join(output, "server", "wanted.pfx"), "output-password", "wanted.example.com")
}

// TestScannerRun_excludingASourceRespectsTheLifecycleMode is the mode contract
// for a path excluded AFTER it had already converted. An exclusion narrows the
// scope this app manages, exactly as switching a format off or changing the
// layout does, so its stranded artifacts are ordinary orphan candidates and
// OUTPUT_LIFECYCLE decides their fate. The invariant across every row: only
// sync ever deletes.
func TestScannerRun_excludingASourceRespectsTheLifecycleMode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        outputpolicy.Lifecycle
		wantRemoved int
		wantPresent bool
		wantReport  bool
	}{
		{name: "keep is silent and deletes nothing", mode: outputpolicy.LifecycleKeep, wantPresent: true},
		{name: "warn reports and deletes nothing", mode: outputpolicy.LifecycleWarn, wantPresent: true, wantReport: true},
		{name: "sync reconciles the excluded artifact away", mode: outputpolicy.LifecycleSync, wantRemoved: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := t.TempDir()
			output := t.TempDir()
			keptCert, keptKey := testcerts.GenerateSelfSignedCert(t, "still-converted.example.com", "ecdsa")
			laterExcluded, laterExcludedKey := testcerts.GenerateSelfSignedCert(t, "later-excluded.example.com", "ecdsa")
			writePEMSource(t, filepath.Join(input, "server"), "kept", keptCert, keptKey)
			writePEMSource(t, filepath.Join(input, "clients"), "identity", laterExcluded, laterExcludedKey)

			// Convert both first, so /output holds an artifact for the path the
			// second scan excludes.
			seed := newExcludingScanner(input, output, layout.ExcludeSet{}, tc.mode)
			if result, err := seed.Run(t.Context()); err != nil || result.Converted != 2 {
				t.Fatalf("Run(before exclusion) = (%+v, %v), want Converted 2 and nil", result, err)
			}
			excludedArtifact := filepath.Join(output, "clients", "identity.pfx")
			if _, statErr := os.Stat(excludedArtifact); statErr != nil {
				t.Fatalf("setup: the artifact under test was not written: %v", statErr)
			}
			logs := capture.Default(t)

			after := newExcludingScanner(input, output, layout.NewExcludeSet([]string{"clients"}), tc.mode)
			result, err := after.Run(t.Context())
			if err != nil {
				t.Fatalf("Run(after exclusion, %s) = %v", tc.mode, err)
			}
			if result.Excluded != 1 {
				t.Fatalf("Run(after exclusion, %s) = %+v, want Excluded 1", tc.mode, result)
			}
			if result.Removed != tc.wantRemoved {
				t.Errorf("Run(after exclusion, %s) Removed = %d, want %d", tc.mode, result.Removed, tc.wantRemoved)
			}
			_, statErr := os.Stat(excludedArtifact)
			if tc.wantPresent && statErr != nil {
				t.Errorf("OUTPUT_LIFECYCLE=%s deleted an artifact; only sync may ever delete: %v", tc.mode, statErr)
			}
			if !tc.wantPresent && !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("os.Stat(excluded artifact) = %v, want it reconciled away under sync", statErr)
			}
			// The source itself is never touched, in any mode.
			assertFileBytes(t, filepath.Join(input, "clients", "identity.crt"), laterExcluded)
			// The still-converted source keeps its artifact in every mode.
			if _, keptErr := os.Stat(filepath.Join(output, "server", "kept.pfx")); keptErr != nil {
				t.Errorf("the still-converted source lost its artifact under %s: %v", tc.mode, keptErr)
			}
			const reported = "output artifacts have no matching input"
			if got := logs.CountLevel(slog.LevelWarn, reported) > 0; got != tc.wantReport {
				t.Errorf("Run(after exclusion, %s) reported stranded artifacts = %v, want %v: %v",
					tc.mode, got, tc.wantReport, logs.Messages())
			}
		})
	}
}

// TestScannerRun_excludingASourceRespectsTheLifecycleModeInMirrorLayout is the
// mirror-layout twin, and it also answers the directory question: sync removes
// the artifact FILES it wrote and never the mirrored directory, because the
// reaper unlinks regular files only.
func TestScannerRun_excludingASourceRespectsTheLifecycleModeInMirrorLayout(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        outputpolicy.Lifecycle
		wantRemoved int
		wantPresent bool
	}{
		{name: "warn keeps all three artifacts", mode: outputpolicy.LifecycleWarn, wantPresent: true},
		{name: "sync removes all three artifacts", mode: outputpolicy.LifecycleSync, wantRemoved: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := t.TempDir()
			output := t.TempDir()
			keptCert, keptKey := testcerts.GenerateSelfSignedCert(t, "mirror-kept.example.com", "ecdsa")
			excludedCert, excludedKey := testcerts.GenerateSelfSignedCert(t, "mirror-excluded.example.com", "ecdsa")
			writePEMSource(t, filepath.Join(input, "server"), "kept", keptCert, keptKey)
			writePEMSource(t, filepath.Join(input, "clients", "eu"), "identity", excludedCert, excludedKey)

			mirrorScanner := func(exclude layout.ExcludeSet) *process.Scanner {
				return process.New(&process.Options{
					CertsRoot: input, OutRoot: output, Password: "output-password",
					Encoder: convert.EncNameModern2023, Formats: outputpolicy.Formats{PFX: true, PEM: true},
					FormatsExplicit: true, Layout: outputpolicy.LayoutMirror, LayoutExplicit: true,
					Lifecycle: tc.mode, Exclude: exclude,
				})
			}
			if result, err := mirrorScanner(layout.ExcludeSet{}).Run(t.Context()); err != nil || result.Converted != 2 {
				t.Fatalf("Run(mirror, before exclusion) = (%+v, %v), want Converted 2 and nil", result, err)
			}
			excludedDir := filepath.Join(output, "clients", "eu")
			artifacts := []string{"identity.pfx", "identity.crt", "identity.key"}
			for _, name := range artifacts {
				if _, statErr := os.Stat(filepath.Join(excludedDir, name)); statErr != nil {
					t.Fatalf("setup: %s was not written: %v", name, statErr)
				}
			}

			result, err := mirrorScanner(layout.NewExcludeSet([]string{"clients"})).Run(t.Context())
			if err != nil {
				t.Fatalf("Run(mirror, after exclusion, %s) = %v", tc.mode, err)
			}
			if result.Removed != tc.wantRemoved || result.Excluded != 1 {
				t.Errorf("Run(mirror, after exclusion, %s) = %+v, want Removed %d Excluded 1", tc.mode, result, tc.wantRemoved)
			}
			for _, name := range artifacts {
				_, statErr := os.Stat(filepath.Join(excludedDir, name))
				if tc.wantPresent && statErr != nil {
					t.Errorf("OUTPUT_LIFECYCLE=%s deleted %s; only sync may ever delete: %v", tc.mode, name, statErr)
				}
				if !tc.wantPresent && !errors.Is(statErr, fs.ErrNotExist) {
					t.Errorf("os.Stat(%s) = %v, want it reconciled away under sync", name, statErr)
				}
			}
			// The mirrored directory itself survives either way: this app unlinks
			// the regular files it wrote and never removes a directory.
			if info, statErr := os.Stat(excludedDir); statErr != nil || !info.IsDir() {
				t.Errorf("os.Stat(%s) = (%v, %v), want the mirrored output directory left in place", excludedDir, info, statErr)
			}
		})
	}
}

// TestScannerRun_excludedPathDoesNotDisableOrphanCleanup pins the difference
// from the permissions workaround this feature replaces: an exclusion is an
// operator assertion about scope, not a coverage hole, so sync keeps reaping
// normally. An unreadable path would disable cleanup for the whole scan and
// leave the genuine orphan in place; an exclusion does not.
func TestScannerRun_excludedPathDoesNotDisableOrphanCleanup(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	keptCert, keptKey := testcerts.GenerateSelfSignedCert(t, "anchor.example.com", "ecdsa")
	goneCert, goneKey := testcerts.GenerateSelfSignedCert(t, "gone.example.com", "ecdsa")
	excludedCert, excludedKey := testcerts.GenerateSelfSignedCert(t, "excluded.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "server"), "anchor", keptCert, keptKey)
	writePEMSource(t, filepath.Join(input, "server"), "gone", goneCert, goneKey)
	writePEMSource(t, filepath.Join(input, "clients"), "identity", excludedCert, excludedKey)

	seed := newExcludingScanner(input, output, layout.ExcludeSet{}, outputpolicy.LifecycleSync)
	if result, err := seed.Run(t.Context()); err != nil || result.Converted != 3 {
		t.Fatalf("Run(seed, no exclusion) = (%+v, %v), want Converted 3 and nil", result, err)
	}
	for _, name := range []string{"gone.crt", "gone.key"} {
		if err := os.Remove(filepath.Join(input, "server", name)); err != nil {
			t.Fatalf("remove %s: %v", name, err)
		}
	}

	scanner := newExcludingScanner(input, output, layout.NewExcludeSet([]string{"clients"}), outputpolicy.LifecycleSync)
	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(with exclusion, sync) = %v", err)
	}
	if result.Excluded != 1 {
		t.Fatalf("Run(with exclusion, sync) = %+v, want Excluded 1", result)
	}
	// The genuine orphan is reaped, which an unreadable path would have blocked.
	// Under the flat layout these sources sit one directory down, so the stem
	// keeps that directory: server/gone.crt emits server/gone.pfx.
	if _, statErr := os.Stat(filepath.Join(output, "server", "gone.pfx")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(gone artifact) = %v, want the genuine orphan reaped: an exclusion must not disable orphan cleanup the way an unreadable path does", statErr)
	}
	// The still-converted source keeps its artifact.
	if _, statErr := os.Stat(filepath.Join(output, "server", "anchor.pfx")); statErr != nil {
		t.Errorf("the live source's artifact was reaped: %v", statErr)
	}
	// And no standing warning claims the input tree could not be enumerated,
	// which is exactly what the permissions workaround produces.
	const disabled = "orphan removal is disabled for this scan"
	logs := capture.Default(t)
	if _, err := scanner.Run(t.Context()); err != nil {
		t.Fatalf("Run(third, steady state) = %v", err)
	}
	if count := logs.CountLevel(slog.LevelWarn, disabled); count != 0 {
		t.Errorf("a scan with exclusions reported %q %d times, want 0: %v", disabled, count, logs.Messages())
	}
}

// TestScannerRun_excludedCertDoesNotShadowItsSiblingBundle pins precedence
// against the exclude set: shadowing is decided among the sources this app will
// actually convert, so excluding one spelling of a stem must not strand the
// other.
func TestScannerRun_excludedCertDoesNotShadowItsSiblingBundle(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	pairCert, pairKey := testcerts.GenerateSelfSignedCert(t, "excluded-pair.example.com", "ecdsa")
	bundleCert, bundleKey := testcerts.GenerateSelfSignedCert(t, "surviving-bundle.example.com", "ecdsa")
	writePEMSource(t, input, "site", pairCert, pairKey)
	writePFXSource(t, input, "site.pfx", bundleCert, bundleKey, "input-password", convert.EncNameModern2023)
	scanner := process.New(&process.Options{
		CertsRoot:          input,
		OutRoot:            output,
		Password:           "output-password",
		InputPassword:      "input-password",
		InputPasswordReady: true,
		Encoder:            convert.EncNameModern2023,
		Formats:            outputpolicy.Formats{PFX: true},
		FormatsExplicit:    true,
		Layout:             outputpolicy.LayoutFlat,
		LayoutExplicit:     true,
		Exclude:            layout.NewExcludeSet([]string{"site.crt"}),
	})

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(excluded cert beside bundle) = %v", err)
	}
	if result.Converted != 1 || result.Excluded != 1 || result.Collided != 0 {
		t.Fatalf("Run(excluded cert beside bundle) = %+v, want Converted 1 Excluded 1 Collided 0", result)
	}
	assertPFXCommonName(t, filepath.Join(output, "site.pfx"), "output-password", "surviving-bundle.example.com")
}

// TestScannerRun_excludingEverySourceIsReported pins the over-broad-exclusion
// diagnostic: a scan that excludes everything produces nothing while reporting
// no failure, which the summary counts alone cannot distinguish from a healthy
// steady state.
func TestScannerRun_excludingEverySourceIsReported(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "all-excluded.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "clients"), "identity", certPEM, keyPEM)
	scanner := newExcludingScanner(input, output, layout.NewExcludeSet([]string{"clients"}), outputpolicy.LifecycleWarn)
	logs := capture.Default(t)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(everything excluded) = %v", err)
	}
	if result.Excluded != 1 || result.Total != 1 || result.Converted != 0 {
		t.Fatalf("Run(everything excluded) = %+v, want Excluded 1 Total 1 Converted 0", result)
	}
	assertOnlyRegularFiles(t, output, nil)
	const msg = "every certificate source under the input root is excluded"
	if count := logs.CountLevel(slog.LevelWarn, msg); count != 1 {
		t.Errorf("Run(everything excluded) logged %q %d times, want 1: %v", msg, count, logs.Messages())
	}
}

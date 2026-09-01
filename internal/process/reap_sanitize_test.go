package process

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

// TestStoreReconcile_sanitizes_output_derived_names_in_log_attributes is the reap-side
// oracle for the path-attribute-runesafe-adoption decision, and the /output half that
// TestScannerRun_sanitizes_walk_supplied_names_in_log_attributes cannot reach: that test
// drives names supplied by the /input walk, while every name in a reap record is derived
// from the OUTPUT tree's own enumeration -- a tree a co-writer chooses the names in.
//
// What it pins, and what breaks without it: dropping logtext.Path from sampleOrphanPaths
// or from keyStillPresent's two WARNs leaves every other test in this package green,
// because every orphan fixture elsewhere carries an ordinary name and sanitizing is
// byte-identical for those.
//
// The property is about the ATTRIBUTE VALUE, not about the rendered line. slog's
// TextHandler quotes and escapes both injected runes on its way out, so no name can forge
// a record through the handler this app installs; what sanitizing buys is that the value
// is already single-line and reorder-free before any handler sees it (a JSON handler
// passes a bidi override through raw) and that an operator reading the attribute reads
// the path the record names.
//
// Warn mode, the default, is what emits both records in one scan: the orphan report
// carries the sample, and the retention loop reaches keyStillPresent for the same
// candidate, whose sibling key this fixture leaves in place.
//
// Runs serially: it swaps slog.Default().
func TestStoreReconcile_sanitizes_output_derived_names_in_log_attributes(t *testing.T) {
	outDir, inDir := t.TempDir(), t.TempDir()
	rawBundle := hostileStem + ".pfx"
	rawCert := layout.CertFor(layout.OutputStem(rawBundle))
	if err := os.WriteFile(filepath.Join(outDir, rawBundle), []byte("pfx"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(%q): %v", rawBundle, err)
	}
	// The sibling key with no certificate: the lone-key retention, so keyStillPresent's
	// WARN names the hostile path too.
	if err := os.WriteFile(filepath.Join(inDir, layout.KeyFor(rawCert)), []byte("key"), 0o600); err != nil {
		t.Fatalf("setup: WriteFile(key): %v", err)
	}
	wantSanitized := logtext.Path(rawBundle)
	if wantSanitized == rawBundle {
		t.Fatalf("the fixture name %q survives sanitizing unchanged, so this test asserts nothing", rawBundle)
	}

	logs := captureLogs(t)
	deleted, err := newReaper(newOutputStore(t, outDir), newInputSource(t, inDir), outputpolicy.LifecycleWarn).
		reconcile(t.Context(), map[string]struct{}{}, &reapContext{
			result: ScanResult{Total: 1}, walkCompleted: true,
		})
	if err != nil {
		t.Fatalf("reconcile = error %v, want nil", err)
	}
	if deleted != 0 {
		t.Errorf("reconcile(warn mode) deleted = %d, want 0", deleted)
	}

	const orphanMsg = "output artifacts have no matching input"
	if !logs.HasAttr(orphanMsg, "paths", wantSanitized) {
		got, _ := logs.AttrValue(orphanMsg, "paths")
		t.Errorf("orphan report paths = %q, want the /output-derived name sanitized to %q", got, wantSanitized)
	}
	if !logs.HasAttr(loneKeyRetainedMsg, "path", wantSanitized) {
		got, _ := logs.AttrValue(loneKeyRetainedMsg, "path")
		t.Errorf("lone-key report path = %q, want %q", got, wantSanitized)
	}
	if want := logtext.Path(rawCert); !logs.HasAttr(loneKeyRetainedMsg, "input", want) {
		got, _ := logs.AttrValue(loneKeyRetainedMsg, "input")
		t.Errorf("lone-key report input = %q, want %q", got, want)
	}
	if want := logtext.Path(layout.KeyFor(rawCert)); !logs.HasAttr(loneKeyRetainedMsg, "key", want) {
		got, _ := logs.AttrValue(loneKeyRetainedMsg, "key")
		t.Errorf("lone-key report key = %q, want %q", got, want)
	}
	// Wider than the records named above: this scan's reap emits the same walk-supplied
	// name in several places, so a gate applied at only the sites a test names is exactly
	// the partial adoption that leaves the rest of them forgeable.
	assertNoUnsafeRunesInAttributes(t, logs)

	// The gate is at the log call and nowhere upstream: the bundle is still addressed by
	// its real bytes, so a sanitized value never reached a stat, a join or a map key.
	if _, statErr := os.Lstat(filepath.Join(outDir, rawBundle)); statErr != nil {
		t.Errorf("Lstat(%q) = %v, want the bundle still at its RAW name: sanitizing must not reach a filesystem decision",
			rawBundle, statErr)
	}
}

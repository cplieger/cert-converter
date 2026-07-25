package process

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestParseLifecycle pins the knob's normalisation, including that an
// unrecognised value falls back to the SAFE mode rather than the destructive one.
func TestParseLifecycle(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw       string
		want      Lifecycle
		wantKnown bool
	}{
		{"", LifecycleWarn, true},
		{"warn", LifecycleWarn, true},
		{"  SYNC  ", LifecycleSync, true},
		{"Keep", LifecycleKeep, true},
		{"delete", LifecycleWarn, false},
		{"true", LifecycleWarn, false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, known := ParseLifecycle(tc.raw)
			if got != tc.want || known != tc.wantKnown {
				t.Errorf("ParseLifecycle(%q) = (%q, %v), want (%q, %v)", tc.raw, got, known, tc.want, tc.wantKnown)
			}
		})
	}
}

// TestStoreReconcile pins every rail on orphan deletion. Each case is a way the
// gate must refuse, because getting a deletion wrong destroys private key material
// and the documented deployment replicates the output tree onward to a second host.
func TestStoreReconcile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		mode        Lifecycle
		rc          reapContext
		wantDeleted int
		wantPresent bool
	}{
		{
			name: "sync removes an orphan after a clean complete scan",
			mode: LifecycleSync, rc: reapContext{scanTotal: 1, walkCompleted: true},
			wantDeleted: 1, wantPresent: false,
		},
		{
			// The rail that matters most: an /input mounted empty but READABLE
			// produces a clean, complete walk, so without this the first scan after
			// a slow or wrong mount would delete every bundle.
			name: "sync refuses when the scan found no pairs at all",
			mode: LifecycleSync, rc: reapContext{scanTotal: 0, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "sync refuses when the walk did not complete",
			mode: LifecycleSync, rc: reapContext{scanTotal: 1, walkCompleted: false},
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "sync refuses when a sub-path was unreadable",
			mode: LifecycleSync, rc: reapContext{scanTotal: 1, unreadable: 1, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			// An input symlink the confined root cannot resolve may hide certificates,
			// so `seen` is incomplete even though the walk reported no error and
			// nothing was unreadable. Reproduced as a live-bundle deletion.
			name: "sync refuses when an input symlink could not be resolved",
			mode: LifecycleSync, rc: reapContext{scanTotal: 1, unresolved: 1, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			// The design promised this rail and the first implementation dropped it: a
			// scan already failing conversions must not also delete.
			name: "sync refuses when a conversion failed",
			mode: LifecycleSync, rc: reapContext{scanTotal: 1, failed: 1, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "warn, the default, reports but never deletes",
			mode: LifecycleWarn, rc: reapContext{scanTotal: 1, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "keep is silent and never deletes",
			mode: LifecycleKeep, rc: reapContext{scanTotal: 1, walkCompleted: true},
			wantDeleted: 0, wantPresent: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			// One orphan (no matching input) and one live bundle whose input is in seen.
			for _, name := range []string{"orphan.pfx", "live.pfx"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("pfx"), 0o600); err != nil {
					t.Fatalf("setup: WriteFile(%s): %v", name, err)
				}
			}
			// A file that is not an output at all must never be a candidate.
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
				t.Fatalf("setup: WriteFile(notes.txt): %v", err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("setup: os.OpenRoot: %v", err)
			}
			defer root.Close()
			s := &store{root: root}
			seen := map[string]struct{}{"live.crt": {}}

			got := s.reconcile(tc.mode, seen, tc.rc)
			if got != tc.wantDeleted {
				t.Errorf("reconcile = %d deleted, want %d", got, tc.wantDeleted)
			}

			_, orphanErr := os.Stat(filepath.Join(dir, "orphan.pfx"))
			if present := orphanErr == nil; present != tc.wantPresent {
				t.Errorf("orphan.pfx present = %v, want %v", present, tc.wantPresent)
			}
			// The live bundle and the unrelated file must survive every mode.
			if _, err := os.Stat(filepath.Join(dir, "live.pfx")); err != nil {
				t.Errorf("live.pfx was removed; its input is present in seen: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
				t.Errorf("notes.txt was removed; only the app's own output shape may be a candidate: %v", err)
			}
		})
	}
}

// TestStoreIsCurrent_rewrites_on_an_encoder_change pins the currency half of the
// preflight, which is the reason it exists.
//
// A bundle's leaf, key and chain are unchanged by a PFX_ENCODER switch, so
// comparing only those reports the bundle CURRENT and the operator's deliberate
// change silently applies to nothing: every file keeps its old algorithms while the
// startup log announces the new profile, until some certificate happens to renew.
func TestStoreIsCurrent_rewrites_on_an_encoder_change(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}

	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()
	s := &store{root: root}

	written, err := convert.Encode(&analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if err := s.write(t.Context(), "out.pfx", written); err != nil {
		t.Fatalf("setup: write: %v", err)
	}

	// Same configured profile: current, nothing to do.
	current, err := s.isCurrent(t.Context(), "out.pfx", &analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("isCurrent(same profile) = error %v, want nil", err)
	}
	if !current {
		t.Error("isCurrent(same profile) = false, want true: nothing about this bundle changed")
	}

	// Every other profile must read as stale, including the sibling that shares an
	// encryption algorithm (modern2026) and the sibling that shares a MAC (legacyrc2
	// vs legacydes) — the pair of fields is what discriminates them.
	for _, other := range []convert.EncoderType{
		convert.EncNameModern2026,
		convert.EncNameLegacyDES,
		convert.EncNameLegacyRC2,
	} {
		t.Run(string(other), func(t *testing.T) {
			current, err := s.isCurrent(t.Context(), "out.pfx", &analysis, other, "pw")
			if err != nil {
				t.Fatalf("isCurrent(configured %s) = error %v, want nil", other, err)
			}
			if current {
				t.Errorf("isCurrent(configured %s over a modern2023 bundle) = true, want false: the encoder change must take effect", other)
			}
		})
	}
}

// concatPEM joins PEM blobs. Duplicated from the convert test package because the
// two live in different packages and a shared test helper module is not worth it.
func concatPEM(blobs ...[]byte) []byte {
	var out []byte
	for _, b := range blobs {
		out = append(out, b...)
	}
	return out
}

package process

import (
	"os"
	"path/filepath"
	"testing"
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
		scanTotal   int
		unreadable  int
		walkDone    bool
		wantDeleted int
		wantPresent bool
	}{
		{
			name: "sync removes an orphan after a clean complete scan",
			mode: LifecycleSync, scanTotal: 1, walkDone: true,
			wantDeleted: 1, wantPresent: false,
		},
		{
			// The rail that matters most: an /input mounted empty but READABLE
			// produces a clean, complete walk, so without this the first scan after
			// a slow or wrong mount would delete every bundle.
			name: "sync refuses when the scan found no pairs at all",
			mode: LifecycleSync, scanTotal: 0, walkDone: true,
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "sync refuses when the walk did not complete",
			mode: LifecycleSync, scanTotal: 1, walkDone: false,
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "sync refuses when a sub-path was unreadable",
			mode: LifecycleSync, scanTotal: 1, unreadable: 1, walkDone: true,
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "warn, the default, reports but never deletes",
			mode: LifecycleWarn, scanTotal: 1, walkDone: true,
			wantDeleted: 0, wantPresent: true,
		},
		{
			name: "keep is silent and never deletes",
			mode: LifecycleKeep, scanTotal: 1, walkDone: true,
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

			got := s.reconcile(tc.mode, seen, tc.scanTotal, tc.unreadable, tc.walkDone)
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

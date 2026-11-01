package mounts

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOverlap_detectsAliasedDirectoryTrees drives Overlap against the running
// process's own /proc/self/mountinfo, so it needs Linux.
func TestOverlap_detectsAliasedDirectoryTrees(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	dir := filepath.Join(base, "certs")
	nested := filepath.Join(dir, "issuer")
	sibling := filepath.Join(base, "output")
	alias := filepath.Join(base, "alias")
	for _, d := range []string{nested, sibling} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("setup: mkdir %s: %v", d, err)
		}
	}
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatalf("setup: symlink: %v", err)
	}

	for _, tc := range []struct {
		name        string
		a, b        string
		wantOverlap bool
	}{
		{name: "same directory", a: dir, b: dir, wantOverlap: true},
		{name: "descendant", a: dir, b: nested, wantOverlap: true},
		{name: "ancestor", a: nested, b: dir, wantOverlap: true},
		{name: "symlink to the same directory", a: alias, b: dir, wantOverlap: true},
		{name: "sibling directories", a: dir, b: sibling, wantOverlap: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Overlap(tc.a, tc.b)
			if err != nil {
				t.Fatalf("Overlap(%q, %q) error = %v, want nil", tc.a, tc.b, err)
			}
			if got != tc.wantOverlap {
				t.Errorf("Overlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.wantOverlap)
			}
		})
	}
}

func TestOverlap_refusesAnUnresolvablePath(t *testing.T) {
	t.Parallel()
	existing := t.TempDir()
	missing := filepath.Join(existing, "absent")
	for _, tc := range []struct {
		name string
		a, b string
	}{
		{name: "first path missing", a: missing, b: existing},
		{name: "second path missing", a: existing, b: missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := Overlap(tc.a, tc.b); err == nil {
				t.Errorf("Overlap(%q, %q) = (%v, nil), want an error for a path that does not resolve", tc.a, tc.b, got)
			}
		})
	}
}

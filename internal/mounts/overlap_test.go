package mounts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadMountInfo_decodesEscapedPaths(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "mountinfo")
	line := "42 1 8:1 /root\\040dir /mnt\\040space rw - ext4 /dev/root rw\n"
	if err := os.WriteFile(file, []byte(line), 0o600); err != nil {
		t.Fatalf("setup: write mountinfo: %v", err)
	}
	entries, err := readMountInfo(file)
	if err != nil {
		t.Fatalf("readMountInfo() = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("readMountInfo() returned %d entries, want 1", len(entries))
	}
	want := mountEntry{device: "8:1", root: "/root dir", mountPoint: "/mnt space"}
	if entries[0] != want {
		t.Errorf("readMountInfo() entry = %+v, want %+v", entries[0], want)
	}
}

func TestPathContains_respectsPathBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		parent       string
		child        string
		wantContains bool
	}{
		{name: "same", parent: "/a", child: "/a", wantContains: true},
		{name: "descendant", parent: "/a", child: "/a/b", wantContains: true},
		{name: "root", parent: "/", child: "/a", wantContains: true},
		{name: "prefix is not ancestor", parent: "/a", child: "/ab", wantContains: false},
		{name: "sibling", parent: "/a/b", child: "/a/c", wantContains: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := pathContains(tc.parent, tc.child); got != tc.wantContains {
				t.Errorf("pathContains(%q, %q) = %v, want %v", tc.parent, tc.child, got, tc.wantContains)
			}
		})
	}
}

// TestResolvePhysicalPath_innermostMountWins pins that a path is attributed to
// the deepest mount containing it, not to a parent mount it also lies beneath:
// a bind mount's device and root are what make two unrelated container paths
// the same physical tree.
func TestResolvePhysicalPath_innermostMountWins(t *testing.T) {
	t.Parallel()
	mountPoint := t.TempDir()
	target := filepath.Join(mountPoint, "certs")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatalf("setup: mkdir: %v", err)
	}
	resolvedMount, err := filepath.EvalSymlinks(mountPoint)
	if err != nil {
		t.Fatalf("setup: resolve mount point: %v", err)
	}
	entries := []mountEntry{
		{device: "0:1", root: "/", mountPoint: "/"},
		{device: "8:1", root: "/volumes/data", mountPoint: filepath.ToSlash(resolvedMount)},
	}

	got, err := resolvePhysicalPath(target, entries)
	if err != nil {
		t.Fatalf("resolvePhysicalPath(%q) error = %v", target, err)
	}
	want := physicalPath{device: "8:1", root: "/volumes/data/certs"}
	if got != want {
		t.Errorf("resolvePhysicalPath(%q) = %+v, want %+v", target, got, want)
	}
}

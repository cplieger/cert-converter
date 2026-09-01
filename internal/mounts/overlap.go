package mounts

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxMountInfoBytes = 1 << 20

// Overlap reports whether a and b resolve to the same physical directory or one
// is beneath the other, including separate bind mounts whose container paths are
// unrelated. Linux mountinfo supplies each mount's filesystem device and root.
func Overlap(a, b string) (bool, error) {
	entries, err := readMountInfo("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	left, err := resolvePhysicalPath(a, entries)
	if err != nil {
		return false, err
	}
	right, err := resolvePhysicalPath(b, entries)
	if err != nil {
		return false, err
	}
	if left.device != right.device {
		return false, nil
	}
	return pathContains(left.root, right.root) || pathContains(right.root, left.root), nil
}

type mountEntry struct {
	device     string
	root       string
	mountPoint string
}

type physicalPath struct {
	device string
	root   string
}

func readMountInfo(filename string) ([]mountEntry, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open mountinfo: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), maxMountInfoBytes)
	var entries []mountEntry
	var readBytes int
	for scanner.Scan() {
		line := scanner.Text()
		readBytes += len(line) + 1
		if readBytes > maxMountInfoBytes {
			return nil, fmt.Errorf("mountinfo exceeds %d bytes", maxMountInfoBytes)
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			return nil, fmt.Errorf("parse mountinfo: line has %d fields", len(fields))
		}
		entries = append(entries, mountEntry{
			device:     fields[2],
			root:       decodeMountField(fields[3]),
			mountPoint: decodeMountField(fields[4]),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read mountinfo: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("mountinfo contains no mounts")
	}
	return entries, nil
}

func resolvePhysicalPath(filename string, entries []mountEntry) (physicalPath, error) {
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil {
		return physicalPath{}, fmt.Errorf("resolve %q: %w", filename, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return physicalPath{}, fmt.Errorf("make %q absolute: %w", resolved, err)
	}
	var best *mountEntry
	for i := range entries {
		entry := &entries[i]
		if !pathContains(entry.mountPoint, filepath.ToSlash(resolved)) {
			continue
		}
		if best == nil || len(entry.mountPoint) > len(best.mountPoint) {
			best = entry
		}
	}
	if best == nil {
		return physicalPath{}, fmt.Errorf("resolve %q: no containing mount", filename)
	}
	rel, err := filepath.Rel(filepath.FromSlash(best.mountPoint), resolved)
	if err != nil {
		return physicalPath{}, fmt.Errorf("resolve %q inside mount %q: %w", filename, best.mountPoint, err)
	}
	return physicalPath{device: best.device, root: path.Clean(path.Join(best.root, filepath.ToSlash(rel)))}, nil
}

func pathContains(parent, child string) bool {
	parent, child = path.Clean(parent), path.Clean(child)
	if parent == child || parent == "/" {
		return true
	}
	return strings.HasPrefix(child, parent+"/")
}

func decodeMountField(field string) string {
	replacer := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return replacer.Replace(field)
}

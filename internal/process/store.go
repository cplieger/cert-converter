package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cplieger/atomicfile/v2"
)

// Output file and directory modes. A PFX carries a private key, so it is
// owner-read/write only; its parent directory is owner-traversable plus group
// read, matching the documented deployment where a matching host UID owns the
// volume.
const (
	pfxFileMode = 0o600
	pfxDirMode  = 0o750
)

// store owns every touch of the output tree.
//
// Before this type, output responsibility was spread across three places: the
// atomic write lived in internal/convert (on a root that package did not own),
// while the root itself, the path derivation, the directory mode, the prior-output
// check and the stale-temp sweep lived in the scan. Deferred finding l-f27 named
// the missing owner directly.
//
// A store does not close its root; the Scanner that opened it does.
type store struct {
	root *os.Root
}

// write puts pfx at rel inside the output tree, atomically, creating rel's parent
// directory if needed. Every touch goes through the confined root, so a symlink
// planted under the output directory cannot redirect the private-key-bearing PFX
// outside the mounted volume.
func (s *store) write(ctx context.Context, rel string, pfx []byte) error {
	if destDir := filepath.Dir(rel); destDir != "." {
		if err := s.root.MkdirAll(destDir, pfxDirMode); err != nil {
			// destDir is filepath.Dir(rel), and the *os.Root error names the
			// failing component, so the caller's path carries the directory too.
			return fmt.Errorf("create output directory: %w", err)
		}
	}
	if _, err := atomicfile.WriteFileInRoot(ctx, s.root, rel, pfx,
		atomicfile.WithMode(pfxFileMode),
	); err != nil {
		return fmt.Errorf("write pfx: %w", err)
	}
	return nil
}

// lstat reports on rel inside the output tree WITHOUT following a symlink.
//
// Lstat rather than Stat is deliberate: a symlink planted under an output name
// must not be accepted as a prior PFX, or unrelated content could satisfy the
// coherence gate. The caller owns what each outcome means, so the raw result is
// returned rather than a boolean.
func (s *store) lstat(rel string) (os.FileInfo, error) {
	return s.root.Lstat(rel)
}

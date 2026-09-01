package process

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/cert-converter/internal/convert"
)

// source owns every read of the input tree.
type source struct {
	root *os.Root
}

// stat reports on rel within the input tree, without following a symlink out of
// it. Used to classify a pair's sibling key before committing to a read.
func (s *source) stat(rel string) (os.FileInfo, error) {
	return s.root.Stat(rel)
}

// pathVanished reports whether an ENOENT read of rel means the PATH ITSELF is gone,
// which is what separates the transient renewal race from a steady-state input the
// scan will never be able to read.
func (s *source) pathVanished(rel string) bool {
	fi, err := s.root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	return fi.Mode()&fs.ModeSymlink == 0
}

// pathAbsent reports whether rel does not exist inside the input tree, and returns any
// failure that left the question UNANSWERED.
func (s *source) pathAbsent(rel string) (bool, error) {
	_, err := s.root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// readBounded opens rel within the input tree and reads it under
// convert.MaxInputBytes (10 MB) — the cap internal/convert's acceptance bounds are
// calibrated against, stated there so raising it lands in the diff beside the bounds
// it invalidates — confining the read to that tree: a symlink or ".." component in rel
// can never redirect the read outside it (Go 1.24+ *os.Root).
func (s *source) readBounded(ctx context.Context, rel string) ([]byte, error) {
	return s.readBoundedTo(ctx, rel, convert.MaxInputBytes)
}

// readBundleBounded admits the largest PKCS#12 this app can itself emit from two
// individually accepted PEM inputs, so PFX output can be fed back as input.
func (s *source) readBundleBounded(ctx context.Context, rel string) ([]byte, error) {
	return s.readBoundedTo(ctx, rel, convert.MaxBundleBytes)
}

func (s *source) readBoundedTo(ctx context.Context, rel string, maxBytes int64) ([]byte, error) {
	return atomicfile.ReadBoundedInRoot(ctx, s.root, rel, maxBytes)
}

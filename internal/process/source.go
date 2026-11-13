package process

import (
	"context"
	"os"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/go/filesafe"
)

// source owns every read of the input tree.
type source struct {
	root *os.Root
}

// stat returns the error resolving rel within the input tree, without
// following a symlink out of it. Used to classify a pair's sibling key before
// committing to a read.
func (s *source) stat(rel string) error {
	_, err := s.root.Stat(rel)
	return err
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
	return filesafe.ReadBoundedInRoot(ctx, s.root, rel, maxBytes)
}

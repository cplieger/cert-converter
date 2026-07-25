package process

import (
	"context"
	"os"

	"github.com/cplieger/atomicfile/v2"
)

// maxFileSize is the maximum size of an input certificate or key file (10 MB).
//
// It lives here rather than in internal/convert because it is a property of the
// FILESYSTEM boundary — how much of an untrusted file this app is willing to read
// — not of the PEM codec, which is handed bytes and never learns where they came
// from.
const maxFileSize = 10 << 20

// source owns every read of the input tree.
//
// It is the single owner of input filesystem policy: the confined root, the
// regular-file requirement, the size bound, and the non-blocking open. That
// policy used to sit in internal/convert, which meant the codec package held an
// *os.Root it did not own and could not have opened, while the walk that DOES own
// the input tree lived here. One owner per tree removes that split.
//
// A source does not close its root; the Scanner that opened it does.
type source struct {
	root *os.Root
}

// stat reports on rel within the input tree, without following a symlink out of
// it. Used to classify a pair's sibling key before committing to a read.
func (s *source) stat(rel string) (os.FileInfo, error) {
	return s.root.Stat(rel)
}

// readBounded opens rel within the input tree and reads it under maxFileSize,
// confining the read to that tree: a symlink or ".." component in rel can never
// redirect the read outside it (Go 1.24+ *os.Root). Only regular files are read,
// so a named pipe, device node or socket planted in the watched tree cannot stall
// the scan.
func (s *source) readBounded(ctx context.Context, rel string) ([]byte, error) {
	return s.readBoundedLimit(ctx, rel, maxFileSize)
}

// readBoundedLimit is readBounded with an explicit cap. Production always uses
// maxFileSize; the parameter exists so the size-cap boundary itself is testable
// without writing a 10 MB fixture per case.
//
// atomicfile owns the confined read: it opens through the root non-blocking (so a
// FIFO planted in the watched tree is rejected rather than wedging the scan's only
// goroutine), requires a regular file, and stats the open handle rather than the
// path. Hand-rolling that sequence here is what deferred finding l-f27 named — the
// same three details the library already guarantees on the write side.
func (s *source) readBoundedLimit(ctx context.Context, rel string, limit int64) ([]byte, error) {
	return atomicfile.ReadBoundedInRoot(ctx, s.root, rel, limit)
}

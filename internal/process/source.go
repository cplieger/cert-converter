package process

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
)

// maxFileSize is the maximum size of an input certificate or key file (10 MB).
//
// It is convert.MaxInputBytes, the cap that package's acceptance bounds are
// calibrated against, so raising it lands in the diff beside the bounds it
// invalidates rather than silently invalidating them from here. This package owns
// ENFORCEMENT — reading an untrusted file under a cap is a property of the
// FILESYSTEM boundary, not of the PEM codec, which is handed bytes and never
// learns where they came from — while the number itself lives where the reasoning
// that depends on it lives.
const maxFileSize = convert.MaxInputBytes

// source owns every read of the input tree.
//
// It is the single owner of input filesystem policy: the confined root, the
// regular-file requirement, the size bound, and the non-blocking open.
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

// pathVanished reports whether an ENOENT read of rel means the PATH ITSELF is gone,
// which is what separates the transient renewal race from a steady-state input the
// scan will never be able to read.
//
// It answers with Lstat, the one question Stat and the read cannot: a read gets the
// same ENOENT whether the entry disappeared between readdir and the open (a renewal
// or an atomic-write temp — gone, and the next scan converts the replacement) or the
// entry is still sitting there as a symlink whose target does not exist (a certbot
// live/ -> archive/ layout with only live/ mounted, a link left behind by a removed
// cert — the same ENOENT on every scan, forever, with no PFX produced).
//
// A path that is gone, or that is now a NON-symlink (it was replaced under the read),
// is the race. A surviving symlink is not. Any other Lstat failure answers false: an
// input the scan cannot even classify is the steady-state case, which is the arm that
// tells an operator something is wrong.
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

// pathAbsent reports whether rel does not exist inside the input tree.
//
// It is the reap's durability question: an orphan candidate is only deleted when its
// certificate is still missing after the confirmation delay, so a "cannot tell"
// answer must read as PRESENT — the caller deletes private key material on a true.
// Any Lstat failure other than ENOENT therefore answers false.
//
// Lstat, like pathVanished, so a dangling symlink at an input name reads as present:
// the entry is still in the tree the operator manages, and no output under it may be
// reaped on the strength of its target being unresolvable.
//
// Deliberately NOT pathVanished, which asks a different question on the READ path:
// there a surviving NON-symlink means the entry was replaced under the read, so
// pathVanished answers true for a path that exists. The reap needs the opposite
// reading of exactly that case — a certificate that is back is a certificate that is
// present — which is why absence is asked for directly rather than through it.
func (s *source) pathAbsent(rel string) bool {
	_, err := s.root.Lstat(rel)
	return errors.Is(err, fs.ErrNotExist)
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
// path. Delegating the sequence keeps the read and write boundaries on the same
// atomicfile guarantees.
func (s *source) readBoundedLimit(ctx context.Context, rel string, limit int64) ([]byte, error) {
	return atomicfile.ReadBoundedInRoot(ctx, s.root, rel, limit)
}

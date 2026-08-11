package process

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
)

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

// pathAbsent reports whether rel does not exist inside the input tree, and returns any
// failure that left the question UNANSWERED.
//
// It is the reap's durability question: an orphan candidate is only deleted when its
// certificate is still missing after the confirmation delay, so a "cannot tell"
// answer must read as NOT ABSENT — the caller deletes private key material on a true.
// Any Lstat failure other than ENOENT therefore answers (false, err): the fail-closed
// half is the false, and the err is what stops a caller narrating the retention as a
// positive observation ("the certificate came back", "the private key is still in
// /input") when the truth is that /input became unreadable, was unmounted, or changed
// permissions during the delay. Both are diagnoses an operator acts on differently, and
// collapsing the second into the first left a retained stale bundle unexplained — at
// LOG_LEVEL=warn, with no record at all.
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
// can never redirect the read outside it (Go 1.24+ *os.Root). Only regular files are
// read, so a named pipe, device node or socket planted in the watched tree cannot
// stall the scan.
//
// atomicfile owns the confined read: it opens through the root non-blocking (so a
// FIFO planted in the watched tree is rejected rather than wedging the scan's only
// goroutine), requires a regular file, and stats the open handle rather than the
// path. Delegating the sequence keeps the read and write boundaries on the same
// atomicfile guarantees, and leaves this package one read method whose cap is the
// documented /input bound — nothing here or in a test picks a different one.
func (s *source) readBounded(ctx context.Context, rel string) ([]byte, error) {
	return atomicfile.ReadBoundedInRoot(ctx, s.root, rel, convert.MaxInputBytes)
}

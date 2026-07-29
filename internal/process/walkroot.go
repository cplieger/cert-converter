package process

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"syscall"
)

// walkFunc is the fs.WalkDir callback contract both mounted trees' visitors
// implement: the /input scan's per-entry visit and the /output store's listing
// visit. Naming it is what lets one walker serve both.
type walkFunc func(rel string, d fs.DirEntry, err error) error

// walkRoot enumerates a confined root's tree and hands every entry to visit,
// root-relative, in the same shape fs.WalkDir did: the root first, then each entry
// pre-order, with a read failure reported through visit for the path it belongs to
// (fatal at the root, one unreadable sub-path below it) and a visit error — a
// cancellation or an entry-budget abort — stopping the walk at once.
//
// It is the ONE spelling of this app's traversal policy for a tree it does not own.
// Both mounts go through it (/input from Scanner.Run, /output from
// store.listOutputs), because the policy — confined descent, streaming batches, one
// directory handle at a time — is a single decision, and it had already drifted while
// each mount enumerated itself: only /input streamed, so a large or hostile /output
// still materialized a whole directory listing on the path that deletes private-key
// material. Each visitor keeps its own accounting and diagnostics; only the mechanics
// are shared.
//
// Two deliberate differences from fs.WalkDir. Entries arrive in directory order
// (sorted only within a batch) rather than globally sorted, because a global sort IS
// the materialization this walk avoids; nothing downstream depends on the order
// (`seen` is a set, the output listing is a membership filter, and the per-path
// diagnostics stand alone). And a directory's own entries are all visited before the
// walk descends into its subdirectories, which is what lets it keep exactly ONE
// directory handle open at a time: a queue of pending directory NAMES cannot exhaust
// the process's descriptors on a deep tree, and on the /input side its own size is
// bounded by the entry budget because every queued directory was counted as an entry
// when it was visited.
func walkRoot(root *os.Root, visit walkFunc) error {
	fi, err := root.Stat(".")
	if err != nil {
		return visit(".", nil, err)
	}
	if visitErr := visit(".", fs.FileInfoToDirEntry(fi), nil); visitErr != nil {
		return visitErr
	}
	pending := []string{"."}
	for len(pending) > 0 {
		dir := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		subdirs, streamErr := streamRootDir(root, dir, visit)
		if streamErr != nil {
			return streamErr
		}
		// Reversed, so the stack pops the subdirectories in the order they were read.
		slices.Reverse(subdirs)
		pending = append(pending, subdirs...)
	}
	return nil
}

// streamRootDir visits one directory's entries in fixed-size batches and reports the
// subdirectories found under it, for the caller to stream in turn. The handle is
// closed before any of them is opened.
//
// A directory that cannot be opened or read is reported through visit for its OWN
// path, which is where fs.WalkDir reported it too: at the root that aborts the walk,
// below the root it counts one unreadable sub-path (or one vanished path) and the
// walk goes on with the rest of the tree.
func streamRootDir(root *os.Root, dir string, visit walkFunc) ([]string, error) {
	// O_DIRECTORY, not os.Root.Open: Open is a plain O_RDONLY openat, and a reader-less
	// FIFO blocks that open(2) forever, wedging the scan's only goroutine — no
	// certificate converted again, no summary logged, the health marker never
	// refreshed, and recovery only at the healthcheck's max-age deadline (18h on the
	// documented 6h cadence). O_DIRECTORY makes the kernel refuse a non-directory
	// occupant with ENOTDIR before it can block, so a FIFO swapped in for a directory
	// between the readdir that classified it and this open is reported as one
	// unreadable sub-path like any other path this walk cannot enter. A real directory
	// is unaffected. It is the same guarantee atomicfile gives every FILE this app
	// opens under a tree it does not own; this is the directory half.
	handle, err := root.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, visit(dir, nil, err)
	}
	defer func() { _ = handle.Close() }()

	var subdirs []string
	for {
		entries, readErr := handle.ReadDir(scanReadDirBatch)
		// Sorted within the batch only: it costs nothing at this size and keeps a
		// single directory's diagnostics stable from scan to scan.
		slices.SortFunc(entries, cmpDirEntryName)
		batchSubdirs, visitErr := visitRootBatch(dir, entries, visit)
		subdirs = append(subdirs, batchSubdirs...)
		if visitErr != nil {
			return nil, visitErr
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return subdirs, nil
			}
			// The entries already read are kept: they were visited, and the failure
			// costs the REST of this directory, not what the walk has seen of it.
			return subdirs, visit(dir, nil, readErr)
		}
	}
}

// visitRootBatch hands one batch of directory entries to visit, root-relative, and
// reports the subdirectories among them for the caller to stream once this
// directory's handle is closed. A visit error (a cancellation, or an entry-budget
// abort) stops the batch and is returned with whatever the batch had already found.
func visitRootBatch(dir string, entries []fs.DirEntry, visit walkFunc) ([]string, error) {
	var subdirs []string
	for _, entry := range entries {
		rel := entry.Name()
		if dir != "." {
			rel = path.Join(dir, entry.Name())
		}
		if visitErr := visit(rel, entry, nil); visitErr != nil {
			return subdirs, visitErr
		}
		if entry.IsDir() {
			subdirs = append(subdirs, rel)
		}
	}
	return subdirs, nil
}

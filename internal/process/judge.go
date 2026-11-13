package process

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"syscall"
)

// verdict is what one scan can prove about an /input path. Every consumer of a
// path's existence (the walk, the claim ledger, the reaper's re-checks, the
// counts and logs) reads this one judgement, so they cannot disagree.
type verdict int

const (
	// verdictPresent: the path resolved inside the input root to what its role
	// says, a regular file for a source or key, a directory for a component.
	verdictPresent verdict = iota + 1
	// verdictAlias: a link to an in-root directory. The walk never descends a link
	// and walks the target under its own path, so a path under the link's name is
	// not an input.
	verdictAlias
	// verdictAbsent: the path cannot exist. Its parent holds no entry, a link there
	// leads nowhere inside the root (ENOENT), or a component on the way is an
	// in-root non-directory (ENOTDIR).
	verdictAbsent
	// verdictUnproven: the path could not be resolved (a target outside the root,
	// a loop, a permission or I/O error); it proves nothing about anything at or
	// under it.
	verdictUnproven
	// verdictMismatch is verdictUnproven for an entry that resolved to the wrong
	// kind: a directory, device, FIFO or socket where a regular file is wanted.
	verdictMismatch
)

// role is what a path is judged as.
type role int

const (
	// roleFile is a source, or the key half of a pair.
	roleFile role = iota
	// roleDir is a component on the way to a source or to a stored path; it
	// carries no name rule.
	roleDir
	roleCount
)

// entryShape is what an /input entry resolved to, through a link when there is one.
type entryShape int

const (
	shapeMissing entryShape = iota
	shapeFile
	shapeDir
	shapeOther
	shapeUnresolved
	shapeCount
)

// verdictTable is the decision point: the verdict for every resolved shape in
// every role. A link to a directory judged as a directory is the one cell that
// also reads whether a link was followed (judgeFacts).
var verdictTable = [shapeCount][roleCount]verdict{
	shapeMissing:    {roleFile: verdictAbsent, roleDir: verdictAbsent},
	shapeFile:       {roleFile: verdictPresent, roleDir: verdictAbsent},
	shapeDir:        {roleFile: verdictMismatch, roleDir: verdictPresent},
	shapeOther:      {roleFile: verdictMismatch, roleDir: verdictAbsent},
	shapeUnresolved: {roleFile: verdictUnproven, roleDir: verdictUnproven},
}

// entryFacts is what the scan gathered about one /input entry: its shape, whether
// it is a link, and the error that left it unresolved or missing.
type entryFacts struct {
	err    error
	shape  entryShape
	linked bool
}

// judgeFacts returns the verdict for facts judged in role want.
func judgeFacts(f entryFacts, want role) verdict {
	if f.linked && f.shape == shapeDir && want == roleDir {
		return verdictAlias
	}
	return verdictTable[f.shape][want]
}

// shapeOfErr classifies a failed stat. ENOTDIR is missing too: a non-directory
// component inside the root proves the path cannot exist, as ENOENT does.
func shapeOfErr(err error) entryShape {
	if missingErr(err) {
		return shapeMissing
	}
	return shapeUnresolved
}

// missingErr reports whether a stat error proves the path does not exist.
func missingErr(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

func shapeOfMode(mode fs.FileMode) entryShape {
	switch {
	case mode.IsRegular():
		return shapeFile
	case mode.IsDir():
		return shapeDir
	default:
		return shapeOther
	}
}

// errKindMismatch is the reason a path judged verdictMismatch proves nothing.
var errKindMismatch = errors.New("input path is not a regular file")

// leafFacts gathers the facts about rel from its own entry, following a link
// once. It assumes rel's parent is a real directory, as it is for every entry
// the walk lists.
func (s *source) leafFacts(rel string) entryFacts {
	fi, err := s.root.Lstat(rel)
	switch {
	case err != nil:
		return entryFacts{shape: shapeOfErr(err), err: err}
	case fi.Mode()&fs.ModeSymlink != 0:
		return s.linkFacts(rel)
	}
	return entryFacts{shape: shapeOfMode(fi.Mode())}
}

// linkFacts gathers the facts about the link rel through its target. The
// confined Stat answers ENOENT at the first missing component before it
// evaluates any later one, and refuses a target that leaves the root.
func (s *source) linkFacts(rel string) entryFacts {
	fi, err := s.root.Stat(rel)
	if err != nil {
		return entryFacts{shape: shapeOfErr(err), err: err, linked: true}
	}
	return entryFacts{shape: shapeOfMode(fi.Mode()), linked: true}
}

// judge returns the verdict for rel as a source or key, judged from the root
// down, and the reason when the verdict is Unproven or a mismatch. A full-path
// Stat cannot stand in for this: it follows an in-root directory alias and
// would find the target's file under the alias's name.
func (s *source) judge(rel string) (verdict, error) {
	f := s.leafFacts(rel)
	if f.shape == shapeMissing {
		return verdictAbsent, nil
	}
	if !f.linked && f.shape == shapeUnresolved {
		return verdictUnproven, f.err
	}
	// rel's own Lstat succeeded, so every ancestor resolved inside the root and a
	// link among them is an alias, even when a final link did not resolve.
	for dir := path.Dir(rel); dir != "."; dir = path.Dir(dir) {
		fi, err := s.root.Lstat(dir)
		if err != nil {
			return verdictUnproven, err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return verdictAbsent, nil
		}
	}
	switch v := judgeFacts(f, roleFile); v {
	case verdictUnproven:
		return v, f.err
	case verdictMismatch:
		return v, fmt.Errorf("%s: %w", rel, errKindMismatch)
	default:
		return v, nil
	}
}

// pathVanished reports whether an ENOENT read of rel means the path itself is
// gone, the transient renewal race, rather than a steady-state input the scan
// will never read: no entry, or a link whose target is missing inside the root.
// A non-link that answers ENOTDIR cannot occur in a directory the walk just
// listed, so it reads as steady state.
func (s *source) pathVanished(rel string) bool {
	fi, err := s.root.Lstat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true
	case err != nil:
		return false
	case fi.Mode()&fs.ModeSymlink != 0:
		return s.linkFacts(rel).shape == shapeMissing
	}
	return true
}

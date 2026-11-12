package process

import (
	"io/fs"
	"path"
	"strings"

	"github.com/cplieger/cert-converter/internal/layout"
)

// scanReach is what one scan can vouch for: a per-path condition the scan did not
// report is gone only when the scan reached the condition's subject. The zero
// value reaches nothing.
type scanReach struct {
	// listed is every /input directory the walk listed in full.
	listed map[string]struct{}
	// entered is every /input directory or symlink the walk enumerated, by the
	// order it was enumerated in: a path under none of them is absent.
	entered map[string]int
	// unread is every /input path of a source the scan could not read to a verdict.
	unread map[string]struct{}
	// resolved is every artifact of a source whose every artifact was inspected
	// and, where stale, written.
	resolved map[string]struct{}
	// whole is whether the walk listed every /input path, so one it did not
	// enumerate is gone.
	whole bool
}

// enter records that the walk enumerated rel, whose entry is d: a directory is
// listed until withdrawn or stopped inside.
func (r *scanReach) enter(rel string, d fs.DirEntry) {
	if !d.IsDir() && d.Type()&fs.ModeSymlink == 0 {
		return
	}
	if r.entered == nil {
		r.entered = make(map[string]int)
		r.listed = make(map[string]struct{})
	}
	r.entered[rel] = len(r.entered)
	if d.IsDir() {
		r.listed[rel] = struct{}{}
	}
}

// withdraw records that the walk could not read rel: a directory is not
// listed, and rel itself is unread.
func (r *scanReach) withdraw(rel string) {
	delete(r.listed, rel)
	if r.unread == nil {
		r.unread = make(map[string]struct{})
	}
	r.unread[rel] = struct{}{}
}

// stop records that the walk ended at rel. The walk lists a directory's entries
// before it walks any subdirectory, depth first in the order it enumerated them
// (filesafe.WalkDirInRoot), so the directories it listed in full are those it
// began before the one holding rel.
func (r *scanReach) stop(rel string) {
	at := path.Dir(rel)
	for dir := range r.listed {
		if !r.walkedBefore(dir, at) {
			delete(r.listed, dir)
		}
	}
}

// walkedBefore reports whether the walk began listing the directory dir before
// the directory at: dir holds at, or dir's branch was enumerated first under the
// directory holding both.
func (r *scanReach) walkedBefore(dir, at string) bool {
	switch {
	case dir == at:
		return false
	case dir == ".":
		return true
	case at == ".":
		return false
	}
	dirParts, atParts := strings.Split(dir, "/"), strings.Split(at, "/")
	for i := range min(len(dirParts), len(atParts)) {
		if dirParts[i] != atParts[i] {
			return r.entered[strings.Join(dirParts[:i+1], "/")] < r.entered[strings.Join(atParts[:i+1], "/")]
		}
	}
	return len(dirParts) < len(atParts)
}

// noteSource records how far the scan got with the source rel, whose artifacts
// are artifacts.
func (r *scanReach) noteSource(rel string, outcome conversionStatus, artifacts []string) {
	switch outcome {
	case statusUnreadable, statusVanished:
		if r.unread == nil {
			r.unread = make(map[string]struct{})
		}
		r.unread[rel] = struct{}{}
		if layout.IsCert(rel) {
			r.unread[layout.KeyFor(rel)] = struct{}{}
		}
	case statusConverted, statusUnchanged, statusUnwritable:
		if r.resolved == nil {
			r.resolved = make(map[string]struct{})
		}
		for _, artifact := range artifacts {
			r.resolved[artifact] = struct{}{}
		}
	default:
	}
}

// input reports whether the scan reached the /input path subject: it listed the
// directory holding it and read it to a verdict, or it listed an ancestor whose
// listing holds nothing on the way to it, so subject is absent.
func (r *scanReach) input(subject string) bool {
	if _, unread := r.unread[subject]; unread {
		return false
	}
	for child, dir := subject, path.Dir(subject); ; child, dir = dir, path.Dir(dir) {
		if _, listed := r.listed[dir]; listed {
			_, entered := r.entered[child]
			return child == subject || !entered
		}
		if dir == "." {
			return false
		}
	}
}

// output reports whether the scan resolved the artifact at the /output path subject.
func (r *scanReach) output(subject string) bool {
	_, ok := r.resolved[subject]
	return ok
}

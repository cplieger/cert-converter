package process

import (
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
	// entered numbers, in enumeration order, every /input directory the walk
	// enumerated and every symlink the scan could not resolve: walkedBefore
	// orders directories by it, and input takes one on the way to a path as a
	// place that path may still exist.
	entered map[string]int
	// unread is every /input path of a source the scan could not read to a verdict.
	unread map[string]struct{}
	// resolved is every artifact of a source whose every artifact was inspected
	// and, where stale, written.
	resolved map[string]struct{}
	// enumerated is every source name the walk enumerated.
	enumerated map[string]struct{}
	// stoppedAt is the entry the walk stopped at, at the entry budget.
	stoppedAt string
	// links is every symlink the scan could not resolve, in enumeration order.
	links []string
}

// enterDir records that the walk enumerated the directory rel: it stays listed
// unless its listing fails (withdraw) or the walk stops before finishing it
// (stop).
func (r *scanReach) enterDir(rel string) {
	r.order(rel)
	r.listed[rel] = struct{}{}
}

// enterLink records that the walk enumerated the symlink rel and the scan could
// not resolve it, so a path under it is not proven absent.
func (r *scanReach) enterLink(rel string) {
	r.order(rel)
	r.links = append(r.links, rel)
}

func (r *scanReach) order(rel string) {
	if r.entered == nil {
		r.entered = make(map[string]int)
		r.listed = make(map[string]struct{})
	}
	r.entered[rel] = len(r.entered)
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
	r.stoppedAt = rel
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

// enumerate records that the walk enumerated the source rel.
func (r *scanReach) enumerate(rel string) {
	if r.enumerated == nil {
		r.enumerated = make(map[string]struct{})
	}
	r.enumerated[rel] = struct{}{}
}

// provenGone reports whether a walk that stopped at the entry budget proved the
// source rel absent: it reached rel's path (input), which after stop means it
// read rel's folder in full, and did not enumerate rel. A source named in a
// listed folder can be enumerated and not processed, so input alone is no proof.
func (r *scanReach) provenGone(rel string) bool {
	if r.stoppedAt == "" || !r.input(rel) {
		return false
	}
	_, enumerated := r.enumerated[rel]
	return !enumerated
}

// inStopFolder reports whether the source rel sits in the folder the walk
// stopped in and the walk neither enumerated nor failed to read it: the walk
// read that folder only in part, so only a direct lookup of rel proves it gone.
func (r *scanReach) inStopFolder(rel string) bool {
	if r.stoppedAt == "" || path.Dir(rel) != path.Dir(r.stoppedAt) {
		return false
	}
	_, enumerated := r.enumerated[rel]
	_, unread := r.unread[rel]
	return !enumerated && !unread
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
// directory holding it and read it to a verdict, or it listed an ancestor that
// holds no directory or unresolved symlink on the way to it, so subject is
// absent.
func (r *scanReach) input(subject string) bool {
	if _, unread := r.unread[subject]; unread {
		return false
	}
	return r.judged(subject)
}

// judged reports whether the scan judged the /input path subject itself: it
// listed the directory holding it, or an ancestor that holds no directory or
// unresolved symlink on the way to it. Unlike input, a source the scan judged
// but could not read counts.
func (r *scanReach) judged(subject string) bool {
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

// outputHidden reports whether the scan did not reach the /input path the mirror
// layout derives the /output path outRel from, so its source may still exist.
func (r *scanReach) outputHidden(outRel string) bool {
	return !r.input(layout.OutputStem(outRel))
}

// output reports whether the scan resolved the artifact at the /output path subject.
func (r *scanReach) output(subject string) bool {
	_, ok := r.resolved[subject]
	return ok
}

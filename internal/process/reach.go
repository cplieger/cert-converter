package process

import (
	"path"

	"github.com/cplieger/cert-converter/internal/layout"
)

// scanReach is what one scan can vouch for: a per-path condition the scan did not
// report is gone only when the scan reached the condition's subject. The zero
// value reaches nothing.
type scanReach struct {
	// listed is every /input directory the walk listed in full.
	listed map[string]struct{}
	// unread is every /input path of a source the scan could not read to a verdict.
	unread map[string]struct{}
	// resolved is every artifact of a source whose every artifact was inspected
	// and, where stale, written.
	resolved map[string]struct{}
}

// list records that the walk is listing the /input directory dir.
func (r *scanReach) list(dir string) {
	if r.listed == nil {
		r.listed = make(map[string]struct{})
	}
	r.listed[dir] = struct{}{}
}

// unlist withdraws dir: its listing failed.
func (r *scanReach) unlist(dir string) {
	delete(r.listed, dir)
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
// directory holding it and read it to a verdict.
func (r *scanReach) input(subject string) bool {
	_, listed := r.listed[path.Dir(subject)]
	_, unread := r.unread[subject]
	return listed && !unread
}

// output reports whether the scan resolved the artifact at the /output path subject.
func (r *scanReach) output(subject string) bool {
	_, ok := r.resolved[subject]
	return ok
}

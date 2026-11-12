package process

import (
	"cmp"
	"log/slog"
	"time"

	"github.com/cplieger/cert-converter/internal/logtext"
)

// standingKey names one standing condition: its kind and, for a per-path
// condition, the path it holds on.
type standingKey struct {
	kind    string
	subject string
}

// The standing condition kinds, as the `condition` attribute spells them.
const (
	condUnreadablePaths    = "unreadable_paths"
	condOrphanCertificates = "orphan_certificates"
	condNoSources          = "no_sources"
	condAllOrphan          = "all_certificates_orphaned"
	condAllExcluded        = "all_excluded"
	condCollision          = "output_name_collision"
	condUnwritable         = "unwritable_output"
	condUnreadablePath     = "unreadable_path"
	condUnresolvedSymlink  = "unresolved_symlink"
	condConversionFailed   = "conversion_failed"
	condPermissiveDir      = "permissive_output_dir"
	condPermissiveFile     = "permissive_output_file"
)

// standingClearedMsg ends a standing condition, with how long it held.
const standingClearedMsg = "standing condition cleared"

// subjectAttr is the key a per-path kind's onset logs its subject under, when
// not `path`; the clear uses the same key, so one value never has two names.
var subjectAttr = map[string]string{
	condCollision:  "output_stem",
	condUnwritable: "output_path",
}

// standing remembers the standing conditions this process has reported, so a
// reader sees each one when it appears, again when its count or state changes,
// and once when it clears, instead of on every scan. A restart starts with none, so the
// new process reports every condition that still holds once more.
type standing struct {
	conditions map[standingKey]standingSince
	// seen is every key this scan reported, so a complete scan can clear the
	// per-path conditions it no longer saw.
	seen map[standingKey]struct{}
}

type standingSince struct {
	since time.Time
	state string
	count int
}

// standingClock is indirected so a test can move the lasted duration.
var standingClock = time.Now

func newStanding() *standing {
	return &standing{
		conditions: make(map[standingKey]standingSince),
		seen:       make(map[standingKey]struct{}),
	}
}

// beginScan forgets which keys the previous scan reported.
func (s *standing) beginScan() {
	if s != nil {
		clear(s.seen)
	}
}

// report records key as holding at count n for this scan and reports whether
// that is news to the reader: the condition is new, or its count changed.
//
// A nil standing remembers nothing, so every report is news.
func (s *standing) report(key standingKey, n int) bool {
	return s.reportState(key, n, "")
}

// reportState is report for a condition whose state, such as a mode or a cause,
// is news when it changes too.
func (s *standing) reportState(key standingKey, n int, state string) bool {
	if s == nil {
		return true
	}
	s.seen[key] = struct{}{}
	held, ok := s.conditions[key]
	if ok && held.count == n && held.state == state {
		return false
	}
	if !ok {
		held.since = standingClock()
	}
	held.count, held.state = n, state
	s.conditions[key] = held
	return true
}

// track reports a count condition: a positive n is reported, and a zero n
// clears it when the scan's evidence can prove it gone (canClear).
func (s *standing) track(key standingKey, n int, canClear bool) bool {
	if n > 0 {
		return s.report(key, n)
	}
	if canClear {
		s.clear(key)
	}
	return false
}

// clear ends key, logging how long it held, when it was standing.
func (s *standing) clear(key standingKey) {
	if s == nil {
		return
	}
	held, ok := s.conditions[key]
	if !ok {
		return
	}
	delete(s.conditions, key)
	attrs := []any{"condition", key.kind}
	if key.subject != "" {
		attrs = append(attrs, cmp.Or(subjectAttr[key.kind], "path"), logtext.Path(key.subject))
	}
	attrs = append(attrs, "lasted", standingClock().Sub(held.since).Round(time.Second).String())
	slog.Info(standingClearedMsg, attrs...)
}

// clearUnseen ends every condition of kind this scan did not report. Only a scan
// that saw the whole tree may call it: a partial scan's silence proves nothing.
func (s *standing) clearUnseen(kind string, quiet bool) {
	if s == nil {
		return
	}
	for key := range s.conditions {
		if _, ok := s.seen[key]; key.kind != kind || ok {
			continue
		}
		if quiet {
			delete(s.conditions, key)
			continue
		}
		s.clear(key)
	}
}

// clearUnless ends every condition of kind whose subject fails holds. Only a
// scan that saw the whole tree may call it.
func (s *standing) clearUnless(kind string, holds func(subject string) bool) {
	if s == nil {
		return
	}
	for key := range s.conditions {
		if key.kind == kind && !holds(key.subject) {
			s.clear(key)
		}
	}
}

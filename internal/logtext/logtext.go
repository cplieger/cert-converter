// Package logtext holds this app's log-boundary text helpers: the app-wide
// truncation marker for text headed for a diagnostic, deliberately louder than
// runesafe's own "...", so an operator can tell a cut record from one that ends
// there; the sanitizing gate every filesystem-derived log attribute passes through
// (Path); the byte-bounding helper that does NOT sanitize (Cap); and the path-inventory
// renderer that composes both (CapJoin).
//
// The rule its four consumers follow, stated once so a reader can check it: in main,
// internal/process, internal/watch and internal/mounts every `"error"` attribute is
// emitted as Path(err.Error()) at the log site, without consulting where the value came
// from — an error's text is filesystem-derived wherever the filesystem reached it.
package logtext

import (
	"strings"

	"github.com/cplieger/runesafe"
)

// Marker is appended to any text Cap had to cut, and is the marker internal/convert
// hands runesafe for the same purpose.
const Marker = "...(truncated)"

// Path makes one filesystem-derived string safe to emit as a log attribute.
func Path(s string) string {
	return runesafe.SanitizeSingleLine(s)
}

// Cap bounds s to limit BYTES, backing the cut off to a rune start, and names the
// cut with Marker.
func Cap(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return runesafe.CapBytes(s, limit) + Marker
}

// CapJoin renders an inventory of filesystem-derived names as one comma-separated log
// attribute of at most limit bytes plus Marker: every name passes the Path gate as it is
// appended and the budget is charged as the bytes accumulate, so an untrusted tree's
// contribution to a sink is bounded BEFORE the whole inventory is materialised. Sanitizing
// can grow a name (an invalid byte becomes the three-byte U+FFFD), so the name that
// crosses the budget is cut on its sanitized bytes rather than dropped, and the sample
// keeps the whole budget it was given.
func CapJoin(names []string, limit int) string {
	var joined strings.Builder
	for i, name := range names {
		part := Path(name)
		if i > 0 {
			part = "," + part
		}
		if joined.Len()+len(part) > limit {
			joined.WriteString(Cap(part, limit-joined.Len()))
			break
		}
		joined.WriteString(part)
	}
	return joined.String()
}

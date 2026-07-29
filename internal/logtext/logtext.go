// Package logtext holds the app-wide truncation marker for text headed for a
// diagnostic, deliberately louder than runesafe's own "...", so an operator can tell
// a cut record from one that ends there, plus the one byte-bounding helper that does
// NOT sanitize.
//
// It exists for the marker and for the ONE consumer whose text must be bounded
// without being sanitized: internal/process's orphan path sample. Those paths come
// from /input, a read-only mount of the operator's own tree, and they are the
// operator's query key for which bundles were reported, so rewriting runes in them
// would damage the attribute (the settled path-attribute-runesafe-adoption
// decision) — which rules out every sanitize-and-cap primitive, runesafe's included.
//
// internal/convert's certificate-derived text is the opposite case and does NOT come
// through here: it takes runesafe.SanitizeSingleLineCapped directly, passing Marker.
// The marker is an operator's log query key, and one condition must not grow two
// vocabularies, so both paths name the cut with the const below. The two differ only
// in what the cap counts: runesafe charges the marker against the limit, Cap appends
// it after the cut (see Cap).
//
// The package is a leaf over runesafe only, so it adds no edge that could cycle.
package logtext

import "github.com/cplieger/runesafe"

// Marker is appended to any text Cap had to cut, and is the marker internal/convert
// hands runesafe for the same purpose.
const Marker = "...(truncated)"

// Cap bounds s to limit BYTES, backing the cut off to a rune start, and names the
// cut with Marker. Sanitizing is NOT part of this, and that is the point: the only
// caller bounds operator-owned filesystem paths that must reach the log verbatim. Any
// caller whose text is UNTRUSTED wants runesafe.SanitizeSingleLineCapped instead —
// sanitizing can GROW the text, so it has to run before the cut, and that primitive
// takes Marker as its marker so the wording still matches.
//
// The marker is appended AFTER the cut, so a truncated value exceeds limit by the
// marker's own length: the bound exists to stop a multi-kilobyte record, not to hit
// the budget exactly. runesafe's Capped pair makes the opposite choice (the marker is
// charged against the cap); this one stays as it is because its caller composes a
// further elision suffix of its own after the cut, and its budget was set against
// this placement.
func Cap(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return runesafe.CapBytes(s, limit) + Marker
}

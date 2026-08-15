// Package logtext holds this app's log-boundary text helpers: the app-wide
// truncation marker for text headed for a diagnostic, deliberately louder than
// runesafe's own "...", so an operator can tell a cut record from one that ends
// there; the sanitizing gate every filesystem-derived log attribute passes through
// (Path); and the one byte-bounding helper that does NOT sanitize (Cap).
package logtext

import "github.com/cplieger/runesafe"

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

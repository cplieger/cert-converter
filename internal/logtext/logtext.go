// Package logtext holds the app-wide bounding of untrusted text headed for a
// diagnostic: one truncation marker, deliberately louder than runesafe's own "...",
// so an operator can tell a cut record from one that ends there.
//
// It exists so the marker and the composition around it have a single home. Both
// internal/convert (certificate subjects, PEM block labels) and internal/process
// (the orphan path sample) bound text this way, and the wording is an operator's
// query key: two copies that drift give one condition two vocabularies. The package
// is a leaf over runesafe only, so it adds no edge that could cycle.
package logtext

import "github.com/cplieger/runesafe"

// Marker is appended to any text Cap had to cut.
const Marker = "...(truncated)"

// Cap bounds s to limit BYTES, backing the cut off to a rune start, and names the
// cut with Marker. Sanitizing is NOT part of this: a caller whose text is untrusted
// composes runesafe.SanitizeSingleLine first, because sanitizing can GROW the text
// and must therefore run before the cut.
//
// The marker is appended AFTER the cut, so a truncated value exceeds limit by the
// marker's own length: the bound exists to stop a multi-kilobyte record, not to hit
// the budget exactly.
func Cap(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return runesafe.CapBytes(s, limit) + Marker
}

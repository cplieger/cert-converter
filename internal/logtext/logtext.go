// Package logtext holds this app's log-boundary text helpers: the app-wide
// truncation marker for text headed for a diagnostic, deliberately louder than
// runesafe's own "...", so an operator can tell a cut record from one that ends
// there; the sanitizing gate every filesystem-derived log attribute passes through
// (Path); and the one byte-bounding helper that does NOT sanitize (Cap).
//
// BOTH mounted trees are untrusted, which is what Path exists for. This is a public
// image: a stranger points /input and /output at whatever they like, so every name
// this app enumerates — a directory entry under /input, a bundle under /output, a path
// an fsnotify event names, a mount path an operator configured — is chosen by a party
// this app knows nothing about, so Path rewrites the unsafe set AT THE EMIT BOUNDARY.
// What that rests on is NOT the escaping of the handler installed today: slogx builds a
// slog.NewTextHandler for this app (main.go's slogx.Setup takes the zero Format), and
// that handler quotes any value holding a control or non-printing rune, so an
// unsanitized CR arrives as `\n` and a bidi mark as `\u200e`, on one line — including
// the raw name inside an *fs.PathError logged as an `error` attribute beside a sanitized
// `path`, which is what every refusal in internal/mounts does. The gate covers what that
// escaping does not: slog's JSONHandler emits bidi controls and C1 introducers RAW, an
// escaped `\u200e` is legible to no operator, and a consumer that unquotes a logfmt
// value recovers the original bytes. Sanitizing is
// byte-identical for an ordinary name — every ASCII path, every domain-derived bundle
// name — so an operator's log query keys are unchanged; only the spellings that could
// reorder or split a record move. Values used for a filesystem DECISION (an open, a
// stat, a walk, a join, a map key, a comparison) stay RAW: the gate is at the log
// call, never upstream of it.
//
// Cap deliberately stays non-sanitizing, for the ONE consumer that sanitizes first
// and caps second: internal/process's orphan path sample, whose caller composes a
// further elision suffix whose budget was set against Cap's marker placement. A
// sanitize-and-cap primitive would move that placement, which is why the composition
// stays split here rather than folded into one call.
//
// internal/convert's certificate-derived text is a separate gate and does NOT come
// through here: it takes runesafe.SanitizeSingleLineBudgeted directly, passing Marker.
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

// Path makes one filesystem-derived string safe to emit as a log attribute. It is
// this app's SINGLE gate for any value that came from a directory entry, a filesystem
// walk, an fsnotify event or a mount path, and every such attribute in
// internal/process, internal/watch, internal/mounts and main goes through it.
//
// The classification is runesafe's, not this package's: C0 controls, DEL, C1 controls
// (U+0080-U+009F), the whole Unicode Bidi_Control set, and the U+2028/U+2029 line
// separators, each replaced by a space, with invalid UTF-8 becoming U+FFFD. CR/LF and
// the bidi controls are the two classes that would split or reorder a record in a sink
// that emits them raw — slog's JSONHandler does; its TextHandler quotes the whole value
// instead, which is safe and unreadable — and hand-rolling the ranges here is exactly
// the drift runesafe exists to prevent.
//
// Apply it AT THE LOG CALL and nowhere else. A sanitized value used for a lookup, a
// join, a stat or a map key is a bug: the two trees are addressed by their real bytes,
// and only the rendered diagnostic is single-line.
//
// It is byte-identical for every ordinary path, so adopting it changed no existing
// attribute value: an operator querying on a bundle name still matches it exactly.
func Path(s string) string {
	return runesafe.SanitizeSingleLine(s)
}

// Cap bounds s to limit BYTES, backing the cut off to a rune start, and names the
// cut with Marker. Sanitizing is NOT part of this, and that is deliberate rather
// than an exemption: its one caller sanitizes FIRST (Path over the joined sample)
// and caps second, because it then composes a further elision suffix whose budget was
// set against this marker placement. A caller that wants ONE call for both jobs takes
// one of runesafe's sanitizing primitives instead — sanitizing can GROW the text, so
// the cut has to account for that, and both take Marker so the wording still matches.
// Which one depends on what bounds the INPUT: SanitizeSingleLineBudgeted when it is
// bounded only by a file size (it pre-caps the raw bytes, so the work is bounded by
// the limit), SanitizeSingleLineCapped when the input is already small and every byte
// of the sanitized form should count. internal/convert is the first case.
//
// The marker is appended AFTER the cut, so a truncated value exceeds limit by the
// marker's own length: the bound exists to stop a multi-kilobyte record, not to hit
// the budget exactly. Every runesafe primitive that takes a caller's marker makes the
// opposite choice, the Budgeted pair above included (the marker is charged against the
// cap); this one stays as it is because its caller composes a further elision suffix of
// its own after the cut, and its budget was set against this placement.
func Cap(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return runesafe.CapBytes(s, limit) + Marker
}

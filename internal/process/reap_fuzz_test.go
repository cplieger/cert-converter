package process

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/cplieger/cert-converter/internal/logtext"
)

// FuzzSampleOrphanPaths_singleLineBoundedSample explores the orphan sample over
// arbitrary BYTES, which neither the tables nor TestSampleOrphanPaths_properties can:
// both build their names from a fixed set of valid runes, so the one input class that
// makes the byte budget non-trivial is unreachable to them -- invalid UTF-8, which the
// sanitizing gate REPLACES WITH U+FFFD and so GROWS by two bytes per bad byte. A cap
// applied to the raw join instead of the sanitized one therefore passes every existing
// assertion and still emits a record over the budget.
//
// Names come from /output, an untrusted tree (this is a public image, so a co-writer on
// that mount chooses what this walk enumerates), and the whole record is a single line in
// the operator's log. Two invariants, both about the ATTRIBUTE VALUE rather than any one
// handler's rendering of it:
//
//   - Single-line and reorder-free: no C0 control, DEL, C1 control or Unicode bidi
//     control survives into the sample, whatever bytes the names held. slog's TextHandler
//     escapes these on the way out, so this is not about forging a record through the
//     handler this app installs; it is what keeps the value safe in a handler that does
//     not (a JSON handler passes a bidi override through raw) and legible to an operator
//     who reads the attribute.
//   - Bounded: the sample never exceeds the budget by more than the marker, which is
//     appended after the cut, and it is always valid UTF-8.
//
// Seeds cover the classes deliberately, because the weekly coverage-guided run starts
// from the committed corpus and never accumulates past it: ordinary names, the two
// hostile runes, a lone invalid byte, a raw C1 byte, one oversized name and a long
// list of short ones.
func FuzzSampleOrphanPaths_singleLineBoundedSample(f *testing.F) {
	f.Add("example.com/host01/fullchain.pfx")
	f.Add("a.pfx\x00b.pfx")
	f.Add("hostile\n\u202egone.pfx")
	f.Add("\xff.pfx")
	f.Add("bad\x9f.pfx\x00ok.pfx")
	f.Add(strings.Repeat("→", maxLoggedOrphanBytes) + "/leaf.pfx")
	// Every byte invalid: sanitizing GROWS this to three bytes per byte, so a cut that
	// counted the raw bytes would emit three times the budget.
	f.Add(strings.Repeat("\xff", maxLoggedOrphanBytes))
	f.Add(strings.Repeat("a.pfx\x00", 25))

	f.Fuzz(func(t *testing.T, joined string) {
		// NUL cannot appear in a filename, so it is the one byte safe to use as the
		// separator that turns one fuzz string into a list of names.
		paths := strings.Split(joined, "\x00")

		got := sampleOrphanPaths(paths)

		for _, r := range got {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Bidi_Control, r) {
				t.Fatalf("sampleOrphanPaths(%q) = %q: rune %U reached the log attribute; a name from the untrusted output tree must not carry a control or bidi rune into a single-line record",
					paths, got, r)
			}
		}
		if !utf8.ValidString(got) {
			t.Fatalf("sampleOrphanPaths(%q) = %q: invalid UTF-8", paths, got)
		}
		if maxLen := maxLoggedOrphanBytes + len(logtext.Marker); len(got) > maxLen {
			t.Fatalf("sampleOrphanPaths(%d names, %d raw bytes) rendered %d bytes, want at most %d: the cut must count the SANITIZED bytes, which invalid UTF-8 grows",
				len(paths), len(joined), len(got), maxLen)
		}
	})
}

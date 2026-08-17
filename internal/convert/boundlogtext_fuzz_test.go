package convert

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/runesafe"
)

// FuzzBoundLogText_bounded_and_loggable fuzzes the package's log-hygiene rule over
// arbitrary certificate-derived text. boundLogText is the single gate every
// diagnostic that interpolates operator-supplied text passes through, so its
// contract is a security-adjacent one: whatever the input, the result must be valid
// UTF-8, must carry no rune runesafe's single-line policy calls unsafe (the class
// one or both slog handlers emit raw), must be marked when it was cut, and must
// never exceed the limit.
//
// The table tests cover a handful of hand-picked strings; the byte cut, the
// mid-rune boundary and the exact limit boundary are input-dependent, which is
// what a fuzz target explores. The seeds pin the boundary lengths so an
// off-by-one (a >= where a > belongs, which marks an exactly-limit string as
// truncated) is caught deterministically on every PR rather than only when the
// weekly run happens to generate a 256-byte input, plus the two ways sanitizing
// moves the cut: a run of unsafe multi-byte runes SHRINKS (each becomes a
// one-byte space) so an over-limit input can end up fitting, and a run of invalid
// bytes GROWS (each becomes the three-byte U+FFFD) so an input well under the
// limit can end up cut.
func FuzzBoundLogText_bounded_and_loggable(f *testing.F) {
	f.Add("")
	f.Add("CN=plain.example.com")
	f.Add("CN=a\u007fb.example.com")
	f.Add("CN=a\xffb.example.com")
	f.Add("CN=a\u202eb.example.com")
	f.Add(strings.Repeat("a", maxSubjectLogLen-1))
	f.Add(strings.Repeat("a", maxSubjectLogLen))
	f.Add(strings.Repeat("a", maxSubjectLogLen+1))
	f.Add(strings.Repeat("\u00e9", 4000))
	// 258 raw bytes of bidi override that sanitize to 86 spaces: over the limit
	// before sanitizing, comfortably under it after. THE class the two library
	// primitives disagree on — the work-bounding one cuts it on the raw bytes.
	f.Add(strings.Repeat("\u202e", 86))
	// 200 invalid bytes that sanitize to 600 bytes of U+FFFD: under the limit
	// before sanitizing, cut after.
	f.Add(strings.Repeat("\xff", 200))
	// Text that legitimately ENDS with the marker without having been cut, which
	// is why marker provenance is asserted in one direction only.
	f.Add(logtext.Marker)
	f.Add("CN=a.example.com" + logtext.Marker)

	f.Fuzz(func(t *testing.T, s string) {
		got := boundLogText(s, maxSubjectLogLen)
		if !utf8.ValidString(got) {
			t.Fatalf("boundLogText(%q) = %q, want valid UTF-8 whatever the input", s, got)
		}
		// The policy itself, cross-checked against the predicate the library's own
		// every-rune sweep pins: no C0 control, CR/LF, DEL, C1 control, bidi control
		// or U+2028/U+2029 may survive, whichever slog handler is wired up.
		for _, r := range got {
			if runesafe.IsUnsafe(r, false) {
				t.Fatalf("boundLogText(%q) = %q, kept unsafe rune %U", s, got, r)
			}
		}

		// BOTH lengths decide, because the primitive is the WORK-bounding one
		// (SanitizeSingleLineBudgeted, user-ratified 2026-08): it pre-caps the RAW
		// bytes at the limit and then re-caps the growth sanitizing can cause. So raw
		// over the limit is cut by the pre-cap even when the sanitized form would have
		// fitted (a run of bidi overrides collapsing to spaces — the class that made
		// this a user decision), and raw under the limit can still be cut by the
		// re-cap when sanitizing GROWS the text (an invalid byte becomes the
		// three-byte U+FFFD). Asserting on the sanitized length alone was the
		// output-bounding primitive's contract and is wrong for this one.
		sanitized := runesafe.SanitizeSingleLine(s)
		if len(s) <= maxSubjectLogLen && len(sanitized) <= maxSubjectLogLen {
			// Text that fits on both counts is returned sanitized and otherwise
			// untouched: no marker, no growth, nothing added. Comparing against the
			// library's own output makes "boundLogText only sanitizes and caps" the
			// assertion, rather than re-deriving the cut rule the production code just
			// applied.
			if got != sanitized {
				t.Fatalf("boundLogText(%d bytes) = %q, want the sanitized form %q unchanged",
					len(s), got, sanitized)
			}
			return
		}
		// Only this direction is a contract. The reverse is not assertable from the
		// result alone: an input that legitimately ENDS with the marker text is
		// returned unchanged when it fits (the seeds above), so a biconditional fails
		// on correct output.
		if !strings.HasSuffix(got, logtext.Marker) {
			t.Fatalf("boundLogText(%d bytes, %d sanitized) = %q, cut text must be marked",
				len(s), len(sanitized), got)
		}
		if len(got) > maxSubjectLogLen {
			t.Fatalf("boundLogText(%d bytes) is %d bytes, want at most %d",
				len(s), len(got), maxSubjectLogLen)
		}
		// The kept text is a prefix of the sanitized form: the cut removes a tail and
		// invents nothing. This is what catches a cap that reorders, re-encodes or
		// drops interior bytes.
		if kept := strings.TrimSuffix(got, logtext.Marker); !strings.HasPrefix(sanitized, kept) {
			t.Fatalf("boundLogText(%q) kept %q, which is not a prefix of the sanitized form %q",
				s, kept, sanitized)
		}
	})
}

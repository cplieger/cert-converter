package convert

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/runesafe/v2"
)

// FuzzBoundLogText_bounded_and_loggable fuzzes the package's log-hygiene rule over
// arbitrary certificate-derived text. boundLogText is the single gate every
// diagnostic that interpolates operator-supplied text passes through: whatever
// the input, the result must be valid UTF-8, carry no rune runesafe's
// single-line policy calls unsafe, be marked when cut, and never exceed the limit.
//
// Seeds pin the boundary lengths (exact limit, off by one) for a deterministic
// fencepost check, plus the two ways sanitizing moves the cut: unsafe multi-byte
// runes SHRINK (each becomes a one-byte space) so an over-limit input can end up
// fitting, and invalid bytes GROW (each becomes U+FFFD) so an under-limit input
// can end up cut.
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
	// raw, under the limit sanitized — the class the two library primitives
	// disagree on.
	f.Add(strings.Repeat("\u202e", 86))
	// 200 invalid bytes that sanitize to 600 bytes of U+FFFD: under the limit
	// raw, cut after sanitizing.
	f.Add(strings.Repeat("\xff", 200))
	// Legitimately ENDS with the marker without having been cut.
	f.Add(logtext.Marker)
	f.Add("CN=a.example.com" + logtext.Marker)

	f.Fuzz(func(t *testing.T, s string) {
		got := boundLogText(s, maxSubjectLogLen)
		if !utf8.ValidString(got) {
			t.Fatalf("boundLogText(%q) = %q, want valid UTF-8 whatever the input", s, got)
		}
		// The policy itself, cross-checked against runesafe's own every-rune
		// sweep: no C0 control, CR/LF, DEL, C1 control, bidi control or
		// U+2028/U+2029 may survive, whichever slog handler is wired up.
		for _, r := range got {
			if runesafe.IsUnsafeSingleLine(r) {
				t.Fatalf("boundLogText(%q) = %q, kept unsafe rune %U", s, got, r)
			}
		}

		// BOTH lengths decide, because the primitive pre-caps the RAW bytes at
		// the limit and then re-caps the growth sanitizing can cause: raw over
		// the limit is cut even when the sanitized form would have fit (bidi
		// overrides collapsing to spaces), and raw under the limit can still be
		// cut when sanitizing GROWS the text (an invalid byte becomes U+FFFD).
		sanitized := runesafe.SanitizeSingleLine(s)
		if len(s) <= maxSubjectLogLen && len(sanitized) <= maxSubjectLogLen {
			// Fits on both counts: returned sanitized and otherwise untouched.
			if got != sanitized {
				t.Fatalf("boundLogText(%d bytes) = %q, want the sanitized form %q unchanged",
					len(s), got, sanitized)
			}
			return
		}
		// Only this direction is a contract; the reverse is not assertable
		// (text that legitimately ends with the marker is returned unchanged
		// when it fits — the seeds above).
		if !strings.HasSuffix(got, logtext.Marker) {
			t.Fatalf("boundLogText(%d bytes, %d sanitized) = %q, cut text must be marked",
				len(s), len(sanitized), got)
		}
		if len(got) > maxSubjectLogLen {
			t.Fatalf("boundLogText(%d bytes) is %d bytes, want at most %d",
				len(s), len(got), maxSubjectLogLen)
		}
		// The kept text is a prefix of the sanitized form: the cut removes a
		// tail and invents nothing.
		if kept := strings.TrimSuffix(got, logtext.Marker); !strings.HasPrefix(sanitized, kept) {
			t.Fatalf("boundLogText(%q) kept %q, which is not a prefix of the sanitized form %q",
				s, kept, sanitized)
		}
	})
}

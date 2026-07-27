package convert

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzBoundLogText_bounded_and_loggable fuzzes the package's log-hygiene rule over
// arbitrary certificate-derived text. boundLogText is the single gate every
// diagnostic that interpolates operator-supplied text passes through, so its
// contract is a security-adjacent one: whatever the input, the result must be
// valid UTF-8, must carry no U+007F (the one rune slog's handlers emit raw), must
// be marked when it was cut, and must never exceed the limit plus the marker.
//
// The table tests cover a handful of hand-picked strings; the byte cut, the
// mid-rune boundary and the exact limit boundary are input-dependent, which is
// what a fuzz target explores. The seeds pin the two boundary lengths so an
// off-by-one (a >= where a > belongs, which marks an exactly-limit string as
// truncated) is caught deterministically on every PR rather than only when the
// weekly run happens to generate a 256-byte input.
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

	f.Fuzz(func(t *testing.T, s string) {
		got := boundLogText(s, maxSubjectLogLen)
		if !utf8.ValidString(got) {
			t.Fatalf("boundLogText(%q) = %q, want valid UTF-8 whatever the input", s, got)
		}
		if strings.ContainsRune(got, 0x7f) {
			t.Fatalf("boundLogText(%q) = %q, kept U+007F, which slog emits raw", s, got)
		}
		// Only the forward direction is a contract. The reverse is not assertable from
		// the result alone: an input that legitimately ENDS with the marker text is
		// returned unchanged when it fits, so a biconditional fails on correct output.
		// The not-cut direction is pinned by length instead, which input content cannot
		// forge - and it is what catches the off-by-one the seeds exist for, because a
		// `>=` cut test appends the marker to an exactly-limit input and blows this bound.
		cut := len(s) > maxSubjectLogLen
		if cut && !strings.HasSuffix(got, truncationMarker) {
			t.Fatalf("boundLogText(%d bytes) = %q, cut text must be marked", len(s), got)
		}
		if !cut && len(got) > maxSubjectLogLen {
			t.Fatalf("boundLogText(%d bytes) is %d bytes, want no growth for text that fits", len(s), len(got))
		}
		if len(got) > maxSubjectLogLen+len(truncationMarker) {
			t.Fatalf("boundLogText(%d bytes) is %d bytes, want at most %d",
				len(s), len(got), maxSubjectLogLen+len(truncationMarker))
		}
	})
}

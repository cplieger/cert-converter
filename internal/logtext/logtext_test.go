package logtext_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/runesafe"
)

// TestMarker pins the exact wording. It is an operator's query key for a cut record
// and is shared by internal/convert and internal/process, so a silent change to it
// would break a log query in two packages at once.
func TestMarker(t *testing.T) {
	t.Parallel()
	if want := "...(truncated)"; logtext.Marker != want {
		t.Errorf("Marker = %q, want %q: the wording is an operator's log query key", logtext.Marker, want)
	}
}

// TestCap_leaves_text_within_the_limit_alone pins that the marker is only ever a
// claim about a cut: text that fits comes back untouched and unmarked.
func TestCap_leaves_text_within_the_limit_alone(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "a", "exactly-ten"} {
		if got := logtext.Cap(s, len(s)); got != s {
			t.Errorf("Cap(%q, %d) = %q, want it unchanged", s, len(s), got)
		}
	}
}

// TestCap_backs_the_cut_off_to_a_rune_start pins the rune-boundary backoff: a cut
// inside a multi-byte rune would mint the partial-UTF-8 tail the app's sanitizing
// exists to remove. The limit deliberately falls mid-rune (3-byte runes, limit 8).
func TestCap_backs_the_cut_off_to_a_rune_start(t *testing.T) {
	t.Parallel()
	const limit = 8
	s := strings.Repeat("日", 6) // 18 bytes, none of them ending at byte 8

	got := logtext.Cap(s, limit)

	kept, ok := strings.CutSuffix(got, logtext.Marker)
	if !ok {
		t.Fatalf("Cap(%d-byte text, %d) = %q, want it to name the cut with %q", len(s), limit, got, logtext.Marker)
	}
	if !utf8.ValidString(kept) {
		t.Errorf("Cap kept %q, which is not valid UTF-8: the cut must back off to a rune start", kept)
	}
	if len(kept) > limit {
		t.Errorf("Cap kept %d bytes, want at most the %d-byte limit", len(kept), limit)
	}
	if !strings.HasPrefix(s, kept) {
		t.Errorf("Cap kept %q, which is not a prefix of the input: the cut must only remove a tail", kept)
	}
}

// TestMarker_names_the_cut_in_both_paths pins the sharing this package exists for,
// from the shared leaf's own side. Two consumers bound text with this marker and must
// not drift on the wording: internal/process caps its orphan path sample with Cap
// (unsanitized on purpose — /input is the operator's own tree and the paths are their
// query key), and internal/convert hands the same const to
// runesafe.SanitizeSingleLineCapped for certificate-derived text.
//
// What the two do NOT share is where the marker's bytes are charged, and that is
// asserted rather than left implicit: Cap appends it after the cut (its caller
// composes a further elision suffix and its budget was set against that placement),
// while the library charges it against the limit. Same wording, two budgets.
func TestMarker_names_the_cut_in_both_paths(t *testing.T) {
	t.Parallel()
	const limit = 32
	long := strings.Repeat("a", 200)

	capped := logtext.Cap(long, limit)
	if !strings.HasSuffix(capped, logtext.Marker) {
		t.Errorf("Cap(200 bytes, %d) = %q, want it to end in %q", limit, capped, logtext.Marker)
	}
	if want := limit + len(logtext.Marker); len(capped) != want {
		t.Errorf("Cap(200 bytes, %d) is %d bytes, want %d: this path appends the marker AFTER the cut",
			limit, len(capped), want)
	}

	sanitized, cut := runesafe.SanitizeSingleLineCapped(long, limit, logtext.Marker)
	if !cut {
		t.Errorf("SanitizeSingleLineCapped(200 bytes, %d) reported no cut, want one", limit)
	}
	if !strings.HasSuffix(sanitized, logtext.Marker) {
		t.Errorf("SanitizeSingleLineCapped(200 bytes, %d) = %q, want the SAME marker %q as Cap: one condition, one vocabulary",
			limit, sanitized, logtext.Marker)
	}
	if len(sanitized) > limit {
		t.Errorf("SanitizeSingleLineCapped(200 bytes, %d) is %d bytes, want at most the limit: that path charges the marker against it",
			limit, len(sanitized))
	}
}

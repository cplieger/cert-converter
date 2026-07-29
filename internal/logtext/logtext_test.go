package logtext_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cplieger/cert-converter/internal/logtext"
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

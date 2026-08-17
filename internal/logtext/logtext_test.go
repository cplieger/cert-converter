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

// TestCap_does_not_sanitize pins the split this package is organised around: Cap
// bounds and marks, Path rewrites, and CapJoin — the one helper that needs both —
// composes them in that order (sanitize, then cap) as it accumulates. Folding
// sanitizing into Cap would move the marker's budget, which is the placement CapJoin's
// per-element accounting is written against — so the separation has to be asserted, not
// left to a comment.
//
// It drives the CUT path, not only the early return: a control rune sits inside the
// retained prefix and the whole result is compared byte for byte. An input at the limit
// asserts nothing here, because an implementation that sanitized only the text it cut
// would satisfy it.
func TestCap_does_not_sanitize(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		in    string
		limit int
		want  string
	}{
		{"within the limit", "a\nb", 3, "a\nb"},
		{"cut, with the control rune inside the kept prefix", "a\nbc", 3, "a\nb" + logtext.Marker},
	} {
		if got := logtext.Cap(tc.in, tc.limit); got != tc.want {
			t.Errorf("Cap(%q, %d) = %q, want %q (%s): Cap bounds text, Path is what rewrites it",
				tc.in, tc.limit, got, tc.want, tc.name)
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
	if want := strings.Repeat("日", 2); kept != want {
		t.Errorf("Cap kept %q, want the maximal complete-rune prefix %q", kept, want)
	}
}

// TestPath_rewrites_the_unsafe_classes_and_leaves_ordinary_names_alone pins the gate
// every filesystem-derived log attribute in this app passes through, from the leaf's own
// side. The wiring — that the walk's emit sites actually reach it — is pinned end to end
// by internal/process's TestScannerRun_sanitizes_walk_supplied_names_in_log_attributes;
// this is the policy half.
//
// Both halves of the decision are asserted, because either one alone permits a wrong
// implementation: a hostile name must be REWRITTEN (an escaper or a truncator would
// satisfy "no unsafe rune survives" while changing every ordinary value too), and an
// ordinary name must come back BYTE-IDENTICAL (which is why adopting the gate moved no
// operator's existing log query key).
func TestPath_rewrites_the_unsafe_classes_and_leaves_ordinary_names_alone(t *testing.T) {
	t.Parallel()

	// Ordinary names: every shape /input and /output actually hold. None may change.
	for _, s := range []string{
		"", "example.com.crt", "example.com.pfx", "sub/dir/wildcard_example.com.pfx",
		"héllo.crt", "日本語.pfx", ".", "a b.crt",
	} {
		if got := logtext.Path(s); got != s {
			t.Errorf("Path(%q) = %q, want it byte-identical: an ordinary name is an operator's query key", s, got)
		}
	}

	// One case per class the policy names, so a hand-rolled subset (the drift runesafe
	// exists to prevent) fails here rather than in a later cycle.
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"LF would split a record in a sink that emits it raw", "a\nb.crt", "a b.crt"},
		{"CR would split a record in a sink that emits it raw", "a\rb.crt", "a b.crt"},
		{"C0 control", "a\x01b.crt", "a b.crt"},
		{"DEL", "a\x7fb.crt", "a b.crt"},
		{"C1 control introduces a terminal escape", "a\u0085b.crt", "a b.crt"},
		{"bidi control reorders the line", "a\u202eb.crt", "a b.crt"},
		{"line separator", "a\u2028b.crt", "a b.crt"},
		{"paragraph separator", "a\u2029b.crt", "a b.crt"},
	} {
		if got := logtext.Path(tc.in); got != tc.want {
			t.Errorf("Path(%q) = %q, want %q (%s)", tc.in, got, tc.want, tc.name)
		}
	}

	// Invalid UTF-8 becomes U+FFFD, so no attribute can carry a partial rune whose tail
	// bytes read as C1 controls on a non-UTF-8 terminal. Compared exactly rather than
	// merely validated: dropping the bad byte, or substituting any other valid rune,
	// would satisfy a validity-only check while losing the fact that a byte was there.
	if got, want := logtext.Path("a\xffb.crt"), "a\ufffdb.crt"; got != want {
		t.Errorf("Path(invalid UTF-8) = %q, want %q: the bad byte is REPLACED, not dropped", got, want)
	}
}

// TestMarker_names_the_cut_in_both_paths pins the sharing this package exists for,
// from the shared leaf's own side. Two consumers bound text with this marker and must
// not drift on the wording: CapJoin caps a path inventory with Cap (after sanitizing
// each name with Path — Cap is the non-sanitizing half of that pair because CapJoin
// charges the marker's placement itself), and internal/convert hands the same const to
// runesafe.SanitizeSingleLineBudgeted for certificate-derived text.
//
// What the two do NOT share is where the marker's bytes are charged, and that is
// asserted rather than left implicit: Cap appends it after the cut, while the library
// charges it against the limit. Same wording, two budgets.
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

	sanitized, cut := runesafe.SanitizeSingleLineBudgeted(long, limit, logtext.Marker)
	if !cut {
		t.Errorf("SanitizeSingleLineBudgeted(200 bytes, %d) reported no cut, want one", limit)
	}
	if !strings.HasSuffix(sanitized, logtext.Marker) {
		t.Errorf("SanitizeSingleLineBudgeted(200 bytes, %d) = %q, want the SAME marker %q as Cap: one condition, one vocabulary",
			limit, sanitized, logtext.Marker)
	}
	if len(sanitized) > limit {
		t.Errorf("SanitizeSingleLineBudgeted(200 bytes, %d) is %d bytes, want at most the limit: that path charges the marker against it",
			limit, len(sanitized))
	}
}

package convert

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestBoundLogText_sanitizes_short_input_too pins the asymmetry this function used to
// carry: it sanitized only the text it had just truncated, so a string SHORTER than
// the limit was returned untouched. Every certificate subject in a normal deployment
// is short, which means the sanitizing half of the contract applied to almost nothing
// it was written for.
func TestBoundLogText_sanitizes_short_input_too(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in       string
		wantGone string
	}{
		"DEL in short input":           {"CN=a\u007fb.example.com", "\u007f"},
		"invalid UTF-8 in short input": {"CN=a\xffb.example.com", "\xff"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := boundLogText(tt.in, maxSubjectLogLen)
			if len(tt.in) > maxSubjectLogLen {
				t.Fatalf("fixture is %d bytes, must be under the %d-byte limit to test the short path",
					len(tt.in), maxSubjectLogLen)
			}
			if strings.Contains(got, tt.wantGone) {
				t.Errorf("boundLogText(%q) = %q, still contains %q", tt.in, got, tt.wantGone)
			}
			if !strings.Contains(got, "b.example.com") {
				t.Errorf("boundLogText(%q) = %q, want the legitimate text preserved", tt.in, got)
			}
			if strings.Contains(got, truncationMarker) {
				t.Errorf("boundLogText(%q) = %q, want no truncation marker on input under the limit", tt.in, got)
			}
			if !utf8.ValidString(got) {
				t.Errorf("boundLogText(%q) = %q, want valid UTF-8", tt.in, got)
			}
		})
	}
}

// TestBoundLogText_strips_the_one_rune_slog_does_not is the paired assertion for the
// claim boundLogText's doc comment makes. DEL must be gone because slog keeps it; the
// bidi override may stay in the returned string because slog escapes it on emit, and
// stripping it here would rewrite legitimate text for no gain. Both halves are pinned
// so a future "sanitize more" change has to argue with the evidence.
func TestBoundLogText_strips_the_one_rune_slog_does_not(t *testing.T) {
	t.Parallel()

	if got := boundLogText("a\u007fb", maxSubjectLogLen); strings.Contains(got, "\u007f") {
		t.Errorf("boundLogText kept U+007F: %q — slog's safeSet lets it reach the log raw", got)
	}
	if got := boundLogText("a\u202eb", maxSubjectLogLen); !strings.Contains(got, "\u202e") {
		t.Errorf("boundLogText stripped U+202E (%q); slog escapes it on emit, so this function need not", got)
	}
}

// TestBoundLogText_slog_escapes_what_this_function_leaves is the evidence behind the
// doc comment, asserted rather than asserted-in-prose. If a future Go release stops
// escaping one of these classes, this test fails and boundLogText has to grow to cover
// it — which is the only way that regression would ever be noticed.
func TestBoundLogText_slog_escapes_what_this_function_leaves(t *testing.T) {
	t.Parallel()

	for name, r := range map[string]string{
		"C1 escape introducer":    "\u009b",
		"bidi right-to-left over": "\u202e",
		"bidi isolate":            "\u2066",
		"arabic letter mark":      "\u061c",
		"line separator":          "\u2028",
		"paragraph separator":     "\u2029",
		"newline":                 "\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).
				Info("x", "detail", boundLogText("a"+r+"b", maxSubjectLogLen))
			// Trim the record terminator: every slog line ends with a real newline,
			// which would otherwise satisfy the newline case against the value.
			out := strings.TrimSuffix(buf.String(), "\n")
			if strings.Contains(out, r) {
				t.Errorf("slog emitted %q raw in %q; boundLogText must strip it instead", r, out)
			}
		})
	}
}

// TestBoundLogText_bounds_and_marks pins the bounding half: oversized text is cut,
// marked, and left as valid UTF-8 even when the cut lands mid-rune.
func TestBoundLogText_bounds_and_marks(t *testing.T) {
	t.Parallel()

	// A multi-byte run guarantees the byte cut lands inside a rune.
	got := boundLogText(strings.Repeat("é", 4000), maxSubjectLogLen)
	if !strings.HasSuffix(got, truncationMarker) {
		t.Errorf("boundLogText(oversized) = %q..., want the truncation marked", got[:32])
	}
	if !utf8.ValidString(got) {
		t.Errorf("boundLogText(oversized) = %q, want valid UTF-8 after a mid-rune cut", got)
	}
	if len(got) > maxSubjectLogLen+len(truncationMarker) {
		t.Errorf("boundLogText(oversized) is %d bytes, want at most limit+marker", len(got))
	}
}

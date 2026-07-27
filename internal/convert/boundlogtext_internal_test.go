package convert

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"errors"
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

// TestBoundedTextError_keeps_the_wrapped_error_reachable pins the Unwrap contract
// boundedTextError's doc comment promises. The type replaces a crypto/x509 error's
// rendered text with a bounded copy, so without Unwrap the wrapping is opaque and
// any errors.Is / errors.As classification a caller applies to a parse failure
// silently stops matching -- a failure mode no test would otherwise notice,
// because the bounded message still reads correctly.
func TestBoundedTextError_keeps_the_wrapped_error_reachable(t *testing.T) {
	t.Parallel()
	inner := errors.New("x509: malformed certificate\u007f")
	wrapped := boundedTextError{inner}

	if !errors.Is(wrapped, inner) {
		t.Error("errors.Is(boundedTextError{inner}, inner) = false, want true: the wrapped error must stay reachable")
	}
	if strings.ContainsRune(wrapped.Error(), 0x7f) {
		t.Errorf("boundedTextError.Error() = %q, want the unloggable rune dropped", wrapped.Error())
	}
}

// TestParsePrivateKey_bounds_an_oversized_pkcs8_algorithm_oid pins the key-side
// half of the bounded-text rule. x509's PKCS#8 fallback ends in "unknown
// algorithm: <OID>", interpolating an OBJECT IDENTIFIER decoded straight out of
// the key file, and asn1 allocates one component per content byte -- so a key
// inside the 10 MB input read bound renders a multi-megabyte ERROR line, re-emitted
// on every scan because a failed pair is never cached.
func TestParsePrivateKey_bounds_an_oversized_pkcs8_algorithm_oid(t *testing.T) {
	t.Parallel()
	oid := testASN1Marshal(t, asn1.RawValue{Tag: asn1.TagOID, Bytes: bytes.Repeat([]byte{0x01}, 64<<10)})
	algorithm := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: oid}
	der := testASN1Marshal(t, struct {
		Version    int
		Algo       asn1.RawValue
		PrivateKey []byte
	}{Version: 0, Algo: algorithm, PrivateKey: []byte{}})

	_, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err == nil {
		t.Fatal("ParsePrivateKey(PKCS#8 with a 64 KB algorithm OID) = nil error, want a parse failure")
	}
	// The static prefix names the block type and the parsers tried; everything
	// input-derived past it is what the bound has to cover.
	const staticPrefix = len("failed to parse private key from PRIVATE KEY block (tried PKCS8, PKCS1, SEC1): ")
	if want := staticPrefix + maxSubjectLogLen + len(truncationMarker); len(err.Error()) > want {
		t.Errorf("error is %d bytes, want at most %d: the OID reaches the log unbounded", len(err.Error()), want)
	}
	if !strings.HasSuffix(err.Error(), truncationMarker) {
		t.Errorf("error = %q, want the truncation marked", err.Error())
	}
}

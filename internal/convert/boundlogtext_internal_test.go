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

// TestBoundLogText_applies_the_runesafe_single_line_policy pins the policy
// boundLogText now delegates to (runesafe.SanitizeSingleLine): each unsafe rune
// becomes a SPACE, invalid UTF-8 becomes U+FFFD, and legitimate text — including
// non-ASCII letters — is untouched. Exact expected values rather than
// "must not contain", because the replacement rune is part of the contract: a
// dropped rune would silently join a subject's neighbouring labels.
//
// This deliberately REVERSES the assertion the previous version of this test made.
// It required U+202E to SURVIVE, on the evidence that the only reachable handler
// (TextHandler) escapes it, so stripping it here would rewrite legitimate text for
// no gain. Delegating widens the policy to the whole unsafe set, which is the
// accepted cost of a sanitizer that is correct under either handler rather than
// under the one currently wired up. Which class each handler emits raw is recorded
// per row in the table below, and asserted end-to-end by
// TestBoundLogText_output_is_safe_under_either_slog_handler.
//
// Every fixture is well under maxSubjectLogLen, so this also pins the asymmetry
// the function once carried: it sanitized only the text it had just truncated, and
// input SHORTER than the limit came back untouched — which is nearly every
// certificate subject in a real deployment. Exact equality against a want that is
// valid UTF-8 and carries no truncation marker states both of those as part of the
// expected value, so no separate assertion is needed for either.
func TestBoundLogText_applies_the_runesafe_single_line_policy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   string
		want string
	}{
		// Raw under BOTH handlers: the leak the old hand-rolled policy existed for.
		"DEL": {"a\u007fb", "a b"},
		// Raw under JSONHandler, escaped by TextHandler: the classes that made the
		// old policy correct only for the handler that happens to be wired up.
		"C1 escape introducer":        {"a\u009bb", "a b"},
		"C1 next line":                {"a\u0085b", "a b"},
		"bidi right-to-left override": {"a\u202eb", "a b"},
		"bidi arabic letter mark":     {"a\u061cb", "a b"},
		"bidi isolate":                {"a\u2066b", "a b"},
		// Escaped by both handlers, but a single-line sink must not carry them.
		"line separator":      {"a\u2028b", "a b"},
		"paragraph separator": {"a\u2029b", "a b"},
		"C0 NUL":              {"a\x00b", "a b"},
		"newline":             {"a\nb", "a b"},
		"carriage return":     {"a\rb", "a b"},
		"tab":                 {"a\tb", "a b"},
		// Invalid bytes become the replacement rune rather than vanishing, so the
		// result is always valid UTF-8 (strings.Map, via the library).
		"invalid UTF-8": {"CN=a\xffb.example.com", "CN=a\ufffdb.example.com"},
		// Legitimate text, including non-ASCII, is returned byte-identical.
		"plain subject":        {"CN=plain.example.com", "CN=plain.example.com"},
		"non-ASCII letters":    {"CN=café.example.com", "CN=café.example.com"},
		"full subject with DN": {"CN=a.example.com,O=Example Ltd,C=NL", "CN=a.example.com,O=Example Ltd,C=NL"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := boundLogText(tt.in, maxSubjectLogLen)
			if got != tt.want {
				t.Errorf("boundLogText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestBoundLogText_output_is_safe_under_either_slog_handler is the evidence behind
// the reason for delegating, asserted rather than asserted-in-prose. Each rune here
// reaches at least one of the two handlers RAW — DEL both of them, C1 and
// Bidi_Control the JSON one — so before delegation the policy was correct only
// because JSONHandler is unreachable. Both handlers are exercised, so the day
// slogx.Setup is given Format: slogx.JSON this test still holds and no widening of
// this package is a prerequisite.
func TestBoundLogText_output_is_safe_under_either_slog_handler(t *testing.T) {
	t.Parallel()

	handlers := map[string]func(*bytes.Buffer) slog.Handler{
		"TextHandler": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"JSONHandler": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	}
	runes := map[string]string{
		"DEL":                     "\u007f",
		"C1 escape introducer":    "\u009b",
		"bidi right-to-left over": "\u202e",
		"bidi isolate":            "\u2066",
		"arabic letter mark":      "\u061c",
		"line separator":          "\u2028",
		"paragraph separator":     "\u2029",
		"newline":                 "\n",
	}

	for handlerName, newHandler := range handlers {
		for name, r := range runes {
			t.Run(handlerName+"/"+name, func(t *testing.T) {
				t.Parallel()
				var buf bytes.Buffer
				slog.New(newHandler(&buf)).
					Info("x", "detail", boundLogText("a"+r+"b", maxSubjectLogLen))
				// Trim the record terminator: every slog line ends with a real newline,
				// which would otherwise satisfy the newline case against the value.
				out := strings.TrimSuffix(buf.String(), "\n")
				if strings.Contains(out, r) {
					t.Errorf("%s emitted %q raw in %q; boundLogText must sanitize it first", handlerName, r, out)
				}
			})
		}
	}
}

// TestBoundLogText_bounds_and_marks pins the bounding half: oversized text is cut,
// marked, and left as valid UTF-8 even when the cut lands mid-rune.
func TestBoundLogText_bounds_and_marks(t *testing.T) {
	t.Parallel()

	// A 3-byte run guarantees the byte cut lands INSIDE a rune: maxSubjectLogLen
	// (256) is not a multiple of 3, so runesafe.CapBytes must back the cut off to
	// the preceding rune start. A 2-byte rune divides 256 evenly and would never
	// exercise that backoff.
	got := boundLogText(strings.Repeat("\u2603", 4000), maxSubjectLogLen)
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
		t.Errorf("boundedTextError.Error() = %q, want the unsafe rune sanitized", wrapped.Error())
	}
}

// TestParsePrivateKey_bounds_an_oversized_pkcs8_algorithm_oid pins the key-side
// half of the bounded-text rule, now enforced BEFORE x509 sees the block. x509's
// PKCS#8 fallback ends in "unknown algorithm: <OID>", interpolating an OBJECT
// IDENTIFIER decoded straight out of the key file, and asn1 allocates one component
// per content byte -- so a key inside the 10 MB input read bound rendered a
// multi-megabyte ERROR line, re-emitted on every scan because a failed pair is
// never cached, after paying that allocation to produce it.
// oversizedKeyAlgorithmOIDError now refuses the block on the identifier's LENGTH
// instead, so neither the allocation nor the unbounded text is paid at all: the
// diagnostic is a size and a ceiling, and the identifier's own bytes never reach it.
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
		t.Fatal("ParsePrivateKey(PKCS#8 with a 64 KB algorithm OID) = nil error, want a refusal")
	}
	// The refusal carries no input-derived text at all, so the same ceiling the
	// truncating path had to respect bounds it with room to spare.
	if want := maxSubjectLogLen + len(truncationMarker) + 256; len(err.Error()) > want {
		t.Errorf("error is %d bytes, want at most %d: the OID reaches the log unbounded", len(err.Error()), want)
	}
	if strings.Contains(err.Error(), strings.Repeat("\x01", 8)) {
		t.Errorf("error = %q, want the identifier's own bytes absent from the diagnostic", err.Error())
	}
	for _, want := range []string{"algorithm identifier", "32-byte ceiling"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q: the operator has to know which bound refused the key", err.Error(), want)
		}
	}
}

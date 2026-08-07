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

	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/runesafe"
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
//
// The TOTAL bound is the assertion that changed when boundLogText stopped composing
// its own cap-and-mark and took runesafe's caller-marker primitive: the marker is now
// charged AGAINST the limit, so the result never exceeds maxSubjectLogLen at all,
// where it used to run to the limit PLUS the marker. Asserting the tighter bound is
// what makes the new contract a contract rather than an accident.
func TestBoundLogText_bounds_and_marks(t *testing.T) {
	t.Parallel()

	// A 3-byte run guarantees the byte cut lands INSIDE a rune: maxSubjectLogLen
	// (256) is not a multiple of 3, so the library's rune-boundary backoff must move
	// the cut. A 2-byte rune divides 256 evenly and would never exercise it.
	got := boundLogText(strings.Repeat("\u2603", 4000), maxSubjectLogLen)
	if !strings.HasSuffix(got, truncationMarker) {
		t.Errorf("boundLogText(oversized) = %q..., want the truncation marked", got[:32])
	}
	if !utf8.ValidString(got) {
		t.Errorf("boundLogText(oversized) = %q, want valid UTF-8 after a mid-rune cut", got)
	}
	if len(got) > maxSubjectLogLen {
		t.Errorf("boundLogText(oversized) is %d bytes, want at most the %d-byte limit: the marker is charged against it",
			len(got), maxSubjectLogLen)
	}
}

// TestBoundLogText_is_the_library_primitive_with_this_apps_marker pins that
// boundLogText adds NOTHING to runesafe.SanitizeSingleLineCapped except this app's
// marker and limit. Comparing against the library's own output is the assertion,
// rather than re-deriving the sanitize-cap-mark rule the production code just
// delegated: a reintroduced local composition — a second cap, a marker appended
// outside the budget, a re-sanitize — shows up here as a difference.
//
// The cut FACT is asserted too, because it is the half boundLogText inherits and
// discards: the fixtures are chosen so the marker's presence and the library's cut
// flag must agree. That equivalence is NOT a general law (a value can legitimately
// end in the marker without having been cut, which is why the fuzz target asserts
// the marker in one direction only); it holds for these inputs, and it is what proves
// the marker in the text comes from a cut this call actually made.
func TestBoundLogText_is_the_library_primitive_with_this_apps_marker(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		in      string
		wantCut bool
	}{
		"empty":                                    {in: ""},
		"a subject that fits":                      {in: "CN=plain.example.com"},
		"a subject at the limit":                   {in: strings.Repeat("a", maxSubjectLogLen)},
		"a subject one byte over":                  {in: strings.Repeat("a", maxSubjectLogLen+1), wantCut: true},
		"multi-byte runes cut mid-rune":            {in: strings.Repeat("\u2603", 4000), wantCut: true},
		"invalid bytes that GROW past the limit":   {in: strings.Repeat("\xff", 200), wantCut: true},
		"unsafe runes that SHRINK under the limit": {in: strings.Repeat("\u202e", 86)},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantText, wantCut := runesafe.SanitizeSingleLineCapped(tc.in, maxSubjectLogLen, logtext.Marker)
			got := boundLogText(tc.in, maxSubjectLogLen)

			if got != wantText {
				t.Errorf("boundLogText(%d bytes) = %q, want the library's own %q: nothing may be composed on top",
					len(tc.in), got, wantText)
			}
			if wantCut != tc.wantCut {
				t.Errorf("runesafe reported cut = %v for %s, want %v: the fixture no longer exercises what it claims",
					wantCut, name, tc.wantCut)
			}
			if marked := strings.HasSuffix(got, truncationMarker); marked != tc.wantCut {
				t.Errorf("boundLogText(%s) = %q, marked = %v, want it marked exactly when the text was cut (%v)",
					name, got, marked, tc.wantCut)
			}
			if len(got) > maxSubjectLogLen {
				t.Errorf("boundLogText(%s) is %d bytes, want at most %d", name, len(got), maxSubjectLogLen)
			}
		})
	}
}

// TestTruncationMarker_does_not_drift_from_the_shared_leaf pins the one thing the
// two bounding paths still share after the sanitizing one moved to the library.
// internal/process bounds its orphan path sample with logtext.Cap (deliberately
// unsanitized: those paths are the operator's own tree and its query key), and this
// package hands runesafe the same const. The marker is an operator's log query key,
// so two spellings would give one condition two vocabularies — the whole reason the
// shared leaf exists. This asserts the wording reaching a diagnostic here IS that
// const, not a copy that happens to match today.
func TestTruncationMarker_does_not_drift_from_the_shared_leaf(t *testing.T) {
	t.Parallel()
	cut := boundLogText(strings.Repeat("a", maxSubjectLogLen+1), maxSubjectLogLen)
	if !strings.HasSuffix(cut, logtext.Marker) {
		t.Errorf("boundLogText marked a cut with %q, want the shared marker %q",
			cut[max(0, len(cut)-32):], logtext.Marker)
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

// TestParsePrivateKey_bounds_an_oversized_pkcs8_parameters_oid pins the SIBLING
// identifier of the one above. The AlgorithmIdentifier's parameters field is decoded
// by the very same x509 call: with algorithm = id-ecPublicKey (7 bytes, so the
// identifier bound passes it) x509 unmarshals parameters into an
// asn1.ObjectIdentifier -- the named curve -- one int per encoded byte, before it can
// reject an unsupported curve. The refusal has to name the parameter identifier and
// carry none of its bytes, exactly like the identifier's own bound.
func TestParsePrivateKey_bounds_an_oversized_pkcs8_parameters_oid(t *testing.T) {
	t.Parallel()
	algorithm := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(
		testASN1Marshal(t, ecPublicKeyOID),
		testASN1Marshal(t, asn1.RawValue{Tag: asn1.TagOID, Bytes: bytes.Repeat([]byte{0x01}, 64<<10)})...)}
	der := testASN1Marshal(t, struct {
		Version    int
		Algo       asn1.RawValue
		PrivateKey []byte
	}{Version: 0, Algo: algorithm, PrivateKey: []byte{}})

	_, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err == nil {
		t.Fatal("ParsePrivateKey(PKCS#8 with a 64 KB parameters OID) = nil error, want a refusal")
	}
	if want := maxSubjectLogLen + len(truncationMarker) + 256; len(err.Error()) > want {
		t.Errorf("error is %d bytes, want at most %d: the parameter OID reaches the log unbounded", len(err.Error()), want)
	}
	if strings.Contains(err.Error(), strings.Repeat("\x01", 8)) {
		t.Errorf("error = %q, want the identifier's own bytes absent from the diagnostic", err.Error())
	}
	for _, want := range []string{"algorithm parameter identifier", "32-byte ceiling"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q", err.Error(), want)
		}
	}
}

// TestParsePrivateKey_bounds_an_oversized_sec1_curve_oid pins the third door on the
// same call chain: parsePrivateKeyBlock tries x509.ParseECPrivateKey on every block
// that fails PKCS#8 and PKCS#1, and that parser decodes the explicit [0] named-curve
// identifier into an asn1.ObjectIdentifier before it can reject an unknown curve.
// Neither the RSA pre-scan (this shape's second element is an OCTET STRING) nor the
// PKCS#8 identifier bound (not this shape) intercepts the block.
func TestParsePrivateKey_bounds_an_oversized_sec1_curve_oid(t *testing.T) {
	t.Parallel()
	curve := testASN1Marshal(t, asn1.RawValue{Tag: asn1.TagOID, Bytes: bytes.Repeat([]byte{0x01}, 64<<10)})
	der := testASN1Marshal(t, struct {
		Version    int
		PrivateKey []byte
		Parameters asn1.RawValue
	}{
		Version:    1,
		PrivateKey: bytes.Repeat([]byte{0x02}, 32),
		Parameters: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: curve},
	})

	_, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err == nil {
		t.Fatal("ParsePrivateKey(SEC1 with a 64 KB curve OID) = nil error, want a refusal")
	}
	if want := maxSubjectLogLen + len(truncationMarker) + 256; len(err.Error()) > want {
		t.Errorf("error is %d bytes, want at most %d: the curve OID reaches the log unbounded", len(err.Error()), want)
	}
	if strings.Contains(err.Error(), strings.Repeat("\x01", 8)) {
		t.Errorf("error = %q, want the identifier's own bytes absent from the diagnostic", err.Error())
	}
	for _, want := range []string{"curve identifier", "32-byte ceiling"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q", err.Error(), want)
		}
	}
}

// TestParsePrivateKey_bounds_an_oversized_sec1_curve_oid_inside_pkcs8 pins the FOURTH
// door, the one the finding behind the PKCS#8 retry was actually about: x509 reaches
// the same SEC1 parser through a PKCS#8 EC container, so for an id-ecPublicKey key
// ParsePKCS8PrivateKey hands the privateKey OCTET STRING to parseECPrivateKey, which
// decodes the INNER explicit [0] named-curve identifier into an asn1.ObjectIdentifier
// and then discards it. Neither the RSA pre-scan (this structure's second element is
// an OCTET STRING) nor the AlgorithmIdentifier bound (whose own identifiers here are
// the ordinary 7 and 8 bytes) sees the inner identifier, so only the PKCS#8 unwrap in
// oversizedSEC1CurveOIDError refuses this shape.
func TestParsePrivateKey_bounds_an_oversized_sec1_curve_oid_inside_pkcs8(t *testing.T) {
	t.Parallel()
	algorithm := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: append(
		testASN1Marshal(t, ecPublicKeyOID),
		testASN1Marshal(t, asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})...)}
	pkcs8WrappingSEC1 := func(t *testing.T, curveOIDBytes int) []byte {
		t.Helper()
		curve := testASN1Marshal(t, asn1.RawValue{Tag: asn1.TagOID, Bytes: bytes.Repeat([]byte{0x01}, curveOIDBytes)})
		sec1 := testASN1Marshal(t, struct {
			Version    int
			PrivateKey []byte
			Parameters asn1.RawValue
		}{
			Version:    1,
			PrivateKey: bytes.Repeat([]byte{0x02}, 32),
			Parameters: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: curve},
		})
		return testASN1Marshal(t, struct {
			Version    int
			Algo       asn1.RawValue
			PrivateKey []byte
		}{Version: 0, Algo: algorithm, PrivateKey: sec1})
	}

	_, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8WrappingSEC1(t, 64<<10),
	}))
	if err == nil {
		t.Fatal("ParsePrivateKey(PKCS#8 wrapping a SEC1 key with a 64 KB curve OID) = nil error, want a refusal")
	}
	for _, want := range []string{"curve identifier", "32-byte ceiling"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q", err.Error(), want)
		}
	}
	if strings.Contains(err.Error(), strings.Repeat("\x01", 8)) {
		t.Errorf("error = %q, want the identifier's own bytes absent from the diagnostic", err.Error())
	}

	// The fail-open half: a NORMAL inner curve identifier must reach the parser, so
	// whatever verdict comes back is x509's own and not this guard's.
	_, smallErr := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8WrappingSEC1(t, 8),
	}))
	if smallErr != nil && strings.Contains(smallErr.Error(), "curve identifier") {
		t.Errorf("ParsePrivateKey(PKCS#8 wrapping a SEC1 key with an 8-byte curve OID) = %v, want no curve-identifier refusal: an ordinary identifier must be left to the parser", smallErr)
	}
}

// TestParseCertChain_bounds_the_pem_label_it_names pins the LABEL axis of the bound
// this file already tests on the subject axis. maxBlockTypeLogLen exists because a PEM
// type line is arbitrary operator-supplied text capped only by the caller's
// MaxInputBytes read bound, and skippedBlocks.firstTypeForLog is what a parse
// diagnostic names -- so a widened or dropped bound puts a multi-megabyte line into the
// container log on every scan that retries the pair, the same failure
// maxSubjectLogLen is tested against. Nothing pinned it: widening
// maxBlockTypeLogLen from 64 to 512 leaves the whole package suite green.
func TestParseCertChain_bounds_the_pem_label_it_names(t *testing.T) {
	t.Parallel()

	label := strings.Repeat("A", 200<<10)
	_, _, err := parseCertChain(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: []byte("opaque")}))
	if err == nil {
		t.Fatal("parseCertChain(a block with a 200 KB label) = nil error, want a refusal")
	}
	quoted := strings.Repeat("A", maxBlockTypeLogLen)
	if !strings.Contains(err.Error(), quoted[:maxBlockTypeLogLen-len(truncationMarker)]+truncationMarker) {
		t.Errorf("parseCertChain error = %q, want the label cut at %d bytes and marked", err.Error(), maxBlockTypeLogLen)
	}
	if len(err.Error()) > 256 {
		t.Errorf("parseCertChain error is %d bytes, want the label bounded before it reaches the log", len(err.Error()))
	}
}

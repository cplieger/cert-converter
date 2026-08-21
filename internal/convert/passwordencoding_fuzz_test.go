package convert_test

import (
	"slices"
	"testing"
	"unicode/utf16"

	"github.com/cplieger/cert-converter/internal/convert"
)

// FuzzInspectPasswordEncoding_classifies_every_unencodable_shape fuzzes the
// classifier both the startup gate (internal/config) and the codec guard
// (Encode) read their verdict from, against oracles derived independently of
// the production predicates.
//
// It is the classifier's only independent check. The existing rapid property
// (convert_prop_test.go) takes InspectPasswordEncoding's own output as the
// expected value, so it pins Encode's AGREEMENT with the classifier rather than
// the classifier's correctness, and the table covers eleven hand-picked
// passwords. A wrongly-clean verdict is silent in exactly the way that matters:
// go-pkcs12 encodes invalid UTF-8 and an interior NUL happily, so the bundle
// lands on disk protected by a different password than the operator supplied and
// the failure surfaces only at whatever later tries to open it.
//
// The oracles are the UCS-2 encoding itself (RFC 7292 appendix B.1), not a copy
// of the production checks: a rune round trip for the UTF-8 verdict, the
// surrogate-pair expansion for the BMP verdict, and a zero code unit for the
// NUL verdict.
func FuzzInspectPasswordEncoding_classifies_every_unencodable_shape(f *testing.F) {
	f.Add("")
	f.Add("correct-horse")
	f.Add("pässwörd-Ω")
	f.Add("\uFFFD")
	f.Add(string([]byte{0xff, 0xfe}) + "tail")
	// The BMP boundary, as a durable seed pair: U+FFFF is the last code point UCS-2
	// carries in one code unit (encodable), U+10000 the first that needs a surrogate
	// pair (not). Coverage-guided exploration effectively never lands on exactly
	// U+FFFF, and the weekly run discards its generated corpus, so only a committed
	// seed pins the comparison.
	f.Add("pw-\uFFFF")
	f.Add("pw-\U00010000")
	f.Add("pw-\U0001F600")
	f.Add("s3cret\x00")
	f.Add("s\x00e\x00c\x00")
	f.Add(string([]byte{0xff}) + "pw-\U0001F600\x00")

	f.Fuzz(func(t *testing.T, password string) {
		issues := convert.InspectPasswordEncoding(password)
		runes := []rune(password)
		units := utf16.Encode(runes)

		// Invalid UTF-8 is exactly what a rune round trip cannot survive: every
		// invalid byte becomes U+FFFD, which is the same substitution the PKCS#12
		// encoding would make, and a password that legitimately holds U+FFFD is
		// returned byte-identical.
		if want := string(runes) != password; issues.InvalidUTF8 != want {
			t.Fatalf("InspectPasswordEncoding(%d bytes).InvalidUTF8 = %v, want %v: the rune round trip %q disagrees",
				len(password), issues.InvalidUTF8, want, string(runes))
		}
		// A rune outside the BMP is exactly a rune UCS-2 must expand into two code
		// units, so the expansion is the oracle.
		if want := len(units) != len(runes); issues.NonBMP != want {
			t.Fatalf("InspectPasswordEncoding(%d bytes).NonBMP = %v, want %v: %d rune(s) encode as %d UCS-2 code unit(s)",
				len(password), issues.NonBMP, want, len(runes), len(units))
		}
		// PKCS#12 passwords are NUL-terminated BMPStrings, so what matters is a zero
		// code unit in the encoded form, not a byte in the input.
		if want := slices.Contains(units, uint16(0)); issues.EmbeddedNUL != want {
			t.Fatalf("InspectPasswordEncoding(%d bytes).EmbeddedNUL = %v, want %v: the UCS-2 form %s a zero code unit",
				len(password), issues.EmbeddedNUL, want, map[bool]string{true: "carries", false: "carries no"}[want])
		}

		// Why must name a shape whenever one was found and none when none was, or
		// the callers that refuse on a non-empty result (config's startup gate,
		// Encode's guard) accept a password the classifier rejected.
		why := issues.Why()
		clean := issues == convert.PasswordEncodingIssues{}
		if (why == "") != clean {
			t.Fatalf("InspectPasswordEncoding(%d bytes) = %+v with Why() = %q; a shape must not go unnamed",
				len(password), issues, why)
		}
	})
}

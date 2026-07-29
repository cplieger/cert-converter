package convert_test

import (
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
)

// TestEncoderName pins both halves of the normalization contract: the name a
// raw PFX_ENCODER value resolves to AND the known flag that decides whether the
// caller warns. internal/config owns the warning, so the flag itself is only
// asserted here; without it a spelling that silently stopped being recognized
// would still return the right default name and go unnoticed.
//
// Which pkcs12.Encoder each name selects is deliberately NOT asserted by pointer
// identity here: that is an implementation detail an equivalent encoder value would
// fail while emitting the same algorithms. The behaviour is pinned end-to-end by
// TestInspect_identifies_every_profile_we_emit (Encode then Inspect, all four
// profiles) and TestCheckCurrency_resolves_an_unknown_encoder_name_the_way_Encode_does
// (the unknown-name fallback).
func TestEncoderName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw       string
		wantName  convert.EncoderType
		wantKnown bool
	}{
		{"", convert.EncNameModern2023, true},
		{"modern", convert.EncNameModern2023, true},
		{"modern2023", convert.EncNameModern2023, true},
		{"MODERN2023", convert.EncNameModern2023, true},
		{"  modern2023\t", convert.EncNameModern2023, true},
		{"modern2026", convert.EncNameModern2026, true},
		{"Modern2026", convert.EncNameModern2026, true},
		{"legacy", convert.EncNameLegacyDES, true},
		{"legacydes", convert.EncNameLegacyDES, true},
		{"LegacyDES", convert.EncNameLegacyDES, true},
		{"legacyrc2", convert.EncNameLegacyRC2, true},
		{"LEGACYRC2", convert.EncNameLegacyRC2, true},
		{"   ", convert.EncNameModern2023, true},
		{"modern2029", convert.EncNameModern2023, false},
		{"legcy", convert.EncNameModern2023, false},
		{"legacy des", convert.EncNameModern2023, false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			name, known := convert.EncoderName(tc.raw)
			if name != tc.wantName {
				t.Errorf("convert.EncoderName(%q) name = %q, want %q", tc.raw, name, tc.wantName)
			}
			if known != tc.wantKnown {
				t.Errorf("convert.EncoderName(%q) known = %v, want %v", tc.raw, known, tc.wantKnown)
			}
		})
	}
}

// TestEncoderNames_advertises_only_spellings_EncoderName_accepts pins the agreement
// between the value domain the app ADVERTISES and the one it ACCEPTS. internal/config
// passes convert.EncoderNames() as the "expected" attribute of its "unknown PFX_ENCODER"
// WARN, so every name in the list is a value an operator is told to use, while
// EncoderName matches a lower-cased, trimmed value against each row's name -- a row
// spelled any other way would be advertised and then silently replaced with the
// modern2023 default, leaving the operator on the same WARN after a restart. Nothing else
// pins it: config's own test compares the RENDERED list against a literal, which stays
// true for a name EncoderName cannot resolve.
func TestEncoderNames_advertises_only_spellings_EncoderName_accepts(t *testing.T) {
	t.Parallel()
	want := []convert.EncoderType{
		convert.EncNameModern2023,
		convert.EncNameModern2026,
		convert.EncNameLegacyDES,
		convert.EncNameLegacyRC2,
	}
	names := convert.EncoderNames()
	if len(names) != len(want) {
		t.Fatalf("convert.EncoderNames() = %v, want the %d canonical spellings %v", names, len(want), want)
	}
	for i, name := range names {
		if name != want[i] {
			t.Errorf("convert.EncoderNames()[%d] = %q, want %q: the list is the profile table's own order", i, name, want[i])
		}
		resolved, known := convert.EncoderName(string(name))
		if !known || resolved != name {
			t.Errorf("convert.EncoderName(%q) = (%q, %v), want (%q, true): an advertised spelling the app cannot resolve leaves the operator on the default",
				name, resolved, known, name)
		}
	}
}

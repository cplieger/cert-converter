package convert_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// hugeKDFIterations rewrites the FIRST key-derivation iteration count of a
// modern2023 bundle to a two-byte maximum, which is the shape of the attack the
// preflight exists to stop: the file names the derivation work and the decoder
// honours it.
//
// modern2023 writes 2048 for both its MAC and its encryption, which DER-encodes as
// 02 02 08 00, and authSafe precedes macData in a PFX (RFC 7292 SEQUENCE order), so
// the patched count is an authSafe one — the preflight bounds every count it can
// read, so which one it is does not change the outcome. The replacement keeps the
// encoding length identical, so the surrounding structure stays valid and only the
// count changes.
//
// Patching the count also invalidates the MAC, which is what makes the bundle a
// usable ORDER detector: the preflight refuses it before any derivation, while a
// decoder handed it first reports a decode failure instead — a different,
// observable reason.
func hugeKDFIterations(t *testing.T, pfx []byte) []byte {
	t.Helper()
	encoded2048 := []byte{0x02, 0x02, 0x08, 0x00}
	if n := bytes.Count(pfx, encoded2048); n == 0 {
		t.Fatalf("no DER-encoded 2048-iteration count found in a modern2023 bundle: the pinned encoder's framing changed, so this test no longer verifies the KDF iteration bound at all")
	}
	return bytes.Replace(bytes.Clone(pfx), encoded2048, []byte{0x02, 0x02, 0x7f, 0xff}, 1)
}

// TestCheckCurrency_runs_the_preflight_and_profile_check_before_the_decode is the
// load-bearing test for why the three read-back steps were collapsed into one
// entry point. The ORDER is the safety property: the preflight bounds every
// key-derivation iteration count the FILE dictates before any of them reaches
// PBKDF2, and the profile comparison answers a PFX_ENCODER change without
// decrypting anything.
//
// A test that only checked the verdict would not catch a reordering, because every
// case here is "not current" either way. Each case is therefore built so that the
// step that MUST run first and the step that must not run yet disagree about the
// diagnosis, and the reason is asserted:
//
//   - an out-of-range iteration count is a preflight refusal; run the decoder
//     first and it becomes a decode failure (the patched bytes invalidate the
//     MAC, which the decoder verifies with the intact 2048-iteration count
//     before any content derivation);
//   - a bundle from another profile is a profile mismatch; run the decoder first
//     (here with a password that cannot open it) and it becomes a decode failure.
func TestCheckCurrency_runs_the_preflight_and_profile_check_before_the_decode(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	good, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if res := analysis.CheckCurrency(good, "pw", convert.EncNameModern2023); res.Reason != convert.CurrencyMatch {
		t.Fatalf("setup: CheckCurrency(the bundle just encoded) = %q, want a match", res.Reason)
	}

	tests := map[string]struct {
		pfx         []byte
		password    string
		wantEncoder convert.EncoderType
		wantReason  convert.CurrencyReason
	}{
		"an out-of-range iteration count is refused by the preflight, not by the decoder": {
			pfx: hugeKDFIterations(t, good), password: "pw",
			wantEncoder: convert.EncNameModern2023,
			wantReason:  convert.CurrencyPreflightFailed,
		},
		"a bundle written by another profile is answered before any derivation runs": {
			pfx: good, password: "a password that cannot open this bundle",
			wantEncoder: convert.EncNameLegacyDES,
			wantReason:  convert.CurrencyProfileMismatch,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res := analysis.CheckCurrency(tt.pfx, tt.password, tt.wantEncoder)
			if res.Reason != tt.wantReason {
				t.Errorf("CheckCurrency reason = %q, want %q: the read-back steps ran out of order",
					res.Reason, tt.wantReason)
			}
			if res.Reason == convert.CurrencyMatch {
				t.Error("CheckCurrency reported the bundle as current, want a rewrite")
			}
		})
	}
}

// TestCheckCurrency_preflight_refusal_is_the_bounded_one pins the other half of
// the ordering claim: the preflight refusal must be the KDF bound speaking, not
// some later arm that happens to reject the same bytes. Without this, a
// preflight-shaped reason produced by a decode failure would satisfy the ordering
// test above.
func TestCheckCurrency_preflight_refusal_is_the_bounded_one(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	good, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	res := analysis.CheckCurrency(hugeKDFIterations(t, good), "pw", convert.EncNameModern2023)
	if res.Reason != convert.CurrencyPreflightFailed {
		t.Fatalf("CheckCurrency reason = %q, want %q", res.Reason, convert.CurrencyPreflightFailed)
	}
	if !errors.Is(res.Err, convert.ErrProfileUnknown) {
		t.Errorf("CheckCurrency error = %v, want it to wrap ErrProfileUnknown: the refusal must come from the preflight's own bound", res.Err)
	}
}

// TestCheckCurrency_classifies_every_outcome pins the return shape the caller
// consumes. internal/process's store.inspect logs a different diagnostic per
// reason — a prior that does not decode at Debug, a profile change at Info, a
// content mismatch silently — so a bare bool would flatten distinctions the
// operator reads. Each case asserts the reason, the derived verdict, and whether
// the reason's own field (Err or Profile) is populated.
func TestCheckCurrency_classifies_every_outcome(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	good, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	strangerPEM, strangerKeyPEM := testcerts.GenerateSelfSignedCert(t, "stranger.example.com", "ecdsa")
	stranger, err := convert.Analyse(t.Context(), strangerPEM, strangerKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse(stranger): %v", err)
	}
	strangerPFX, err := stranger.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode(stranger): %v", err)
	}

	tests := map[string]struct {
		pfx         []byte
		password    string
		wantEncoder convert.EncoderType
		wantReason  convert.CurrencyReason
		wantErr     bool
		wantProfile convert.EncoderType
	}{
		"the bundle these inputs produce is current": {
			pfx: good, password: "pw", wantEncoder: convert.EncNameModern2023,
			wantReason: convert.CurrencyMatch,
		},
		"a file that is not a bundle at all is proven foreign by the preflight": {
			pfx: []byte("this is not a pkcs12 bundle"), password: "pw",
			wantEncoder: convert.EncNameModern2023,
			wantReason:  convert.CurrencyForeign, wantErr: true,
		},
		"a bundle from another profile reports the profile it was written with": {
			pfx: good, password: "pw", wantEncoder: convert.EncNameModern2026,
			wantReason: convert.CurrencyProfileMismatch, wantProfile: convert.EncNameModern2023,
		},
		"a rotated password is a decode failure": {
			pfx: good, password: "rotated", wantEncoder: convert.EncNameModern2023,
			wantReason: convert.CurrencyDecodeFailed, wantErr: true,
		},
		"a bundle for different inputs is a content mismatch": {
			pfx: strangerPFX, password: "pw", wantEncoder: convert.EncNameModern2023,
			wantReason: convert.CurrencyContentMismatch,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			before := bytes.Clone(tt.pfx)
			res := analysis.CheckCurrency(tt.pfx, tt.password, tt.wantEncoder)
			if res.Reason != tt.wantReason {
				t.Errorf("CheckCurrency reason = %q, want %q", res.Reason, tt.wantReason)
			}
			if (res.Err != nil) != tt.wantErr {
				t.Errorf("CheckCurrency error = %v, want an error: %v", res.Err, tt.wantErr)
			}
			if res.Profile != tt.wantProfile {
				t.Errorf("CheckCurrency profile = %q, want %q", res.Profile, tt.wantProfile)
			}
			if !bytes.Equal(before, tt.pfx) {
				t.Error("CheckCurrency mutated its input")
			}
		})
	}
}

// TestCurrency_zero_value_is_not_current pins the choice of a string reason whose
// zero value is not a match: a Currency nobody filled in must read as "rewrite
// it", never as "the file on disk is fine".
func TestCurrency_zero_value_is_not_current(t *testing.T) {
	t.Parallel()
	if (convert.Currency{}).Reason == convert.CurrencyMatch {
		t.Error("Currency{}.Reason = CurrencyMatch, want anything else: an unfilled verdict must never report a bundle as current")
	}
}

// TestCheckCurrency_resolves_an_unknown_encoder_name_the_way_Encode_does pins the
// agreement between the write side and the read-back side. resolvedProfile is total: an
// EncoderType no profile row names still selects modern2023, so Encode WRITES a
// modern2023 bundle. If CheckCurrency compared the file against the raw name it
// was handed, it would report profile-mismatch on the very bundle Encode had just
// produced, and the caller would rewrite the file on every scan forever.
func TestCheckCurrency_resolves_an_unknown_encoder_name_the_way_Encode_does(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}

	const unknown = convert.EncoderType("modern2024")
	pfx, err := analysis.Encode(unknown, "pw")
	if err != nil {
		t.Fatalf("Encode(unknown encoder name) = error %v, want the modern2023 fallback to succeed", err)
	}
	if res := analysis.CheckCurrency(pfx, "pw", unknown); res.Reason != convert.CurrencyMatch {
		t.Errorf("CheckCurrency(the bundle Encode just wrote for %q) = %q, want a match",
			unknown, res.Reason)
	}
}

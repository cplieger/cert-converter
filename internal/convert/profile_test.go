package convert_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestInspect_identifies_every_profile_we_emit is the load-bearing test for
// encoder-profile currency: each of the four profiles must be recognised from the
// bytes alone, because decoding cannot reveal which one wrote a bundle and a
// PFX_ENCODER change would otherwise rewrite nothing.
//
// Both fields are needed and this proves it: modern2023 and modern2026 differ only
// in their MAC, while legacydes and legacyrc2 share a SHA-1 MAC and differ only in
// their encryption. Either field alone leaves two profiles indistinguishable.
func TestInspect_identifies_every_profile_we_emit(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}

	for _, want := range []convert.EncoderType{
		convert.EncNameModern2023,
		convert.EncNameModern2026,
		convert.EncNameLegacyDES,
		convert.EncNameLegacyRC2,
	} {
		t.Run(string(want), func(t *testing.T) {
			t.Parallel()
			pfx, err := convert.Encode(&analysis, want, "pw")
			if err != nil {
				t.Fatalf("Encode(%s) = %v, want nil", want, err)
			}
			got, err := convert.Inspect(pfx)
			if err != nil {
				t.Fatalf("Inspect(a %s bundle) = error %v, want nil", want, err)
			}
			if got.Profile != want {
				t.Errorf("Inspect identified %q, want %q", got.Profile, want)
			}
		})
	}
}

// TestInspect_rejects_what_we_would_not_have_written pins the failure paths. Every
// one of them means the same thing to the caller — this is not a bundle we wrote, so
// replace it — which is what makes a parse failure safe rather than fatal.
func TestInspect_rejects_what_we_would_not_have_written(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	good, err := convert.Encode(&analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	for _, tc := range []struct {
		name string
		pfx  []byte
	}{
		{"empty input", nil},
		{"not DER at all", []byte("this is not a pkcs12 bundle")},
		{"truncated bundle", good[:len(good)/2]},
		{"trailing garbage after a valid bundle", append(bytes.Clone(good), 0xff, 0xff)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := convert.Inspect(tc.pfx); err == nil {
				t.Error("Inspect = nil error, want a rejection")
			}
		})
	}
}

// TestInspect_bounds_iteration_counts pins the safety half. PKCS#12 stores the
// key-derivation iteration counts IN THE FILE and the decoder honours them, so a
// crafted output could otherwise spend arbitrary CPU on the scan's only goroutine.
// The read-size cap does not help: a small file can name a huge iteration count.
//
// The bound is asserted through the public surface by patching the MAC iteration
// count inside a real bundle, which is exactly the shape of the attack.
func TestInspect_bounds_iteration_counts(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	// modern2023 writes a MAC iteration count of 2048, which DER-encodes as 02 02
	// 08 00. Rewriting that to a two-byte maximum keeps the encoding length
	// identical, so the surrounding structure stays valid and only the count changes.
	pfx, err := convert.Encode(&analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if _, err := convert.Inspect(pfx); err != nil {
		t.Fatalf("setup: Inspect(unmodified) = %v, want nil", err)
	}

	encoded2048 := []byte{0x02, 0x02, 0x08, 0x00}
	if n := bytes.Count(pfx, encoded2048); n == 0 {
		t.Fatalf("no DER-encoded 2048-iteration count found in a modern2023 bundle: the pinned encoder's framing changed, so this test no longer verifies the KDF iteration bound at all")
	}
	huge := bytes.Replace(bytes.Clone(pfx), encoded2048, []byte{0x02, 0x02, 0x7f, 0xff}, 1)

	_, err = convert.Inspect(huge)
	if err == nil {
		t.Fatal("Inspect(bundle naming a 32767-round derivation) = nil error, want a rejection before any derivation runs")
	}
	if !errors.Is(err, convert.ErrProfileUnknown) {
		t.Errorf("Inspect error = %v, want it to wrap ErrProfileUnknown", err)
	}
}

package convert_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// macDigestFlipped returns pfx with the last byte of its MAC digest inverted. The
// preflight accepts the result, because it reads the digest's shape and never its
// content, so this is the seed that carries the corpus past the preflight and into
// the DER parse and MAC verification behind it.
func macDigestFlipped(tb testing.TB, pfx []byte) []byte {
	tb.Helper()

	var preamble struct {
		Version  int
		AuthSafe asn1.RawValue
		MacData  struct {
			Mac struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}
			MacSalt    []byte
			Iterations int `asn1:"optional"`
		} `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(pfx, &preamble); err != nil {
		tb.Fatalf("setup: decode PFX preamble: %v", err)
	}
	digest := preamble.MacData.Mac.Digest
	if len(digest) == 0 {
		tb.Fatal("setup: encoded PFX carries no MAC digest")
	}
	at := bytes.LastIndex(pfx, digest)
	if at < 0 {
		tb.Fatal("setup: MAC digest not found in the encoded PFX")
	}
	flipped := bytes.Clone(pfx)
	flipped[at+len(digest)-1] ^= 0xff
	return flipped
}

// FuzzCheckCurrency_boundedVerdict fuzzes the exported currency door with the bytes
// found at the output path -- a file this app did not necessarily write. Where
// FuzzInspect_boundedProfile stops at the preflight, this target runs the whole
// door, so accepted bytes go on to a DER parse and a MAC verification.
//
// The invariants are the ones a caller acts on: the input slice is the store's own
// buffer and must come back untouched, the verdict is one of the declared reasons,
// Err is present exactly on the reasons that document one, Profile is set only on
// the arm that documents it and never names a profile this app does not emit (a
// caller reading Profile off any other arm would report a fabricated one), and the
// same bytes yield the same verdict twice.
//
// Content equality on a match is deliberately not asserted here:
// FuzzToPFXRoundTrip owns that oracle on the same generated material.
func FuzzCheckCurrency_boundedVerdict(f *testing.F) {
	m := testcerts.GenerateChainMaterial(f)
	analysis, err := convert.Analyse(f.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		f.Fatalf("setup: Analyse: %v", err)
	}
	// The weekly fuzz corpus is discarded after each run, so these committed seeds
	// are the durable reach: a real bundle from every profile, the truncation and
	// trailing-byte mutations the preflight refuses, and the digest flip it accepts.
	for _, enc := range []convert.EncoderType{
		convert.EncNameModern2023,
		convert.EncNameModern2026,
		convert.EncNameLegacyDES,
		convert.EncNameLegacyRC2,
	} {
		pfx, encErr := analysis.Encode(enc, "pw")
		if encErr != nil {
			f.Fatalf("setup: Encode(%s): %v", enc, encErr)
		}
		f.Add(pfx)
		f.Add(pfx[:len(pfx)/2])
		f.Add(append(bytes.Clone(pfx), 0xff, 0xff))
		f.Add(macDigestFlipped(f, pfx))
	}
	f.Add([]byte(nil))
	f.Add([]byte("not a pkcs12 bundle"))
	// A DER SEQUENCE header whose length overruns the buffer.
	f.Add([]byte{0x30, 0x7f, 0x02, 0x01, 0x03})

	declared := map[convert.CurrencyReason]bool{
		convert.CurrencyMatch:           true,
		convert.CurrencyPreflightFailed: true,
		convert.CurrencyForeign:         true,
		convert.CurrencyProfileMismatch: true,
		convert.CurrencyDecodeFailed:    true,
		convert.CurrencyContentMismatch: true,
	}
	// The reasons whose documented contract is to carry the underlying failure.
	carriesErr := map[convert.CurrencyReason]bool{
		convert.CurrencyPreflightFailed: true,
		convert.CurrencyForeign:         true,
		convert.CurrencyDecodeFailed:    true,
	}
	known := map[convert.EncoderType]bool{
		convert.EncNameModern2023: true,
		convert.EncNameModern2026: true,
		convert.EncNameLegacyDES:  true,
		convert.EncNameLegacyRC2:  true,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		got := analysis.CheckCurrency(data, "pw", convert.EncNameModern2023)
		if !bytes.Equal(before, data) {
			t.Fatal("CheckCurrency mutated its input; the slice it reads is the caller's own buffer")
		}
		if !declared[got.Reason] {
			t.Fatalf("CheckCurrency reported reason %q, which is not one of the declared CurrencyReason values", got.Reason)
		}
		if carriesErr[got.Reason] != (got.Err != nil) {
			t.Fatalf("CheckCurrency reason %q carries Err %v; Err is documented on preflight-failed, foreign and decode-failed only", got.Reason, got.Err)
		}
		if got.Profile != "" {
			if got.Reason != convert.CurrencyProfileMismatch {
				t.Fatalf("CheckCurrency reason %q carries profile %q; only profile-mismatch names one", got.Reason, got.Profile)
			}
			if !known[got.Profile] {
				t.Fatalf("CheckCurrency named profile %q, which is not one of the four this app emits", got.Profile)
			}
		}
		again := analysis.CheckCurrency(data, "pw", convert.EncNameModern2023)
		if again.Reason != got.Reason || again.Profile != got.Profile {
			t.Fatalf("CheckCurrency is not deterministic: second call = (%q, %q), first = (%q, %q)",
				again.Reason, again.Profile, got.Reason, got.Profile)
		}
	})
}

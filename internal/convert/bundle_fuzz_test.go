package convert_test

import (
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

func FuzzAnalyseBundle_pemRoundTrip(f *testing.F) {
	m := testcerts.GenerateChainMaterial(f)
	analysis, err := convert.Analyse(f.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		f.Fatalf("setup: Analyse = %v", err)
	}
	valid, err := analysis.Encode(convert.EncNameModern2023, "seed-password")
	if err != nil {
		f.Fatalf("setup: Encode = %v", err)
	}
	f.Add(valid, "seed-password")
	f.Add([]byte("not a bundle"), "")

	f.Fuzz(func(t *testing.T, pfx []byte, password string) {
		if len(pfx) > convert.MaxBundleBytes {
			return
		}
		decoded, err := convert.AnalyseBundle(t.Context(), pfx, password)
		if err != nil {
			return
		}
		certPEM, keyPEM, err := decoded.EncodePEM()
		if err != nil {
			t.Fatalf("EncodePEM(decoded input) = %v", err)
		}
		roundTripped, err := convert.Analyse(t.Context(), certPEM, keyPEM)
		if err != nil {
			t.Fatalf("Analyse(EncodePEM(decoded input)) = %v", err)
		}
		wantPFX, err := decoded.Encode(convert.EncNameModern2023, "roundtrip-password")
		if err != nil {
			t.Fatalf("Encode(decoded input) = %v", err)
		}
		if currency := roundTripped.CheckCurrency(wantPFX, "roundtrip-password", convert.EncNameModern2023); currency.Reason != convert.CurrencyMatch {
			t.Fatalf("PEM round trip changed decoded identity: CheckCurrency = %q, want %q", currency.Reason, convert.CurrencyMatch)
		}
	})
}

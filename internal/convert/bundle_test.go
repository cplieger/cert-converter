package convert_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

func TestAnalyseBundle_roundTripsEveryEncoderProfile(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	original, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse(PEM pair) = %v", err)
	}

	for _, encoder := range []convert.EncoderType{
		convert.EncNameModern2023,
		convert.EncNameModern2026,
		convert.EncNameLegacyDES,
		convert.EncNameLegacyRC2,
	} {
		t.Run(string(encoder), func(t *testing.T) {
			t.Parallel()
			pfx, err := original.Encode(encoder, "input-password")
			if err != nil {
				t.Fatalf("setup: Encode(%s) = %v", encoder, err)
			}

			got, err := convert.AnalyseBundleWithBudget(t.Context(), pfx, "input-password", convert.NewBundleWorkBudget())
			if err != nil {
				t.Fatalf("AnalyseBundleWithBudget(%s output) = %v, want nil", encoder, err)
			}
			if currency := got.CheckCurrency(pfx, "input-password", encoder); currency.Reason != convert.CurrencyMatch {
				t.Errorf("AnalyseBundleWithBudget(%s output).CheckCurrency(original) = %q, want %q: leaf, key and chain must survive the decode",
					encoder, currency.Reason, convert.CurrencyMatch)
			}
		})
	}
}

func TestAnalyseBundle_rejectsWrongPassword(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "wrong-password.example.com", "ecdsa")
	analysis, err := convert.Analyse(t.Context(), certPEM, keyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse = %v", err)
	}
	pfx, err := analysis.Encode(convert.EncNameModern2023, "right-password")
	if err != nil {
		t.Fatalf("setup: Encode = %v", err)
	}

	if _, err := convert.AnalyseBundleWithBudget(t.Context(), pfx, "wrong-password", convert.NewBundleWorkBudget()); err == nil {
		t.Fatal("AnalyseBundleWithBudget(bundle, wrong password) = nil error, want a decode failure")
	}
}

func TestEncodePEM_isDeterministicAndRoundTrips(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := convert.Analyse(t.Context(), concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse = %v", err)
	}

	certPEM, keyPEM, err := analysis.EncodePEM()
	if err != nil {
		t.Fatalf("EncodePEM() = %v, want nil", err)
	}
	certAgain, keyAgain, err := analysis.EncodePEM()
	if err != nil {
		t.Fatalf("EncodePEM() second call = %v, want nil", err)
	}
	if !bytes.Equal(certPEM, certAgain) || !bytes.Equal(keyPEM, keyAgain) {
		t.Fatal("EncodePEM() returned different bytes on the second call, want deterministic output")
	}

	roundTripped, err := convert.Analyse(t.Context(), certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Analyse(EncodePEM()) = %v, want nil", err)
	}
	pfx, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode = %v", err)
	}
	if currency := roundTripped.CheckCurrency(pfx, "pw", convert.EncNameModern2023); currency.Reason != convert.CurrencyMatch {
		t.Errorf("Analyse(EncodePEM()).CheckCurrency(original identity) = %q, want %q",
			currency.Reason, convert.CurrencyMatch)
	}
}

func TestAnalyseBundle_honorsCancelledContext(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "cancelled.example.com", "ecdsa")
	analysis, err := convert.Analyse(t.Context(), certPEM, keyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse = %v", err)
	}
	pfx, err := analysis.Encode(convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = convert.AnalyseBundleWithBudget(ctx, pfx, "pw", convert.NewBundleWorkBudget())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("AnalyseBundleWithBudget(cancelled context) = %v, want context.Canceled", err)
	}
}

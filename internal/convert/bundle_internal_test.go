package convert

import (
	"errors"
	"slices"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

func TestAnalyseBundle_rejectsExcessiveIterationsBeforeDecode(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(t.Context(), slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse = %v", err)
	}

	for _, tc := range []struct {
		name   string
		enc    EncoderType
		mutate func(*testing.T, *pfxPreamble)
	}{
		{
			name: "outer mac", enc: EncNameModern2023,
			mutate: func(_ *testing.T, p *pfxPreamble) { p.MacData.Iterations = int(maxBundleKDFWork) + 1 },
		},
		{
			name: "pbmac1 mac", enc: EncNameModern2026,
			mutate: func(t *testing.T, p *pfxPreamble) {
				setTestPBKDF2Iterations(t, &p.MacData.Mac.Algorithm, int(maxBundleKDFWork/4)+1)
			},
		},
		{
			name: "modern encrypted safe", enc: EncNameModern2023,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestEncryptedSafe(t, p, func(alg *algorithmIdentifier) {
					setTestPBKDF2Iterations(t, alg, int(maxBundleKDFWork/4)+1)
				})
			},
		},
		{
			name: "modern shrouded key", enc: EncNameModern2023,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestShroudedKeyBag(t, p, func(alg *algorithmIdentifier) {
					setTestPBKDF2Iterations(t, alg, int(maxBundleKDFWork/4)+1)
				})
			},
		},
		{
			name: "legacy encrypted safe", enc: EncNameLegacyDES,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestEncryptedSafe(t, p, func(alg *algorithmIdentifier) {
					setTestLegacyIterations(t, alg, int(maxBundleKDFWork/3)+1)
				})
			},
		},
		{
			name: "legacy des shrouded key", enc: EncNameLegacyDES,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestShroudedKeyBag(t, p, func(alg *algorithmIdentifier) {
					setTestLegacyIterations(t, alg, int(maxBundleKDFWork/3)+1)
				})
			},
		},
		{
			name: "legacy rc2 encrypted safe", enc: EncNameLegacyRC2,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestEncryptedSafe(t, p, func(alg *algorithmIdentifier) {
					setTestLegacyIterations(t, alg, int(maxBundleKDFWork/2)+1)
				})
			},
		},
		{
			name: "legacy rc2 shrouded key", enc: EncNameLegacyRC2,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestShroudedKeyBag(t, p, func(alg *algorithmIdentifier) {
					setTestLegacyIterations(t, alg, int(maxBundleKDFWork/2)+1)
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pfx, err := analysis.Encode(tc.enc, "pw")
			if err != nil {
				t.Fatalf("setup: Encode(%s) = %v", tc.enc, err)
			}
			var preamble pfxPreamble
			testASN1Unmarshal(t, pfx, &preamble)
			tc.mutate(t, &preamble)

			_, err = AnalyseBundleWithBudget(t.Context(), testASN1Marshal(t, preamble), "pw", NewBundleWorkBudget())
			if !errors.Is(err, ErrBundleUnbounded) {
				t.Errorf("AnalyseBundleWithBudget(%s with excessive iterations) = %v, want ErrBundleUnbounded", tc.name, err)
			}
		})
	}
}

func TestAnalyseBundle_rejectsAggregateDerivationWorkAboveBudget(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(t.Context(), slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse = %v", err)
	}
	pfx, err := analysis.Encode(EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode = %v", err)
	}
	var preamble pfxPreamble
	testASN1Unmarshal(t, pfx, &preamble)
	preamble.MacData.Iterations = 2_000_000
	mutateTestEncryptedSafe(t, &preamble, func(alg *algorithmIdentifier) {
		setTestPBKDF2Iterations(t, alg, 1_000_000)
	})

	_, err = AnalyseBundleWithBudget(t.Context(), testASN1Marshal(t, preamble), "pw", NewBundleWorkBudget())
	if !errors.Is(err, ErrBundleUnbounded) {
		t.Errorf("AnalyseBundleWithBudget(bundle with 6,000,000 weighted rounds) = %v, want ErrBundleUnbounded", err)
	}
}

func TestAnalyseBundle_rejectsPlaintextSafeAboveBagBudget(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(t.Context(), slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse = %v", err)
	}
	pfx, err := analysis.Encode(EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode = %v", err)
	}
	var preamble pfxPreamble
	testASN1Unmarshal(t, pfx, &preamble)
	mutateTestAuthenticatedSafe(t, &preamble, oidDataContentType, func(safe *contentInfo) {
		mutateTestSafeBags(t, safe, func(bags []safeBag) []safeBag {
			for len(bags) <= maxSafeBags {
				bags = append(bags, bags[0])
			}
			return bags
		})
	})

	_, err = AnalyseBundleWithBudget(t.Context(), testASN1Marshal(t, preamble), "pw", NewBundleWorkBudget())
	if !errors.Is(err, ErrBundleUnbounded) {
		t.Errorf("AnalyseBundleWithBudget(plaintext safe with %d bags) = %v, want ErrBundleUnbounded", maxSafeBags+1, err)
	}
}

func TestBoundInputBundle_appliesScanWideWorkBudget(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(t.Context(), slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse = %v", err)
	}
	pfx, err := analysis.Encode(EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode = %v", err)
	}
	var preamble pfxPreamble
	testASN1Unmarshal(t, pfx, &preamble)
	preamble.MacData.Iterations = 3_000_000
	mutated := testASN1Marshal(t, preamble)
	budget := NewBundleWorkBudget()
	for i := 1; i <= 6; i++ {
		if err := boundInputBundle(mutated, budget); err != nil {
			t.Fatalf("boundInputBundle(bundle %d of 6) = %v, want nil inside scan budget", i, err)
		}
	}
	if err := boundInputBundle(mutated, budget); !errors.Is(err, ErrBundleUnbounded) {
		t.Errorf("boundInputBundle(bundle 7) = %v, want ErrBundleUnbounded after cumulative scan work", err)
	}
}

func TestBoundInputBundle_rejectsOverflowWithoutPoisoningScanBudget(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(t.Context(), slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse = %v", err)
	}
	valid, err := analysis.Encode(EncNameModern2026, "pw")
	if err != nil {
		t.Fatalf("setup: Encode = %v", err)
	}
	var preamble pfxPreamble
	testASN1Unmarshal(t, valid, &preamble)
	setTestPBKDF2Iterations(t, &preamble.MacData.Mac.Algorithm, int(^uint(0)>>1))
	malicious := testASN1Marshal(t, preamble)
	budget := NewBundleWorkBudget()

	if err := boundInputBundle(malicious, budget); !errors.Is(err, ErrBundleUnbounded) {
		t.Fatalf("boundInputBundle(overflowing PBMAC1 count) = %v, want ErrBundleUnbounded", err)
	}
	if err := boundInputBundle(valid, budget); err != nil {
		t.Errorf("boundInputBundle(valid bundle after rejection) = %v, want nil: a rejected bundle must not poison scan budget", err)
	}
}

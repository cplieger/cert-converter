package convert_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestAnalyse_abandons_the_analysis_when_the_context_is_cancelled pins the
// cancellation contract Analyse's own doc states: a cancellation abandons the
// analysis and returns an error wrapping ctx.Err(), so errors.Is(err,
// context.Canceled) holds and process.IsShutdown classifies it as a shutdown
// rather than a conversion failure that would flip the health marker.
//
// The live-context call is the fixture's own falsifiability check, not decoration:
// without it a bundle that simply failed to analyse would satisfy every assertion
// below for the wrong reason.
func TestAnalyse_abandons_the_analysis_when_the_context_is_cancelled(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	certPEM := slices.Concat(m.LeafPEM, m.CAPEM)

	if _, err := convert.Analyse(t.Context(), certPEM, m.LeafKeyPEM); err != nil {
		t.Fatalf("setup: Analyse with a live context: %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	analysis, err := convert.Analyse(ctx, certPEM, m.LeafKeyPEM)
	if err == nil {
		t.Fatalf("Analyse(cancelled ctx) = %v, nil, want an error", analysis)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(%v, context.Canceled) = false, want true: the caller classifies a shutdown through this wrap", err)
	}
	if analysis != nil {
		t.Errorf("Analyse(cancelled ctx) returned analysis %v, want nil: a verdict from a partially built graph must never be propagated", analysis)
	}
}

// TestAnalyse_cancellation_observed_mid_analysis_never_yields_a_verdict pins the
// half of the cancellation contract the test above cannot reach. That test's
// bundle holds a self-signed CA, so graph CONSTRUCTION pays the first signature
// verification and the cancellation latches before identity selection begins. A
// fullchain-shaped bundle (leaf + intermediate, root absent) pays its first
// verification only inside identity selection or the path walk, so the latch
// lands mid-analysis -- and a verdict derived from that partially built graph
// must never be propagated: with the intermediate's key the live-context verdict
// is the issuer-role refusal, and a cancelled graph reports the proven issuance
// as false, so without the post-phase latch checks the analysis SUCCEEDS with
// the CA as the identity and the leaf excluded.
func TestAnalyse_cancellation_observed_mid_analysis_never_yields_a_verdict(t *testing.T) {
	t.Parallel()

	now := time.Now()
	rootKey := testcerts.NewECDSAKey(t)
	_, rootCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(700),
		Subject:               pkix.Name{CommonName: "Absent Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &rootKey.PublicKey, nil, rootKey)

	intermediateKey := testcerts.NewECDSAKey(t)
	intermediatePEM, intermediateCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(701),
		Subject:               pkix.Name{CommonName: "Mid Intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &intermediateKey.PublicKey, rootCert, rootKey)

	leafKey := testcerts.NewECDSAKey(t)
	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(702),
		Subject:      pkix.Name{CommonName: "mid-leaf.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
	}, &leafKey.PublicKey, intermediateCert, intermediateKey)

	bundle := slices.Concat(leafPEM, intermediatePEM)

	for name, tc := range map[string]struct {
		keyPEM []byte
		// wantLiveErr documents what a live context produces, asserted so the
		// fixture stays falsifiable: if the live verdict drifts, the cancelled
		// assertion below may pass for the wrong reason.
		wantLiveErr string
	}{
		// First verification is paid in pathFrom's proven() on the leaf ->
		// intermediate hop: the latch must be honoured after the path walk.
		"the leaf key: latch lands in the path walk": {
			keyPEM: testcerts.KeyPEM(t, leafKey),
		},
		// First verification is paid in dropIssuerMatches' isIssuer() during
		// identity selection: the latch must be honoured before the selection
		// verdict is trusted. With a live context this bundle is REFUSED (the
		// key belongs to an issuer); a cancelled graph reads the issuance as
		// unproven, so without the latch the analysis succeeds with the CA as
		// the identity.
		"the intermediate key: latch lands in identity selection": {
			keyPEM:      testcerts.KeyPEM(t, intermediateKey),
			wantLiveErr: "is an issuer of another certificate in this bundle",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Falsifiability check: the live-context outcome is the one the
			// cancelled call must NOT produce.
			liveAnalysis, liveErr := convert.Analyse(t.Context(), bundle, tc.keyPEM)
			if tc.wantLiveErr == "" {
				if liveErr != nil {
					t.Fatalf("setup: Analyse with a live context: %v, want nil", liveErr)
				}
			} else {
				if liveErr == nil {
					t.Fatalf("setup: Analyse with a live context = %v, nil, want the issuer-role refusal", liveAnalysis)
				}
				if !strings.Contains(liveErr.Error(), tc.wantLiveErr) {
					t.Fatalf("setup: live-context error = %q, want it to contain %q", liveErr, tc.wantLiveErr)
				}
			}

			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			analysis, err := convert.Analyse(ctx, bundle, tc.keyPEM)
			if err == nil {
				t.Fatalf("Analyse(cancelled ctx) = %v, nil, want an error: a verdict from a partially built graph must never be propagated", analysis)
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("errors.Is(%v, context.Canceled) = false, want true: the caller classifies a shutdown through this wrap, and a refusal here logs a bogus conversion failure and flips the health marker on a container that was only asked to stop", err)
			}
			if analysis != nil {
				t.Errorf("Analyse(cancelled ctx) returned analysis %v, want nil", analysis)
			}
		})
	}
}

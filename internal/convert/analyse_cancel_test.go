package convert_test

import (
	"context"
	"errors"
	"slices"
	"testing"

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

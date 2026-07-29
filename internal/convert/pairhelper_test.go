package convert_test

import (
	"context"
	"os"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/cert-converter/internal/convert"
)

// convertPairInRoot is the test-side stand-in for the retired production helper that did
// all three steps in one call: analyse, encode, then write confined to root.
//
// It exists because the three steps are no longer one function. internal/convert
// is now a pure codec — Analyse resolves the pair and Encode produces the bytes,
// neither touching a filesystem — and the confined atomic write belongs to
// internal/process, which owns the output tree. Production composes the same three
// calls in scanWalk.convertEntry.
//
// Observations are returned even when the write fails, matching the production
// composition: they describe the input, not the outcome.
func convertPairInRoot(ctx context.Context, certPEM, keyPEM []byte, root *os.Root,
	rel, password string, enc convert.EncoderType,
) ([]convert.Observation, error) {
	analysis, err := convert.Analyse(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pfx, err := convert.Encode(&analysis, enc, password)
	if err != nil {
		return analysis.Observations(), err
	}
	if _, err := atomicfile.WriteFileInRoot(ctx, root, rel, pfx, atomicfile.WithMode(0o600)); err != nil {
		return analysis.Observations(), err
	}
	return analysis.Observations(), nil
}

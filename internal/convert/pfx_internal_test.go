package convert

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestEncode_encode_failure_is_wrapped pins Encode's failure branch: a private key
// the PKCS#12 encoder cannot marshal must surface as a wrapped "encode pfx" error.
//
// It stays in package convert (not convert_test) because it constructs an Analysis
// directly with a nil key, which Analyse cannot return and so cannot be built
// through the exported surface.
func TestEncode_encode_failure_is_wrapped(t *testing.T) {
	t.Parallel()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "encode-fail", "ecdsa")
	certs, err := ParseCertChain(certPEM)
	if err != nil {
		t.Fatalf("setup: ParseCertChain: %v", err)
	}

	// A nil private key cannot be marshalled to PKCS#8, so the encoder fails.
	broken := Analysis{leaf: certs[0], key: nil}
	_, err = broken.Encode(EncNameModern2023, "pw")
	if err == nil {
		t.Fatal("Encode(nil private key) = nil error, want a wrapped encode error")
	}
	if !strings.Contains(err.Error(), "encode pfx") {
		t.Errorf("Encode(nil private key) error = %q, want it to contain %q", err.Error(), "encode pfx")
	}
}

// TestDecode_bounds_the_library_message pins the log-hygiene bound at decode's
// error site. Two of go-pkcs12 v0.7.3's decode diagnostics interpolate an object
// identifier read out of the bundle, and the bundle is a file found in the output
// tree, so the rendered text is bounded only by the file size unless decode wraps
// it. Dropping the wrapper here would let a bundle-sized error line reach the
// container log the next time a prior bundle does not decode.
func TestDecode_bounds_the_library_message(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "bounded-error", "ecdsa")
	analysis, err := Analyse(t.Context(), certPEM, keyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := analysis.Encode(EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	_, err = decode(pfx, "rotated")
	if err == nil {
		t.Fatal("decode(bundle, wrong password) = nil error, want a decode failure")
	}
	if _, ok := errors.AsType[boundedTextError](err); !ok {
		t.Errorf("decode error = %v, want its chain to carry boundedTextError so a bundle-controlled identifier cannot reach the log unbounded", err)
	}
	if !strings.HasPrefix(err.Error(), "decode pfx: ") {
		t.Errorf("decode error = %q, want it to name the stage that failed", err.Error())
	}
}

// The codec's entry points are METHODS on Analysis with VALUE receivers: Analyse
// hands back a value, and a value receiver cannot be nil. These declarations
// DOCUMENT that shape — turning either entry point into a free function, or
// moving either receiver to a pointer, stops this file compiling, which is the
// whole check. A pointer receiver would let a caller reach these through a
// *Analysis, reopening the nil this shape keeps out of the codec.
//
// The leaf invariant is NOT structural (convert.Analysis{} stays constructible);
// TestAnalyse_always_populates_the_leaf below is its witness.
var (
	_ func(Analysis, EncoderType, string) ([]byte, error)  = Analysis.Encode
	_ func(Analysis, []byte, string, EncoderType) Currency = Analysis.CheckCurrency
)

// TestAnalyse_always_populates_the_leaf is the only witness of the leaf invariant,
// across the input shapes that reach the producer by a different route: a plain
// self-signed pair, a leaf-plus-CA chain, and a bundle whose leaf is not the first
// block. A future edit that let a leafless value out fails on this test's own nil
// check rather than nil-dereferencing inside go-pkcs12's sha1.Sum(certificate.Raw)
// at conversion time.
func TestAnalyse_always_populates_the_leaf(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	selfPEM, selfKeyPEM := testcerts.GenerateSelfSignedCert(t, "leaf-invariant", "ecdsa")

	for name, in := range map[string]struct{ certPEM, keyPEM []byte }{
		"a self-signed pair":         {selfPEM, selfKeyPEM},
		"a leaf-first chain":         {slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM},
		"a chain with the leaf last": {slices.Concat(m.CAPEM, m.LeafPEM), m.LeafKeyPEM},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, err := Analyse(t.Context(), in.certPEM, in.keyPEM)
			if err != nil {
				t.Fatalf("Analyse(%s) = error %v, want a resolved analysis", name, err)
			}
			if a.leaf == nil {
				t.Errorf("Analyse(%s) returned an Analysis with no leaf: the codec no longer checks for one", name)
			}
		})
	}
}

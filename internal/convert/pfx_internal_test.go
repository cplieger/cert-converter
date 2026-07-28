package convert

import (
	"errors"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestEncode_encode_failure_is_wrapped pins Encode's failure branch: a private key
// the PKCS#12 encoder cannot marshal must surface as a wrapped "encode pfx" error.
//
// This replaces the same assertion against the retired toPFXInRoot. Encode no
// longer writes anything, so the old "and leaves no file behind" half of the test
// moved with the write itself: internal/process now owns the confined write, and
// the ordering that guarantees nothing is written on an encode failure is visible
// there — scanWalk.convertEntry returns before calling store.write.
//
// It stays in package convert (not convert_test) because it constructs an
// Analysis directly with a nil key, which is not a state Analyse can return and
// so cannot be built through the exported surface.
func TestEncode_encode_failure_is_wrapped(t *testing.T) {
	t.Parallel()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "encode-fail", "ecdsa")
	certs, err := ParseCertChain(certPEM)
	if err != nil {
		t.Fatalf("setup: ParseCertChain: %v", err)
	}

	// A nil private key cannot be marshalled to PKCS#8, so the encoder fails.
	_, err = Encode(&Analysis{leaf: certs[0], key: nil}, EncNameModern2023, "pw")
	if err == nil {
		t.Fatal("Encode(nil private key) = nil error, want a wrapped encode error")
	}
	if !strings.Contains(err.Error(), "encode pfx") {
		t.Errorf("Encode(nil private key) error = %q, want it to contain %q", err.Error(), "encode pfx")
	}
}

// TestDecode_bounds_the_library_message pins the log-hygiene bound at decode's
// error site. Two of go-pkcs12 v0.7.3's decode diagnostics interpolate an OBJECT
// IDENTIFIER read out of the bundle, and the bundle is a file found in the output
// tree, so the rendered text is bounded only by the file size unless decode wraps
// it. The wrapper's own truncation rule is pinned in boundlogtext_internal_test.go;
// what nothing pins is that decode still USES it -- drop the wrapper here and no
// test fails, while a bundle-sized error line reaches the container log the next
// time a prior bundle does not decode.
func TestDecode_bounds_the_library_message(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "bounded-error", "ecdsa")
	analysis, err := Analyse(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	_, err = decode(pfx, "rotated")
	if err == nil {
		t.Fatal("decode(bundle, wrong password) = nil error, want a decode failure")
	}
	var bounded boundedTextError
	if !errors.As(err, &bounded) {
		t.Errorf("decode error = %v, want its chain to carry boundedTextError so a bundle-controlled identifier cannot reach the log unbounded", err)
	}
	if !strings.HasPrefix(err.Error(), "decode pfx: ") {
		t.Errorf("decode error = %q, want it to name the stage that failed", err.Error())
	}
}

// TestEncode_refuses_an_analysis_that_did_not_come_from_Analyse pins the leaf guard
// Encode grew this cycle. The zero Analysis is constructible from outside the package,
// and without the guard the encoder dereferences the nil *x509.Certificate inside
// go-pkcs12 (sha1.Sum(certificate.Raw)), killing the process instead of failing one
// conversion. Delete the guard and no other test in this package notices; the panic
// comes back.
func TestEncode_refuses_an_analysis_that_did_not_come_from_Analyse(t *testing.T) {
	t.Parallel()
	_, err := Encode(&Analysis{}, EncNameModern2023, "pw")
	if err == nil {
		t.Fatal("Encode(zero Analysis) = nil error, want a refusal rather than a nil-leaf panic in the encoder")
	}
	if !strings.Contains(err.Error(), "no leaf certificate") {
		t.Errorf("Encode(zero Analysis) error = %q, want it to name the missing leaf", err.Error())
	}
}

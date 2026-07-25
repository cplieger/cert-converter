package convert

import (
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
	_, err = Encode(&Analysis{Leaf: certs[0], Key: nil}, EncNameModern2023, "pw")
	if err == nil {
		t.Fatal("Encode(nil private key) = nil error, want a wrapped encode error")
	}
	if !strings.Contains(err.Error(), "encode pfx") {
		t.Errorf("Encode(nil private key) error = %q, want it to contain %q", err.Error(), "encode pfx")
	}
}

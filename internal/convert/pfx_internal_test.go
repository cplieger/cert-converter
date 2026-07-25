package convert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
	"software.sslmate.com/src/go-pkcs12"
)

// TestToPFXInRoot_encode_failure_is_wrapped pins the encode branch of the
// confined write helper: a private key the PKCS#12 encoder cannot marshal must
// surface as a wrapped "encode pfx" error and must leave no file behind. The
// helper is package-internal (PairInRoot is the only PFX-writing API convert
// exports), so this focused branch test lives in package convert rather than
// exporting a production bypass for it.
func TestToPFXInRoot_encode_failure_is_wrapped(t *testing.T) {
	t.Parallel()
	certPEM, _ := testcerts.GenerateSelfSignedCert(t, "encode-fail", "ecdsa")
	certs, err := ParseCertChain(certPEM)
	if err != nil {
		t.Fatalf("setup: ParseCertChain: %v", err)
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot: %v", err)
	}
	defer root.Close()

	// A nil private key cannot be marshalled to PKCS#8, so the encoder fails
	// before any temp file is created.
	err = toPFXInRoot(t.Context(), nil, certs[0], nil, root, "out.pfx", "pw", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("toPFXInRoot(nil private key) = nil error, want a wrapped encode error")
	}
	if !strings.Contains(err.Error(), "encode pfx") {
		t.Errorf("toPFXInRoot(nil private key) error = %q, want it to contain %q", err.Error(), "encode pfx")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.pfx")); statErr == nil {
		t.Error("toPFXInRoot wrote a file after an encode failure; want none")
	}
}

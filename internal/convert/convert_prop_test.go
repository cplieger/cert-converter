package convert_test

import (
	"bytes"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"pgregory.net/rapid"
	"software.sslmate.com/src/go-pkcs12"
)

// TestPairInRoot_password_guard_agrees_with_the_pkcs12_encoder is the oracle
// property for the PFX password guard: for an arbitrary password,
// InspectPasswordEncoding must predict the encoder's verdict exactly. A
// password it reports as non-BMP must be rejected with the actionable
// BMP message and leave no file behind, and any other password must produce a
// PFX that decodes with that same password. The guard exists because
// go-pkcs12's own refusal names neither the password nor the constraint, so a
// drift between the guard and the encoder turns a clear startup-level
// diagnostic back into an opaque conversion failure.
func TestPairInRoot_password_guard_agrees_with_the_pkcs12_encoder(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "password-oracle.example.com", "ecdsa")
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("setup: the generated certificate PEM does not decode")
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("setup: os.OpenRoot(%q) = %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	dest := filepath.Join(dir, "out.pfx")

	rapid.Check(t, func(rt *rapid.T) {
		password := rapid.String().Draw(rt, "password")
		if err := os.Remove(dest); err != nil && !errors.Is(err, fs.ErrNotExist) {
			rt.Fatalf("setup: remove %q: %v", dest, err)
		}
		issues := convert.InspectPasswordEncoding(password)

		_, err := convertPairInRoot(rt.Context(), certPEM, keyPEM, root, "out.pfx", password, convert.EncNameModern2023)

		if issues.NonBMP {
			if err == nil {
				rt.Fatalf("PairInRoot with a non-BMP password (%d bytes) = nil, want the BMP rejection", len(password))
			}
			if !strings.Contains(err.Error(), "Basic Multilingual Plane") {
				rt.Errorf("PairInRoot error = %q, want it to name the Basic Multilingual Plane limit rather than the vendor message", err.Error())
			}
			if _, statErr := os.Stat(dest); !errors.Is(statErr, fs.ErrNotExist) {
				rt.Errorf("PairInRoot wrote %q for a rejected password (stat error %v); want no file", dest, statErr)
			}
			return
		}

		if err != nil {
			rt.Fatalf("PairInRoot with an encodable password (%d bytes) = %v, want nil", len(password), err)
		}
		pfxData, readErr := os.ReadFile(dest)
		if readErr != nil {
			rt.Fatalf("PairInRoot wrote no readable pfx: %v", readErr)
		}
		_, leaf, _, decErr := pkcs12.DecodeChain(pfxData, password)
		if decErr != nil {
			rt.Fatalf("the pfx cannot be decoded with the same password (%d bytes): %v", len(password), decErr)
		}
		if !bytes.Equal(leaf.Raw, certBlock.Bytes) {
			rt.Errorf("the decoded leaf is not the certificate that was encoded")
		}
	})
}

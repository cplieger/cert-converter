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

// TestConvertPair_password_guard_agrees_with_the_pkcs12_encoder is the oracle
// property for the PFX password guard: for an arbitrary password,
// InspectPasswordEncoding must predict the guard's verdict exactly, and the
// guard must refuse EVERY shape the inspection reports — not just the one
// go-pkcs12 refuses on its own.
//
// The two the library accepts are why the guard is this wide: with invalid UTF-8
// it substitutes U+FFFD rune-by-rune and with an interior NUL it encodes the NUL
// verbatim, so in both cases it happily writes a bundle protected by a DIFFERENT
// password than the one supplied, and the failure surfaces at whatever later
// tries to open the bundle. So a password carrying any of the three shapes must
// be rejected with a message naming that shape, leaving no file behind, and any
// other password must produce a PFX that decodes with that same password.
//
// The draw injects each shape deliberately rather than hoping rapid.String()
// stumbles onto one: a generator of valid UTF-8 BMP text would exercise only the
// accept path, and the property would pin nothing.
func TestConvertPair_password_guard_agrees_with_the_pkcs12_encoder(t *testing.T) {
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
		// Each fabricated fragment is the minimal carrier of one unencodable
		// shape; any combination of them (including none) is a valid draw.
		if rapid.Bool().Draw(rt, "inject_invalid_utf8") {
			password += string([]byte{0xff})
		}
		if rapid.Bool().Draw(rt, "inject_non_bmp") {
			password += "\U0001F600"
		}
		if rapid.Bool().Draw(rt, "inject_embedded_nul") {
			password += "\x00"
		}
		if err := os.Remove(dest); err != nil && !errors.Is(err, fs.ErrNotExist) {
			rt.Fatalf("setup: remove %q: %v", dest, err)
		}
		issues := convert.InspectPasswordEncoding(password)

		_, err := convertPairInRoot(rt.Context(), certPEM, keyPEM, root, "out.pfx", password, convert.EncNameModern2023)

		// The shape the message must name when a password carries several.
		// Deliberately an INDEPENDENT restatement of the precedence, not a call to
		// issues.Why(): nothing outside this package ever selects on a shape, so
		// this switch is the only pin on NonBMP outranking EmbeddedNUL.
		var wantShape string
		switch {
		case issues.InvalidUTF8:
			wantShape = "not valid UTF-8"
		case issues.NonBMP:
			wantShape = "outside the Basic Multilingual Plane"
		case issues.EmbeddedNUL:
			wantShape = "contains a NUL byte"
		}

		if wantShape != "" {
			if err == nil {
				rt.Fatalf("convertPairInRoot with an unencodable password (%+v, %d bytes) = nil, want a rejection naming %q",
					issues, len(password), wantShape)
			}
			if !strings.Contains(err.Error(), wantShape) {
				rt.Errorf("convertPairInRoot error = %q, want it to name %q for a password with issues %+v",
					err.Error(), wantShape, issues)
			}
			if _, statErr := os.Stat(dest); !errors.Is(statErr, fs.ErrNotExist) {
				rt.Errorf("convertPairInRoot wrote %q for a rejected password (stat error %v); want no file", dest, statErr)
			}
			return
		}

		if err != nil {
			rt.Fatalf("convertPairInRoot with an encodable password (%d bytes) = %v, want nil", len(password), err)
		}
		pfxData, readErr := os.ReadFile(dest)
		if readErr != nil {
			rt.Fatalf("convertPairInRoot wrote no readable pfx: %v", readErr)
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

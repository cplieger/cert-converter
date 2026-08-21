package convert_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// convertPairToPath opens destPath's parent directory as an *os.Root and
// converts the pair into it, so a path-oriented case reads naturally against
// the root-relative write API.
func convertPairToPath(t *testing.T, certPEM, keyPEM []byte, destPath, password string, enc convert.EncoderType) error {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(destPath))
	if err != nil {
		t.Fatalf("setup: os.OpenRoot(%q) = %v", filepath.Dir(destPath), err)
	}
	defer func() { _ = root.Close() }()
	_, err = convertPairInRoot(t.Context(), certPEM, keyPEM, root, filepath.Base(destPath), password, enc)
	return err
}

// TestConvertPair_rejects_malformed_input_without_writing_output pins the
// failure contract at the /input boundary: malformed PEM on either side is
// rejected with an error naming the stage that failed, and no .pfx is left at
// destPath. A partially written or stale-content output would be silently
// replicated to consumers as a valid certificate bundle.
func TestConvertPair_rejects_malformed_input_without_writing_output(t *testing.T) {
	t.Parallel()
	goodCert, goodKey := testcerts.GenerateSelfSignedCert(t, "good.example.com", "ecdsa")

	tests := []struct {
		name    string
		wantErr string
		certPEM []byte
		keyPEM  []byte
	}{
		{"garbage cert bytes", "parse cert chain", []byte("this is not a PEM file"), goodKey},
		{"empty cert", "parse cert chain", nil, goodKey},
		{"cert PEM with a corrupt DER body", "parse cert chain", []byte("-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"), goodKey},
		{"garbage key bytes", "parse private key", goodCert, []byte("this is not a PEM file")},
		{"empty key", "parse private key", goodCert, nil},
		{"encrypted key is rejected, not silently converted", "parse private key", goodCert, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nQUJD\n-----END ENCRYPTED PRIVATE KEY-----\n")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			destPath := filepath.Join(t.TempDir(), "out.pfx")

			err := convertPairToPath(t, tt.certPEM, tt.keyPEM, destPath, "pw", convert.EncNameModern2023)
			if err == nil {
				t.Fatalf("convertPairInRoot(%s) = nil, want an error", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("convertPairInRoot(%s) error = %q, want it to contain %q", tt.name, err.Error(), tt.wantErr)
			}
			if _, statErr := os.Stat(destPath); !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("convertPairInRoot(%s) left a file at %q (stat error %v); want no output written on failure", tt.name, destPath, statErr)
			}
		})
	}
}

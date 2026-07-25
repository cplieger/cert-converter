package process_test

import (
	"errors"
	"fmt"
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

// TestPair_accepts_a_pair_iff_the_key_matches_the_leaf is the oracle
// property for the cert/key correspondence gate: over every combination drawn
// from a pool of independently generated pairs (including a cross-key-type
// combination), Pair must succeed exactly when the key belongs to the
// leaf, and must leave no .pfx behind otherwise. A PFX written from a
// mismatched key deploys a certificate no consumer can serve.
func TestPair_accepts_a_pair_iff_the_key_matches_the_leaf(t *testing.T) {
	t.Parallel()

	type certKeyPair struct {
		name    string
		cn      string
		certPEM []byte
		keyPEM  []byte
	}
	pool := make([]certKeyPair, 0, 3)
	for _, spec := range []struct{ name, keyType string }{
		{"ecdsa-a", "ecdsa"},
		{"ecdsa-b", "ecdsa"},
		{"rsa", "rsa"},
	} {
		cn := spec.name + ".example.com"
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, cn, spec.keyType)
		pool = append(pool, certKeyPair{name: spec.name, cn: cn, certPEM: certPEM, keyPEM: keyPEM})
	}
	outDir := t.TempDir()

	rapid.Check(t, func(rt *rapid.T) {
		i := rapid.IntRange(0, len(pool)-1).Draw(rt, "cert_index")
		j := rapid.IntRange(0, len(pool)-1).Draw(rt, "key_index")
		destPath := filepath.Join(outDir, fmt.Sprintf("%s-%s.pfx", pool[i].name, pool[j].name))
		_ = os.Remove(destPath)

		err := convert.Pair(rt.Context(), pool[i].certPEM, pool[j].keyPEM, destPath, "pw", pkcs12.Modern2023)

		if i == j {
			if err != nil {
				rt.Fatalf("Pair(cert %s, its own key) = %v, want nil", pool[i].name, err)
			}
			pfxData, readErr := os.ReadFile(destPath)
			if readErr != nil {
				rt.Fatalf("Pair(cert %s, its own key) wrote no readable pfx: %v", pool[i].name, readErr)
			}
			_, leaf, _, decErr := pkcs12.DecodeChain(pfxData, "pw")
			if decErr != nil {
				rt.Fatalf("decode pfx for %s: %v", pool[i].name, decErr)
			}
			if leaf.Subject.CommonName != pool[i].cn {
				rt.Errorf("pfx for %s has leaf CN %q, want %q", pool[i].name, leaf.Subject.CommonName, pool[i].cn)
			}
			return
		}

		if err == nil {
			rt.Fatalf("Pair(cert %s, key %s) = nil, want a mismatch error", pool[i].name, pool[j].name)
		}
		if !strings.Contains(err.Error(), "does not match") {
			rt.Errorf("Pair(cert %s, key %s) error = %q, want it to report the key does not match", pool[i].name, pool[j].name, err.Error())
		}
		if _, statErr := os.Stat(destPath); !errors.Is(statErr, fs.ErrNotExist) {
			rt.Errorf("Pair(cert %s, key %s) left a pfx at %q (stat error %v); want no output for a mismatched pair", pool[i].name, pool[j].name, destPath, statErr)
		}
	})
}

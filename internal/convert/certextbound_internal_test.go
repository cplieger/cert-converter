package convert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestOversizedExtensionIdentifiersError_applies_the_aggregate_ceilings pins the
// post-parse retention bound that replaced the pre-parse certoidscan walk
// (class-c1-1): the predicate reads the PARSED certificate, so it cannot be
// starved by anything earlier in the block, and it bounds the AGGREGATE — the
// extension count and the total identifier arcs — rather than any one identifier.
func TestOversizedExtensionIdentifiersError_applies_the_aggregate_ceilings(t *testing.T) {
	t.Parallel()

	extWithArcs := func(n int) pkix.Extension {
		id := make([]int, n)
		id[0], id[1] = 1, 3
		for i := 2; i < n; i++ {
			id[i] = 1
		}
		return pkix.Extension{Id: id}
	}

	cases := []struct {
		name    string
		cert    *x509.Certificate
		refused bool
	}{
		{
			name:    "a realistic extension set passes",
			cert:    &x509.Certificate{Extensions: []pkix.Extension{extWithArcs(9), extWithArcs(7), extWithArcs(10)}},
			refused: false,
		},
		{
			name: "exactly at both ceilings passes",
			cert: &x509.Certificate{Extensions: func() []pkix.Extension {
				exts := make([]pkix.Extension, maxCertExtensions)
				for i := range exts {
					exts[i] = extWithArcs(maxCertExtensionOIDArcs / maxCertExtensions)
				}
				return exts
			}()},
			refused: false,
		},
		{
			name: "one extension over the count ceiling is refused",
			cert: &x509.Certificate{Extensions: func() []pkix.Extension {
				exts := make([]pkix.Extension, maxCertExtensions+1)
				for i := range exts {
					exts[i] = extWithArcs(4)
				}
				return exts
			}()},
			refused: true,
		},
		{
			name:    "one arc over the aggregate arc ceiling is refused",
			cert:    &x509.Certificate{Extensions: []pkix.Extension{extWithArcs(maxCertExtensionOIDArcs + 1)}},
			refused: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := oversizedParsedCertificateError(tc.cert)
			if tc.refused && err == nil {
				t.Fatal("oversizedParsedCertificateError = nil, want a refusal")
			}
			if !tc.refused && err != nil {
				t.Fatalf("oversizedParsedCertificateError = %v, want nil", err)
			}
			if tc.refused && !strings.Contains(err.Error(), "not an X.509 limit") {
				t.Errorf("refusal %q does not name the ceiling as this app's own resource policy", err)
			}
		})
	}
}

// TestParseCertChain_refuses_a_certificate_whose_extension_identifiers_exceed_the_retention_ceiling
// drives the bound through the production parse edge: a syntactically valid,
// signed certificate carrying one extension identifier above the aggregate arc
// ceiling is refused as a conversion failure, exactly as an unparseable block is,
// and the refusal names the block it landed on.
func TestParseCertChain_refuses_a_certificate_whose_extension_identifiers_exceed_the_retention_ceiling(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: generate key: %v", err)
	}
	oversizedID := make([]int, maxCertExtensionOIDArcs+1)
	oversizedID[0], oversizedID[1] = 1, 3
	for i := 2; i < len(oversizedID); i++ {
		oversizedID[i] = 1
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "retention-ceiling.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    oversizedID,
			Value: []byte{0x05, 0x00}, // DER NULL: the value is opaque to the bound, which reads only Id
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("setup: create certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})

	_, _, parseErr := parseCertChain(pemBytes)
	if parseErr == nil {
		t.Fatal("parseCertChain accepted a certificate above the extension-identifier retention ceiling")
	}
	if !strings.Contains(parseErr.Error(), "certificate PEM block 1") {
		t.Errorf("refusal %q does not name the block it landed on", parseErr)
	}
	if !strings.Contains(parseErr.Error(), "not an X.509 limit") {
		t.Errorf("refusal %q does not name the ceiling as this app's own resource policy", parseErr)
	}
}

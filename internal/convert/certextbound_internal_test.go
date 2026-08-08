package convert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestOversizedParsedCertificateError_applies_the_aggregate_ceilings pins the
// post-parse retention bound that replaced the pre-parse certoidscan walk
// (class-c1-1): the predicate reads the PARSED certificate, so it cannot be
// starved by anything earlier in the block, and it bounds the AGGREGATE — the
// extension count, the total identifier arcs, and the decoded extension content —
// rather than any one identifier. The cases below cover the first two; the
// decoded-content arm is covered separately, by
// TestOversizedParsedCertificateError_bounds_decoded_extension_content.
func TestOversizedParsedCertificateError_applies_the_aggregate_ceilings(t *testing.T) {
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

// TestParseCertChain_refuses_a_certificate_block_above_the_DER_ceiling drives
// maxCertDERBytes through the production parse edge, and the ORDER is the property:
// the length check must run BEFORE x509.ParseCertificate, because the ceiling exists
// to bound the parse's own transient allocation (a post-parse refusal fires only once
// the 534 MB has already been paid). The DER here is deliberately unparseable
// garbage, so if the check ever moves below the parse this test sees the parser's
// error instead of the ceiling text and fails — which is the only way a test can tell
// the two arms apart.
func TestParseCertChain_refuses_a_certificate_block_above_the_DER_ceiling(t *testing.T) {
	t.Parallel()

	oversized := pem.EncodeToMemory(&pem.Block{
		Type:  pemTypeCertificate,
		Bytes: bytes.Repeat([]byte{0xff}, maxCertDERBytes+1),
	})

	_, _, parseErr := parseCertChain(oversized)
	if parseErr == nil {
		t.Fatal("parseCertChain accepted a certificate block above maxCertDERBytes")
	}
	if !strings.Contains(parseErr.Error(), "bytes of DER") {
		t.Errorf("refusal %q is not the DER-size refusal: the length check must run BEFORE"+
			" x509.ParseCertificate, or an unparseable oversized block reports a parse error instead",
			parseErr)
	}
	if !strings.Contains(parseErr.Error(), "not an X.509 limit") {
		t.Errorf("refusal %q does not name the ceiling as this app's own resource policy", parseErr)
	}
	if !strings.Contains(parseErr.Error(), "certificate PEM block 1") {
		t.Errorf("refusal %q does not name the block it landed on", parseErr)
	}

	// At exactly the ceiling the size check must NOT fire: the block reaches the parser
	// and fails there instead, which is what proves the boundary is inclusive. Same
	// garbage payload, one byte shorter.
	atCeiling := pem.EncodeToMemory(&pem.Block{
		Type:  pemTypeCertificate,
		Bytes: bytes.Repeat([]byte{0xff}, maxCertDERBytes),
	})
	_, _, ceilingErr := parseCertChain(atCeiling)
	if ceilingErr == nil {
		t.Fatal("parseCertChain(garbage DER exactly at maxCertDERBytes) = nil error, want the parser's own error")
	}
	if strings.Contains(ceilingErr.Error(), "bytes of DER") {
		t.Errorf("parseCertChain(exactly maxCertDERBytes) refused on size (%q): the ceiling is"+
			" inclusive, so a block AT it must reach the parser", ceilingErr)
	}
}

// TestOversizedParsedCertificateError_bounds_decoded_extension_content pins the third
// arm — the decoded extension CONTENT ceiling, the axis the 534 MB measurement ran
// through — on both sides of the boundary, and pins that the count is an AGGREGATE
// across fields rather than a per-field limit.
func TestOversizedParsedCertificateError_bounds_decoded_extension_content(t *testing.T) {
	t.Parallel()

	atCeiling := &x509.Certificate{URIs: make([]*url.URL, maxCertExtensionElements)}
	if err := oversizedParsedCertificateError(atCeiling); err != nil {
		t.Errorf("oversizedParsedCertificateError(exactly maxCertExtensionElements URIs) = %v, want nil:"+
			" the ceiling is inclusive", err)
	}

	over := &x509.Certificate{URIs: make([]*url.URL, maxCertExtensionElements+1)}
	err := oversizedParsedCertificateError(over)
	if err == nil {
		t.Fatal("oversizedParsedCertificateError accepted a certificate retaining more than" +
			" maxCertExtensionElements decoded elements")
	}
	if !strings.Contains(err.Error(), "retained elements") {
		t.Errorf("refusal %q does not name the retained-element ceiling", err)
	}
	if !strings.Contains(err.Error(), "not an X.509 limit") {
		t.Errorf("refusal %q does not name the ceiling as this app's own resource policy", err)
	}

	// The count is a SUM across fields, so no single field may carry the ceiling on its
	// own: half in each of two fields must still refuse. A per-field ceiling would pass
	// both halves and retain twice the bound.
	half := maxCertExtensionElements/2 + 1
	split := &x509.Certificate{
		URIs:     make([]*url.URL, half),
		DNSNames: make([]string, half),
	}
	if err := oversizedParsedCertificateError(split); err == nil {
		t.Error("oversizedParsedCertificateError accepted the ceiling split across two fields," +
			" so the bound is not the aggregate it claims to be")
	}
}

// TestRetainedExtensionElements_counts_every_extension_derived_slice pins the
// INVENTORY, which is the failure mode no other test in this file can see: a term
// silently dropped from the sum leaves the ceiling intact and the refusal working,
// while the field it stopped counting becomes an unbounded retention axis again.
func TestRetainedExtensionElements_counts_every_extension_derived_slice(t *testing.T) {
	t.Parallel()

	// One element in each of the fields x509.ParseCertificate grows per encoded
	// GeneralName, policy, OID or URI. The expected value IS the field count, so
	// dropping a term from the sum — or adding one without extending this fixture —
	// fails here.
	c := &x509.Certificate{
		DNSNames:                []string{"a"},
		EmailAddresses:          []string{"a@b"},
		IPAddresses:             []net.IP{net.IPv4(127, 0, 0, 1)},
		URIs:                    []*url.URL{{}},
		UnknownExtKeyUsage:      []asn1.ObjectIdentifier{{1, 3}},
		ExtKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		PolicyIdentifiers:       []asn1.ObjectIdentifier{{1, 3}},
		Policies:                []x509.OID{{}},
		CRLDistributionPoints:   []string{"http://a"},
		OCSPServer:              []string{"http://a"},
		IssuingCertificateURL:   []string{"http://a"},
		PermittedDNSDomains:     []string{"a"},
		ExcludedDNSDomains:      []string{"a"},
		PermittedEmailAddresses: []string{"a"},
		ExcludedEmailAddresses:  []string{"a"},
		PermittedIPRanges:       []*net.IPNet{{}},
		ExcludedIPRanges:        []*net.IPNet{{}},
		PermittedURIDomains:     []string{"a"},
		ExcludedURIDomains:      []string{"a"},
	}
	if got, want := retainedExtensionElements(c), 19; got != want {
		t.Errorf("retainedExtensionElements(one element per counted field) = %d, want %d:"+
			" a term was dropped from or added to the sum", got, want)
	}
	if got := retainedExtensionElements(&x509.Certificate{}); got != 0 {
		t.Errorf("retainedExtensionElements(empty certificate) = %d, want 0", got)
	}
}

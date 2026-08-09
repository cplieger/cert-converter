package convert_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
)

// The shapes in this file all come from adversarial review of the structural
// Analyse rewrite, and of the guards later added to it. Each one was REPRODUCED
// against the implementation it found wanting, so each test here fails without its
// fix.
//
// The certificate/key fixtures come from internal/testcerts (Mint, KeyPEM,
// NewECDSAKey): how this app mints a test certificate has one home, so a change to
// it (a new default extension, a signature-algorithm pin) is made once.

// chainSerials renders an emitted chain's serial numbers. Serials are what tell
// two same-subject candidates apart in a failure message, where the subject by
// definition cannot.
func chainSerials(chain []*x509.Certificate) []string {
	out := make([]string, 0, len(chain))
	for _, c := range chain {
		out = append(out, c.SerialNumber.String())
	}
	return out
}

// assertOrderInvariant runs Analyse over every rotation of certBlobs and asserts
// the selected identity and the emitted chain are byte-identical every time.
//
// Rotations rather than full permutations keeps the helper cheap while still
// placing each certificate first at least once, which is what every reproduced
// order defect turned on: the losing comparator fell back to "whichever came
// first in the file".
func assertOrderInvariant(t *testing.T, label string, certBlobs [][]byte, keyPEM []byte) {
	t.Helper()
	var wantLeaf []byte
	var wantChain [][]byte

	for r := range certBlobs {
		rotated := make([][]byte, 0, len(certBlobs))
		for i := range certBlobs {
			rotated = append(rotated, certBlobs[(i+r)%len(certBlobs)])
		}
		got, err := convert.Analyse(t.Context(), concatPEM(rotated...), keyPEM)
		if err != nil {
			t.Fatalf("%s: Analyse(rotation %d) = error %v, want nil", label, r, err)
		}
		chain := make([][]byte, 0, len(got.Chain()))
		for _, c := range got.Chain() {
			chain = append(chain, c.Raw)
		}

		if r == 0 {
			wantLeaf, wantChain = got.Leaf().Raw, chain
			continue
		}
		if !bytes.Equal(got.Leaf().Raw, wantLeaf) {
			t.Errorf("%s: rotation %d selected a DIFFERENT identity than rotation 0 (%q vs the first); selection depends on input order",
				label, r, got.Leaf().Subject.CommonName)
		}
		if len(chain) != len(wantChain) {
			t.Errorf("%s: rotation %d emitted a chain of %d, rotation 0 emitted %d", label, r, len(chain), len(wantChain))
			continue
		}
		for i := range chain {
			if !bytes.Equal(chain[i], wantChain[i]) {
				t.Errorf("%s: rotation %d chain[%d] differs from rotation 0; chain order depends on input order", label, r, i)
			}
		}
	}
}

// unverifiableCA builds the certificate template every candidate issuer in the
// inclusive-route tests uses: a CA with the given subject and validity window.
func unverifiableCA(serial int64, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
}

// utf8SubjectView returns a parent VIEW of c whose subject is the same name encoded
// as a UTF8String rather than c's own canonical encoding, with the subject key
// identifier removed.
//
// A certificate minted against this view therefore carries an issuer name that is
// SEMANTICALLY equal to c's subject but byte-distinct, and no authority key
// identifier — exactly the RFC 5280 permitted-encoding difference that defeats both
// of the inclusive edge signals while the signature itself stays valid.
func utf8SubjectView(c *x509.Certificate, cn string) *x509.Certificate {
	view := *c
	view.RawSubject = nil
	view.SubjectKeyId = nil
	view.Subject = pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{
		Type: oidCommonName,
		Value: asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagUTF8String,
			Bytes: []byte(cn),
		},
	}}}
	return &view
}

// rawNameOf marshals an RDN sequence to DER for use as a template's RawSubject.
func rawNameOf(t *testing.T, seq pkix.RDNSequence) []byte {
	t.Helper()
	der, err := asn1.Marshal(seq)
	if err != nil {
		t.Fatalf("setup: marshal RDNSequence: %v", err)
	}
	return der
}

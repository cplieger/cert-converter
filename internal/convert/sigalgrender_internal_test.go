package convert

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"slices"
	"strings"
	"testing"
)

// algorithmIdentifierDER builds the DER AlgorithmIdentifier crypto/x509 retains in
// RawSignatureAlgorithm: SEQUENCE { OBJECT IDENTIFIER }, parameters absent.
func algorithmIdentifierDER(tb testing.TB, oidContent []byte) []byte {
	tb.Helper()

	oid, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagOID,
		Bytes: oidContent,
	})
	if err != nil {
		tb.Fatalf("setup: marshal OBJECT IDENTIFIER: %v", err)
	}
	seq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      oid,
	})
	if err != nil {
		tb.Fatalf("setup: marshal AlgorithmIdentifier: %v", err)
	}
	return seq
}

// TestSignatureAlgorithmForLog_names_an_algorithm_x509_does_not_implement pins the
// diagnostic RawSignatureAlgorithm exists for. crypto/x509 parses a certificate
// whose signature AlgorithmIdentifier it does not recognise, sets SignatureAlgorithm
// to UnknownSignatureAlgorithm, and renders that as the bare number "0" — so before
// this the code knew an algorithm was unrecognised and could not say which one.
//
// The oversized case is not a curiosity: the value is certificate-controlled and
// asn1 allocates one int per encoded byte, which is the allocation
// oversizedKeyAlgorithmOIDError refuses at the same maxOIDBytes ceiling one level
// up. Naming an algorithm must not become a way to spend that allocation.
func TestSignatureAlgorithmForLog_names_an_algorithm_x509_does_not_implement(t *testing.T) {
	t.Parallel()

	// One byte for arcs 1.2, then one byte per further arc: maxOIDBytes+1 content
	// bytes is the smallest identifier the ceiling refuses.
	oversized := append([]byte{0x2A}, slices.Repeat([]byte{0x01}, maxOIDBytes)...)

	const cannotName = "an algorithm crypto/x509 does not implement"
	for name, tc := range map[string]struct {
		cert *x509.Certificate
		want string
	}{
		"a known algorithm is named by x509": {
			cert: &x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA256},
			want: "ECDSA-SHA256",
		},
		"a known but refused algorithm is still named by x509": {
			cert: &x509.Certificate{SignatureAlgorithm: x509.MD5WithRSA},
			want: "MD5-RSA",
		},
		"an unimplemented algorithm is named by its identifier": {
			cert: &x509.Certificate{
				RawSignatureAlgorithm: algorithmIdentifierDER(t, []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x63}),
			},
			want: "the unimplemented algorithm 1.2.840.10045.4.3.99",
		},
		"an absent identifier falls back": {
			cert: &x509.Certificate{},
			want: cannotName,
		},
		"a truncated identifier falls back": {
			cert: &x509.Certificate{RawSignatureAlgorithm: []byte{0x30, 0x0A, 0x06}},
			want: cannotName,
		},
		"an identifier that is not a SEQUENCE falls back": {
			cert: &x509.Certificate{RawSignatureAlgorithm: []byte{0x06, 0x03, 0x2A, 0x03, 0x04}},
			want: cannotName,
		},
		"an oversized identifier is refused rather than decoded": {
			cert: &x509.Certificate{RawSignatureAlgorithm: algorithmIdentifierDER(t, oversized)},
			want: cannotName,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := signatureAlgorithmForLog(tc.cert); got != tc.want {
				t.Errorf("signatureAlgorithmForLog() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSignatureAlgorithmForLog_accepts_the_widest_identifier_it_will_decode is the
// other side of the ceiling: maxOIDBytes content bytes is accepted, so the refusal
// above is the boundary rather than a blanket refusal of long identifiers.
func TestSignatureAlgorithmForLog_accepts_the_widest_identifier_it_will_decode(t *testing.T) {
	t.Parallel()

	widest := append([]byte{0x2A}, slices.Repeat([]byte{0x01}, maxOIDBytes-1)...)
	cert := &x509.Certificate{RawSignatureAlgorithm: algorithmIdentifierDER(t, widest)}

	got := signatureAlgorithmForLog(cert)
	if !strings.HasPrefix(got, "the unimplemented algorithm 1.2.1.1.") {
		t.Errorf("signatureAlgorithmForLog(a %d-byte identifier) = %q, want it named: the ceiling is inclusive",
			len(widest), got)
	}
}

// TestUnverifiableAnchorReason_reports_the_ceiling_ahead_of_the_algorithm pins the
// precedence. A key above this app's verification ceilings means NO signature was
// checked, so naming the algorithm there would describe a check that never ran.
func TestUnverifiableAnchorReason_reports_the_ceiling_ahead_of_the_algorithm(t *testing.T) {
	t.Parallel()

	overCeiling := &rsa.PublicKey{
		N: new(big.Int).Lsh(big.NewInt(1), maxVerifiableKeyBits),
		E: 65537,
	}
	cert := &x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          overCeiling,
	}

	got := unverifiableAnchorReason(cert)
	if !strings.Contains(got, "modulus ceiling") {
		t.Errorf("unverifiableAnchorReason(an over-ceiling key) = %q, want the modulus ceiling reason", got)
	}
	if strings.Contains(got, "SHA256-RSA") {
		t.Errorf("unverifiableAnchorReason(an over-ceiling key) = %q, want no algorithm name: no signature was checked", got)
	}

	inRange := &x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537},
	}
	if got := unverifiableAnchorReason(inRange); !strings.Contains(got, "SHA256-RSA") {
		t.Errorf("unverifiableAnchorReason(an in-range key) = %q, want the algorithm named", got)
	}
}

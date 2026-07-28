package convert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

// The pre-scan guard's tests live in the internal package because the guard is
// deliberately not on the package surface: it is a step inside
// parsePrivateKeyBlock, and both halves of its contract (the size it measures and
// the shapes it refuses to measure) are only observable from here.

// oidRSAEncryption is 1.2.840.113549.1.1.1, the PKCS#8 algorithm identifier that
// says the wrapped privateKey OCTET STRING holds a PKCS#1 RSAPrivateKey.
var oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

// pkcs1KeyDER mirrors crypto/x509's own pkcs1PrivateKey so a test can marshal a
// key of any modulus size without generating one. Field ORDER is the DER contract
// and must not be reordered.
type pkcs1KeyDER struct {
	Version       int
	N, E, D, P, Q *big.Int
	Dp, Dq, Qinv  *big.Int
}

// pkcs8KeyDER mirrors the PKCS#8 PrivateKeyInfo wrapper: version, algorithm, and
// the privateKey OCTET STRING that holds the PKCS#1 structure above.
type pkcs8KeyDER struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// oversizedRSAKeyDER builds PKCS#1 DER whose modulus is bits wide and whose other
// components are trivial. It is deliberately NOT a consistent key: the guard reads
// the modulus INTEGER's length and nothing else, so this is the cheapest input
// that exercises it, and no parser is ever supposed to see it.
func oversizedRSAKeyDER(t *testing.T, bits int) []byte {
	t.Helper()
	one := big.NewInt(1)
	n := new(big.Int).Lsh(one, uint(bits-1))
	n.SetBit(n, 0, 1)
	der, err := asn1.Marshal(pkcs1KeyDER{
		N: n, E: big.NewInt(65537), D: one, P: one, Q: one, Dp: one, Dq: one, Qinv: one,
	})
	if err != nil {
		t.Fatalf("setup: marshal oversized PKCS#1 key: %v", err)
	}
	return der
}

// wrapPKCS8 puts PKCS#1 key DER inside a PKCS#8 PrivateKeyInfo, the second shape
// an RSA private key arrives in.
func wrapPKCS8(t *testing.T, pkcs1DER []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(pkcs8KeyDER{
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue},
		PrivateKey: pkcs1DER,
	})
	if err != nil {
		t.Fatalf("setup: marshal PKCS#8 wrapper: %v", err)
	}
	return der
}

// consistentRSAKeyDER builds PKCS#1 DER of exactly bits that crypto/x509 accepts,
// without generating a real key: x509 does not primality-test p and q, it checks
// n == p*q and that d inverts e modulo both p-1 and q-1, so composite factors of
// the right size satisfy it. rsa.GenerateKey at 16384 bits takes minutes; this
// takes under a millisecond, which is what keeps the ceiling's accept case in the
// default test path.
func consistentRSAKeyDER(t *testing.T, keyBits int) []byte {
	t.Helper()
	one := big.NewInt(1)
	e := big.NewInt(65537)
	for attempt := range 8 {
		p := randomOdd(t, keyBits/2)
		q := randomOdd(t, keyBits/2)
		n := new(big.Int).Mul(p, q)
		pm := new(big.Int).Sub(p, one)
		qm := new(big.Int).Sub(q, one)
		lcm := new(big.Int).Div(new(big.Int).Mul(pm, qm), new(big.Int).GCD(nil, nil, pm, qm))
		d := new(big.Int).ModInverse(e, lcm)
		qInv := new(big.Int).ModInverse(q, p)
		if d == nil || qInv == nil || n.BitLen() != keyBits {
			continue
		}
		der, err := asn1.Marshal(pkcs1KeyDER{
			N: n, E: e, D: d, P: p, Q: q,
			Dp:   new(big.Int).Mod(d, pm),
			Dq:   new(big.Int).Mod(d, qm),
			Qinv: qInv,
		})
		if err != nil {
			t.Fatalf("setup: marshal PKCS#1 key: %v", err)
		}
		// Confirm the toolchain accepts the construction, so a failure in the test
		// below is the guard's and not the fixture's.
		if _, parseErr := x509.ParsePKCS1PrivateKey(der); parseErr == nil {
			return der
		}
		t.Logf("setup: attempt %d produced a key x509 rejected, retrying", attempt)
	}
	t.Fatalf("setup: could not build a %d-bit key x509 accepts in 8 attempts", keyBits)
	return nil
}

// randomOdd returns a random odd integer of exactly bitLen bits.
func randomOdd(t *testing.T, bitLen int) *big.Int {
	t.Helper()
	v, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bitLen)))
	if err != nil {
		t.Fatalf("setup: rand.Int: %v", err)
	}
	v.SetBit(v, bitLen-1, 1)
	v.SetBit(v, 0, 1)
	return v
}

// The non-RSA key shapes the pre-scan must pass through untouched. All three are
// cheap for x509 to parse, which is why the guard has nothing to add for them.
func mustMarshalEC(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("setup: MarshalECPrivateKey: %v", err)
	}
	return der
}

func mustMarshalPKCS8EC(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("setup: MarshalPKCS8PrivateKey(ecdsa): %v", err)
	}
	return der
}

func mustMarshalPKCS8Ed25519(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("setup: ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("setup: MarshalPKCS8PrivateKey(ed25519): %v", err)
	}
	return der
}

// TestParsePrivateKeyBlock_accepts_a_key_at_the_modulus_ceiling pins the ceiling as
// INCLUSIVE, and with it that the guard did not break normal operation: a key
// exactly at maxVerifiableKeyBits still parses into a usable signer.
func TestParsePrivateKeyBlock_accepts_a_key_at_the_modulus_ceiling(t *testing.T) {
	t.Parallel()
	der := consistentRSAKeyDER(t, maxVerifiableKeyBits)

	key, err := parsePrivateKeyBlock(&pem.Block{Type: pemTypeRSAPrivateKey, Bytes: der})
	if err != nil {
		t.Fatalf("parsePrivateKeyBlock(a %d-bit RSA key) = error %v, want it accepted: the ceiling is inclusive",
			maxVerifiableKeyBits, err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("parsePrivateKeyBlock returned %T, want *rsa.PrivateKey", key)
	}
	if got := rsaKey.N.BitLen(); got != maxVerifiableKeyBits {
		t.Errorf("parsed modulus is %d bits, want %d", got, maxVerifiableKeyBits)
	}
}

// TestParsePrivateKeyBlock_refuses_an_oversized_rsa_key pins the refusal on both
// shapes an RSA private key arrives in.
//
// The assertion is the MESSAGE, and that is the proof the guard runs before the
// parser: this wording exists only in oversizedRSAKeyError, which is reached
// before x509 is called at all. Neither x509 parser can produce it — and neither
// could reject these keys without first paying RSA precomputation on the
// file-supplied integers, which is the stall the guard exists to prevent (measured
// on go1.26.5: 369ms for a self-consistent 131072-bit key, on the scan's only
// goroutine, with no cancellation path). Elapsed time is deliberately NOT
// asserted: the threshold that separates guarded from unguarded depends on the
// machine, and a timing assertion would be flaky in CI.
func TestParsePrivateKeyBlock_refuses_an_oversized_rsa_key(t *testing.T) {
	t.Parallel()
	const oversizedBits = 131072
	pkcs1 := oversizedRSAKeyDER(t, oversizedBits)

	for name, block := range map[string]*pem.Block{
		"pkcs1": {Type: pemTypeRSAPrivateKey, Bytes: pkcs1},
		"pkcs8": {Type: pemTypePrivateKey, Bytes: wrapPKCS8(t, pkcs1)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := parsePrivateKeyBlock(block)
			if err == nil {
				t.Fatalf("parsePrivateKeyBlock(a %d-bit RSA key) = nil error, want a refusal", oversizedBits)
			}
			got := err.Error()
			for _, want := range []string{"131072-bit RSA modulus", "16384-bit ceiling", block.Type} {
				if !strings.Contains(got, want) {
					t.Errorf("error = %q, want it to contain %q", got, want)
				}
			}
		})
	}
}

// TestRSAModulusBitsFromKeyDER_measures_or_fails_open pins both halves of the
// pre-scan's contract. The sizes it must measure are what makes the refusal
// possible; the shapes it must NOT measure are what keeps the guard from becoming
// a second parser that rejects input the app accepts today. Every not-measured
// case here reaches the existing parsers unchanged, which is why a malformed RSA
// block still produces the label-specific parse error pinned in convert_test.go.
func TestRSAModulusBitsFromKeyDER_measures_or_fails_open(t *testing.T) {
	t.Parallel()

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}
	pkcs8RSA, err := x509.MarshalPKCS8PrivateKey(rsa2048)
	if err != nil {
		t.Fatalf("setup: MarshalPKCS8PrivateKey: %v", err)
	}
	atCeiling := consistentRSAKeyDER(t, maxVerifiableKeyBits)
	negativeModulus, err := asn1.Marshal(pkcs1KeyDER{
		N: big.NewInt(-3), E: big.NewInt(65537), D: big.NewInt(1), P: big.NewInt(1),
		Q: big.NewInt(1), Dp: big.NewInt(1), Dq: big.NewInt(1), Qinv: big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("setup: marshal negative-modulus key: %v", err)
	}

	cases := map[string]struct {
		der      []byte
		wantBits int
		wantOK   bool
	}{
		"pkcs1 rsa":                 {der: x509.MarshalPKCS1PrivateKey(rsa2048), wantBits: 2048, wantOK: true},
		"pkcs8 rsa":                 {der: pkcs8RSA, wantBits: 2048, wantOK: true},
		"pkcs1 at the ceiling":      {der: atCeiling, wantBits: maxVerifiableKeyBits, wantOK: true},
		"pkcs1 oversized":           {der: oversizedRSAKeyDER(t, 131072), wantBits: 131072, wantOK: true},
		"pkcs8 oversized":           {der: wrapPKCS8(t, oversizedRSAKeyDER(t, 131072)), wantBits: 131072, wantOK: true},
		"sec1 ec":                   {der: mustMarshalEC(t)},
		"pkcs8 ecdsa":               {der: mustMarshalPKCS8EC(t)},
		"pkcs8 ed25519":             {der: mustMarshalPKCS8Ed25519(t)},
		"garbage":                   {der: []byte("this is not valid DER")},
		"empty":                     {der: nil},
		"truncated pkcs1":           {der: x509.MarshalPKCS1PrivateKey(rsa2048)[:12]},
		"negative modulus":          {der: negativeModulus},
		"doubly wrapped past depth": {der: wrapPKCS8(t, wrapPKCS8(t, oversizedRSAKeyDER(t, 131072)))},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gotBits, gotOK := rsaModulusBitsFromKeyDER(tc.der, 1)
			if gotOK != tc.wantOK {
				t.Fatalf("rsaModulusBitsFromKeyDER(%s) measured = %v, want %v", name, gotOK, tc.wantOK)
			}
			if gotOK && gotBits != tc.wantBits {
				t.Errorf("rsaModulusBitsFromKeyDER(%s) = %d bits, want %d", name, gotBits, tc.wantBits)
			}
		})
	}
}

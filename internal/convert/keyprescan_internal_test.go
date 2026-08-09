package convert

import (
	"bytes"
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

// hugePrimeRSAKeyDER builds PKCS#1 DER whose modulus is trivial but whose
// primes are bits wide: the shape that bypassed the pre-scan when it measured
// only the modulus, and the one crypto/rsa spends its precompute on.
func hugePrimeRSAKeyDER(t *testing.T, bits int) []byte {
	t.Helper()
	one := big.NewInt(1)
	p := new(big.Int).Lsh(one, uint(bits-1))
	p.SetBit(p, 0, 1)
	der, err := asn1.Marshal(pkcs1KeyDER{
		N: big.NewInt(196611), E: big.NewInt(65537), D: one, P: p, Q: p,
		Dp: one, Dq: one, Qinv: one,
	})
	if err != nil {
		t.Fatalf("setup: marshal huge-prime PKCS#1 key: %v", err)
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
//
// The retries are for ONE residual: p and q are random odd numbers, not primes, so
// roughly one pair in five shares a factor and has no qInv (P(coprime) over odd
// integers is (6/pi^2)/(1-1/4) ~ 0.81). randomOdd's top-two-bits construction
// removes the other, larger cause -- an n of 2*bitLen-1 bits, which used to fail
// ~39% of attempts and made the 8-attempt bound miss about 0.4% of calls.
func consistentRSAKeyDER(t *testing.T, keyBits int) []byte {
	t.Helper()
	one := big.NewInt(1)
	e := big.NewInt(65537)
	const attempts = 16
	for attempt := range attempts {
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
	t.Fatalf("setup: could not build a %d-bit key x509 accepts in %d attempts", keyBits, attempts)
	return nil
}

// randomOdd returns a random odd integer of exactly bitLen bits whose top TWO bits
// are set. The second bit is what makes the product of two such numbers exactly
// 2*bitLen bits: each is >= 3*2^(bitLen-2), so the product is >= 2.25*2^(2*bitLen-2),
// which is above the 2^(2*bitLen-1) boundary, and both are < 2^bitLen so it stays
// below 2^(2*bitLen). Setting only the top bit leaves the product's length a coin
// flip (P(2*bitLen bits) = 2-2*ln2 ~ 0.61), and consistentRSAKeyDER discards a pair
// of the wrong length -- which is the same construction real RSA keygen uses, and
// for the same reason.
func randomOdd(t *testing.T, bitLen int) *big.Int {
	t.Helper()
	v, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bitLen)))
	if err != nil {
		t.Fatalf("setup: rand.Int: %v", err)
	}
	v.SetBit(v, bitLen-1, 1)
	v.SetBit(v, bitLen-2, 1)
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
	// The huge-PRIME shape is the bypass this guard was re-keyed for: its modulus is
	// 18 bits, so measuring only the modulus waved it through and crypto/rsa spent
	// ~60s on the file's primes. Both arrival shapes carry it.
	hugePrime := hugePrimeRSAKeyDER(t, oversizedBits)

	for name, block := range map[string]*pem.Block{
		"pkcs1":                  {Type: pemTypeRSAPrivateKey, Bytes: pkcs1},
		"pkcs8":                  {Type: pemTypePrivateKey, Bytes: wrapPKCS8(t, pkcs1)},
		"pkcs1 with huge primes": {Type: pemTypeRSAPrivateKey, Bytes: hugePrime},
		"pkcs8 with huge primes": {Type: pemTypePrivateKey, Bytes: wrapPKCS8(t, hugePrime)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := parsePrivateKeyBlock(block)
			if err == nil {
				t.Fatalf("parsePrivateKeyBlock(a %d-bit RSA key) = nil error, want a refusal", oversizedBits)
			}
			got := err.Error()
			for _, want := range []string{"131072-bit RSA integer", "16384-bit ceiling", block.Type} {
				if !strings.Contains(got, want) {
					t.Errorf("error = %q, want it to contain %q", got, want)
				}
			}
		})
	}
}

// TestParsePrivateKeyBlock_refuses_an_oversized_final_RSA_integer pins the walk's
// ENDPOINT. The rows above put the oversized value in the modulus or in p and q,
// all of which are reached early; nothing placed it in Qinv, the LAST top-level
// INTEGER, so a walk that stopped one element short still passed the whole suite
// while the pre-scan silently stopped enforcing its "modulus, prime or CRT value"
// contract and handed the key to crypto/x509 instead.
func TestParsePrivateKeyBlock_refuses_an_oversized_final_RSA_integer(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	hugeQinv := new(big.Int).Lsh(one, 131071)
	hugeQinv.SetBit(hugeQinv, 0, 1)
	der, err := asn1.Marshal(pkcs1KeyDER{
		N: big.NewInt(196611), E: big.NewInt(65537), D: one, P: one, Q: one,
		Dp: one, Dq: one, Qinv: hugeQinv,
	})
	if err != nil {
		t.Fatalf("setup: marshal huge-Qinv PKCS#1 key: %v", err)
	}

	_, err = parsePrivateKeyBlock(&pem.Block{Type: pemTypeRSAPrivateKey, Bytes: der})
	if err == nil {
		t.Fatal("parsePrivateKeyBlock(a key with a 131072-bit final CRT integer) = nil error, want a pre-scan refusal")
	}
	for _, want := range []string{"131072-bit RSA integer", "16384-bit ceiling", pemTypeRSAPrivateKey} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// otherPrimeInfoDER mirrors PKCS#1's OtherPrimeInfo (RFC 8017 A.1.2), so a test can
// build the multi-prime collection the factor ceiling bounds. Field ORDER is the
// DER contract.
type otherPrimeInfoDER struct {
	Prime, Exponent, Coefficient *big.Int
}

// multiPrimeKeyDER is pkcs1KeyDER with the optional OtherPrimeInfos collection
// present, which is where a file hides MANY small primes rather than one large one.
type multiPrimeKeyDER struct {
	Version         int
	N, E, D, P, Q   *big.Int
	Dp, Dq, Qinv    *big.Int
	OtherPrimeInfos []otherPrimeInfoDER
}

// TestParsePrivateKeyBlock_refuses_too_many_RSA_prime_factors pins the SECOND
// pre-scan bound, which no size check can express. Every integer here is tiny, so
// the per-integer ceiling passes the block through; the cost is in the COUNT,
// because crypto/x509 decodes the collection into a slice and crypto/rsa's
// precomputeLegacy then runs one ModInverse per additional prime against a growing
// product. Measured on go1.26.5: 10,000 entries in a 127 KB block (far inside the
// reader's 10 MB cap) cost 160ms and 292 MB on the scan's only goroutine.
func TestParsePrivateKeyBlock_refuses_too_many_RSA_prime_factors(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	extras := make([]otherPrimeInfoDER, maxRSAPrimeFactors)
	for i := range extras {
		extras[i] = otherPrimeInfoDER{Prime: big.NewInt(3), Exponent: one, Coefficient: one}
	}
	der, err := asn1.Marshal(multiPrimeKeyDER{
		Version: 1,
		N:       big.NewInt(196611), E: big.NewInt(65537), D: one, P: one, Q: one,
		Dp: one, Dq: one, Qinv: one,
		OtherPrimeInfos: extras,
	})
	if err != nil {
		t.Fatalf("setup: marshal multi-prime PKCS#1 key: %v", err)
	}
	// The whole block stays small: the amplification is the element count, which is
	// exactly why a size bound cannot catch it.
	if len(der) > 1<<12 {
		t.Fatalf("setup: multi-prime fixture is %d bytes, want a small block: the point is that size does not bound this shape", len(der))
	}

	for name, block := range map[string]*pem.Block{
		"pkcs1": {Type: pemTypeRSAPrivateKey, Bytes: der},
		"pkcs8": {Type: pemTypePrivateKey, Bytes: wrapPKCS8(t, der)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := parsePrivateKeyBlock(block)
			if err == nil {
				t.Fatalf("parsePrivateKeyBlock(a key declaring %d prime factors) = nil error, want a pre-scan refusal",
					maxRSAPrimeFactors+2)
			}
			for _, want := range []string{"more than 64 RSA prime factors", "64-factor ceiling", block.Type} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// TestParsePrivateKeyBlock_refuses_an_oversized_prime_inside_OtherPrimeInfos pins the
// SIZE half of the OtherPrimeInfos walk, which no other case in this file reaches:
// every multi-prime fixture here declares tiny extra primes, so the collection has
// only ever contributed to the FACTOR count. A key whose factor count is legal but
// which hides one huge integer inside the collection is the other amplification
// shape -- crypto/x509 decodes the collection and crypto/rsa runs its precompute on
// those integers, on the scan's only goroutine, with no cancellation path -- and the
// only thing that refuses it is the collection's contribution to the measured size.
func TestParsePrivateKeyBlock_refuses_an_oversized_prime_inside_OtherPrimeInfos(t *testing.T) {
	t.Parallel()
	const oversizedBits = 131072
	one := big.NewInt(1)
	hugePrime := new(big.Int).Lsh(one, oversizedBits-1)
	hugePrime.SetBit(hugePrime, 0, 1)
	der, err := asn1.Marshal(multiPrimeKeyDER{
		Version: 1,
		N:       big.NewInt(196611), E: big.NewInt(65537), D: one, P: one, Q: one,
		Dp: one, Dq: one, Qinv: one,
		OtherPrimeInfos: []otherPrimeInfoDER{{Prime: hugePrime, Exponent: one, Coefficient: one}},
	})
	if err != nil {
		t.Fatalf("setup: marshal a three-prime key with an oversized extra prime: %v", err)
	}

	for name, block := range map[string]*pem.Block{
		"pkcs1": {Type: pemTypeRSAPrivateKey, Bytes: der},
		"pkcs8": {Type: pemTypePrivateKey, Bytes: wrapPKCS8(t, der)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := parsePrivateKeyBlock(block)
			if err == nil {
				t.Fatalf("parsePrivateKeyBlock(a key with a %d-bit prime inside OtherPrimeInfos) = nil error, want the size refusal",
					oversizedBits)
			}
			got := err.Error()
			for _, want := range []string{"131072-bit RSA integer", "16384-bit ceiling", block.Type} {
				if !strings.Contains(got, want) {
					t.Errorf("error = %q, want it to contain %q: an integer inside OtherPrimeInfos must count towards the measured size",
						got, want)
				}
			}
			// The factor count is legal here (three primes), so the refusal must be the
			// SIZE one, and it must still precede crypto/x509 rather than follow it.
			if strings.Contains(got, "RSA prime factors") {
				t.Errorf("error = %q, want the size refusal: three prime factors are inside the ceiling", got)
			}
			if strings.Contains(got, "x509:") {
				t.Errorf("error = %q, want the app's own bounded refusal before the parser runs", got)
			}
		})
	}
}

// TestScanRSAKeyEnvelope_saturates_the_factor_count pins the walk's own
// bound. The count feeds one refusal and nothing reads the exact number, so once the
// scan has seen one factor past the ceiling the collection must not be measured any
// further: continuing costs one RawValue walk per entry of an attacker-sized
// collection (a 10 MB PEM holds hundreds of thousands of them) to learn a number the
// refusal does not print.
func TestScanRSAKeyEnvelope_saturates_the_factor_count(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	extras := make([]otherPrimeInfoDER, 10_000)
	for i := range extras {
		extras[i] = otherPrimeInfoDER{Prime: big.NewInt(3), Exponent: one, Coefficient: one}
	}
	der, err := asn1.Marshal(multiPrimeKeyDER{
		Version: 1,
		N:       big.NewInt(196611), E: big.NewInt(65537), D: one, P: one, Q: one,
		Dp: one, Dq: one, Qinv: one,
		OtherPrimeInfos: extras,
	})
	if err != nil {
		t.Fatalf("setup: marshal multi-prime PKCS#1 key: %v", err)
	}

	scan := scanRSAKeyEnvelope(der, 1)
	if !scan.isRSA {
		t.Fatalf("scanRSAKeyEnvelope(a 10,000-entry multi-prime key) did not recognise the envelope; the refusal depends on it")
	}
	if scan.factors != maxRSAPrimeFactors+1 {
		t.Errorf("scan.factors = %d, want %d: the walk must stop one factor past the ceiling instead of counting every entry",
			scan.factors, maxRSAPrimeFactors+1)
	}
}

// TestRSAOtherPrimeInfos_stops_at_the_first_element_that_is_not_an_OtherPrimeInfo pins
// the walk's stop rule over a MALFORMED collection, which nothing else feeds it: every
// fixture in this file builds a well-formed OtherPrimeInfos to its end. The count feeds
// a refusal, so crediting an element the walk could not read would refuse a damaged key
// with the factor-ceiling diagnostic where the contract is that the parser reports the
// damage -- the same precedence
// TestParsePrivateKeyBlock_leaves_a_plain_malformed_modulus_to_the_parser pins for the
// modulus.
func TestRSAOtherPrimeInfos_stops_at_the_first_element_that_is_not_an_OtherPrimeInfo(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	info := testASN1Marshal(t, otherPrimeInfoDER{Prime: big.NewInt(3), Exponent: one, Coefficient: one})

	cases := map[string]struct {
		body           []byte
		wantAdditional int
		wantMaxBits    int
	}{
		// The entry before the stop still counts, and its widest integer (the 2-bit
		// prime) is still measured.
		"one entry then an element that is not a sequence": {
			body:           append(bytes.Clone(info), testASN1Marshal(t, 5)...),
			wantAdditional: 1,
			wantMaxBits:    2,
		},
		// Nothing readable at all: the walk credits no prime rather than counting an
		// element it could not parse.
		"a body that is not an element at all": {body: []byte("not DER")},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			additional, maxBits := rsaOtherPrimeInfos(tc.body, maxRSAPrimeFactors)
			if additional != tc.wantAdditional {
				t.Errorf("rsaOtherPrimeInfos(%s) counted %d additional prime(s), want %d: the walk must stop rather than re-read the same element",
					name, additional, tc.wantAdditional)
			}
			if maxBits != tc.wantMaxBits {
				t.Errorf("rsaOtherPrimeInfos(%s) = %d bits, want %d", name, maxBits, tc.wantMaxBits)
			}
		})
	}
}

// TestParsePrivateKeyBlock_refuses_a_malformed_modulus_declaring_too_many_factors is
// the end-to-end proof that the envelope scan closed the hole: a key whose modulus is
// unreadable AND which declares a huge OtherPrimeInfos collection is refused by THIS
// app, from its DER, before crypto/x509 decodes the collection.
//
// Both properties are load-bearing. The modulus is what a size-only pre-scan gave up
// on (so both ceilings were skipped), and the collection is the cost: x509 decodes
// every entry into a slice before it ever looks at the modulus, which at the 10 MiB
// input cap extrapolates to ~950,000 entries, ~152 MB and ~408 ms on the scan's only
// goroutine with no cancellation path.
//
// The error PRECEDENCE is asserted, not just the refusal: the message must be the
// app's own bounded diagnostic naming the factor ceiling, and must NOT be x509's
// malformed-key error. That inversion is a deliberate, accepted consequence — the
// file is refused either way, and this wording is the one that names the ceiling.
func TestParsePrivateKeyBlock_refuses_a_malformed_modulus_declaring_too_many_factors(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	extras := make([]otherPrimeInfoDER, maxRSAPrimeFactors)
	for i := range extras {
		extras[i] = otherPrimeInfoDER{Prime: big.NewInt(3), Exponent: one, Coefficient: one}
	}
	der, err := asn1.Marshal(multiPrimeKeyDER{
		Version: 1,
		N:       big.NewInt(0), E: big.NewInt(65537), D: one, P: one, Q: one,
		Dp: one, Dq: one, Qinv: one,
		OtherPrimeInfos: extras,
	})
	if err != nil {
		t.Fatalf("setup: marshal zero-modulus multi-prime key: %v", err)
	}

	for name, block := range map[string]*pem.Block{
		"pkcs1": {Type: pemTypeRSAPrivateKey, Bytes: der},
		"pkcs8": {Type: pemTypePrivateKey, Bytes: wrapPKCS8(t, der)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := parsePrivateKeyBlock(block)
			if err == nil {
				t.Fatalf("parsePrivateKeyBlock(a zero-modulus key declaring %d prime factors) = nil error, want the pre-scan refusal",
					maxRSAPrimeFactors+2)
			}
			got := err.Error()
			for _, want := range []string{"more than 64 RSA prime factors", "64-factor ceiling", block.Type} {
				if !strings.Contains(got, want) {
					t.Errorf("error = %q, want it to contain %q", got, want)
				}
			}
			// The proof that the refusal is the app's and precedes the parser: this
			// wording exists only in oversizedRSAKeyError, and x509's own complaint
			// about the modulus is absent.
			if strings.Contains(got, "x509:") {
				t.Errorf("error = %q, want the app's own bounded refusal rather than a crypto/x509 error: the guard must run first", got)
			}
		})
	}
}

// TestParsePrivateKeyBlock_leaves_a_plain_malformed_modulus_to_the_parser pins the
// OTHER side of that precedence, and it is what keeps the change from becoming "the
// pre-scan is a second parser". A malformed modulus is not itself a refusal: with a
// legal factor count and no oversized integer there is nothing for either ceiling to
// say, so the block still goes to crypto/x509 and the operator still gets the
// parser's diagnosis of the damage, wrapped in this package's label-naming message.
func TestParsePrivateKeyBlock_leaves_a_plain_malformed_modulus_to_the_parser(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	der, err := asn1.Marshal(multiPrimeKeyDER{
		Version: 1,
		N:       big.NewInt(0), E: big.NewInt(65537), D: one, P: one, Q: one,
		Dp: one, Dq: one, Qinv: one,
		OtherPrimeInfos: []otherPrimeInfoDER{{Prime: big.NewInt(3), Exponent: one, Coefficient: one}},
	})
	if err != nil {
		t.Fatalf("setup: marshal zero-modulus three-prime key: %v", err)
	}

	_, err = parsePrivateKeyBlock(&pem.Block{Type: pemTypeRSAPrivateKey, Bytes: der})
	if err == nil {
		t.Fatal("parsePrivateKeyBlock(a zero-modulus key) = nil error, want the parser's own rejection")
	}
	got := err.Error()
	if !strings.Contains(got, "failed to parse private key") {
		t.Errorf("error = %q, want the parser's own failure: neither ceiling applies to this block", got)
	}
	for _, unwanted := range []string{"RSA prime factors", "RSA integer"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("error = %q, want no pre-scan refusal: a malformed modulus is not itself over a ceiling", got)
		}
	}
}

// TestParsePrivateKeyBlock_accepts_a_realistic_multi_prime_key keeps that ceiling
// from becoming a refusal of legitimate keys: a three-prime key is inside the
// bound, so the pre-scan must measure it and decide nothing. The parser's own
// verdict on the (deliberately inconsistent) fixture is irrelevant here; what
// matters is that the refusal above is not what stops it.
func TestParsePrivateKeyBlock_accepts_a_realistic_multi_prime_key(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	der, err := asn1.Marshal(multiPrimeKeyDER{
		Version: 1,
		N:       big.NewInt(196611), E: big.NewInt(65537), D: one, P: one, Q: one,
		Dp: one, Dq: one, Qinv: one,
		OtherPrimeInfos: []otherPrimeInfoDER{{Prime: big.NewInt(3), Exponent: one, Coefficient: one}},
	})
	if err != nil {
		t.Fatalf("setup: marshal three-prime PKCS#1 key: %v", err)
	}

	_, err = parsePrivateKeyBlock(&pem.Block{Type: pemTypeRSAPrivateKey, Bytes: der})
	if err != nil && strings.Contains(err.Error(), "RSA prime factors") {
		t.Errorf("parsePrivateKeyBlock(a three-prime key) = %v, want the factor ceiling to stay out of it: multi-prime RSA is legal and rare, not an amplification shape", err)
	}
}

// TestScanRSAKeyEnvelope_reports_shape_and_optional_size pins the envelope scan's
// three answers at once: whether the block IS an RSA private-key envelope, and — for
// one that is — the size of its widest integer when any integer could be sized. The
// sizes it must measure are what makes the size refusal possible; the shapes it must
// NOT claim are what keeps the guard from becoming a second parser that rejects input
// the app converts today. Every non-envelope case here reaches the existing parsers
// unchanged, which is why a malformed non-RSA block still produces the
// label-specific parse error pinned in convert_test.go.
//
// Shape and size are asserted as INDEPENDENT answers because that independence is
// the contract: the rows whose modulus is unreadable are still envelopes, and the
// factor ceiling reads their shape (see
// TestScanRSAKeyEnvelope_counts_factors_through_an_unmeasurable_modulus).
func TestScanRSAKeyEnvelope_reports_shape_and_optional_size(t *testing.T) {
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
		der       []byte
		wantBits  int
		wantRSA   bool
		wantSized bool
	}{
		"pkcs1 rsa":            {der: x509.MarshalPKCS1PrivateKey(rsa2048), wantBits: 2048, wantRSA: true, wantSized: true},
		"pkcs8 rsa":            {der: pkcs8RSA, wantBits: 2048, wantRSA: true, wantSized: true},
		"pkcs1 at the ceiling": {der: atCeiling, wantBits: maxVerifiableKeyBits, wantRSA: true, wantSized: true},
		"pkcs1 oversized":      {der: oversizedRSAKeyDER(t, 131072), wantBits: 131072, wantRSA: true, wantSized: true},
		"pkcs1 small modulus, oversized primes": {
			der: hugePrimeRSAKeyDER(t, 131072), wantBits: 131072, wantRSA: true, wantSized: true,
		},
		"pkcs8 small modulus, oversized primes": {
			der: wrapPKCS8(t, hugePrimeRSAKeyDER(t, 131072)), wantBits: 131072, wantRSA: true, wantSized: true,
		},
		"pkcs8 oversized": {der: wrapPKCS8(t, oversizedRSAKeyDER(t, 131072)), wantBits: 131072, wantRSA: true, wantSized: true},
		// An unreadable modulus is a missing MEASUREMENT, not a missing envelope: the
		// widest integer still readable here is the 17-bit public exponent, which is
		// what the size half of the pre-scan now compares against its ceiling (and
		// passes). The block still reaches x509, which rejects it — but as a key with
		// a legal factor count, not because the scan gave up.
		"negative modulus is still an envelope": {der: negativeModulus, wantBits: 17, wantRSA: true, wantSized: true},
		"sec1 ec":                               {der: mustMarshalEC(t)},
		"pkcs8 ecdsa":                           {der: mustMarshalPKCS8EC(t)},
		"pkcs8 ed25519":                         {der: mustMarshalPKCS8Ed25519(t)},
		"garbage":                               {der: []byte("this is not valid DER")},
		"empty":                                 {der: nil},
		"truncated pkcs1":                       {der: x509.MarshalPKCS1PrivateKey(rsa2048)[:12]},
		"doubly wrapped past depth":             {der: wrapPKCS8(t, wrapPKCS8(t, oversizedRSAKeyDER(t, 131072)))},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			scan := scanRSAKeyEnvelope(tc.der, 1)
			if scan.isRSA != tc.wantRSA {
				t.Fatalf("scanRSAKeyEnvelope(%s) isRSA = %v, want %v", name, scan.isRSA, tc.wantRSA)
			}
			if scan.sized != tc.wantSized {
				t.Fatalf("scanRSAKeyEnvelope(%s) sized = %v, want %v", name, scan.sized, tc.wantSized)
			}
			if scan.sized && scan.maxBits != tc.wantBits {
				t.Errorf("scanRSAKeyEnvelope(%s) = %d bits, want %d", name, scan.maxBits, tc.wantBits)
			}
		})
	}
}

// TestScanRSAKeyEnvelope_counts_factors_through_an_unmeasurable_modulus is the
// REPLACEMENT for the assertion this test file used to make, and it reverses it.
//
// The old defence was "a zero modulus is no modulus": the scan abandoned the whole
// block, reported nothing, and the block went to crypto/x509 with BOTH ceilings
// skipped. That fail-open was defended as leaving a malformed key to the parser's own
// error — but the factor ceiling does not need the modulus, and skipping it made one
// malformed integer a way past the guard: x509 decodes the entire OtherPrimeInfos
// collection into a slice before it looks at the modulus at all (extrapolated to
// ~950,000 entries, ~152 MB and ~408 ms at the 10 MiB input cap, on the scan's only
// goroutine, with no cancellation path).
//
// The new defence is that an unreadable modulus costs the SIZE answer only: the
// envelope is still recognised and its factor count still read, from tag-length
// headers that never depended on the modulus being a number.
func TestScanRSAKeyEnvelope_counts_factors_through_an_unmeasurable_modulus(t *testing.T) {
	t.Parallel()
	one := big.NewInt(1)
	extras := make([]otherPrimeInfoDER, maxRSAPrimeFactors)
	for i := range extras {
		extras[i] = otherPrimeInfoDER{Prime: big.NewInt(3), Exponent: one, Coefficient: one}
	}

	for name, modulus := range map[string]*big.Int{
		"a zero modulus":     big.NewInt(0),
		"a negative modulus": big.NewInt(-3),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			der, err := asn1.Marshal(multiPrimeKeyDER{
				Version: 1,
				N:       modulus, E: big.NewInt(65537), D: one, P: one, Q: one,
				Dp: one, Dq: one, Qinv: one,
				OtherPrimeInfos: extras,
			})
			if err != nil {
				t.Fatalf("setup: marshal multi-prime key with %s: %v", name, err)
			}

			scan := scanRSAKeyEnvelope(der, 1)
			if !scan.isRSA {
				t.Fatalf("scanRSAKeyEnvelope(%s) reported no envelope; the factor ceiling then never runs", name)
			}
			if scan.factors <= maxRSAPrimeFactors {
				t.Errorf("scanRSAKeyEnvelope(%s) counted %d factors, want more than the %d-factor ceiling: the count does not depend on the modulus",
					name, scan.factors, maxRSAPrimeFactors)
			}
		})
	}
}

// TestScanRSAKeyEnvelope_fails_open_on_shapes_that_are_not_an_envelope covers the
// container shapes TestScanRSAKeyEnvelope_reports_shape_and_optional_size does not
// reach. The pre-scan is the guard that keeps an oversized or over-factored
// file-supplied RSA key out of crypto/x509's precomputation (a measured 369ms stall
// on the scan's only goroutine, with no cancellation path), so a misread is
// operator-visible in both directions: a shape wrongly claimed as an RSA envelope
// refuses a key the app converts today, and a shape wrongly skipped admits the stall
// the guard exists to prevent. None of these rows is reachable through the DER
// already in that table, so today a walk missing one of these header checks passes
// the suite unchanged.
//
// The zero-modulus case deliberately does NOT belong here any more: it is an
// envelope, and it moved to
// TestScanRSAKeyEnvelope_counts_factors_through_an_unmeasurable_modulus.
func TestScanRSAKeyEnvelope_fails_open_on_shapes_that_are_not_an_envelope(t *testing.T) {
	t.Parallel()

	version := testASN1Marshal(t, 0)
	rsaOID := testASN1Marshal(t, oidRSAEncryption)

	for name, der := range map[string][]byte{
		"a first element that is not the version":        derTestSequence(t, derTestSequence(t, rsaOID), version),
		"nothing after the version":                      derTestSequence(t, version),
		"a pkcs8 shape whose key is not an octet string": derTestSequence(t, version, derTestSequence(t, rsaOID), testASN1Marshal(t, 5)),
		"a pkcs8 shape with nothing after the algorithm": derTestSequence(t, version, derTestSequence(t, rsaOID)),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			scan := scanRSAKeyEnvelope(der, 1)
			if scan.isRSA {
				t.Errorf("scanRSAKeyEnvelope(%s) claimed an RSA envelope (%d bits, %d factors), want it to fail open",
					name, scan.maxBits, scan.factors)
			}
		})
	}
}

// derTestSequence wraps already-encoded DER elements in a SEQUENCE, so a case can
// build a container shape by hand without a struct per shape.
func derTestSequence(t *testing.T, elements ...[]byte) []byte {
	t.Helper()
	var body []byte
	for _, e := range elements {
		body = append(body, e...)
	}
	return testASN1Marshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

// TestPKCS8HoldsECKey_answers_true_only_for_an_ec_algorithm_identifier pins the
// FALSE side of the EC PARAMETERS companion rule, which no existing input reaches:
// the only production caller (holdsECPrivateKey) reaches this function with a
// PKCS#8 block, every input the suite builds is an EC one, and an
// `openssl ecparam -genkey` RSA-key file is PKCS#1-labelled, so it never arrives
// here at all. A walk that answered "yes" for any PKCS#8 container would pass the
// whole suite today, and the consequence is silent: an `openssl pkcs8 -topk8` RSA
// key beside a stray EC PARAMETERS block in the certificate file would be treated
// as that block's companion, so ObsUnrelatedBlocksSkipped -- the only thing
// telling the operator a block was left out of the bundle -- would never be
// emitted.
//
// The unreadable shapes are the other half of the contract: the walk must FAIL
// OPEN (answer "no", so the block is reported) on anything it cannot read, rather
// than grow into a second key parser.
func TestPKCS8HoldsECKey_answers_true_only_for_an_ec_algorithm_identifier(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("setup: rsa.GenerateKey: %v", err)
	}
	pkcs8RSA, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("setup: MarshalPKCS8PrivateKey(rsa): %v", err)
	}
	version := testASN1Marshal(t, 0)
	ecOID := testASN1Marshal(t, ecPublicKeyOID)

	cases := map[string]struct {
		der  []byte
		want bool
	}{
		"a pkcs8 ec key is the companion":           {der: mustMarshalPKCS8EC(t), want: true},
		"a pkcs8 rsa key is not":                    {der: pkcs8RSA},
		"a pkcs8 ed25519 key is not":                {der: mustMarshalPKCS8Ed25519(t)},
		"a sec1 ec key is not a pkcs8 container":    {der: mustMarshalEC(t)},
		"garbage":                                   {der: []byte("this is not valid DER")},
		"empty":                                     {der: nil},
		"not a sequence at all":                     {der: testASN1Marshal(t, 42)},
		"a first element that is not the version":   {der: derTestSequence(t, derTestSequence(t, ecOID), ecOID)},
		"nothing after the version":                 {der: derTestSequence(t, version)},
		"an algorithm identifier that is not a seq": {der: derTestSequence(t, version, version)},
		"an algorithm identifier holding no oid":    {der: derTestSequence(t, version, derTestSequence(t, version))},
		"an algorithm oid whose body cannot decode": {der: derTestSequence(t, version, derTestSequence(t, []byte{0x06, 0x01, 0x80}))},
		"a truncated pkcs8 rsa container":           {der: pkcs8RSA[:16]},
		"a pkcs8 container naming rsaEncryption":    {der: derTestSequence(t, version, derTestSequence(t, testASN1Marshal(t, oidRSAEncryption)))},
		// The identifier is decoded through decodeOID, so maxOIDBytes applies here
		// too: a syntactically valid but oversized identifier must answer false
		// rather than spend one int per encoded byte to say so.
		"an algorithm oid above the maxOIDBytes bound": {der: derTestSequence(t, version, derTestSequence(t,
			testASN1Marshal(t, asn1.RawValue{Tag: asn1.TagOID, Bytes: bytes.Repeat([]byte{0x01}, maxOIDBytes+1)})))},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := pkcs8HoldsECKey(tc.der); got != tc.want {
				t.Errorf("pkcs8HoldsECKey(%s) = %v, want %v", name, got, tc.want)
			}
		})
	}
}

// FuzzScanRSAKeyEnvelope_reports_a_bounded_shape fuzzes the DER-only pre-scan every
// private-key block passes through before crypto/x509 sees it. The bytes are an
// operator-supplied file's, bounded only by the caller's 10 MB read cap, and the walk
// is what keeps an oversized or over-factored key out of RSA precomputation, so its
// structural promises are worth exploring beyond the shapes hand-built above.
//
// The invariants are the walk's own contract, not "does not panic": a shape it does not
// recognise reports the ZERO value (oversizedRSAKeyError returns nil on !isRSA without
// reading the other fields, so a partly-filled report would be acted on later), the
// factor count SATURATES one past the ceiling (the bound that stops the walk from
// measuring an attacker-sized collection to the end), a measured size is a positive one
// (the ceiling comparison reads maxBits only when sized), and the same bytes always
// yield the same verdict.
func FuzzScanRSAKeyEnvelope_reports_a_bounded_shape(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("setup: rsa.GenerateKey: %v", err)
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		f.Fatalf("setup: MarshalPKCS8PrivateKey: %v", err)
	}
	one := big.NewInt(1)
	extras := make([]otherPrimeInfoDER, 200)
	for i := range extras {
		extras[i] = otherPrimeInfoDER{Prime: big.NewInt(3), Exponent: one, Coefficient: one}
	}
	overFactored, err := asn1.Marshal(multiPrimeKeyDER{
		Version: 1,
		N:       big.NewInt(196611), E: big.NewInt(65537), D: one, P: one, Q: one,
		Dp: one, Dq: one, Qinv: one,
		OtherPrimeInfos: extras,
	})
	if err != nil {
		f.Fatalf("setup: marshal multi-prime key: %v", err)
	}
	// The committed seeds ARE the durable coverage: the weekly run's generated corpus is
	// discarded, so each shape the refusals depend on is pinned here.
	f.Add(pkcs1)
	f.Add(pkcs8)
	f.Add(overFactored)
	f.Add(pkcs1[:12])
	f.Add([]byte("this is not valid DER"))
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, der []byte) {
		scan := scanRSAKeyEnvelope(der, 1)
		if !scan.isRSA && scan != (rsaKeyPreScan{}) {
			t.Fatalf("scanRSAKeyEnvelope(%d bytes) failed open with %+v, want the zero value: a caller reads the other fields only after isRSA",
				len(der), scan)
		}
		if scan.factors > maxRSAPrimeFactors+1 {
			t.Fatalf("scanRSAKeyEnvelope(%d bytes) counted %d factors, want at most %d: past the ceiling the exact count buys nothing and the counting is attacker-controlled work",
				len(der), scan.factors, maxRSAPrimeFactors+1)
		}
		if scan.sized != (scan.maxBits > 0) {
			t.Fatalf("scanRSAKeyEnvelope(%d bytes) reported sized = %v with maxBits = %d, want a size exactly when one was measured",
				len(der), scan.sized, scan.maxBits)
		}
		if again := scanRSAKeyEnvelope(der, 1); again != scan {
			t.Fatalf("scanRSAKeyEnvelope is not deterministic: second call = %+v, first = %+v", again, scan)
		}
	})
}

// TestSEC1CurveOIDBytes_fails_open_on_shapes_that_are_not_a_sec1_key is the
// missing sibling of TestScanRSAKeyEnvelope_fails_open_on_shapes_that_are_not_an_envelope
// and TestPKCS8HoldsECKey_answers_true_only_for_an_ec_algorithm_identifier: every
// other DER shape-walker in this package has a fail-open test and this one does not.
//
// It is the reader behind oversizedSEC1CurveOIDError, the bound that keeps a
// file-supplied curve identifier out of encoding/asn1's one-int-per-encoded-byte
// decode, so a misread is operator-visible in BOTH directions: a shape wrongly read
// as a SEC1 key measures the wrong element and can refuse an EC key the app converts
// today (a conversion failure, which flips health), while a shape wrongly skipped
// leaves the identifier unbounded, which is the allocation the bound exists to close.
// The existing tests reach this walker only with well-formed SEC1 DER.
//
// The two context-specific rows are the class half of the contract: isASN1 checks the
// ASN.1 CLASS as well as the tag, precisely so a [2] or [4] element cannot be mistaken
// for a universal INTEGER or OCTET STRING, and nothing in the package asserted that.
func TestSEC1CurveOIDBytes_fails_open_on_shapes_that_are_not_a_sec1_key(t *testing.T) {
	t.Parallel()

	version := testASN1Marshal(t, 1)
	privateKey := testASN1Marshal(t, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: bytes.Repeat([]byte{0x02}, 32)})
	// prime256v1, whose identifier content is 8 bytes (2A 86 48 CE 3D 03 01 07).
	curve := testASN1Marshal(t, asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	params := func(body []byte) []byte {
		return testASN1Marshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: body})
	}
	contextTagged := func(tag int, body []byte) []byte {
		return testASN1Marshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: body})
	}

	cases := map[string]struct {
		der       []byte
		wantSize  int
		wantFound bool
	}{
		"a real sec1 key reports its curve identifier's length": {
			der: derTestSequence(t, version, privateKey, params(curve)), wantSize: 8, wantFound: true,
		},
		"not a sequence at all":                     {der: version},
		"a first element that is not the version":   {der: derTestSequence(t, privateKey, privateKey, params(curve))},
		"nothing after the version":                 {der: derTestSequence(t, version)},
		"a private key that is not an octet string": {der: derTestSequence(t, version, version, params(curve))},
		"parameters that are not the explicit [0] field": {
			der: derTestSequence(t, version, privateKey, curve),
		},
		"parameters holding something that is not an identifier": {
			der: derTestSequence(t, version, privateKey, params(version)),
		},
		"a context-specific [2] element where the version belongs": {
			der: derTestSequence(t, contextTagged(asn1.TagInteger, nil), privateKey, params(curve)),
		},
		"a context-specific [4] element where the private key belongs": {
			der: derTestSequence(t, version, contextTagged(asn1.TagOctetString, nil), params(curve)),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			size, found := sec1CurveOIDBytes(tc.der)
			if found != tc.wantFound {
				t.Errorf("sec1CurveOIDBytes(%s) found = %v, want %v", name, found, tc.wantFound)
			}
			if size != tc.wantSize {
				t.Errorf("sec1CurveOIDBytes(%s) size = %d, want %d", name, size, tc.wantSize)
			}
		})
	}
}

// TestPKCS8PrivateKeyDER_fails_open_on_shapes_that_are_not_a_pkcs8_container pins
// the one-level unwrap oversizedSEC1CurveOIDError needs to reach the curve identifier
// nested INSIDE a PKCS#8 EC container -- the fourth door
// TestParsePrivateKey_bounds_an_oversized_sec1_curve_oid_inside_pkcs8 exercises, but
// only with a well-formed container.
//
// Both directions are operator-visible. A shape wrongly unwrapped hands the inner
// walker bytes taken from the wrong element, so an ordinary EC key can earn a
// curve-identifier refusal it should never see; a well-formed container wrongly
// skipped leaves the nested identifier unbounded.
//
// The context-specific rows pin isASN1's class check, which nothing else in the
// package asserts: without it a [2], [16] or [4] element passes for the universal tag
// of the same number and the unwrap hands out the wrong bytes.
func TestPKCS8PrivateKeyDER_fails_open_on_shapes_that_are_not_a_pkcs8_container(t *testing.T) {
	t.Parallel()

	version := testASN1Marshal(t, 0)
	algorithm := derTestSequence(t, testASN1Marshal(t, ecPublicKeyOID))
	innerKey := []byte{0x30, 0x00}
	inner := testASN1Marshal(t, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: innerKey})
	contextTagged := func(tag int, body []byte) []byte {
		return testASN1Marshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: body})
	}

	cases := map[string]struct {
		der  []byte
		want []byte
	}{
		"a real pkcs8 container yields its inner key structure": {
			der: derTestSequence(t, version, algorithm, inner), want: innerKey,
		},
		"not a sequence at all":                     {der: version},
		"a first element that is not the version":   {der: derTestSequence(t, algorithm, algorithm, inner)},
		"nothing after the version":                 {der: derTestSequence(t, version)},
		"an algorithm field that is not a sequence": {der: derTestSequence(t, version, version, inner)},
		"nothing after the algorithm":               {der: derTestSequence(t, version, algorithm)},
		"a private key that is not an octet string": {der: derTestSequence(t, version, algorithm, version)},
		"a context-specific [2] element where the version belongs": {
			der: derTestSequence(t, contextTagged(asn1.TagInteger, nil), algorithm, inner),
		},
		"a context-specific [16] element where the algorithm belongs": {
			der: derTestSequence(t, version, contextTagged(asn1.TagSequence, nil), inner),
		},
		"a context-specific [4] element where the private key belongs": {
			der: derTestSequence(t, version, algorithm, contextTagged(asn1.TagOctetString, innerKey)),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := pkcs8PrivateKeyDER(tc.der); !bytes.Equal(got, tc.want) {
				t.Errorf("pkcs8PrivateKeyDER(%s) = %x, want %x", name, got, tc.want)
			}
		})
	}
}

// TestDerIntegerBits_reports_no_size_for_a_value_that_is_not_one pins the sign and
// padding rules the envelope pre-scan's SIZE half rests on, which its doc comment
// states and no test asserts: an empty content, a negative value and zero are not
// sizes, so they must leave the scan unsized while the shape and factor count it
// derives from tag-length headers still stand.
//
// The consequence of a wrong verdict is a wrong refusal. maxBits feeds
// oversizedRSAKeyError, so treating a negative INTEGER as a measurement makes a
// malformed key earn a bit-count ceiling message instead of the parser's own
// diagnosis, and an operator reads a size problem where there is none. Dropping the
// sign check leaves the whole package suite green today, including
// TestScanRSAKeyEnvelope_counts_factors_through_an_unmeasurable_modulus, which asserts
// the factor count on a negative modulus but never the unsized verdict.
func TestDerIntegerBits_reports_no_size_for_a_value_that_is_not_one(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		content  []byte
		wantBits int
		wantOK   bool
	}{
		"a one-byte positive value":           {content: []byte{0x7f}, wantBits: 7, wantOK: true},
		"a padded large positive value":       {content: []byte{0x00, 0xff, 0xff}, wantBits: 16, wantOK: true},
		"empty content":                       {content: nil},
		"zero":                                {content: []byte{0x00}},
		"a negative value":                    {content: []byte{0xff}},
		"a large negative value":              {content: []byte{0x80, 0x00, 0x01}},
		"a negative value that looks padded":  {content: []byte{0xff, 0x00, 0x00}},
		"only DER's positive-keeping padding": {content: []byte{0x00, 0x00}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			bits, ok := derIntegerBits(tc.content)
			if ok != tc.wantOK {
				t.Errorf("derIntegerBits(%x) ok = %v, want %v", tc.content, ok, tc.wantOK)
			}
			if bits != tc.wantBits {
				t.Errorf("derIntegerBits(%x) = %d bits, want %d", tc.content, bits, tc.wantBits)
			}
		})
	}
}

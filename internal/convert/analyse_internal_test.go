package convert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

// TestVerifiableKey_bounds_rsa_only pins the cost guard the graph runs every signature
// verification behind. Two halves matter and neither is observable from Analyse's result:
// the RSA ceiling (an unbounded modulus is a file-controlled modexp - 184ms at 131072 bits,
// 11.9s at 1 Mbit, on the scan's only goroutine), and the non-RSA default. Inverting the
// default would refuse verification for every ECDSA and Ed25519 bundle, silently demoting
// chain selection to the inclusive candidate path with no error and no log line.
func TestVerifiableKey_bounds_rsa_only(t *testing.T) {
	t.Parallel()

	// Lsh(1, n) has BitLen n+1, so the shift is one below the ceiling for the
	// at-limit key and exactly the ceiling for the one past it.
	atLimit := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), maxVerifiableKeyBits-1), E: 65537}
	oversized := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), maxVerifiableKeyBits), E: 65537}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}

	if got := atLimit.N.BitLen(); got != maxVerifiableKeyBits {
		t.Fatalf("setup: at-limit modulus is %d bits, want %d", got, maxVerifiableKeyBits)
	}
	if !verifiableKey(atLimit) {
		t.Errorf("verifiableKey(a %d-bit RSA key) = false, want true: the ceiling is inclusive", maxVerifiableKeyBits)
	}
	if verifiableKey(oversized) {
		t.Errorf("verifiableKey(a %d-bit RSA key) = true, want false: one modexp with it costs the scan goroutine hundreds of ms", maxVerifiableKeyBits+1)
	}
	if verifiableKey(&rsa.PublicKey{E: 65537}) {
		t.Error("verifiableKey(an RSA key with no modulus) = true, want false: BitLen on a nil modulus panics")
	}
	if !verifiableKey(&ecKey.PublicKey) {
		t.Error("verifiableKey(an ECDSA key) = false, want true: only RSA is size-unbounded, and refusing the rest would demote every chain to unverified edges")
	}
}

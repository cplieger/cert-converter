package convert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"
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
	// The exponent is the other half of the cost: it sets the NUMBER of squarings
	// crypto/rsa pays, so a file-supplied 2^31-1 triples one verification at the
	// modulus ceiling. Both boundaries are inclusive.
	atExponentLimit := &rsa.PublicKey{N: atLimit.N, E: maxVerifiablePublicExponent}
	pastExponentLimit := &rsa.PublicKey{N: atLimit.N, E: maxVerifiablePublicExponent + 1}
	if !verifiableKey(atExponentLimit) {
		t.Errorf("verifiableKey(an RSA key with exponent %d) = false, want true: the exponent ceiling is inclusive", maxVerifiablePublicExponent)
	}
	if verifiableKey(pastExponentLimit) {
		t.Errorf("verifiableKey(an RSA key with exponent %d) = true, want false: the exponent sets the squaring count and exceeds the cost this app permits an input to dictate", maxVerifiablePublicExponent+1)
	}
	if !verifiableKey(&ecKey.PublicKey) {
		t.Error("verifiableKey(an ECDSA key) = false, want true: only RSA is size-unbounded, and refusing the rest would demote every chain to unverified edges")
	}
}

// testSelfSignedPEM builds a self-signed certificate over an exact validity
// window. Validity is the only property that varies here, so the template
// carries nothing else: no basic constraints (the shape `openssl req -x509`
// produces without CA flags) and no extensions Analyse consults.
func testSelfSignedPEM(t *testing.T, key *ecdsa.PrivateKey, cn string, serial int64, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("setup: CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// testKeyPEM PEM-encodes key as PKCS#8, the form parsePrivateKeys reads first.
func testKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("setup: MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// testValidityKinds reports the identity-validity observations in a, dropping the
// chain-shaped ones so a fixture's chain arrangement cannot move the assertion.
func testValidityKinds(a *Analysis) []ObservationKind {
	var kinds []ObservationKind
	for _, o := range a.observations {
		if o.Kind == ObsIdentityNotYetValid || o.Kind == ObsIdentityExpired {
			kinds = append(kinds, o.Kind)
		}
	}
	return kinds
}

// TestAnalyseAt_validity_window_is_inclusive_at_both_edges pins the inclusivity of
// validAt at the exact instants the boundaries sit on. Analyse reads the clock, so
// through the exported entry point a fixture can only be placed loosely before or
// after a moving now, and the two edge instants -- where a certificate is valid ON
// its NotBefore and still valid ON its NotAfter -- are exactly the ones that are
// unreachable that way. An off-by-one here would report a freshly issued
// certificate as not-yet-valid on every scan in its first second.
func TestAnalyseAt_validity_window_is_inclusive_at_both_edges(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}
	// Whole seconds: DER encodes validity at second granularity, so a fixture with
	// sub-second components would not round-trip and the boundary would move.
	notBefore := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(24 * time.Hour)
	certPEM := testSelfSignedPEM(t, key, "boundary.example.com", 1, notBefore, notAfter)
	keyPEM := testKeyPEM(t, key)

	tests := map[string]struct {
		now  time.Time
		want []ObservationKind
	}{
		"one nanosecond before NotBefore": {notBefore.Add(-time.Nanosecond), []ObservationKind{ObsIdentityNotYetValid}},
		"exactly NotBefore":               {notBefore, nil},
		"exactly NotAfter":                {notAfter, nil},
		"one nanosecond after NotAfter":   {notAfter.Add(time.Nanosecond), []ObservationKind{ObsIdentityExpired}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, err := analyseAt(certPEM, keyPEM, tt.now)
			if err != nil {
				t.Fatalf("analyseAt(_, _, %s) = error %v, want a resolved analysis", tt.now.UTC().Format(time.RFC3339Nano), err)
			}
			if got := testValidityKinds(&a); !slices.Equal(got, tt.want) {
				t.Errorf("analyseAt at %s produced validity observations %v, want %v",
					tt.now.UTC().Format(time.RFC3339Nano), got, tt.want)
			}
		})
	}
}

// TestAnalyseAt_renewed_cert_tie_turns_on_validity_at_the_instant pins the tie
// transition betterIdentity's first key exists for: one key matching two
// certificates picks the one usable AT THE SCAN INSTANT, not the newest. Both
// arrangements are the same input, so only the supplied instant can decide, and
// crossing the transition is what proves NotBefore alone is not the ranking key --
// ranking on it would return the future-dated certificate at both instants and
// produce a bundle no consumer accepts yet.
func TestAnalyseAt_renewed_cert_tie_turns_on_validity_at_the_instant(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("setup: GenerateKey: %v", err)
	}
	// A renewal reusing its key: same subject, same key, later window. Key reuse is
	// not issuance, so neither certificate is the other's issuer and the pair
	// reaches the tie-break rather than the role check.
	current := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	renewalStart := current.Add(48 * time.Hour)
	certPEM := slices.Concat(
		testSelfSignedPEM(t, key, "renewed.example.com", 1, current.Add(-24*time.Hour), current.Add(24*time.Hour)),
		testSelfSignedPEM(t, key, "renewed.example.com", 2, renewalStart, renewalStart.Add(24*time.Hour)),
	)
	keyPEM := testKeyPEM(t, key)

	tests := map[string]struct {
		now           time.Time
		wantNotBefore time.Time
	}{
		"before the renewal starts, the current certificate wins": {current, current.Add(-24 * time.Hour)},
		"once the current one has expired, the renewal wins":      {renewalStart.Add(time.Hour), renewalStart},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, err := analyseAt(certPEM, keyPEM, tt.now)
			if err != nil {
				t.Fatalf("analyseAt(_, _, %s) = error %v, want a resolved analysis", tt.now.UTC().Format(time.RFC3339), err)
			}
			if got := a.leaf.NotBefore.UTC(); !got.Equal(tt.wantNotBefore.UTC()) {
				t.Errorf("analyseAt at %s selected the certificate with NotBefore %s, want %s",
					tt.now.UTC().Format(time.RFC3339), got.Format(time.RFC3339), tt.wantNotBefore.UTC().Format(time.RFC3339))
			}
		})
	}
}

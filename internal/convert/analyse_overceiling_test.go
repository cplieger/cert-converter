package convert_test

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// Over-ceiling issuer regressions: a certificate whose key is above this app's
// verification ceilings is never verified, so it must not be promoted on a claim
// alone, and must not displace an issuer that was proven.

// oversizedRSAPublicKey fabricates an RSA public key whose modulus is exactly bits
// bits long. The modulus is not a product of primes and nothing can sign with it,
// which is all an over-ceiling issuer needs to be: the key size is read out of the
// SubjectPublicKeyInfo, and the point of the ceiling is that no signature is ever
// checked against such a key. Generating a real 16k-bit RSA key costs minutes, so
// no test may do that.
func oversizedRSAPublicKey(bits uint) *rsa.PublicKey {
	// Lsh(1, bits-1) is the smallest integer of that bit length; +1 makes it odd,
	// as a real modulus is, and keeps it the positive value x509 requires.
	n := new(big.Int).Lsh(big.NewInt(1), bits-1)
	return &rsa.PublicKey{N: n.Add(n, big.NewInt(1)), E: 65537}
}

// TestAnalyse_refuses_an_over_ceiling_rsa_issuer pins the refusal that the key
// ceiling has to carry, and with it the invariant
// TestAnalyse_prefers_the_certificate_that_actually_signed_the_leaf states.
//
// The ceiling stops a file from dictating CPU cost: no signature is verified
// against an RSA key above maxVerifiableKeyBits, because one modexp with an
// oversized modulus runs for seconds to minutes on the scan's only goroutine and
// cannot be cancelled. Leaving such an edge merely UNVERIFIED, the way the SHA-1
// and name-encoding cases are, is what created a second defect: a same-subject
// certificate holding an ordinary key satisfies the identical name match, so both
// candidate edges are unverified, and betterParent then ranks them on keys the
// impostor wins — it is a self-signed root (which the ceiling denies the oversized
// certificate), it expires later, or it takes the DER tie-break. The PFX written
// from that carries a chain no consumer can verify, from input that resolved
// correctly before the ceiling existed.
//
// So the bundle is refused, naming the size observed. Both input orders are
// asserted: a refusal that depended on which candidate came first would be the
// same order-dependence every other test in this file exists to prevent.
func TestAnalyse_refuses_an_over_ceiling_rsa_issuer(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		contestedCN   = "Oversized Issuer CA"
		oversizedBits = convert.MaxVerifiableKeyBits + 17
	)

	ca := func(serial int64, notAfter time.Time) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: contestedCN},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}

	// The over-ceiling candidate issuer: the leaf's issuer name over a modulus past
	// the ceiling. Its own signature is from a throwaway key, because nothing here
	// reads that signature — the refusal is decided on the modulus in the
	// SubjectPublicKeyInfo — and minting it for real would mean generating a
	// 16k-bit RSA key, which costs minutes.
	throwawayKey := testcerts.NewECDSAKey(t)
	oversizedPEM, oversizedCert := testcerts.Mint(t, ca(210, notBefore.Add(240*time.Hour)),
		oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	if k, ok := oversizedCert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != oversizedBits {
		t.Fatalf("setup: minted certificate carries a %T, want a %d-bit RSA modulus; x509 no longer parses one that large",
			oversizedCert.PublicKey, oversizedBits)
	}

	// The same-subject decoy with an ordinary key. Self-signed, so it reaches a root
	// in zero hops and outranks the oversized certificate on every key left once
	// neither edge can be verified.
	decoyKey := testcerts.NewECDSAKey(t)
	decoyPEM, _ := testcerts.Mint(t, ca(211, notBefore.Add(72*time.Hour)), &decoyKey.PublicKey, nil, decoyKey)

	// The leaf's real signer shares that subject and is NOT in the bundle, so
	// neither candidate edge verifies — the state the ceiling produces for a leaf
	// whose genuine issuer is the oversized one.
	absentKey := testcerts.NewECDSAKey(t)
	_, absentCACert := testcerts.Mint(t, ca(212, notBefore.Add(240*time.Hour)), &absentKey.PublicKey, nil, absentKey)

	leafKey := testcerts.NewECDSAKey(t)
	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(213),
		Subject:      pkix.Name{CommonName: "oversized-issuer-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentCACert, absentKey)

	// The same oversized key under extensions that DISQUALIFY it from issuing.
	// candidateEdge admits a non-eligible parent only on a PROVEN signature, which
	// the ceiling forbids, so these variants never gain a children[] entry — a
	// refusal keyed on candidate survival skipped them while the decoy still won the
	// chain, which is precisely the substitution the refusal exists to prevent.
	oversizedNoCA := ca(220, notBefore.Add(240*time.Hour))
	oversizedNoCA.IsCA = false
	noCAPEM, _ := testcerts.Mint(t, oversizedNoCA, oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	oversizedNoBC := ca(221, notBefore.Add(240*time.Hour))
	oversizedNoBC.BasicConstraintsValid = false
	noBCPEM, _ := testcerts.Mint(t, oversizedNoBC, oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"oversized first", [][]byte{leafPEM, oversizedPEM, decoyPEM}},
		{"decoy first", [][]byte{leafPEM, decoyPEM, oversizedPEM}},
		{"CA false, oversized first", [][]byte{leafPEM, noCAPEM, decoyPEM}},
		{"CA false, decoy first", [][]byte{leafPEM, decoyPEM, noCAPEM}},
		{"no basic constraints, oversized first", [][]byte{leafPEM, noBCPEM, decoyPEM}},
		{"no basic constraints, decoy first", [][]byte{leafPEM, decoyPEM, noBCPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(t.Context(), concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err == nil {
				t.Fatalf("Analyse(leaf + a %d-bit RSA issuer + a same-subject ordinary-key certificate) = nil error and a chain of serial(s) %v, want a refusal: with the oversized edge left unverified the decoy (serial 211) outranks it, so the emitted chain does not verify",
					oversizedBits, chainSerials(got.Chain()))
			}
			// The size and the subject are what make the refusal actionable: which
			// certificate to remove, and the fact that its key is why.
			for _, want := range []string{fmt.Sprintf("%d-bit", oversizedBits), contestedCN} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Analyse error = %q, want it to name %q", err.Error(), want)
				}
			}
		})
	}
}

// TestAnalyse_refuses_an_over_ceiling_issuer_whose_alternative_is_cycle_excluded
// pins the resolution witness against the walk that actually spends it. A proven
// alternative parent only exempts the bundle if selection can still USE it:
// pathFrom carries an onPath set and bestParent skips every candidate already on it,
// so a proven candidate that leads back to the child through candidate edges is the
// one the walk has already consumed by the time the child's own hop is chosen — and
// the unverifiable oversized edge wins that hop unopposed.
//
// Shape: leaf -> A proven, A -> C proven, C -> A proven (a mutually-signed pair, both
// reachable from the leaf), plus an oversized same-subject decoy for A. C's only
// other proven candidate is A, which is on the path when C is reached, so C is NOT
// resolved without the oversized edge and the bundle must be refused. Before the
// cycle check the witness was accepted and Analyse emitted A, C, oversized.
func TestAnalyse_refuses_an_over_ceiling_issuer_whose_alternative_is_cycle_excluded(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		cycleACN      = "Cycle CA A"
		cycleCCN      = "Cycle CA C"
		oversizedBits = convert.MaxVerifiableKeyBits + 17
	)

	keyA := testcerts.NewECDSAKey(t)
	keyC := testcerts.NewECDSAKey(t)

	// A scaffold for C, used only as the issuer template A is minted against: it
	// carries C's subject and C's key, so A's signature verifies under the C that
	// ships in the bundle.
	_, scaffoldC := testcerts.Mint(t,
		unverifiableCA(240, cycleCCN, notBefore, notBefore.Add(480*time.Hour)),
		&keyC.PublicKey, nil, keyC)

	cyclePEMA, certA := testcerts.Mint(t,
		unverifiableCA(241, cycleACN, notBefore, notBefore.Add(240*time.Hour)),
		&keyA.PublicKey, scaffoldC, keyC)
	// C is signed by A, closing the cycle: A's issuer is C's subject and C's issuer
	// is A's subject, and both signatures verify.
	cyclePEMC, _ := testcerts.Mint(t,
		unverifiableCA(242, cycleCCN, notBefore, notBefore.Add(480*time.Hour)),
		&keyC.PublicKey, certA, keyA)

	// The oversized same-subject decoy for A: a linked candidate parent of the leaf
	// AND of C, and no signature may ever be checked against it.
	throwawayKey := testcerts.NewECDSAKey(t)
	oversizedPEM, oversizedCert := testcerts.Mint(t,
		unverifiableCA(243, cycleACN, notBefore, notBefore.Add(720*time.Hour)),
		oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	if k, ok := oversizedCert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != oversizedBits {
		t.Fatalf("setup: minted certificate carries a %T, want a %d-bit RSA modulus", oversizedCert.PublicKey, oversizedBits)
	}

	leafKey := testcerts.NewECDSAKey(t)
	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(244),
		Subject:      pkix.Name{CommonName: "cycle-issuer-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, certA, keyA)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"oversized last", [][]byte{leafPEM, cyclePEMA, cyclePEMC, oversizedPEM}},
		{"oversized first", [][]byte{leafPEM, oversizedPEM, cyclePEMA, cyclePEMC}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(t.Context(), concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err == nil {
				t.Fatalf("Analyse(a mutually-signed pair + a same-subject %d-bit decoy) = nil error and a chain of serial(s) %v, want a refusal: the only proven alternative for the second hop is excluded by cycle avoidance, so the oversized edge is guessed",
					oversizedBits, chainSerials(got.Chain()))
			}
			for _, want := range []string{fmt.Sprintf("%d-bit", oversizedBits), cycleACN} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Analyse error = %q, want it to name %q", err.Error(), want)
				}
			}
		})
	}
}

// TestAnalyse_converts_when_a_proven_parent_outranks_an_over_ceiling_namesake pins
// the OTHER edge of that refusal: it fires on a guess, not on the mere presence of
// an unverifiable key.
//
// Shape: a leaf, the ordinary CA that really signed it, and a same-subject
// over-ceiling decoy. The decoy carries the leaf's issuer name, so it is a linked
// candidate parent — but the real CA's signature over the leaf verifies, so nothing
// about this chain has to be guessed and the decoy can only be excluded. Refusing
// here (which keying the refusal on "is anything named as its issuer" did) failed a
// bundle the app resolves correctly, withholding the health marker over an input
// whose every emitted hop is proven.
func TestAnalyse_converts_when_a_proven_parent_outranks_an_over_ceiling_namesake(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		contestedCN   = "Resolvable Issuer CA"
		oversizedBits = convert.MaxVerifiableKeyBits + 1
	)

	// The CA that really signs the leaf, self-signed so it is a root in its own
	// right and needs no parent of its own.
	caKey := testcerts.NewECDSAKey(t)
	caPEM, caCert := testcerts.Mint(t,
		unverifiableCA(230, contestedCN, notBefore, notBefore.Add(240*time.Hour)),
		&caKey.PublicKey, nil, caKey)

	// The same-subject over-ceiling decoy. Its signature is from a throwaway key
	// because nothing reads it: the ceiling is decided on the modulus in the
	// SubjectPublicKeyInfo, and minting a real 16k-bit RSA key costs minutes.
	throwawayKey := testcerts.NewECDSAKey(t)
	oversizedPEM, oversizedCert := testcerts.Mint(t,
		unverifiableCA(231, contestedCN, notBefore, notBefore.Add(480*time.Hour)),
		oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	if k, ok := oversizedCert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != oversizedBits {
		t.Fatalf("setup: minted certificate carries a %T, want a %d-bit RSA modulus", oversizedCert.PublicKey, oversizedBits)
	}

	leafKey := testcerts.NewECDSAKey(t)
	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(232),
		Subject:      pkix.Name{CommonName: "resolvable-issuer-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"oversized first", [][]byte{leafPEM, oversizedPEM, caPEM}},
		{"proven CA first", [][]byte{leafPEM, caPEM, oversizedPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(t.Context(), concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse(leaf + its proven CA + a same-subject %d-bit decoy) = error %v, want the bundle converted: the proven edge leaves nothing to guess",
					oversizedBits, err)
			}
			if serials := strings.Join(chainSerials(got.Chain()), ","); serials != "230" {
				t.Fatalf("chain serials = %s, want 230: the CA whose signature verifies is the only emitted hop", serials)
			}
			for _, c := range got.Chain() {
				if c.SerialNumber.Cmp(big.NewInt(231)) == 0 {
					t.Errorf("chain holds the over-ceiling decoy (serial 231), want it excluded: no signature can be checked against it")
				}
			}
		})
	}
}

// TestAnalyse_converts_when_the_path_enters_a_signed_cycle_at_its_proven_hop pins the
// OTHER entry order into a mutually-signed pair, the one a graph-wide reachability
// question refused.
//
// Shape: leaf -> C proven, C -> P proven, P -> C proven, plus an over-ceiling
// same-subject namesake of P. pathFrom enters at C, so C's own hop spends the proven
// C -> P edge and P's only candidate parent (C) is already onPath, which ends the
// walk. Every emitted hop is proven and the namesake competes for nothing, so the
// bundle must convert.
//
// TestAnalyse_refuses_an_over_ceiling_issuer_whose_alternative_is_cycle_excluded is
// the mirror: the same cycle entered at P, where C's proven parent IS consumed before
// C is reached and the guessed hop is real. The two differ only in where the path
// enters, which is why the question is asked of the selected path's hops rather than
// of the graph — reachability holds in both orders and cannot tell them apart.
func TestAnalyse_converts_when_the_path_enters_a_signed_cycle_at_its_proven_hop(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		cycleCCN      = "Entered Cycle CA C"
		cyclePCN      = "Entered Cycle CA P"
		oversizedBits = convert.MaxVerifiableKeyBits + 17
	)

	keyC := testcerts.NewECDSAKey(t)
	keyP := testcerts.NewECDSAKey(t)

	// A scaffold for P, used only as the issuer template C is minted against: it
	// carries P's subject and P's key, so C's signature verifies under the P that
	// ships in the bundle.
	_, scaffoldP := testcerts.Mint(t,
		unverifiableCA(250, cyclePCN, notBefore, notBefore.Add(480*time.Hour)),
		&keyP.PublicKey, nil, keyP)

	cyclePEMC, certC := testcerts.Mint(t,
		unverifiableCA(251, cycleCCN, notBefore, notBefore.Add(240*time.Hour)),
		&keyC.PublicKey, scaffoldP, keyP)
	// P is signed by C, closing the cycle.
	cyclePEMP, _ := testcerts.Mint(t,
		unverifiableCA(252, cyclePCN, notBefore, notBefore.Add(480*time.Hour)),
		&keyP.PublicKey, certC, keyC)

	// The over-ceiling namesake of P: a linked candidate parent of C, and no
	// signature may ever be checked against it.
	throwawayKey := testcerts.NewECDSAKey(t)
	oversizedPEM, oversizedCert := testcerts.Mint(t,
		unverifiableCA(253, cyclePCN, notBefore, notBefore.Add(720*time.Hour)),
		oversizedRSAPublicKey(oversizedBits), nil, throwawayKey)
	if k, ok := oversizedCert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != oversizedBits {
		t.Fatalf("setup: minted certificate carries a %T, want a %d-bit RSA modulus", oversizedCert.PublicKey, oversizedBits)
	}

	// The leaf is signed by C, so the path ENTERS the cycle at C.
	leafKey := testcerts.NewECDSAKey(t)
	leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(254),
		Subject:      pkix.Name{CommonName: "entered-cycle-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, certC, keyC)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"oversized last", [][]byte{leafPEM, cyclePEMC, cyclePEMP, oversizedPEM}},
		{"oversized first", [][]byte{leafPEM, oversizedPEM, cyclePEMC, cyclePEMP}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(t.Context(), concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse(a mutually-signed pair entered at its proven hop + a same-subject %d-bit namesake) = error %v, want the bundle converted: every hop the path selects is proven, so nothing is guessed",
					oversizedBits, err)
			}
			if serials := chainSerials(got.Chain()); len(serials) < 2 || serials[0] != "251" || serials[1] != "252" {
				t.Errorf("chain serials = %v, want it to BEGIN 251,252: the path enters at C and spends the proven C -> P edge", serials)
			}
			// The namesake may still be APPENDED by the additive fallback (it is
			// issuer-eligible and unplaceable, which assembleChain reports as its own
			// observation). What must not happen is it winning a HOP: it is not part
			// of the proven prefix above.
		})
	}
}

// TestAnalyse_converts_beside_an_over_ceiling_certificate_that_issues_nothing keeps
// the refusal narrow, the way the self-signed carve-out keeps the additive fallback
// narrow. A certificate this bundle names as nobody's issuer is never a parent in a
// signature check, so its key size decides nothing: it can only be excluded (said
// out loud) or kept by the additive fallback (also said out loud). Refusing the
// whole pair over it would turn a convertible input into a conversion failure,
// which withholds the health marker and restart-loops the container.
func TestAnalyse_converts_beside_an_over_ceiling_certificate_that_issues_nothing(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	identityKey := testcerts.NewECDSAKey(t)
	identityPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(214),
		Subject:      pkix.Name{CommonName: "narrow-refusal.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &identityKey.PublicKey, nil, identityKey)

	// Oversized, and unrelated to the identity by name and by key identifier, so it
	// is a candidate issuer of nothing here.
	throwawayKey := testcerts.NewECDSAKey(t)
	strangerPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(215),
		Subject:               pkix.Name{CommonName: "Unrelated Oversized CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(240 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, oversizedRSAPublicKey(convert.MaxVerifiableKeyBits+17), nil, throwawayKey)

	got, err := convert.Analyse(t.Context(), concatPEM(identityPEM, strangerPEM), testcerts.KeyPEM(t, identityKey))
	if err != nil {
		t.Fatalf("Analyse(self-signed identity + an unrelated oversized certificate) = error %v, want nil: an oversized certificate that issues nothing here cannot influence the chain", err)
	}
	if len(got.Chain()) != 0 {
		t.Errorf("chain length = %d, want 0: a self-signed identity has no chain", len(got.Chain()))
	}
	if len(got.Extra()) != 1 {
		t.Fatalf("Extra holds %d certificate(s), want the unrelated oversized certificate excluded", len(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want the exclusion reported", got.Observations())
	}
}

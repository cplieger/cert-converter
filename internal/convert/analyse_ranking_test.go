package convert_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// Parent-ranking regressions: which candidate issuer Analyse promotes when the
// bundle offers several, and what evidence outranks what.

// TestAnalyse_prefers_the_certificate_that_actually_signed_the_leaf pins edge
// STRENGTH as the top ranking key in chain assembly.
//
// The inclusive candidate signal (name chaining or key-identifier match) exists so
// a relationship we cannot verify — a SHA-1 signature Go refuses, a permitted
// name-encoding difference — does not cause a real CA to be dropped. But it also
// admits an IMPOSTOR: a certificate sharing the issuer's subject while holding a
// different key satisfies name chaining without having signed anything. Ranking
// only on validity, root distance and NotAfter let such a certificate win, emitting
// a chain no consumer can verify. Reproduced by the GPT adversary.
func TestAnalyse_prefers_the_certificate_that_actually_signed_the_leaf(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	realKey := testcerts.NewECDSAKey(t)
	realTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Contested CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	_, realPEM, realCert := testcerts.Mint(t, realTmpl, &realKey.PublicKey, nil, realKey)

	// Same subject, different key, and a LATER NotAfter so every ranking key below
	// edge strength would prefer it.
	impostorKey := testcerts.NewECDSAKey(t)
	_, impostorPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "Contested CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &impostorKey.PublicKey, nil, impostorKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: "contested-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, realCert, realKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"impostor first", [][]byte{leafPEM, impostorPEM, realPEM}},
		{"real first", [][]byte{leafPEM, realPEM, impostorPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(t.Context(), concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) == 0 {
				t.Fatal("chain is empty; want the issuing CA")
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(100)) != 0 {
				t.Errorf("chain[0] serial = %s, want 100 (the certificate that actually signed the leaf, not the same-subject impostor with the later NotAfter)",
					got.Chain()[0].SerialNumber)
			}
		})
	}
}

// TestAnalyse_role_check_ignores_an_unverified_claim keeps the strict signal strict
// in the other direction: an identity must not be rejected because some unrelated
// certificate merely NAMES it as issuer. Only a verified signature makes a
// certificate an issuer.
func TestAnalyse_role_check_ignores_an_unverified_claim(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	// A perfectly ordinary self-signed identity.
	idKey := testcerts.NewECDSAKey(t)
	_, idPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(110),
		Subject:      pkix.Name{CommonName: "Claimed Issuer"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &idKey.PublicKey, nil, idKey)

	// A stranger that CLAIMS the identity as its issuer by name but was signed by
	// its own key. Name chaining alone would make the identity look like an issuer
	// and reject it.
	strangerKey := testcerts.NewECDSAKey(t)
	strangerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(111),
		Subject:      pkix.Name{CommonName: "Freeloader"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}
	strangerSelf := &x509.Certificate{
		SerialNumber: big.NewInt(111),
		Subject:      pkix.Name{CommonName: "Claimed Issuer"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}
	_, strangerPEM, _ := testcerts.Mint(t, strangerTmpl, &strangerKey.PublicKey, strangerSelf, strangerKey)

	got, err := convert.Analyse(t.Context(), concatPEM(idPEM, strangerPEM), testcerts.KeyPEM(t, idKey))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil: a certificate merely CLAIMING this one as issuer must not make it an issuer", err)
	}
	if got.Leaf().SerialNumber.Cmp(big.NewInt(110)) != 0 {
		t.Errorf("selected identity serial = %s, want 110", got.Leaf().SerialNumber)
	}
}

// TestAnalyse_prefers_the_issuer_whose_route_to_a_root_verifies is the verified
// -distance case: a candidate whose DIRECT signature over the child checks out can
// still have an unverifiable continuation above it.
//
// Two intermediates share a subject AND a public key, so both genuinely verify
// their signature over the leaf and the branch is real. Only one of them was signed
// by a root included in the bundle; the other names a same-subject root whose
// included certificate holds a different key. Ranking on the inclusive, name-based
// distance to a root cannot tell them apart, so the later-expiring decoy won and
// the emitted chain carried an intermediate that does not verify under the root
// shipped beside it — while the fully verified path sat in the same input.
func TestAnalyse_prefers_the_issuer_whose_route_to_a_root_verifies(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		sharedRootCN  = "Shared Root"
		sharedInterCN = "Shared Intermediate"
	)

	ca := func(serial int64, cn string, notAfter time.Time) *x509.Certificate {
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

	// The root that actually signed the good intermediate.
	realRootKey := testcerts.NewECDSAKey(t)
	_, realRootPEM, realRootCert := testcerts.Mint(t, ca(200, sharedRootCN, notBefore.Add(240*time.Hour)),
		&realRootKey.PublicKey, nil, realRootKey)

	// A same-named root holding a DIFFERENT key. Present in the bundle, so a
	// name-only walk reaches a "root" through it, but it signed nothing here.
	fakeRootKey := testcerts.NewECDSAKey(t)
	_, fakeRootPEM, _ := testcerts.Mint(t, ca(201, sharedRootCN, notBefore.Add(240*time.Hour)),
		&fakeRootKey.PublicKey, nil, fakeRootKey)

	// A third same-named root that is NOT in the bundle. It signs the decoy
	// intermediate, so no included certificate can verify that intermediate.
	absentRootKey := testcerts.NewECDSAKey(t)
	_, _, absentRootCert := testcerts.Mint(t, ca(202, sharedRootCN, notBefore.Add(240*time.Hour)),
		&absentRootKey.PublicKey, nil, absentRootKey)

	// One key across both intermediates: that is what makes both of them verify the
	// leaf, so edge strength at the leaf's own hop cannot separate them.
	interKey := testcerts.NewECDSAKey(t)
	_, goodInterPEM, goodInterCert := testcerts.Mint(t, ca(203, sharedInterCN, notBefore.Add(24*time.Hour)),
		&interKey.PublicKey, realRootCert, realRootKey)
	// The decoy expires LATER, so every ranking key below route strength prefers it.
	_, decoyInterPEM, _ := testcerts.Mint(t, ca(204, sharedInterCN, notBefore.Add(72*time.Hour)),
		&interKey.PublicKey, absentRootCert, absentRootKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(205),
		Subject:      pkix.Name{CommonName: "verified-route-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, goodInterCert, interKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"decoy first", [][]byte{leafPEM, decoyInterPEM, fakeRootPEM, goodInterPEM, realRootPEM}},
		{"verified first", [][]byte{leafPEM, goodInterPEM, realRootPEM, decoyInterPEM, fakeRootPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(t.Context(), concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) != 2 {
				t.Fatalf("chain length = %d, want 2 (the verified intermediate and the root that signed it)", len(got.Chain()))
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(203)) != 0 {
				t.Errorf("chain[0] serial = %s, want 203 (the intermediate whose route to an included root verifies, not the later-expiring decoy)",
					got.Chain()[0].SerialNumber)
			}
			// The contract the ranking exists to protect: every emitted hop verifies,
			// so a consumer can build a path out of the bundle it was handed.
			if err := got.Leaf().CheckSignatureFrom(got.Chain()[0]); err != nil {
				t.Errorf("leaf does not verify under chain[0] (serial %s): %v", got.Chain()[0].SerialNumber, err)
			}
			if err := got.Chain()[0].CheckSignatureFrom(got.Chain()[1]); err != nil {
				t.Errorf("chain[0] (serial %s) does not verify under chain[1] (serial %s): %v; the emitted chain cannot be validated by a consumer",
					got.Chain()[0].SerialNumber, got.Chain()[1].SerialNumber, err)
			}
		})
	}
}

// TestAnalyse_ranks_verified_issuers_by_validity_then_expiry pins the two
// chain-selection keys betterParent documents but nothing else exercises:
// currently-valid beats not-yet-valid, and among equally valid candidates the
// later NotAfter wins. Both rows use two same-subject, same-key self-signed
// issuers so signature strength and root distance tie and only the ranking under
// test can decide the emitted chain.
func TestAnalyse_ranks_verified_issuers_by_validity_then_expiry(t *testing.T) {
	t.Parallel()
	now := time.Now()

	tests := map[string]struct {
		firstNotBefore  time.Time
		firstNotAfter   time.Time
		secondNotBefore time.Time
		secondNotAfter  time.Time
		wantSerial      int64
	}{
		"a current issuer outranks a future-dated issuer with a later expiry": {
			firstNotBefore:  now.Add(48 * time.Hour),
			firstNotAfter:   now.Add(72 * time.Hour),
			secondNotBefore: now.Add(-time.Hour),
			secondNotAfter:  now.Add(24 * time.Hour),
			wantSerial:      221,
		},
		"the later expiry breaks a tie between two current issuers": {
			firstNotBefore:  now.Add(-time.Hour),
			firstNotAfter:   now.Add(48 * time.Hour),
			secondNotBefore: now.Add(-time.Hour),
			secondNotAfter:  now.Add(24 * time.Hour),
			wantSerial:      220,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			issuerKey := testcerts.NewECDSAKey(t)
			issuer := func(serial int64, notBefore, notAfter time.Time) *x509.Certificate {
				return &x509.Certificate{
					SerialNumber:          big.NewInt(serial),
					Subject:               pkix.Name{CommonName: "Ranked Issuer CA"},
					NotBefore:             notBefore,
					NotAfter:              notAfter,
					IsCA:                  true,
					BasicConstraintsValid: true,
					KeyUsage:              x509.KeyUsageCertSign,
				}
			}
			_, firstPEM, _ := testcerts.Mint(t, issuer(220, tt.firstNotBefore, tt.firstNotAfter),
				&issuerKey.PublicKey, nil, issuerKey)
			_, secondPEM, secondCert := testcerts.Mint(t, issuer(221, tt.secondNotBefore, tt.secondNotAfter),
				&issuerKey.PublicKey, nil, issuerKey)

			leafKey := testcerts.NewECDSAKey(t)
			_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
				SerialNumber: big.NewInt(222),
				Subject:      pkix.Name{CommonName: "ranked-issuer-leaf.example.com"},
				NotBefore:    now.Add(-time.Hour),
				NotAfter:     now.Add(24 * time.Hour),
			}, &leafKey.PublicKey, secondCert, issuerKey)

			got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, firstPEM, secondPEM), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) != 1 {
				t.Fatalf("chain length = %d, want 1", len(got.Chain()))
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(tt.wantSerial)) != 0 {
				t.Errorf("chain[0] serial = %s, want %d", got.Chain()[0].SerialNumber, tt.wantSerial)
			}
		})
	}
}

// TestAnalyse_prefers_an_unverified_issuer_with_a_route_to_a_root pins the FIRST
// of the two inclusive-distance ranking keys in betterParent, the pair that only
// decides anything once NEITHER candidate has a verified route to a root -- the
// documented SHA-1 and name-encoding fallback, where no signature can be checked
// at all. Every other ranking test gives at least one candidate a verified route,
// so a mutation that drops or inverts this key emits a chain whose top link has
// no route to any root in the bundle, with no error and no observation.
//
// Both candidate issuers here carry the leaf's issuer name without having signed
// it (the leaf's real signer is absent), so the leaf's own hop cannot separate
// them. Only one of them chains by name to a root present in the bundle. The
// stranded candidate expires LATER, so every ranking key BELOW this one prefers
// it: if the route-presence key stops deciding, the emitted chain changes.
func TestAnalyse_prefers_an_unverified_issuer_with_a_route_to_a_root(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		sharedRootCN = "Shared Root"
		contestedCN  = "Contested CA"
	)

	// A root present in the bundle, and a same-named root that is NOT, holding a
	// different key. The absent one signs the routed candidate, so that candidate's
	// route to the included root is a NAME match no signature can confirm.
	fakeRootKey := testcerts.NewECDSAKey(t)
	_, fakeRootPEM, _ := testcerts.Mint(t, unverifiableCA(300, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&fakeRootKey.PublicKey, nil, fakeRootKey)
	absentRootKey := testcerts.NewECDSAKey(t)
	_, _, absentRootCert := testcerts.Mint(t, unverifiableCA(301, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentRootKey.PublicKey, nil, absentRootKey)

	// The routed candidate: names the included root as its issuer, so it has an
	// inclusive route to a root.
	routedKey := testcerts.NewECDSAKey(t)
	_, routedPEM, _ := testcerts.Mint(t, unverifiableCA(302, contestedCN, notBefore, notBefore.Add(24*time.Hour)),
		&routedKey.PublicKey, absentRootCert, absentRootKey)

	// The stranded candidate: names an issuer nothing in the bundle carries, so it
	// has no route to a root at all -- and it expires later, which is what every
	// lower-ranked key would reward.
	absentOtherKey := testcerts.NewECDSAKey(t)
	_, _, absentOtherCert := testcerts.Mint(t, unverifiableCA(303, "Nobody CA", notBefore, notBefore.Add(240*time.Hour)),
		&absentOtherKey.PublicKey, nil, absentOtherKey)
	strandedKey := testcerts.NewECDSAKey(t)
	_, strandedPEM, _ := testcerts.Mint(t, unverifiableCA(304, contestedCN, notBefore, notBefore.Add(72*time.Hour)),
		&strandedKey.PublicKey, absentOtherCert, absentOtherKey)

	// The leaf's real signer shares the contested subject and is absent, so neither
	// candidate verifies the leaf's signature.
	absentSignerKey := testcerts.NewECDSAKey(t)
	_, _, absentSignerCert := testcerts.Mint(t, unverifiableCA(305, contestedCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentSignerKey.PublicKey, nil, absentSignerKey)
	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(306),
		Subject:      pkix.Name{CommonName: "inclusive-route-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentSignerCert, absentSignerKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"stranded first", [][]byte{leafPEM, strandedPEM, routedPEM, fakeRootPEM}},
		{"routed first", [][]byte{leafPEM, routedPEM, strandedPEM, fakeRootPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(t.Context(), concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) == 0 {
				t.Fatal("chain is empty; want the candidate issuer that chains to a root")
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(302)) != 0 {
				t.Errorf("chain[0] serial = %s, want 302 (the unverified candidate with a route to a root in the bundle, not the later-expiring candidate with none)",
					got.Chain()[0].SerialNumber)
			}
		})
	}
}

// TestAnalyse_prefers_the_shorter_inclusive_route pins the SECOND inclusive
// ranking key: with neither candidate verifiable and BOTH chaining by name to a
// root, the shorter route wins. Same reachability as the test above -- nothing
// else in the suite gets two unverified candidates that both reach a root, so a
// mutation that inverts this comparison silently emits the longer, later-expiring
// route instead.
func TestAnalyse_prefers_the_shorter_inclusive_route(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const (
		sharedRootCN = "Shared Root"
		midCN        = "Mid CA"
		contestedCN  = "Contested CA"
	)

	fakeRootKey := testcerts.NewECDSAKey(t)
	_, fakeRootPEM, _ := testcerts.Mint(t, unverifiableCA(310, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&fakeRootKey.PublicKey, nil, fakeRootKey)
	absentRootKey := testcerts.NewECDSAKey(t)
	_, _, absentRootCert := testcerts.Mint(t, unverifiableCA(311, sharedRootCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentRootKey.PublicKey, nil, absentRootKey)

	// One name-hop from the included root.
	nearKey := testcerts.NewECDSAKey(t)
	_, nearPEM, _ := testcerts.Mint(t, unverifiableCA(312, contestedCN, notBefore, notBefore.Add(24*time.Hour)),
		&nearKey.PublicKey, absentRootCert, absentRootKey)

	// An intermediate one name-hop from the root, and the far candidate below it:
	// two hops, and a LATER expiry so the NotAfter key would reward it.
	midKey := testcerts.NewECDSAKey(t)
	_, midPEM, _ := testcerts.Mint(t, unverifiableCA(313, midCN, notBefore, notBefore.Add(240*time.Hour)),
		&midKey.PublicKey, absentRootCert, absentRootKey)
	absentMidKey := testcerts.NewECDSAKey(t)
	_, _, absentMidCert := testcerts.Mint(t, unverifiableCA(314, midCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentMidKey.PublicKey, nil, absentMidKey)
	farKey := testcerts.NewECDSAKey(t)
	_, farPEM, _ := testcerts.Mint(t, unverifiableCA(315, contestedCN, notBefore, notBefore.Add(72*time.Hour)),
		&farKey.PublicKey, absentMidCert, absentMidKey)

	absentSignerKey := testcerts.NewECDSAKey(t)
	_, _, absentSignerCert := testcerts.Mint(t, unverifiableCA(316, contestedCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentSignerKey.PublicKey, nil, absentSignerKey)
	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(317),
		Subject:      pkix.Name{CommonName: "shorter-route-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentSignerCert, absentSignerKey)

	for _, order := range []struct {
		name  string
		certs [][]byte
	}{
		{"far first", [][]byte{leafPEM, farPEM, midPEM, nearPEM, fakeRootPEM}},
		{"near first", [][]byte{leafPEM, nearPEM, fakeRootPEM, farPEM, midPEM}},
	} {
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(t.Context(), concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if len(got.Chain()) == 0 {
				t.Fatal("chain is empty; want the nearer candidate issuer")
			}
			if got.Chain()[0].SerialNumber.Cmp(big.NewInt(312)) != 0 {
				t.Errorf("chain[0] serial = %s, want 312 (the candidate one name-hop from a root in the bundle, not the later-expiring candidate two hops away)",
					got.Chain()[0].SerialNumber)
			}
		})
	}
}

// TestAnalyse_keeps_an_unproven_name_match_from_being_promoted holds the other side
// of the widened name signal: teaching the graph semantically-equal names must not
// let a name alone stand in for a signature.
//
// Both halves were reproduced against a model that compared decoded names without
// re-applying the exclusions the raw-name model already had.
func TestAnalyse_keeps_an_unproven_name_match_from_being_promoted(t *testing.T) {
	t.Parallel()

	// Proof outranks name fidelity: the certificate that actually signed the leaf is
	// linked to it only SEMANTICALLY, while an impostor matching the leaf's issuer
	// name byte for byte holds a different key and expires later, so every ranking
	// key below edge strength -- and any rule preferring an exact name match to a
	// decoded one -- would emit the impostor as the leaf's CA.
	t.Run("an exact name match does not outrank a proven signature", func(t *testing.T) {
		t.Parallel()
		notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

		realKey := testcerts.NewECDSAKey(t)
		_, realPEM, realCert := testcerts.Mint(t, unverifiableCA(810, "Promoted Encoding CA", notBefore, notBefore.Add(48*time.Hour)),
			&realKey.PublicKey, nil, realKey)
		leafKey := testcerts.NewECDSAKey(t)
		_, leafPEM, leafCert := testcerts.Mint(t, &x509.Certificate{
			SerialNumber: big.NewInt(811),
			Subject:      pkix.Name{CommonName: "promoted-encoding-leaf.example.com"},
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(24 * time.Hour),
		}, &leafKey.PublicKey, utf8SubjectView(realCert, "Promoted Encoding CA"), realKey)

		// The impostor's subject is the leaf's issuer name EXACTLY, copied from the
		// leaf so the DER cannot drift, and it signed nothing here.
		impostorKey := testcerts.NewECDSAKey(t)
		impostor := unverifiableCA(812, "", notBefore, notBefore.Add(240*time.Hour))
		impostor.RawSubject = leafCert.RawIssuer
		_, impostorPEM, impostorCert := testcerts.Mint(t, impostor, &impostorKey.PublicKey, nil, impostorKey)

		if !bytes.Equal(impostorCert.RawSubject, leafCert.RawIssuer) {
			t.Fatal("setup: the impostor's subject is not the leaf's issuer name byte for byte, so it is not the exact-match candidate under test")
		}
		if bytes.Equal(realCert.RawSubject, leafCert.RawIssuer) {
			t.Fatal("setup: the real signer's subject matches the leaf's issuer name byte for byte, so the semantic signal is not exercised")
		}

		for _, order := range []struct {
			name  string
			certs [][]byte
		}{
			{"impostor first", [][]byte{leafPEM, impostorPEM, realPEM}},
			{"real signer first", [][]byte{leafPEM, realPEM, impostorPEM}},
		} {
			t.Run(order.name, func(t *testing.T) {
				t.Parallel()
				got, err := convert.Analyse(t.Context(), concatPEM(order.certs...), testcerts.KeyPEM(t, leafKey))
				if err != nil {
					t.Fatalf("Analyse = error %v, want nil", err)
				}
				if len(got.Chain()) == 0 {
					t.Fatal("chain is empty; want the CA that signed the leaf")
				}
				if got.Chain()[0].SerialNumber.Cmp(big.NewInt(810)) != 0 {
					t.Errorf("chain[0] serial = %s, want 810 (the proven signer named through an encoding difference, not the byte-exact same-name impostor)",
						got.Chain()[0].SerialNumber)
				}
			})
		}
	})

	// The key-reuse exclusion has to survive the decoded comparison too. Two
	// self-signed certificates holding ONE key, the second re-encoding the same
	// subject, are a regenerated certificate beside its predecessor: each verifies
	// against the other, so without the exclusion both read as issuers, both matches
	// are dropped, and the role check refuses a bundle that converts fine today.
	t.Run("key reuse across an encoding difference is not issuance", func(t *testing.T) {
		t.Parallel()
		notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
		sharedKey := testcerts.NewECDSAKey(t)

		_, firstPEM, firstCert := testcerts.Mint(t, unverifiableCA(820, "Regenerated Encoding CA", notBefore, notBefore.Add(48*time.Hour)),
			&sharedKey.PublicKey, nil, sharedKey)
		// Same name, encoded the other permitted way, same key: a regeneration.
		reissued := unverifiableCA(821, "", notBefore.Add(time.Minute), notBefore.Add(96*time.Hour))
		reissuedView := utf8SubjectView(firstCert, "Regenerated Encoding CA")
		reissued.RawSubject = nil
		reissued.Subject = reissuedView.Subject
		_, secondPEM, secondCert := testcerts.Mint(t, reissued, &sharedKey.PublicKey, reissuedView, sharedKey)

		if bytes.Equal(firstCert.RawSubject, secondCert.RawSubject) {
			t.Fatal("setup: both certificates encode the subject identically, so the raw-name exclusion alone would cover this bundle")
		}
		if !bytes.Equal(secondCert.RawSubject, secondCert.RawIssuer) {
			t.Fatal("setup: the regenerated certificate is not self-signed under its own re-encoded name")
		}

		got, err := convert.Analyse(t.Context(), concatPEM(firstPEM, secondPEM), testcerts.KeyPEM(t, sharedKey))
		if err != nil {
			t.Fatalf("Analyse(a regenerated self-signed certificate re-encoding its own subject) = error %v, want nil: reusing a key is not issuing a certificate", err)
		}
		if got.Leaf().SerialNumber.Cmp(big.NewInt(821)) != 0 {
			t.Errorf("selected identity serial = %s, want 821 (the later-issued certificate of the pair)", got.Leaf().SerialNumber)
		}
		if len(got.Chain()) != 0 {
			t.Errorf("chain = %v, want empty: a self-signed identity has no chain, and its predecessor did not issue it",
				chainSerials(got.Chain()))
		}
	})
}

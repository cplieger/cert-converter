package convert_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// Additive-fallback and terminus-observation regressions: what Analyse emits, keeps
// and reports when the chain cannot be completed from the bundle.

// TestAnalyse_keeps_certificates_when_the_issuer_cannot_be_established pins the
// additive-only fallback.
//
// Structural chain building can fail to prove a relationship that genuinely
// exists: Go refuses to verify a SHA-1 signature at all, and RFC 5280 permits
// issuer and subject names to be encoded differently in ways a byte comparison
// rejects. The first implementation treated "could not prove related" the same as
// "proved unrelated" and dropped the certificate, silently removing a CA that the
// previous positional code shipped — which breaks path building at the consumer
// after nothing more than an image bump.
//
// So when no issuer for a non-self-signed identity can be established at all, the
// remaining certificates are KEPT. That makes the structural rewrite additive: it
// can improve a chain, never quietly shrink one.
func TestAnalyse_keeps_certificates_when_the_issuer_cannot_be_established(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	// An issuer that is NOT placed in the bundle, so the leaf's issuer name
	// matches nothing present: the same observable state a signature we cannot
	// verify produces.
	absentCAKey := testcerts.NewECDSAKey(t)
	_, _, absentCACert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(80),
		Subject:               pkix.Name{CommonName: "Absent Issuer CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &absentCAKey.PublicKey, nil, absentCAKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(81),
		Subject:      pkix.Name{CommonName: "orphaned-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentCACert, absentCAKey)

	// Some other certificate sits in the bundle. Under the old positional rule it
	// would have been embedded; it must still be embedded rather than dropped,
	// because we cannot show it is off the chain.
	otherKey := testcerts.NewECDSAKey(t)
	_, otherPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(82),
		Subject:               pkix.Name{CommonName: "Possibly Related CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &otherKey.PublicKey, nil, otherKey)

	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, otherPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(leaf whose issuer is absent) = error %v, want nil", err)
	}
	if got.Leaf().Subject.CommonName != "orphaned-leaf.example.com" {
		t.Errorf("selected identity = %q, want the leaf", got.Leaf().Subject.CommonName)
	}
	if len(got.Chain()) != 1 {
		t.Fatalf("chain length = %d, want 1: an unprovable certificate must be kept, not dropped", len(got.Chain()))
	}
	if got.Chain()[0].Subject.CommonName != "Possibly Related CA" {
		t.Errorf("chain[0] = %q, want the kept certificate", got.Chain()[0].Subject.CommonName)
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra holds %d certificate(s), want 0: nothing was shown to be off the chain", len(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want one of kind %q so the operator knows the chain was not verified",
			got.Observations(), convert.ObsChainUnverified)
	}
	// The split between the two terminus kinds is what leftovers decide: here a
	// certificate this app could not place was carried into the bundle anyway, which is
	// the warning's subject. The informational anchor-absent kind is for the bundle
	// where nothing was left over at all.
	if hasObservation(got.Observations(), convert.ObsChainTrustAnchorAbsent) {
		t.Errorf("observations = %v, want no %q: a certificate was kept whose ancestry is unestablished, which is more than an absent anchor",
			got.Observations(), convert.ObsChainTrustAnchorAbsent)
	}
	if got := convert.ObsChainUnverified.Class(); got != convert.ObservationClassWarning {
		t.Errorf("ObsChainUnverified.Class() = %q, want %q: this signal must not be quietened by the class split",
			got, convert.ObservationClassWarning)
	}
}

// TestAnalyse_still_excludes_an_unrelated_cert_from_a_self_signed_identity keeps
// the fallback narrow. A self-signed identity has no issuer BY CONSTRUCTION, so
// an empty chain is proof rather than a failure to prove, and the fallback must
// not fire — otherwise the unrelated-certificate exclusion (the whole point of
// replacing `caCerts = chain[1:]`) would be undone for every self-signed input.
func TestAnalyse_still_excludes_an_unrelated_cert_from_a_self_signed_identity(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	key := testcerts.NewECDSAKey(t)
	_, identityPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(90),
		Subject:      pkix.Name{CommonName: "self.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &key.PublicKey, nil, key)

	strangerKey := testcerts.NewECDSAKey(t)
	_, strangerPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(91),
		Subject:      pkix.Name{CommonName: "stranger.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &strangerKey.PublicKey, nil, strangerKey)

	got, err := convert.Analyse(t.Context(), concatPEM(identityPEM, strangerPEM), testcerts.KeyPEM(t, key))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if len(got.Chain()) != 0 {
		t.Errorf("chain length = %d, want 0: a self-signed identity has no chain", len(got.Chain()))
	}
	if len(got.Extra()) != 1 {
		t.Fatalf("Extra holds %d certificate(s), want 1", len(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want the exclusion reported", got.Observations())
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want NO chain-unverified fallback for a self-signed identity", got.Observations())
	}
}

// TestAnalyse_excludes_a_certificate_that_cannot_issue_certificates keeps the
// additive fallback from emitting chain material nothing supports.
//
// The rule this pins is narrow, and the narrowing is the point. RFC 5280
// eligibility on its own never removes a certificate — a CA that demonstrably
// SIGNED the leaf is emitted whatever its extensions claim, with
// ObsChainCertCannotIssue naming it
// (TestAnalyse_keeps_a_signing_CA_that_is_not_issuer_eligible pins that half).
// What is excluded here is a certificate for which BOTH kinds of evidence are
// absent: it signed nothing in this bundle, and its own extensions say it could not
// have. With the leaf's real issuer absent and a same-named certificate asserting
// CA:false beside it, the reproduced defect emitted that stranger as the sole CA
// bag, so every consumer's path validation rejected the generated PFX while
// conversion reported success. A certificate that is merely unverifiable must still
// be kept (TestAnalyse_keeps_certificates_when_the_issuer_cannot_be_established pins
// that half).
func TestAnalyse_excludes_a_certificate_that_cannot_issue_certificates(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	for _, tc := range []struct {
		name string
		// disqualify shapes the decoy's issuing-related fields.
		disqualify func(*x509.Certificate)
	}{
		{
			name: "basic constraints say CA:false",
			disqualify: func(c *x509.Certificate) {
				c.BasicConstraintsValid = true
				c.IsCA = false
				c.KeyUsage = x509.KeyUsageCertSign
			},
		},
		{
			name: "v3 certificate with no basic constraints",
			disqualify: func(c *x509.Certificate) {
				c.BasicConstraintsValid = false
				c.IsCA = false
				c.KeyUsage = x509.KeyUsageCertSign
			},
		},
		{
			name: "stated key usage omits certificate signing",
			disqualify: func(c *x509.Certificate) {
				c.BasicConstraintsValid = true
				c.IsCA = true
				c.KeyUsage = x509.KeyUsageDigitalSignature
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The leaf's real issuer is NOT in the bundle, so nothing present can
			// be proven to be its issuer.
			absentCAKey := testcerts.NewECDSAKey(t)
			_, _, absentCACert := testcerts.Mint(t, &x509.Certificate{
				SerialNumber:          big.NewInt(400),
				Subject:               pkix.Name{CommonName: "Absent Encoding CA"},
				NotBefore:             notBefore,
				NotAfter:              notBefore.Add(48 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}, &absentCAKey.PublicKey, nil, absentCAKey)

			leafKey := testcerts.NewECDSAKey(t)
			_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
				SerialNumber: big.NewInt(401),
				Subject:      pkix.Name{CommonName: "disqualified-issuer-leaf.example.com"},
				NotBefore:    notBefore,
				NotAfter:     notBefore.Add(24 * time.Hour),
			}, &leafKey.PublicKey, absentCACert, absentCAKey)

			// A decoy carrying the absent issuer's NAME, so name chaining alone
			// admits it, but disqualified from issuing certificates by its own
			// extensions.
			decoyKey := testcerts.NewECDSAKey(t)
			decoy := &x509.Certificate{
				SerialNumber: big.NewInt(402),
				Subject:      pkix.Name{CommonName: "Absent Encoding CA"},
				NotBefore:    notBefore,
				NotAfter:     notBefore.Add(48 * time.Hour),
			}
			tc.disqualify(decoy)
			_, decoyPEM, _ := testcerts.Mint(t, decoy, &decoyKey.PublicKey, nil, decoyKey)

			got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, decoyPEM), testcerts.KeyPEM(t, leafKey))
			if err != nil {
				t.Fatalf("Analyse(leaf beside a %s) = error %v, want nil", tc.name, err)
			}
			if len(got.Chain()) != 0 {
				t.Errorf("chain = %v, want empty: a certificate that cannot issue certificates is no chain material",
					chainSerials(got.Chain()))
			}
			if len(got.Extra()) != 1 {
				t.Fatalf("Extra holds %d certificate(s), want 1 (the disqualified decoy)", len(got.Extra()))
			}
			if !hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
				t.Errorf("observations = %v, want the exclusion reported", got.Observations())
			}
			if !hasObservation(got.Observations(), convert.ObsChainUnverified) {
				t.Errorf("observations = %v, want the unverified chain reported too", got.Observations())
			}
		})
	}
}

// TestAnalyse_reports_an_unproven_edge_linked_only_by_key_identifier pins the
// key-identifier arm of the unproven-edge diagnostic. The emitted chain here is
// linked to its issuer by AKI/SKI alone -- the names differ -- so a regression that
// collapsed the two arms would tell the operator the issuer name matches when it
// does not, pointing them at a field they can check and find wrong. Every other
// unproven-edge test covers the name-linked arm, so that collapse passes the suite.
func TestAnalyse_reports_an_unproven_edge_linked_only_by_key_identifier(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	keyID := []byte{0x01, 0x23, 0x45, 0x67}

	absentKey := testcerts.NewECDSAKey(t)
	absentTemplate := unverifiableCA(870, "Absent AKI Signer", notBefore, notBefore.Add(48*time.Hour))
	absentTemplate.SubjectKeyId = keyID
	_, _, absentCert := testcerts.Mint(t, absentTemplate, &absentKey.PublicKey, nil, absentKey)

	decoyKey := testcerts.NewECDSAKey(t)
	decoyTemplate := unverifiableCA(871, "Different Subject CA", notBefore, notBefore.Add(48*time.Hour))
	decoyTemplate.SubjectKeyId = keyID
	_, decoyPEM, decoyCert := testcerts.Mint(t, decoyTemplate, &decoyKey.PublicKey, nil, decoyKey)

	leafKey := testcerts.NewECDSAKey(t)
	leafTemplate := unverifiableCA(872, "aki-only-leaf.example.com", notBefore, notBefore.Add(24*time.Hour))
	leafTemplate.IsCA = false
	leafTemplate.BasicConstraintsValid = false
	leafTemplate.KeyUsage = 0
	_, leafPEM, leafCert := testcerts.Mint(t, leafTemplate, &leafKey.PublicKey, absentCert, absentKey)

	if bytes.Equal(leafCert.RawIssuer, decoyCert.RawSubject) {
		t.Fatal("setup: issuer and subject names match, so the key-identifier-only branch is not reached")
	}
	if !bytes.Equal(leafCert.AuthorityKeyId, decoyCert.SubjectKeyId) {
		t.Fatal("setup: authority and subject key identifiers differ, so no candidate edge exists")
	}

	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, decoyPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if serials := strings.Join(chainSerials(got.Chain()), ","); serials != "871" {
		t.Fatalf("chain serials = %s, want 871: the AKI/SKI-linked decoy is the emitted unproven edge", serials)
	}
	detail, ok := observationDetail(got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	if !ok {
		t.Fatalf("observations = %v, want %q", got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	}
	if !strings.Contains(detail, "carries the subject key identifier named as the authority key identifier of") {
		t.Errorf("observation detail = %q, want the AKI/SKI evidence named", detail)
	}
	if strings.Contains(detail, "matches the issuer name of") {
		t.Errorf("observation detail = %q, want no issuer-name claim for an edge whose names differ", detail)
	}
}

// observationDetail returns the detail of the first observation of kind k. Tests
// that assert an observation NAMES a certificate need the text, not just the kind:
// a diagnostic that fires without saying which certificate is at fault costs the
// operator the same investigation as no diagnostic at all.
func observationDetail(obs []convert.Observation, k convert.ObservationKind) (string, bool) {
	for _, o := range obs {
		if o.Kind == k {
			return o.Detail, true
		}
	}
	return "", false
}

// TestAnalyse_keeps_a_signing_CA_that_is_not_issuer_eligible pins the split
// between what a certificate DID and what its extensions say it SHOULD have done.
//
// The shape is an internal CA minted by a bare `openssl req -x509`: self-signed,
// no basicConstraints extension at all, and it genuinely signed the leaf. RFC 5280
// 4.2.1.9 says such a key must not be used to verify certificate signatures, which
// is why crypto/x509's CheckSignatureFrom refuses it as a parent, so no VERIFIED
// edge to it can ever exist. Applying that eligibility rule to candidacy as well
// removed the certificate from the graph outright: the emitted PFX lost its only CA
// bag, and the operator was told the chain was unverified and the CA excluded --
// worse than the silence that preceded it, because the material was gone too.
//
// This app converts formats and holds no trust store; PKCS#12 CA bags are a bag of
// certificates, not a validated path. So a signature is ground truth and eligibility
// is a diagnostic: the CA is emitted, and ObsChainCertCannotIssue tells the operator
// their CA is non-compliant and that a strict consumer will reject the chain. The
// fallback observations must be absent, because there is nothing unestablished here
// -- the chain was proven by signature.
func TestAnalyse_keeps_a_signing_CA_that_is_not_issuer_eligible(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	// A self-signed CA with NO basic constraints: BasicConstraintsValid false emits
	// no extension, and a zero KeyUsage emits none either, so its only
	// disqualification is the missing basicConstraints RFC 5280 requires of a v3
	// issuer. This is what `openssl req -x509` produces without CA flags.
	caKey := testcerts.NewECDSAKey(t)
	_, caPEM, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(500),
		Subject:      pkix.Name{CommonName: "No-BC Internal CA"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(72 * time.Hour),
	}, &caKey.PublicKey, nil, caKey)
	if caCert.BasicConstraintsValid {
		t.Fatal("setup: the CA fixture carries basic constraints; the shape under test is a CA without them")
	}

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(501),
		Subject:      pkix.Name{CommonName: "no-bc-ca-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, caPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(leaf signed by a CA with no basic constraints) = error %v, want nil", err)
	}

	if len(got.Chain()) != 1 {
		t.Fatalf("chain = %v, want the signing CA as the one CA bag: a certificate that demonstrably signed the leaf is chain material whatever its extensions claim",
			chainSerials(got.Chain()))
	}
	if !bytes.Equal(got.Chain()[0].Raw, caCert.Raw) {
		t.Errorf("chain[0] = %q, want %q", got.Chain()[0].Subject.CommonName, caCert.Subject.CommonName)
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra holds %d certificate(s), want 0: the CA belongs in the chain, not beside it", len(got.Extra()))
	}

	detail, ok := observationDetail(got.Observations(), convert.ObsChainCertCannotIssue)
	if !ok {
		t.Fatalf("observations = %v, want %q: carrying a non-compliant CA silently is the defect that preceded the exclusion",
			got.Observations(), convert.ObsChainCertCannotIssue)
	}
	if !strings.Contains(detail, "No-BC Internal CA") {
		t.Errorf("%s detail = %q, want it to name the non-compliant CA", convert.ObsChainCertCannotIssue, detail)
	}
	if !strings.Contains(detail, "basicConstraints") {
		t.Errorf("%s detail = %q, want it to name the missing extension the operator has to fix", convert.ObsChainCertCannotIssue, detail)
	}

	// The chain IS established -- by signature -- so neither fallback observation
	// applies, and nothing may report the emitted CA as excluded.
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: the CA's signature over the leaf establishes the chain",
			got.Observations(), convert.ObsChainUnverified)
	}
	if excluded, ok := observationDetail(got.Observations(), convert.ObsExtraCertsExcluded); ok {
		t.Errorf("observations report %q = %q, want no exclusion: the only other certificate is in the emitted chain",
			convert.ObsExtraCertsExcluded, excluded)
	}
}

// TestAnalyse_emits_a_compliant_chain_unchanged_and_silently is the common-path
// guard for the eligibility/signature split: an ordinary leaf + intermediate + root
// bundle must emit exactly the same three bags in the same order it always did, and
// say nothing at all.
//
// Both halves are load-bearing. The bag sequence is a PKCS#12 contract (decoders
// read it positionally), so it is asserted on the DER rather than on subject names.
// The silence is what keeps the new non-compliance diagnostic from becoming noise:
// a warning that fires on every well-formed renewal in the deployment would be
// tuned out long before the one bundle that needs it appears.
func TestAnalyse_emits_a_compliant_chain_unchanged_and_silently(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	rootKey := testcerts.NewECDSAKey(t)
	_, rootPEM, rootCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(510),
		Subject:               pkix.Name{CommonName: "Compliant Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &rootKey.PublicKey, nil, rootKey)

	interKey := testcerts.NewECDSAKey(t)
	_, interPEM, interCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(511),
		Subject:               pkix.Name{CommonName: "Compliant Intermediate CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &interKey.PublicKey, rootCert, rootKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(512),
		Subject:      pkix.Name{CommonName: "compliant-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, interCert, interKey)

	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, interPEM, rootPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(compliant leaf+intermediate+root) = error %v, want nil", err)
	}

	want := []*x509.Certificate{interCert, rootCert}
	if len(got.Chain()) != len(want) {
		t.Fatalf("chain = %v, want %v (intermediate then root)", chainSerials(got.Chain()), chainSerials(want))
	}
	for i := range want {
		if !bytes.Equal(got.Chain()[i].Raw, want[i].Raw) {
			t.Errorf("chain[%d] = serial %s, want serial %s", i, got.Chain()[i].SerialNumber, want[i].SerialNumber)
		}
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra holds %d certificate(s), want 0", len(got.Extra()))
	}
	if len(got.Observations()) != 0 {
		t.Errorf("observations = %v, want none: every certificate here is well-formed, in order and current", got.Observations())
	}
}

// TestAnalyse_reports_an_unproven_emitted_chain_edge pins the observation for the
// shape ObsChainUnverified cannot reach: the discovered path ends at a certificate
// that IS proven self-signed, so the additive fallback branch is skipped, while the
// hop below it rests on a name match alone. Here the leaf's real signer is absent
// and a same-subject self-signed decoy holding a different key wins the chain, so
// the emitted issuer never signed anything in this bundle. The chain is deliberate
// (bestParent falls back to a merely-linked candidate when no proven one exists),
// but before this observation existed the whole bundle converted with ZERO
// observations, and a PKCS#12 CA bag a consumer imports into a trust store is the
// wrong place for that to be silent.
func TestAnalyse_reports_an_unproven_emitted_chain_edge(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	const issuerCN = "Absent Signer CA"

	// The real signer, absent from the bundle.
	absentKey := testcerts.NewECDSAKey(t)
	_, _, absentCert := testcerts.Mint(t, unverifiableCA(840, issuerCN, notBefore, notBefore.Add(240*time.Hour)),
		&absentKey.PublicKey, nil, absentKey)

	// The decoy: same subject, different key, self-signed - so it is a proven root
	// and the path terminates on it, while its key never signed the leaf.
	decoyKey := testcerts.NewECDSAKey(t)
	_, decoyPEM, _ := testcerts.Mint(t, unverifiableCA(841, issuerCN, notBefore, notBefore.Add(240*time.Hour)),
		&decoyKey.PublicKey, nil, decoyKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(842),
		Subject:      pkix.Name{CommonName: "unproven-edge-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, absentCert, absentKey)

	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, decoyPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if serials := strings.Join(chainSerials(got.Chain()), ","); serials != "841" {
		t.Fatalf("chain serials = %s, want 841 alone: the setup's premise is that the decoy wins the chain", serials)
	}
	if !hasObservation(got.Observations(), convert.ObsChainEdgeUnprovenIssuer) {
		t.Errorf("observations = %v, want %q: the emitted issuer never signed the leaf, and nothing else in the output says so",
			got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	}
}

// TestAnalyse_treats_a_reencoded_self_issued_certificate_as_its_own_root pins the
// positive direction of the decoded self-issuance rule (checkSelfSigned): a
// certificate whose own subject and issuer differ only in a permitted
// DirectoryString encoding is self-signed, so the additive fallback stays quiet
// and an unrelated eligible bystander is EXCLUDED rather than kept. Under the
// byte-only rule this bundle read as rootless: ObsChainUnverified fired and the
// bystander was appended to the chain.
func TestAnalyse_treats_a_reencoded_self_issued_certificate_as_its_own_root(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	key := testcerts.NewECDSAKey(t)
	tmpl := unverifiableCA(860, "Self Encoding Root CA", notBefore, notBefore.Add(48*time.Hour))
	// Sign against a view of the SAME template whose subject is the UTF8String
	// encoding, so RawIssuer is a permitted re-encoding of RawSubject.
	_, selfPEM, selfCert := testcerts.Mint(t, tmpl, &key.PublicKey,
		utf8SubjectView(tmpl, "Self Encoding Root CA"), key)
	if bytes.Equal(selfCert.RawSubject, selfCert.RawIssuer) {
		t.Fatal("setup: subject and issuer encode identically, so the branch under test is not reached")
	}

	strangerKey := testcerts.NewECDSAKey(t)
	_, strangerPEM, _ := testcerts.Mint(t, unverifiableCA(861, "Unrelated Bystander CA", notBefore, notBefore.Add(48*time.Hour)),
		&strangerKey.PublicKey, nil, strangerKey)

	got, err := convert.Analyse(t.Context(), concatPEM(selfPEM, strangerPEM), testcerts.KeyPEM(t, key))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if len(got.Chain()) != 0 {
		t.Errorf("chain = %v, want empty: a self-issued certificate is its own root", chainSerials(got.Chain()))
	}
	if len(got.Extra()) != 1 || got.Extra()[0].SerialNumber.Cmp(big.NewInt(861)) != 0 {
		t.Fatalf("Extra = %v, want the bystander alone", chainSerials(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want %q: the bystander's exclusion is never silent",
			got.Observations(), convert.ObsExtraCertsExcluded)
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: the identity is proven self-signed, so the additive fallback must not fire",
			got.Observations(), convert.ObsChainUnverified)
	}
}

// TestAnalyse_reports_an_unfinished_chain_with_nothing_left_over pins the fact the
// terminus diagnostic was once gated on leftovers for: a CA-signed leaf ALONE has an
// unfinished chain and no leftover certificate to append, so the diagnostic branch was
// skipped and the app's only input-diagnostic channel said nothing about the missing
// issuer. Conversion still succeeds with an empty chain - a PFX holding just the
// identity is a legitimate output - but it must not be silent.
//
// Which KIND it is not silent with was settled separately: nothing was left over, so
// there is nothing this app failed to place, and the only fact is that the issuer above
// the leaf is absent. That is ObsChainTrustAnchorAbsent at the informational class, and
// ObsChainUnverified (a warning about certificates carried without established
// ancestry) must NOT fire here - it was reporting a leftover disposition for a bundle
// with no leftovers.
func TestAnalyse_reports_an_unfinished_chain_with_nothing_left_over(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	caKey := testcerts.NewECDSAKey(t)
	_, _, caCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(870),
		Subject:               pkix.Name{CommonName: "Absent Issuing CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(871),
		Subject:      pkix.Name{CommonName: "lonely-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	got, err := convert.Analyse(t.Context(), leafPEM, testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(a CA-signed leaf alone) = error %v, want nil", err)
	}
	if len(got.Chain()) != 0 {
		t.Errorf("chain = %v, want empty: the issuer is not in the bundle", chainSerials(got.Chain()))
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra = %v, want empty: there is nothing besides the identity", chainSerials(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainTrustAnchorAbsent) {
		t.Errorf("observations = %v, want %q: the leaf is not self-signed and its issuer could not be established",
			got.Observations(), convert.ObsChainTrustAnchorAbsent)
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: nothing was left over, so nothing was carried without established ancestry",
			got.Observations(), convert.ObsChainUnverified)
	}
	if got := convert.ObsChainTrustAnchorAbsent.Class(); got != convert.ObservationClassInfo {
		t.Errorf("ObsChainTrustAnchorAbsent.Class() = %q, want %q: an absent anchor is the documented fullchain shape, not a warning",
			got, convert.ObservationClassInfo)
	}
	// The sentence must name THIS bundle: the identity ships alone, so a consumer that
	// does not already hold the issuer cannot build a path. Saying "every certificate
	// supplied is in the chain" here claimed the opposite of the operator's situation,
	// because the emitted chain is empty.
	if detail, ok := observationDetail(got.Observations(), convert.ObsChainTrustAnchorAbsent); !ok ||
		!strings.Contains(detail, "no chain certificates at all") {
		t.Errorf("anchor-absent detail = %q, want it to name that no chain certificate was supplied at all", detail)
	}
	if hasObservation(got.Observations(), convert.ObsExtraCertsExcluded) {
		t.Errorf("observations = %v, want no %q: no certificate was held back",
			got.Observations(), convert.ObsExtraCertsExcluded)
	}
}

// TestAnalyse_reports_an_unfinished_chain_when_only_the_root_is_absent is the same
// gap one link further up, and it is this app's PRIMARY DOCUMENTED INPUT: a Caddy/ACME
// fullchain is leaf + intermediate with the root deliberately absent. The
// leaf-to-intermediate hop is PROVEN, so the path walk consumes every parsed
// certificate and leaves nothing over, and the terminus is still not self-signed. The
// intermediate must stay in the chain and the missing root must be named.
//
// Named at the INFORMATIONAL class, not as a warning: the operator has nothing to act
// on (the consumer is expected to hold the root), and the condition recurs on first
// sight, after every renewal and after every restart, so ObsChainUnverified's warning
// here was log noise on the app's most ordinary input.
func TestAnalyse_reports_an_unfinished_chain_when_only_the_root_is_absent(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	rootKey := testcerts.NewECDSAKey(t)
	_, _, rootCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(872),
		Subject:               pkix.Name{CommonName: "Absent Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &rootKey.PublicKey, nil, rootKey)

	interKey := testcerts.NewECDSAKey(t)
	_, interPEM, interCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(873),
		Subject:               pkix.Name{CommonName: "Present Intermediate CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &interKey.PublicKey, rootCert, rootKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(874),
		Subject:      pkix.Name{CommonName: "rootless-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, interCert, interKey)

	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, interPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(a proven leaf/intermediate pair without its root) = error %v, want nil", err)
	}
	if len(got.Chain()) != 1 || got.Chain()[0].SerialNumber.Cmp(big.NewInt(873)) != 0 {
		t.Fatalf("chain = %v, want the intermediate alone", chainSerials(got.Chain()))
	}
	if len(got.Extra()) != 0 {
		t.Errorf("Extra = %v, want empty: every parsed certificate is on the path", chainSerials(got.Extra()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainTrustAnchorAbsent) {
		t.Errorf("observations = %v, want %q: the intermediate's own issuer is absent",
			got.Observations(), convert.ObsChainTrustAnchorAbsent)
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: a fullchain's absent root is not an unplaceable leftover, and warning about it on every renewal is noise",
			got.Observations(), convert.ObsChainUnverified)
	}
	if hasObservation(got.Observations(), convert.ObsChainEdgeUnprovenIssuer) {
		t.Errorf("observations = %v, want no %q: the one emitted edge is proven by signature",
			got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	}
	// The fullchain shape carries chain material, so it must NOT get the sentence
	// written for a bundle holding the identity alone: this operator has nothing to do.
	if detail, ok := observationDetail(got.Observations(), convert.ObsChainTrustAnchorAbsent); !ok ||
		strings.Contains(detail, "no chain certificates at all") {
		t.Errorf("anchor-absent detail = %q, want no claim that chain material is missing: the intermediate is in the bundle", detail)
	}
}

// TestAnalyse_reports_a_terminus_whose_self_signature_does_not_verify pins the THIRD
// terminus fact, the one both absent-anchor kinds mis-stated: the chain ends at a
// certificate that names ITSELF as its own issuer, so its anchor is PRESENT, but this
// app could not verify that self-signature (a corrupt or re-signed certificate, an
// algorithm crypto/x509 refuses such as MD5 or DSA, or a key above the verification
// ceilings).
//
// Before ObsChainAnchorUnverifiable this shape was reported as
// ObsChainTrustAnchorAbsent - the INFORMATIONAL kind minted for the normal Caddy/ACME
// fullchain - with a Detail claiming "whose issuer is not in the bundle" about a
// certificate whose issuer IS in the bundle. A trust anchor whose own signature does
// not verify was therefore indistinguishable in the log from a healthy fullchain,
// while a consumer validating the chain will reject it, so it is a warning.
//
// The root's signature over the LEAF is left intact, so the leaf->root hop stays
// proven and ObsChainEdgeUnprovenIssuer does not fire: the only broken thing is the
// root's signature over itself.
func TestAnalyse_reports_a_terminus_whose_self_signature_does_not_verify(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)

	rootKey := testcerts.NewECDSAKey(t)
	rootDER, _, rootCert := testcerts.Mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(875),
		Subject:               pkix.Name{CommonName: "legacy-root.example.com"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(96 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &rootKey.PublicKey, nil, rootKey)

	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(876),
		Subject:      pkix.Name{CommonName: "broken-anchor-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, rootCert, rootKey)

	// Flip one bit inside the root's own signature. ParseCertificate never decodes a
	// signature's contents, so the certificate still parses; only CheckSignature over
	// its own TBS fails, which is exactly the condition isSelfSigned collapses into
	// "not self-signed".
	tampered := bytes.Clone(rootDER)
	at := bytes.Index(tampered, rootCert.Signature)
	if at < 0 {
		t.Fatalf("the root's signature was not found in its own DER, so it cannot be tampered with")
	}
	tampered[at] ^= 0x01
	brokenRootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tampered})

	got, err := convert.Analyse(t.Context(), concatPEM(leafPEM, brokenRootPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(a leaf under a root whose self-signature is broken) = error %v, want nil", err)
	}
	if len(got.Chain()) != 1 || got.Chain()[0].SerialNumber.Cmp(big.NewInt(875)) != 0 {
		t.Fatalf("chain = %v, want the tampered root alone: it is still the leaf's proven issuer", chainSerials(got.Chain()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainAnchorUnverifiable) {
		t.Errorf("observations = %v, want %q: the anchor is present and its self-signature could not be verified",
			got.Observations(), convert.ObsChainAnchorUnverifiable)
	}
	if got := convert.ObsChainAnchorUnverifiable.Class(); got != convert.ObservationClassWarning {
		t.Errorf("ObsChainAnchorUnverifiable.Class() = %q, want %q: a consumer validating the chain will reject this anchor",
			got, convert.ObservationClassWarning)
	}
	if hasObservation(got.Observations(), convert.ObsChainTrustAnchorAbsent) {
		t.Errorf("observations = %v, want no %q: the issuer of the terminus IS in the bundle - it is the terminus itself",
			got.Observations(), convert.ObsChainTrustAnchorAbsent)
	}
	if hasObservation(got.Observations(), convert.ObsChainUnverified) {
		t.Errorf("observations = %v, want no %q: nothing was left over to carry without established ancestry",
			got.Observations(), convert.ObsChainUnverified)
	}
	if hasObservation(got.Observations(), convert.ObsChainEdgeUnprovenIssuer) {
		t.Errorf("observations = %v, want no %q: the root's signature over the leaf is intact",
			got.Observations(), convert.ObsChainEdgeUnprovenIssuer)
	}
}

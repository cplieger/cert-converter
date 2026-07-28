package convert_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"pgregory.net/rapid"
)

// concatPEM joins PEM blobs in the given order.
func concatPEM(blobs ...[]byte) []byte {
	var out []byte
	for _, b := range blobs {
		out = append(out, b...)
	}
	return out
}

// truncatedKeyBlock returns a key declaration whose armour is cut off mid-body,
// as a partial write into /input leaves it: encoding/pem drops it entirely, so
// only the declaration count knows it was ever there. The body stays a
// low-entropy placeholder (as convert_test.go's truncated block does), and the
// single definition keeps the file from holding two unterminated BEGIN headers —
// a pair of them reads as one multi-line private key to the secret scanner.
func truncatedKeyBlock() []byte {
	return []byte("-----BEGIN PRIVATE KEY-----\nZm9v\n")
}

// derOf returns the DER bytes of a single-certificate PEM blob.
func derOf(tb testing.TB, certPEM []byte) []byte {
	tb.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		tb.Fatal("setup: certificate PEM did not decode")
		return nil
	}
	return block.Bytes
}

// shuffleIndices draws a permutation of [0,n) from rapid via explicit
// Fisher-Yates swaps, so each swap is a named draw rapid can shrink.
func shuffleIndices(rt *rapid.T, n int, label string) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := rapid.IntRange(0, i).Draw(rt, fmt.Sprintf("%s-swap-%d", label, i))
		idx[i], idx[j] = idx[j], idx[i]
	}
	return idx
}

// TestAnalyse_is_invariant_under_input_order is the property the structural
// rewrite exists to satisfy. Identity selection is key-first, so NEITHER the
// certificate order NOR the position of the real key among decoys may change the
// result: the same leaf, the same chain and the same key must come back every
// time.
//
// The old positional rule (leaf = certs[0], key = the first parseable block)
// failed this for every permutation that did not happen to put the leaf first,
// and for every key file whose first block was not the matching key.
func TestAnalyse_is_invariant_under_input_order(t *testing.T) {
	t.Parallel()

	// Key material is generated once: the property is about ordering, not about
	// the keys, and regenerating per iteration would only slow the run.
	m := testcerts.GenerateChainMaterial(t)
	wantLeafDER := derOf(t, m.LeafPEM)
	wantCADER := derOf(t, m.CAPEM)

	_, decoy1KeyPEM := testcerts.GenerateSelfSignedCert(t, "decoy-one.example.com", "ecdsa")
	_, decoy2KeyPEM := testcerts.GenerateSelfSignedCert(t, "decoy-two.example.com", "ecdsa")

	rapid.Check(t, func(rt *rapid.T) {
		certBlobs := [][]byte{m.LeafPEM, m.CAPEM}
		certOrder := shuffleIndices(rt, len(certBlobs), "certs")
		orderedCerts := make([][]byte, 0, len(certBlobs))
		for _, i := range certOrder {
			orderedCerts = append(orderedCerts, certBlobs[i])
		}

		// The real key sits among 0-2 decoys, at any position.
		keyBlobs := [][]byte{m.LeafKeyPEM}
		switch rapid.IntRange(0, 2).Draw(rt, "decoy-count") {
		case 1:
			keyBlobs = append(keyBlobs, decoy1KeyPEM)
		case 2:
			keyBlobs = append(keyBlobs, decoy1KeyPEM, decoy2KeyPEM)
		}
		keyOrder := shuffleIndices(rt, len(keyBlobs), "keys")
		orderedKeys := make([][]byte, 0, len(keyBlobs))
		for _, i := range keyOrder {
			orderedKeys = append(orderedKeys, keyBlobs[i])
		}

		got, err := convert.Analyse(concatPEM(orderedCerts...), concatPEM(orderedKeys...))
		if err != nil {
			rt.Fatalf("Analyse(cert order %v, key order %v) = error %v, want nil", certOrder, keyOrder, err)
		}
		if !bytes.Equal(got.Leaf().Raw, wantLeafDER) {
			rt.Errorf("Analyse(cert order %v) selected leaf %q, want the end-entity certificate", certOrder, got.Leaf().Subject.CommonName)
		}
		if len(got.Chain()) != 1 {
			rt.Fatalf("Analyse(cert order %v) chain length = %d, want 1", certOrder, len(got.Chain()))
		}
		if !bytes.Equal(got.Chain()[0].Raw, wantCADER) {
			rt.Errorf("Analyse(cert order %v) chain[0] = %q, want the issuing CA", certOrder, got.Chain()[0].Subject.CommonName)
		}
		if len(got.Extra()) != 0 {
			rt.Errorf("Analyse(cert order %v) excluded %d certificate(s), want 0", certOrder, len(got.Extra()))
		}
		// The invariant that makes the bundle internally consistent: the returned
		// key is the private half of the returned leaf.
		assertKeyMatchesLeaf(rt, got)
	})
}

// assertKeyMatchesLeaf checks Analyse's core invariant.
func assertKeyMatchesLeaf(tb interface {
	Errorf(string, ...any)
	Fatalf(string, ...any)
}, a convert.Analysis,
) {
	signer, ok := a.Key().(crypto.Signer)
	if !ok {
		tb.Fatalf("Analyse returned a key of type %T that is not a crypto.Signer", a.Key())
	}
	matcher, ok := a.Leaf().PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		tb.Fatalf("selected leaf carries a public key of type %T with no Equal method", a.Leaf().PublicKey)
	}
	if !matcher.Equal(signer.Public()) {
		tb.Errorf("Analyse returned a key that is not the private half of the selected leaf")
	}
}

// TestAnalyse_resolves_every_documented_input_shape walks the outcome table the
// design specifies, so each row is pinned as a decision rather than left to
// whatever the algorithm happens to do.
func TestAnalyse_resolves_every_documented_input_shape(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	unrelatedCertPEM, unrelatedKeyPEM := testcerts.GenerateSelfSignedCert(t, "unrelated.example.com", "ecdsa")
	secondLeafPEM, secondLeafKeyPEM := testcerts.GenerateSelfSignedCert(t, "second-identity.example.com", "ecdsa")

	for _, tc := range []struct {
		name     string
		certPEM  []byte
		keyPEM   []byte
		wantErr  string
		wantLeaf string
		wantObs  convert.ObservationKind
		wantLen  int // expected chain length when no error
	}{
		{
			name:     "the supplied key belongs to the issuer, not an end entity",
			certPEM:  concatPEM(m.LeafPEM, m.CAPEM),
			keyPEM:   m.CAKeyPEM,
			wantErr:  "is an issuer of another certificate in this bundle",
			wantLeaf: "",
		},
		{
			name:    "no key matches any certificate",
			certPEM: concatPEM(m.LeafPEM, m.CAPEM),
			keyPEM:  unrelatedKeyPEM,
			wantErr: "none of the 1 private key block(s) matches any of the 2 certificate(s)",
		},
		{
			name:    "two distinct identities cannot be one bundle",
			certPEM: concatPEM(m.LeafPEM, secondLeafPEM),
			keyPEM:  concatPEM(m.LeafKeyPEM, secondLeafKeyPEM),
			wantErr: "distinct certificate/key identities",
		},
		{
			name:     "several keys, one match, resolves and reports the extra keys",
			certPEM:  concatPEM(m.LeafPEM, m.CAPEM),
			keyPEM:   concatPEM(unrelatedKeyPEM, m.LeafKeyPEM),
			wantLeaf: "material-leaf.example.com",
			wantObs:  convert.ObsMultipleKeys,
			wantLen:  1,
		},
		{
			name:     "a renewed certificate reusing its key wins on NotBefore",
			certPEM:  concatPEM(m.LeafPEM, m.RenewedPEM, m.CAPEM),
			keyPEM:   m.LeafKeyPEM,
			wantLeaf: "material-renewed.example.com",
			wantObs:  convert.ObsRenewedCertTie,
			wantLen:  1,
		},
		{
			name: "a future-dated renewal does NOT beat a currently valid certificate",
			// FutureRenewedPEM has the latest NotBefore of the three. Ranking on
			// NotBefore alone would pick it and emit a bundle no consumer accepts
			// yet, so validity at scan time outranks recency.
			certPEM:  concatPEM(m.LeafPEM, m.FutureRenewedPEM, m.CAPEM),
			keyPEM:   m.LeafKeyPEM,
			wantLeaf: "material-leaf.example.com",
			wantObs:  convert.ObsRenewedCertTie,
			wantLen:  1,
		},
		{
			name:     "a duplicated certificate is an artefact, not an error",
			certPEM:  concatPEM(m.LeafPEM, m.LeafPEM, m.CAPEM),
			keyPEM:   m.LeafKeyPEM,
			wantLeaf: "material-leaf.example.com",
			wantObs:  convert.ObsDuplicateCerts,
			wantLen:  1,
		},
		{
			name:     "a certificate outside the leaf's chain is excluded",
			certPEM:  concatPEM(m.LeafPEM, m.CAPEM, unrelatedCertPEM),
			keyPEM:   m.LeafKeyPEM,
			wantLeaf: "material-leaf.example.com",
			wantObs:  convert.ObsExtraCertsExcluded,
			wantLen:  1,
		},
		{
			name:     "a CA that issued nothing here may serve as the identity, loudly",
			certPEM:  m.CAPEM,
			keyPEM:   m.CAKeyPEM,
			wantLeaf: "Material Test CA",
			wantObs:  convert.ObsCAAsIdentity,
			wantLen:  0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := convert.Analyse(tc.certPEM, tc.keyPEM)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Analyse = nil error, want one containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("Analyse error = %q, want it to contain %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Analyse = error %v, want nil", err)
			}
			if got.Leaf().Subject.CommonName != tc.wantLeaf {
				t.Errorf("Analyse selected leaf %q, want %q", got.Leaf().Subject.CommonName, tc.wantLeaf)
			}
			if len(got.Chain()) != tc.wantLen {
				t.Errorf("Analyse chain length = %d, want %d", len(got.Chain()), tc.wantLen)
			}
			if tc.wantObs != "" && !hasObservation(got.Observations(), tc.wantObs) {
				t.Errorf("Analyse observations = %v, want one of kind %q", got.Observations(), tc.wantObs)
			}
			assertKeyMatchesLeaf(t, got)
		})
	}
}

// TestAnalyse_orders_the_chain_nearest_parent_first pins the emitted order.
// PKCS#12 stores an ordered SEQUENCE of bags and decoders read it positionally,
// so the chain is a contract: leaf, then its issuer, then that issuer's issuer.
func TestAnalyse_orders_the_chain_nearest_parent_first(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)

	// Deliberately the worst input order: CA first, leaf last.
	got, err := convert.Analyse(concatPEM(m.CAPEM, m.LeafPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	if got.Leaf().Subject.CommonName != "material-leaf.example.com" {
		t.Fatalf("selected leaf = %q, want the end-entity certificate", got.Leaf().Subject.CommonName)
	}
	wantChain := []string{"Material Test CA"}
	gotChain := subjectCNs(got.Chain())
	if len(gotChain) != len(wantChain) {
		t.Fatalf("chain = %v, want %v", gotChain, wantChain)
	}
	for i := range wantChain {
		if gotChain[i] != wantChain[i] {
			t.Errorf("chain[%d] = %q, want %q", i, gotChain[i], wantChain[i])
		}
	}
	if !hasObservation(got.Observations(), convert.ObsLeafNotFirst) {
		t.Errorf("observations = %v, want one of kind %q", got.Observations(), convert.ObsLeafNotFirst)
	}
}

// subjectCNs renders certificate common names for a comparison message.
func subjectCNs(certs []*x509.Certificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.Subject.CommonName)
	}
	return out
}

// TestAnalyse_treats_a_key_repeated_twice_as_one_key pins the key-dedupe half of
// identity resolution. A key file that carries the same key twice is an ordinary
// copy-paste artefact (an aborted rotation that appended the key it already
// held), and it must convert exactly as the single-block file does: one key, no
// multiple-keys observation. Without the dedupe the two blocks become two
// signers, both match the same certificate, and the ambiguity rule reports "the
// input contains 2 distinct certificate/key identities" -- a hard conversion
// failure that keeps the container unhealthy until an operator edits the file.
func TestAnalyse_treats_a_key_repeated_twice_as_one_key(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "repeated-key.example.com", "ecdsa")

	got, err := convert.Analyse(certPEM, concatPEM(keyPEM, keyPEM))
	if err != nil {
		t.Fatalf("Analyse(one certificate, the same key twice) = error %v, want nil: two blocks holding one key are one key", err)
	}
	if got.Leaf().Subject.CommonName != "repeated-key.example.com" {
		t.Errorf("selected identity = %q, want %q", got.Leaf().Subject.CommonName, "repeated-key.example.com")
	}
	if hasObservation(got.Observations(), convert.ObsMultipleKeys) {
		t.Errorf("observations = %v, want NO %q: the file holds one key written twice",
			got.Observations(), convert.ObsMultipleKeys)
	}
	assertKeyMatchesLeaf(t, got)
}

// TestAnalyse_reports_an_out_of_window_identity_without_refusing_it pins the
// documented non-gate: validity is never a reason to refuse a conversion (an
// operator migrating an expired certificate is a supported case), so the
// observation is the ONLY signal that the bundle just written is out of window.
// Both arms are asserted against each other, so swapping them -- or dropping
// either -- fails here instead of silently converting an expired certificate with
// no record.
func TestAnalyse_reports_an_out_of_window_identity_without_refusing_it(t *testing.T) {
	t.Parallel()
	now := time.Now()

	for _, tc := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      convert.ObservationKind
		unwanted  convert.ObservationKind
	}{
		{
			name:      "an expired identity still converts, loudly",
			notBefore: now.Add(-48 * time.Hour),
			notAfter:  now.Add(-24 * time.Hour),
			want:      convert.ObsIdentityExpired,
			unwanted:  convert.ObsIdentityNotYetValid,
		},
		{
			name:      "a not-yet-valid identity still converts, loudly",
			notBefore: now.Add(24 * time.Hour),
			notAfter:  now.Add(48 * time.Hour),
			want:      convert.ObsIdentityNotYetValid,
			unwanted:  convert.ObsIdentityExpired,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := newKey(t)
			certPEM, _ := mint(t, &x509.Certificate{
				SerialNumber: big.NewInt(120),
				Subject:      pkix.Name{CommonName: "window.example.com"},
				NotBefore:    tc.notBefore,
				NotAfter:     tc.notAfter,
			}, &key.PublicKey, nil, key)

			got, err := convert.Analyse(certPEM, keyPEMOf(t, key))
			if err != nil {
				t.Fatalf("Analyse(%s) = error %v, want nil: validity is never a gate", tc.name, err)
			}
			if !hasObservation(got.Observations(), tc.want) {
				t.Errorf("Analyse(%s) observations = %v, want one of kind %q", tc.name, got.Observations(), tc.want)
			}
			if hasObservation(got.Observations(), tc.unwanted) {
				t.Errorf("Analyse(%s) observations = %v, want NO observation of kind %q", tc.name, got.Observations(), tc.unwanted)
			}
		})
	}
}

// TestAnalyse_reports_no_validity_observation_for_a_current_identity is the
// negative half: a certificate inside its window must produce neither validity
// observation, so an operator's log filter on those kinds means what it says.
func TestAnalyse_reports_no_validity_observation_for_a_current_identity(t *testing.T) {
	t.Parallel()
	now := time.Now()
	key := newKey(t)
	certPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(121),
		Subject:      pkix.Name{CommonName: "current.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}, &key.PublicKey, nil, key)

	got, err := convert.Analyse(certPEM, keyPEMOf(t, key))
	if err != nil {
		t.Fatalf("Analyse = error %v, want nil", err)
	}
	for _, kind := range []convert.ObservationKind{convert.ObsIdentityExpired, convert.ObsIdentityNotYetValid} {
		if hasObservation(got.Observations(), kind) {
			t.Errorf("Analyse(a currently valid identity) observations = %v, want no %q", got.Observations(), kind)
		}
	}
}

// TestAnalyse_reports_an_out_of_window_chain_certificate pins the chain half of the
// validity report. The historically real shape is a still-valid leaf beside an EXPIRED
// issuing intermediate (the ISRG X1 cross-sign class of event): the identity check sees a
// leaf inside its window and says nothing, the bundle is written, the scan reports a clean
// conversion, and without this observation no signal anywhere names the link that will fail
// path validation at the consumer.
func TestAnalyse_reports_an_out_of_window_chain_certificate(t *testing.T) {
	t.Parallel()
	now := time.Now()

	caKey := newKey(t)
	caPEM, caCert := mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(140),
		Subject:               pkix.Name{CommonName: "Expired Intermediate"},
		NotBefore:             now.Add(-72 * time.Hour),
		NotAfter:              now.Add(-24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &caKey.PublicKey, nil, caKey)

	leafKey := newKey(t)
	leafPEM, _ := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(141),
		Subject:      pkix.Name{CommonName: "valid-leaf.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}, &leafKey.PublicKey, caCert, caKey)

	got, err := convert.Analyse(concatPEM(leafPEM, caPEM), keyPEMOf(t, leafKey))
	if err != nil {
		t.Fatalf("Analyse(valid leaf + expired issuer) = error %v, want nil: validity is never a gate", err)
	}
	if len(got.Chain()) != 1 {
		t.Fatalf("Analyse chain = %d certificate(s), want the expired issuer emitted", len(got.Chain()))
	}
	if !hasObservation(got.Observations(), convert.ObsChainCertOutOfWindow) {
		t.Errorf("observations = %v, want one of kind %q naming the expired issuer",
			got.Observations(), convert.ObsChainCertOutOfWindow)
	}
	if hasObservation(got.Observations(), convert.ObsIdentityExpired) {
		t.Errorf("observations = %v, want NO %q: the identity itself is inside its window",
			got.Observations(), convert.ObsIdentityExpired)
	}
}

// TestAnalyse_caps_the_subjects_it_names_in_the_exclusion_observation pins the
// count cap on the excluded-certificate observation. Subjects are
// certificate-controlled text bounded only by the 10 MB input read bound, and
// boundSubject caps each one at 256 bytes but not how MANY are listed; the cap of
// three plus an "and N more" summary is the only thing keeping a bundle full of
// extras from producing an observation line that grows with the input, logged on
// every scan that revisits the pair.
func TestAnalyse_caps_the_subjects_it_names_in_the_exclusion_observation(t *testing.T) {
	t.Parallel()
	identityCertPEM, identityKeyPEM := testcerts.GenerateSelfSignedCert(t, "identity.example.com", "ecdsa")
	bundle := append([]byte{}, identityCertPEM...)
	for _, cn := range []string{"extra-1", "extra-2", "extra-3", "extra-4", "extra-5"} {
		extraPEM, _ := testcerts.GenerateSelfSignedCert(t, cn+".example.com", "ecdsa")
		bundle = append(bundle, extraPEM...)
	}

	got, err := convert.Analyse(bundle, identityKeyPEM)
	if err != nil {
		t.Fatalf("Analyse(identity + 5 unrelated certificates) = error %v, want nil", err)
	}
	var detail string
	for _, o := range got.Observations() {
		if o.Kind == convert.ObsExtraCertsExcluded {
			detail = o.Detail
		}
	}
	if detail == "" {
		t.Fatalf("observations = %v, want one of kind %q", got.Observations(), convert.ObsExtraCertsExcluded)
	}
	if !strings.Contains(detail, "and 2 more") {
		t.Errorf("observation detail = %q, want the certificates past the cap summarised as a count", detail)
	}
	if strings.Contains(detail, "extra-4.example.com") || strings.Contains(detail, "extra-5.example.com") {
		t.Errorf("observation detail = %q, want at most 3 subjects named", detail)
	}
}

// relabelPEM re-encodes the first PEM block of blob under a different label, the
// way `openssl x509 -trustout` emits a "TRUSTED CERTIFICATE" instead of a plain
// CERTIFICATE.
func relabelPEM(tb testing.TB, blob []byte, label string) []byte {
	tb.Helper()
	block, _ := pem.Decode(blob)
	if block == nil {
		tb.Fatal("setup: PEM did not decode")
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: block.Bytes})
}

// TestAnalyse_reports_a_chain_link_left_out_because_its_label_is_not_CERTIFICATE
// pins the signal for the silent-drop case: a chain file whose CA link arrives
// as "TRUSTED CERTIFICATE" (or the legacy "X509 CERTIFICATE" alias) still
// converts, but the block that was left out of the bundle is named, so the
// consumer-side path-validation failure has something to grep for.
func TestAnalyse_reports_a_chain_link_left_out_because_its_label_is_not_CERTIFICATE(t *testing.T) {
	leafPEM, keyPEM, caPEM, _ := testcerts.GenerateCertChain(t)

	for _, label := range []string{"TRUSTED CERTIFICATE", "X509 CERTIFICATE", "CERTIFICATE REQUEST"} {
		t.Run(label, func(t *testing.T) {
			bundle := concatPEM(leafPEM, relabelPEM(t, caPEM, label))

			got, err := convert.Analyse(bundle, keyPEM)
			if err != nil {
				t.Fatalf("Analyse(leaf + %q block) = error %v, want nil", label, err)
			}
			var detail string
			for _, o := range got.Observations() {
				if o.Kind == convert.ObsUnrelatedBlocksSkipped {
					detail = o.Detail
				}
			}
			if detail == "" {
				t.Fatalf("observations = %v, want one of kind %q", got.Observations(), convert.ObsUnrelatedBlocksSkipped)
			}
			if !strings.Contains(detail, label) {
				t.Errorf("observation detail = %q, want the skipped block's label named", detail)
			}
		})
	}
}

// TestAnalyse_reports_no_skipped_block_for_a_combined_cert_and_key_file is the
// other half of the rule: a private key in the certificate file is a documented
// supported input, so it must stay silent. Without this the observation would
// fire on every combined .crt.
func TestAnalyse_reports_no_skipped_block_for_a_combined_cert_and_key_file(t *testing.T) {
	leafPEM, keyPEM, caPEM, _ := testcerts.GenerateCertChain(t)
	combined := concatPEM(leafPEM, keyPEM, caPEM)

	got, err := convert.Analyse(combined, keyPEM)
	if err != nil {
		t.Fatalf("Analyse(combined cert+key file) = error %v, want nil", err)
	}
	if hasObservation(got.Observations(), convert.ObsUnrelatedBlocksSkipped) {
		t.Errorf("observations = %v, want no %q for a private key in the certificate file",
			got.Observations(), convert.ObsUnrelatedBlocksSkipped)
	}
}

// TestAnalyse_names_the_unusable_key_blocks_when_nothing_matches pins the
// mid-rotation diagnosis: a key file whose appended block is truncated still
// parses its other key, so the count in the no-match sentence is of USABLE keys
// and understates the file. The blocks that yielded no key must be named after
// the base sentence, or the operator reads "the key does not match the
// certificate" and goes looking at the certificate.
func TestAnalyse_names_the_unusable_key_blocks_when_nothing_matches(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	_, unrelatedKeyPEM := testcerts.GenerateSelfSignedCert(t, "unrelated.example.com", "ecdsa")

	// A second key declaration whose armour is cut off mid-body, as a partial
	// write into /input leaves it.
	truncated := truncatedKeyBlock()

	_, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), concatPEM(unrelatedKeyPEM, truncated))
	if err == nil {
		t.Fatal("Analyse(unrelated key + truncated key block) = nil error, want a no-match error")
	}
	got := err.Error()
	// The base sentence stays an exact prefix of the diagnosis (analyse_test.go's
	// documented-input-shape row and convert_test.go both match on it).
	for _, want := range []string{
		"none of the 1 private key block(s) matches any of the 2 certificate(s) in the chain",
		"1 declared block(s) could not be decoded",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Analyse error = %q, want it to contain %q", got, want)
		}
	}
}

// TestAnalyse_names_an_unparseable_and_an_encrypted_key_block_when_nothing_matches
// covers the other two keyDefects clauses. Only the undecoded one is exercised by
// the test above, so a mutation to either of these strings — or to the
// parseFailures / sawEncrypted plumbing that feeds them — survives the whole
// suite while the operator loses the same mid-rotation diagnosis.
func TestAnalyse_names_an_unparseable_and_an_encrypted_key_block_when_nothing_matches(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	_, unrelatedKeyPEM := testcerts.GenerateSelfSignedCert(t, "unrelated.example.com", "ecdsa")

	// A key-labelled block whose DER no parser accepts, and a PKCS#8 encrypted
	// block: both decode as PEM, neither yields a key, so both are counted while
	// the unrelated key still makes parsePrivateKeys succeed.
	garbage := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a DER key")})
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("ciphertext")})

	_, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), concatPEM(unrelatedKeyPEM, garbage, encrypted))
	if err == nil {
		t.Fatal("Analyse(unrelated key + unparseable key + encrypted key) = nil error, want a no-match error")
	}
	got := err.Error()
	for _, want := range []string{
		"none of the 1 private key block(s) matches any of the 2 certificate(s) in the chain",
		"1 could not be parsed",
		"at least one is encrypted",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Analyse error = %q, want it to contain %q", got, want)
		}
	}
}

// TestAnalyse_reports_unusable_key_blocks_when_a_usable_key_still_matches is the
// success-path half of the same mid-rotation diagnosis, and the one the two
// no-match tests above cannot reach. A rotation that appends a damaged key beside
// the matching one converts fine today, so no error names the damaged block;
// without an observation it stays silent until the next renewal turns it into a
// conversion failure whose message points at the certificate.
func TestAnalyse_reports_unusable_key_blocks_when_a_usable_key_still_matches(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)

	// Same truncated declaration as the no-match test: encoding/pem drops it, so
	// only the declaration count knows it was ever there.
	truncated := truncatedKeyBlock()

	got, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), concatPEM(m.LeafKeyPEM, truncated))
	if err != nil {
		t.Fatalf("Analyse(matching key + truncated key block) = %v, want success: the usable key still matches", err)
	}
	var detail string
	for _, o := range got.Observations() {
		if o.Kind == convert.ObsUnusableKeyBlocksSkipped {
			detail = o.Detail
		}
	}
	if detail == "" {
		t.Fatalf("observations = %v, want one of kind %q naming the block that yielded no key",
			got.Observations(), convert.ObsUnusableKeyBlocksSkipped)
	}
	if !strings.Contains(detail, "1 declared block(s) could not be decoded") {
		t.Errorf("observation detail = %q, want it to name the undecoded declaration", detail)
	}
}

// TestAnalyse_reports_unusable_key_blocks_for_an_unreadable_label covers the one
// mid-rotation shape the three counted defect classes miss: an appended key in an
// armour label this app does not read (an OpenSSH-format key). encoding/pem
// decodes the block fine, so no parse failure is counted and the declaration
// count does not see it either; without the label rule the whole half of the key
// file is ignored in silence until the next renewal turns it into a cert/key
// mismatch pointing at the certificate.
func TestAnalyse_reports_unusable_key_blocks_for_an_unreadable_label(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)

	// Low-entropy placeholder body: only the label matters to the rule under test.
	openssh := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("foo")})

	got, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), concatPEM(m.LeafKeyPEM, openssh))
	if err != nil {
		t.Fatalf("Analyse(matching key + OpenSSH-format block) = %v, want success: the usable key still matches", err)
	}
	var detail string
	for _, o := range got.Observations() {
		if o.Kind == convert.ObsUnusableKeyBlocksSkipped {
			detail = o.Detail
		}
	}
	if detail == "" {
		t.Fatalf("observations = %v, want one of kind %q naming the block whose label names no key format this app reads",
			got.Observations(), convert.ObsUnusableKeyBlocksSkipped)
	}
	for _, want := range []string{"1 block(s) carry a label", "OPENSSH PRIVATE KEY"} {
		if !strings.Contains(detail, want) {
			t.Errorf("observation detail = %q, want it to contain %q", detail, want)
		}
	}
}

// TestAnalyse_reports_no_key_block_observation_for_a_certificate_passenger pins
// the other half of the label rule: a combined cert+key file is a supported
// input, so the CERTIFICATE block riding along in the key file must NOT be
// reported — otherwise every scan of a healthy combined pair emits a WARN nobody
// can act on. This is the mirror of parseCertChain treating a private-key block
// as an expected passenger of the chain file.
func TestAnalyse_reports_no_key_block_observation_for_a_certificate_passenger(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	got, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), concatPEM(m.LeafKeyPEM, m.LeafPEM))
	if err != nil {
		t.Fatalf("Analyse(combined cert+key file) = %v, want success", err)
	}
	if hasObservation(got.Observations(), convert.ObsUnusableKeyBlocksSkipped) {
		t.Errorf("observations = %v, want no %q for a CERTIFICATE block riding in the key file",
			got.Observations(), convert.ObsUnusableKeyBlocksSkipped)
	}
}

// TestAnalyse_reports_no_key_block_observation_for_an_ec_parameters_passenger
// pins the second expected companion of a real key file. `openssl ecparam
// -genkey` writes an EC PARAMETERS block immediately before the EC PRIVATE KEY
// it describes, so that two-block file is the ordinary output of a standard
// keygen command, not a key this app failed to read. Reporting it would emit a
// WARN on every scan of a perfectly healthy pair, forever.
func TestAnalyse_reports_no_key_block_observation_for_an_ec_parameters_passenger(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)

	// The DER `openssl ecparam` writes for a named curve: the prime256v1 OID
	// (1.2.840.10045.3.1.7). Only the label drives the rule under test.
	ecParams := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PARAMETERS",
		Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	})

	got, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), concatPEM(ecParams, m.LeafKeyPEM))
	if err != nil {
		t.Fatalf("Analyse(ecparam -genkey key file) = %v, want success", err)
	}
	if hasObservation(got.Observations(), convert.ObsUnusableKeyBlocksSkipped) {
		t.Errorf("observations = %v, want no %q for the EC PARAMETERS block `openssl ecparam -genkey` writes beside the key",
			got.Observations(), convert.ObsUnusableKeyBlocksSkipped)
	}
}

// TestAnalyse_reports_no_key_block_observation_for_a_clean_key_file guards the
// other direction: the observation must stay absent for the ordinary input, or
// every scan of every healthy pair emits a WARN nobody can act on.
func TestAnalyse_reports_no_key_block_observation_for_a_clean_key_file(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	got, err := convert.Analyse(concatPEM(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("Analyse(clean input) = %v, want success", err)
	}
	if hasObservation(got.Observations(), convert.ObsUnusableKeyBlocksSkipped) {
		t.Errorf("observations = %v, want no %q for a key file whose every block yielded a key",
			got.Observations(), convert.ObsUnusableKeyBlocksSkipped)
	}
}

package convert_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

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
		if !bytes.Equal(got.Leaf.Raw, wantLeafDER) {
			rt.Errorf("Analyse(cert order %v) selected leaf %q, want the end-entity certificate", certOrder, got.Leaf.Subject.CommonName)
		}
		if len(got.Chain) != 1 {
			rt.Fatalf("Analyse(cert order %v) chain length = %d, want 1", certOrder, len(got.Chain))
		}
		if !bytes.Equal(got.Chain[0].Raw, wantCADER) {
			rt.Errorf("Analyse(cert order %v) chain[0] = %q, want the issuing CA", certOrder, got.Chain[0].Subject.CommonName)
		}
		if len(got.Extra) != 0 {
			rt.Errorf("Analyse(cert order %v) excluded %d certificate(s), want 0", certOrder, len(got.Extra))
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
	signer, ok := a.Key.(crypto.Signer)
	if !ok {
		tb.Fatalf("Analyse returned a key of type %T that is not a crypto.Signer", a.Key)
	}
	matcher, ok := a.Leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		tb.Fatalf("selected leaf carries a public key of type %T with no Equal method", a.Leaf.PublicKey)
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
			if got.Leaf.Subject.CommonName != tc.wantLeaf {
				t.Errorf("Analyse selected leaf %q, want %q", got.Leaf.Subject.CommonName, tc.wantLeaf)
			}
			if len(got.Chain) != tc.wantLen {
				t.Errorf("Analyse chain length = %d, want %d", len(got.Chain), tc.wantLen)
			}
			if tc.wantObs != "" && !hasObservation(got.Observations, tc.wantObs) {
				t.Errorf("Analyse observations = %v, want one of kind %q", got.Observations, tc.wantObs)
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
	if got.Leaf.Subject.CommonName != "material-leaf.example.com" {
		t.Fatalf("selected leaf = %q, want the end-entity certificate", got.Leaf.Subject.CommonName)
	}
	wantChain := []string{"Material Test CA"}
	gotChain := subjectCNs(got.Chain)
	if len(gotChain) != len(wantChain) {
		t.Fatalf("chain = %v, want %v", gotChain, wantChain)
	}
	for i := range wantChain {
		if gotChain[i] != wantChain[i] {
			t.Errorf("chain[%d] = %q, want %q", i, gotChain[i], wantChain[i])
		}
	}
	if !hasObservation(got.Observations, convert.ObsLeafNotFirst) {
		t.Errorf("observations = %v, want one of kind %q", got.Observations, convert.ObsLeafNotFirst)
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

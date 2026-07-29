package convert_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestEncode_preserves_the_order_of_a_multi_CA_chain pins the bag-order contract
// Encode documents at the only chain length that can express it. PKCS#12 stores an
// ordered SEQUENCE of bags (RFC 7292 §4.2) and decoders read it positionally, and
// decoded.matchesAnalysis compares the CA bags POSITIONALLY against the analysis,
// so an encoder that reordered them would make CheckCurrency report
// content-mismatch on the bundle this app had just written and rewrite the file on
// every scan forever, churning its mtime and re-replicating it downstream.
//
// Every other round trip in this package uses a chain of one CA (testcerts'
// GenerateChainMaterial and GenerateCertChain both emit leaf + one CA), where
// order is unobservable, and FuzzToPFXRoundTrip's own order invariant is limited
// the same way by its committed seeds. A two-CA chain is what makes the assertion
// bite.
func TestEncode_preserves_the_order_of_a_multi_CA_chain(t *testing.T) {
	t.Parallel()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	ca := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             notBefore,
			NotAfter:              notBefore.Add(240 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}
	rootKey := testcerts.NewECDSAKey(t)
	_, rootPEM, rootCert := testcerts.Mint(t, ca(701, "Chain Order Root"), &rootKey.PublicKey, nil, rootKey)
	interKey := testcerts.NewECDSAKey(t)
	_, interPEM, interCert := testcerts.Mint(t, ca(702, "Chain Order Intermediate"), &interKey.PublicKey, rootCert, rootKey)
	leafKey := testcerts.NewECDSAKey(t)
	_, leafPEM, _ := testcerts.Mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(703),
		Subject:      pkix.Name{CommonName: "chain-order-leaf.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}, &leafKey.PublicKey, interCert, interKey)

	analysis, err := convert.Analyse(concatPEM(leafPEM, rootPEM, interPEM), testcerts.KeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("setup: Analyse(leaf, root, intermediate) = error %v, want nil", err)
	}
	want := []string{"Chain Order Intermediate", "Chain Order Root"}
	if got := subjectCNs(analysis.Chain()); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("setup: Analyse chain = %v, want %v nearest-parent-first", got, want)
	}

	pfx, err := convert.Encode(&analysis, convert.EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("Encode = error %v, want nil", err)
	}
	decoded, err := convert.Decode(pfx, "pw")
	if err != nil {
		t.Fatalf("Decode(the bundle Encode just produced) = error %v, want nil", err)
	}
	got := subjectCNs(decoded.CACerts)
	if len(got) != len(want) {
		t.Fatalf("round-tripped %d CA bag(s) %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("round-tripped CA bag[%d] = %q, want %q: the bag order is the contract, not an implementation detail",
				i, got[i], want[i])
		}
	}
	if res := convert.CheckCurrency(pfx, "pw", &analysis, convert.EncNameModern2023); !res.Current() {
		t.Errorf("CheckCurrency(the bundle Encode just wrote) = %q, want a match: a chain order the round trip does not preserve makes every scan rewrite the file",
			res.Reason)
	}
}

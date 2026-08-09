package convert_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/testcerts"
)

func BenchmarkConvertPair(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certPEM, _ := testcerts.Mint(b, tmpl, &key.PublicKey, nil, key)
	keyPEM := testcerts.KeyPEM(b, key)

	root, err := os.OpenRoot(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := convertPairInRoot(b.Context(), certPEM, keyPEM, root, "bench.pfx", "bench", convert.EncNameModern2023); err != nil {
			b.Fatal(err)
		}
	}
}

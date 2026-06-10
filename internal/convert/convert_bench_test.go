package convert_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cplieger/cert-watcher/internal/convert"
	"software.sslmate.com/src/go-pkcs12"
)

func BenchmarkToPFX(b *testing.B) {
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
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		b.Fatal(err)
	}

	enc := pkcs12.Modern2023
	destPath := b.TempDir() + "/bench.pfx"

	b.ResetTimer()
	for range b.N {
		if err := convert.ToPFX(b.Context(), key, cert, nil, destPath, "bench", enc); err != nil {
			b.Fatal(err)
		}
	}
}

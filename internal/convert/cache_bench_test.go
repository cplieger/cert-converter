package convert_test

import (
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
)

func BenchmarkFingerprint(b *testing.B) {
	cert := make([]byte, 4096)
	key := make([]byte, 4096)
	for i := range cert {
		cert[i] = byte(i % 256)
		key[i] = byte((i + 1) % 256)
	}

	b.SetBytes(int64(len(cert) + len(key)))
	b.ResetTimer()
	for range b.N {
		_ = convert.Fingerprint(cert, key)
	}
}

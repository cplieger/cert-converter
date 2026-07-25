package process

import (
	"testing"
)

func BenchmarkPairFingerprint(b *testing.B) {
	cert := make([]byte, 4096)
	key := make([]byte, 4096)
	for i := range cert {
		cert[i] = byte(i % 256)
		key[i] = byte((i + 1) % 256)
	}

	b.SetBytes(int64(len(cert) + len(key)))
	b.ReportAllocs()
	for b.Loop() {
		_ = pairFingerprint(cert, key)
	}
}

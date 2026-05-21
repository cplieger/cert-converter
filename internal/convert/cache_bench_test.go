package convert_test

import (
	"os"
	"testing"

	"cert-watcher/internal/convert"
)

func BenchmarkHashFile(b *testing.B) {
	f, err := os.CreateTemp(b.TempDir(), "bench-hash-*")
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if _, err := f.Write(data); err != nil {
		b.Fatal(err)
	}
	f.Close()

	cache := convert.NewHashCache()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		if _, err := cache.HashFile(f.Name()); err != nil {
			b.Fatal(err)
		}
	}
}

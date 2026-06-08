package convert_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cplieger/cert-watcher/internal/convert"
	"github.com/cplieger/cert-watcher/internal/testcerts"
	"pgregory.net/rapid"
)

// writeCertAndKey writes a .crt and .key file pair into dir and returns their paths.
func writeCertAndKey(t testing.TB, dir, base string, certPEM, keyPEM []byte) (crtPath, keyPath string) {
	t.Helper()
	crtPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return crtPath, keyPath
}

func TestHashFile(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	t.Run("consistent hash for same content", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(path, []byte("hello world"), 0o644); err != nil {
			t.Fatal(err)
		}

		h1, err := cache.HashFile(path)
		if err != nil {
			t.Fatalf("cache.HashFile: %v", err)
		}
		h2, err := cache.HashFile(path)
		if err != nil {
			t.Fatalf("cache.HashFile: %v", err)
		}
		if h1 != h2 {
			t.Errorf("cache.HashFile returned different hashes for same file: %q vs %q", h1, h2)
		}
		if len(h1) != 64 {
			t.Errorf("cache.HashFile returned hash of length %d, want 64 (SHA-256 hex)", len(h1))
		}
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		p1 := filepath.Join(dir, "a.txt")
		p2 := filepath.Join(dir, "b.txt")
		if err := os.WriteFile(p1, []byte("aaa"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p2, []byte("bbb"), 0o644); err != nil {
			t.Fatal(err)
		}

		h1, _ := cache.HashFile(p1)
		h2, _ := cache.HashFile(p2)
		if h1 == h2 {
			t.Error("cache.HashFile returned same hash for different content")
		}
	})

	t.Run("rejects oversized file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "big.txt")
		if err := os.WriteFile(path, make([]byte, convert.MaxFileSize+1), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := cache.HashFile(path)
		if err == nil {
			t.Fatal("cache.HashFile should reject files exceeding convert.MaxFileSize")
		}
		if !strings.Contains(err.Error(), "size limit") {
			t.Errorf("cache.HashFile error = %q, want it to contain %q", err.Error(), "size limit")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()
		_, err := cache.HashFile("/nonexistent/file.txt")
		if err == nil {
			t.Fatal("cache.HashFile should fail for nonexistent file")
		}
	})
}

func TestHashFile_empty_file(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	h, err := cache.HashFile(path)
	if err != nil {
		t.Fatalf("cache.HashFile(empty) = error %v", err)
	}
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if h != want {
		t.Errorf("cache.HashFile(empty) = %q, want %q", h, want)
	}
}

func TestHashFile_exactly_at_max_size(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	path := filepath.Join(t.TempDir(), "exact-max.bin")
	data := make([]byte, convert.MaxFileSize)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	h, err := cache.HashFile(path)
	if err != nil {
		t.Fatalf("cache.HashFile(exactly convert.MaxFileSize) = error %v, want success", err)
	}
	if len(h) != 64 {
		t.Errorf("cache.HashFile returned hash of length %d, want 64", len(h))
	}
}

func TestChanged(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

	if !cache.Changed(crtPath, keyPath) {
		t.Error("first call should report changed")
	}
	if cache.Changed(crtPath, keyPath) {
		t.Error("second call should report not changed")
	}

	// Replace with new content.
	certPEM2, keyPEM2 := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	writeCertAndKey(t, tmpDir, "test", certPEM2, keyPEM2)

	if !cache.Changed(crtPath, keyPath) {
		t.Error("should report changed after content update")
	}
}

func TestChangedOversizedFile(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	tmpDir := t.TempDir()
	crtPath := filepath.Join(tmpDir, "big.crt")
	keyPath := filepath.Join(tmpDir, "big.key")

	bigData := make([]byte, 11<<20)
	if err := os.WriteFile(crtPath, bigData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !cache.Changed(crtPath, keyPath) {
		t.Error("oversized file should report changed (hash error)")
	}
}

func TestInvalidateHash(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "test", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

	if !cache.Changed(crtPath, keyPath) {
		t.Fatal("first call should report changed")
	}
	if cache.Changed(crtPath, keyPath) {
		t.Fatal("second call should report not changed")
	}

	cache.Invalidate(crtPath)
	if !cache.Changed(crtPath, keyPath) {
		t.Error("should report changed after invalidateHash")
	}
}

func TestChanged_oversized_key_file(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	tmpDir := t.TempDir()
	crtPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	if err := os.WriteFile(crtPath, []byte("small cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	bigData := make([]byte, 11<<20)
	if err := os.WriteFile(keyPath, bigData, 0o600); err != nil {
		t.Fatal(err)
	}

	if !cache.Changed(crtPath, keyPath) {
		t.Error("cache.Changed() should return true when key file exceeds size limit")
	}
}

func TestChanged_nonexistent_cert(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !cache.Changed(filepath.Join(tmpDir, "missing.crt"), keyPath) {
		t.Error("cache.Changed() should return true when cert file doesn't exist")
	}
}

func TestChanged_nonexistent_key(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	tmpDir := t.TempDir()
	crtPath := filepath.Join(tmpDir, "test.crt")
	if err := os.WriteFile(crtPath, []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !cache.Changed(crtPath, filepath.Join(tmpDir, "missing.key")) {
		t.Error("cache.Changed() should return true when key file doesn't exist")
	}
}

func TestChanged_concurrent_callers_are_race_free(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	tmpDir := t.TempDir()

	const nPairs = 20
	paths := make([][2]string, nPairs)
	for i := range nPairs {
		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, fmt.Sprintf("pair-%d", i), "ecdsa")
		crt, key := writeCertAndKey(t, tmpDir, fmt.Sprintf("pair-%d", i), certPEM, keyPEM)
		paths[i] = [2]string{crt, key}
	}

	const nGoroutines = 8
	const iterations = 200

	var wg sync.WaitGroup
	for g := range nGoroutines {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			for i := range iterations {
				p := paths[(gi*iterations+i)%nPairs]
				_ = cache.Changed(p[0], p[1])
				if i%5 == 0 {
					cache.Invalidate(p[0])
				}
			}
		}(g)
	}
	wg.Wait()

	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "post-concurrent", "ecdsa")
	crt, key := writeCertAndKey(t, tmpDir, "post-concurrent", certPEM, keyPEM)
	if !cache.Changed(crt, key) {
		t.Error("cache.Changed should return true for new file after concurrent run")
	}
}

func TestChanged_invariant_idempotent_between_writes(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		cache := convert.NewHashCache()
		tmpDir, err := os.MkdirTemp("", "cert-convert-rapid-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "rapid", "ecdsa")
		crtPath := filepath.Join(tmpDir, "rapid.crt")
		keyPath := filepath.Join(tmpDir, "rapid.key")
		if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}

		if !cache.Changed(crtPath, keyPath) {
			t.Error("first cache.Changed() call must return true")
		}
		nCalls := rapid.IntRange(0, 20).Draw(t, "subsequent_calls")
		for range nCalls {
			if cache.Changed(crtPath, keyPath) {
				t.Error("subsequent cache.Changed() call returned true without invalidate or rewrite")
			}
		}

		cache.Invalidate(crtPath)
		if !cache.Changed(crtPath, keyPath) {
			t.Error("cache.Changed() after invalidateHash must return true")
		}
	})
}

func TestHashFile_deterministic(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	rapid.Check(t, func(t *rapid.T) {
		content := rapid.SliceOfN(rapid.Byte(), 0, 1024).Draw(t, "content")
		dir := os.TempDir()
		path := filepath.Join(dir, "rapid-hash-test.tmp")
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)

		h1, err1 := cache.HashFile(path)
		h2, err2 := cache.HashFile(path)
		if err1 != nil || err2 != nil {
			t.Fatalf("cache.HashFile errors: %v, %v", err1, err2)
		}
		if h1 != h2 {
			t.Errorf("cache.HashFile not deterministic: %q != %q for same content", h1, h2)
		}
		if len(h1) != 64 {
			t.Errorf("cache.HashFile returned hash of length %d, want 64", len(h1))
		}
	})
}

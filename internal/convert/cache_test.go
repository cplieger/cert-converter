package convert_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cplieger/cert-watcher/internal/convert"
	"pgregory.net/rapid"
)

func TestFingerprint(t *testing.T) {
	t.Parallel()

	t.Run("deterministic for same input", func(t *testing.T) {
		t.Parallel()
		a := convert.Fingerprint([]byte("cert"), []byte("key"))
		b := convert.Fingerprint([]byte("cert"), []byte("key"))
		if a != b {
			t.Errorf("Fingerprint not deterministic: %q != %q", a, b)
		}
		if len(a) != 64 {
			t.Errorf("Fingerprint length = %d, want 64 (SHA-256 hex)", len(a))
		}
	})

	t.Run("changes when cert changes", func(t *testing.T) {
		t.Parallel()
		if convert.Fingerprint([]byte("cert-a"), []byte("key")) == convert.Fingerprint([]byte("cert-b"), []byte("key")) {
			t.Error("Fingerprint must differ when the cert differs")
		}
	})

	t.Run("changes when key changes", func(t *testing.T) {
		t.Parallel()
		if convert.Fingerprint([]byte("cert"), []byte("key-a")) == convert.Fingerprint([]byte("cert"), []byte("key-b")) {
			t.Error("Fingerprint must differ when the key differs")
		}
	})

	t.Run("boundary between cert and key is unambiguous", func(t *testing.T) {
		t.Parallel()
		// Moving a byte across the cert/key boundary must change the
		// fingerprint; hashing each input separately guarantees this where a
		// plain concatenation ("ab"+"c" == "a"+"bc") would not.
		if convert.Fingerprint([]byte("ab"), []byte("c")) == convert.Fingerprint([]byte("a"), []byte("bc")) {
			t.Error("Fingerprint collided across the cert/key boundary")
		}
	})

	t.Run("empty inputs are stable and non-empty", func(t *testing.T) {
		t.Parallel()
		if got := convert.Fingerprint(nil, nil); len(got) != 64 {
			t.Errorf("Fingerprint(nil, nil) length = %d, want 64", len(got))
		}
	})
}

func TestChanged(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()

	if !cache.Changed("key", "fp-1") {
		t.Error("first call should report changed")
	}
	if cache.Changed("key", "fp-1") {
		t.Error("second call with same fingerprint should report not changed")
	}
	if !cache.Changed("key", "fp-2") {
		t.Error("call with a new fingerprint should report changed")
	}
	if cache.Changed("key", "fp-2") {
		t.Error("repeat of the new fingerprint should report not changed")
	}
}

func TestChanged_distinct_keys_are_independent(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	if !cache.Changed("a", "fp") {
		t.Fatal("first call for key a should report changed")
	}
	if !cache.Changed("b", "fp") {
		t.Error("first call for key b should report changed even with the same fingerprint")
	}
}

func TestInvalidate(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()

	if !cache.Changed("key", "fp") {
		t.Fatal("first call should report changed")
	}
	if cache.Changed("key", "fp") {
		t.Fatal("second call should report not changed")
	}
	cache.Invalidate("key")
	if !cache.Changed("key", "fp") {
		t.Error("should report changed after Invalidate")
	}
}

func TestPrune(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	cache.Changed("keep", "fp1")
	cache.Changed("drop", "fp2")

	cache.Prune(map[string]struct{}{"keep": {}})

	if cache.Changed("keep", "fp1") {
		t.Error("pruned a key that was in the seen set")
	}
	if !cache.Changed("drop", "fp2") {
		t.Error("key absent from seen set should have been pruned")
	}
}

func TestChanged_concurrent_callers_are_race_free(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()

	const nKeys = 20
	keys := make([]string, nKeys)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
	}

	const nGoroutines = 8
	const iterations = 200

	var wg sync.WaitGroup
	for g := range nGoroutines {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			for i := range iterations {
				k := keys[(gi*iterations+i)%nKeys]
				_ = cache.Changed(k, fmt.Sprintf("fp-%d", i))
				if i%5 == 0 {
					cache.Invalidate(k)
				}
			}
		}(g)
	}
	wg.Wait()

	if !cache.Changed("post-concurrent", "fp") {
		t.Error("Changed should return true for a new key after the concurrent run")
	}
}

func TestChanged_invariant_idempotent_between_changes(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		cache := convert.NewHashCache()
		key := rapid.String().Draw(t, "key")
		fp := rapid.String().Draw(t, "fingerprint")

		if !cache.Changed(key, fp) {
			t.Error("first Changed call must return true")
		}
		n := rapid.IntRange(0, 20).Draw(t, "subsequent_calls")
		for range n {
			if cache.Changed(key, fp) {
				t.Error("subsequent Changed call returned true without a fingerprint change or Invalidate")
			}
		}
		cache.Invalidate(key)
		if !cache.Changed(key, fp) {
			t.Error("Changed after Invalidate must return true")
		}
	})
}

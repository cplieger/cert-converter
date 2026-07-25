package process

import (
	"fmt"
	"sync"
	"testing"

	"pgregory.net/rapid"
)

func TestPairFingerprint(t *testing.T) {
	t.Parallel()

	t.Run("deterministic for same input", func(t *testing.T) {
		t.Parallel()
		a := pairFingerprint([]byte("cert"), []byte("key"))
		b := pairFingerprint([]byte("cert"), []byte("key"))
		if a != b {
			t.Errorf("pairFingerprint not deterministic: %q != %q", a, b)
		}
		if len(a) != 64 {
			t.Errorf("pairFingerprint length = %d, want 64 (SHA-256 hex)", len(a))
		}
	})

	t.Run("changes when cert changes", func(t *testing.T) {
		t.Parallel()
		if pairFingerprint([]byte("cert-a"), []byte("key")) == pairFingerprint([]byte("cert-b"), []byte("key")) {
			t.Error("pairFingerprint must differ when the cert differs")
		}
	})

	t.Run("changes when key changes", func(t *testing.T) {
		t.Parallel()
		if pairFingerprint([]byte("cert"), []byte("key-a")) == pairFingerprint([]byte("cert"), []byte("key-b")) {
			t.Error("pairFingerprint must differ when the key differs")
		}
	})

	t.Run("boundary between cert and key is unambiguous", func(t *testing.T) {
		t.Parallel()
		// Moving a byte across the cert/key boundary must change the
		// fingerprint; hashing each input separately guarantees this where a
		// plain concatenation ("ab"+"c" == "a"+"bc") would not.
		if pairFingerprint([]byte("ab"), []byte("c")) == pairFingerprint([]byte("a"), []byte("bc")) {
			t.Error("pairFingerprint collided across the cert/key boundary")
		}
	})

	t.Run("empty inputs are stable and non-empty", func(t *testing.T) {
		t.Parallel()
		if got := pairFingerprint(nil, nil); len(got) != 64 {
			t.Errorf("pairFingerprint(nil, nil) length = %d, want 64", len(got))
		}
	})
}

func TestMatches(t *testing.T) {
	t.Parallel()
	cache := newHashCache()

	if cache.matches("key", "fp-1") {
		t.Error("a key never recorded must not match")
	}
	cache.record("key", "fp-1")
	if !cache.matches("key", "fp-1") {
		t.Error("a recorded fingerprint must match")
	}
	if cache.matches("key", "fp-2") {
		t.Error("a different fingerprint must not match the recorded one")
	}
	cache.record("key", "fp-2")
	if !cache.matches("key", "fp-2") {
		t.Error("the newly recorded fingerprint must match")
	}
	if cache.matches("key", "fp-1") {
		t.Error("the superseded fingerprint must no longer match")
	}
}

// TestMatches_is_a_pure_query pins the read-only contract record depends on: a
// miss must never record anything, so a conversion that fails after the query
// (nothing recorded) leaves the pair due for a retry with no rollback.
func TestMatches_is_a_pure_query(t *testing.T) {
	t.Parallel()
	cache := newHashCache()

	cache.record("key", "fp-old")
	for range 3 {
		if cache.matches("key", "fp-new") {
			t.Fatal("matches must report false for a fingerprint that was never recorded")
		}
	}
	if !cache.matches("key", "fp-old") {
		t.Error("a failed matches query must not disturb the recorded fingerprint")
	}
}

func TestMatches_distinct_keys_are_independent(t *testing.T) {
	t.Parallel()
	cache := newHashCache()
	cache.record("a", "fp")
	if !cache.matches("a", "fp") {
		t.Fatal("key a should match its recorded fingerprint")
	}
	if cache.matches("b", "fp") {
		t.Error("key b must not match on the strength of key a's fingerprint")
	}
}

func TestPrune(t *testing.T) {
	t.Parallel()
	cache := newHashCache()
	cache.record("keep", "fp1")
	cache.record("drop", "fp2")

	cache.prune(map[string]struct{}{"keep": {}})

	if !cache.matches("keep", "fp1") {
		t.Error("pruned a key that was in the seen set")
	}
	if cache.matches("drop", "fp2") {
		t.Error("key absent from seen set should have been pruned")
	}
}

func TestCache_concurrent_callers_are_race_free(t *testing.T) {
	t.Parallel()
	cache := newHashCache()

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
				fp := fmt.Sprintf("fp-%d", i)
				if !cache.matches(k, fp) {
					cache.record(k, fp)
				}
			}
		}(g)
	}
	wg.Wait()

	if cache.matches("post-concurrent", "fp") {
		t.Error("matches should return false for a key never recorded during the concurrent run")
	}
}

func TestCache_invariant_record_then_match_is_stable(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		cache := newHashCache()
		key := rapid.String().Draw(t, "key")
		fp := rapid.String().Draw(t, "fingerprint")

		if cache.matches(key, fp) {
			t.Error("an unrecorded key must not match")
		}
		cache.record(key, fp)
		n := rapid.IntRange(0, 20).Draw(t, "subsequent_calls")
		for range n {
			if !cache.matches(key, fp) {
				t.Error("a recorded fingerprint must keep matching without another record")
			}
		}
		other := fp + "\x00differs"
		if cache.matches(key, other) {
			t.Error("a different fingerprint must not match the recorded one")
		}
		// The failed query above must not have mutated the entry.
		if !cache.matches(key, fp) {
			t.Error("a failed matches query must leave the recorded fingerprint intact")
		}
	})
}

// TestPairFingerprint_boundary_shift_property generalises the single hardcoded
// "ab"+"c" vs "a"+"bc" case: for arbitrary bytes, ANY two distinct split
// points of the same joined buffer must produce different fingerprints (the
// cert/key boundary is unambiguous), and the same split must be deterministic.
// A concatenate-then-hash implementation fails this for every distinct pair.
func TestPairFingerprint_boundary_shift_property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		joined := rapid.SliceOfN(rapid.Byte(), 2, 64).Draw(t, "joined")
		i := rapid.IntRange(0, len(joined)).Draw(t, "split_a")
		j := rapid.IntRange(0, len(joined)).Draw(t, "split_b")

		fpA := pairFingerprint(joined[:i], joined[i:])
		fpB := pairFingerprint(joined[:j], joined[j:])

		if i == j {
			if fpA != fpB {
				t.Fatalf("pairFingerprint not deterministic at split %d: %q != %q", i, fpA, fpB)
			}
			return
		}
		if fpA == fpB {
			t.Fatalf("pairFingerprint collided across the cert/key boundary: splits %d and %d of %q both gave %q",
				i, j, joined, fpA)
		}
	})
}

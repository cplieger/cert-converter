package convert_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
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

func TestMatches(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()

	if cache.Matches("key", "fp-1") {
		t.Error("a key never recorded must not match")
	}
	cache.Record("key", "fp-1")
	if !cache.Matches("key", "fp-1") {
		t.Error("a recorded fingerprint must match")
	}
	if cache.Matches("key", "fp-2") {
		t.Error("a different fingerprint must not match the recorded one")
	}
	cache.Record("key", "fp-2")
	if !cache.Matches("key", "fp-2") {
		t.Error("the newly recorded fingerprint must match")
	}
	if cache.Matches("key", "fp-1") {
		t.Error("the superseded fingerprint must no longer match")
	}
}

// TestMatches_is_a_pure_query pins the read-only contract Record depends on: a
// miss must never record anything, so a conversion that fails after the query
// (nothing recorded) leaves the pair due for a retry with no rollback.
func TestMatches_is_a_pure_query(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()

	cache.Record("key", "fp-old")
	for range 3 {
		if cache.Matches("key", "fp-new") {
			t.Fatal("Matches must report false for a fingerprint that was never recorded")
		}
	}
	if !cache.Matches("key", "fp-old") {
		t.Error("a failed Matches query must not disturb the recorded fingerprint")
	}
}

func TestMatches_distinct_keys_are_independent(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	cache.Record("a", "fp")
	if !cache.Matches("a", "fp") {
		t.Fatal("key a should match its recorded fingerprint")
	}
	if cache.Matches("b", "fp") {
		t.Error("key b must not match on the strength of key a's fingerprint")
	}
}

func TestPrune(t *testing.T) {
	t.Parallel()
	cache := convert.NewHashCache()
	cache.Record("keep", "fp1")
	cache.Record("drop", "fp2")

	cache.Prune(map[string]struct{}{"keep": {}})

	if !cache.Matches("keep", "fp1") {
		t.Error("pruned a key that was in the seen set")
	}
	if cache.Matches("drop", "fp2") {
		t.Error("key absent from seen set should have been pruned")
	}
}

func TestCache_concurrent_callers_are_race_free(t *testing.T) {
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
				fp := fmt.Sprintf("fp-%d", i)
				if !cache.Matches(k, fp) {
					cache.Record(k, fp)
				}
			}
		}(g)
	}
	wg.Wait()

	if cache.Matches("post-concurrent", "fp") {
		t.Error("Matches should return false for a key never recorded during the concurrent run")
	}
}

func TestCache_invariant_record_then_match_is_stable(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		cache := convert.NewHashCache()
		key := rapid.String().Draw(t, "key")
		fp := rapid.String().Draw(t, "fingerprint")

		if cache.Matches(key, fp) {
			t.Error("an unrecorded key must not match")
		}
		cache.Record(key, fp)
		n := rapid.IntRange(0, 20).Draw(t, "subsequent_calls")
		for range n {
			if !cache.Matches(key, fp) {
				t.Error("a recorded fingerprint must keep matching without another Record")
			}
		}
		other := fp + "\x00differs"
		if cache.Matches(key, other) {
			t.Error("a different fingerprint must not match the recorded one")
		}
		// The failed query above must not have mutated the entry.
		if !cache.Matches(key, fp) {
			t.Error("a failed Matches query must leave the recorded fingerprint intact")
		}
	})
}

// TestFingerprint_boundary_shift_property generalises the single hardcoded
// "ab"+"c" vs "a"+"bc" case: for arbitrary bytes, ANY two distinct split
// points of the same joined buffer must produce different fingerprints (the
// cert/key boundary is unambiguous), and the same split must be deterministic.
// A concatenate-then-hash implementation fails this for every distinct pair.
func TestFingerprint_boundary_shift_property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		joined := rapid.SliceOfN(rapid.Byte(), 2, 64).Draw(t, "joined")
		i := rapid.IntRange(0, len(joined)).Draw(t, "split_a")
		j := rapid.IntRange(0, len(joined)).Draw(t, "split_b")

		fpA := convert.Fingerprint(joined[:i], joined[i:])
		fpB := convert.Fingerprint(joined[:j], joined[j:])

		if i == j {
			if fpA != fpB {
				t.Fatalf("Fingerprint not deterministic at split %d: %q != %q", i, fpA, fpB)
			}
			return
		}
		if fpA == fpB {
			t.Fatalf("Fingerprint collided across the cert/key boundary: splits %d and %d of %q both gave %q",
				i, j, joined, fpA)
		}
	})
}

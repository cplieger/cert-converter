package process_test

import (
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/process"
)

// CacheCheckerContract verifies behavioral invariants that any CacheChecker
// implementation must satisfy. The cache is keyed by an opaque string and a
// content fingerprint and performs no file I/O.
func CacheCheckerContract(t *testing.T, newCache func() process.CacheChecker) {
	t.Helper()

	t.Run("Changed_returns_true_on_first_call", func(t *testing.T) {
		cache := newCache()
		if !cache.Changed("k", "fp") {
			t.Fatal("expected Changed to return true on first call")
		}
	})

	t.Run("Changed_returns_false_without_fingerprint_change", func(t *testing.T) {
		cache := newCache()
		cache.Changed("k", "fp") // prime
		if cache.Changed("k", "fp") {
			t.Fatal("expected Changed to return false when the fingerprint is unchanged")
		}
	})

	t.Run("Changed_returns_true_on_fingerprint_change", func(t *testing.T) {
		cache := newCache()
		cache.Changed("k", "fp-1") // prime
		if !cache.Changed("k", "fp-2") {
			t.Fatal("expected Changed to return true when the fingerprint changes")
		}
	})

	t.Run("Invalidate_causes_next_Changed_to_return_true", func(t *testing.T) {
		cache := newCache()
		cache.Changed("k", "fp") // prime
		cache.Invalidate("k")
		if !cache.Changed("k", "fp") {
			t.Fatal("expected Changed to return true after Invalidate")
		}
	})

	t.Run("Prune_removes_entries_not_in_seen", func(t *testing.T) {
		cache := newCache()
		cache.Changed("k1", "fp1")
		cache.Changed("k2", "fp2")

		// Only k1 is in the seen set; k2 should be pruned.
		cache.Prune(map[string]struct{}{"k1": {}})

		if cache.Changed("k1", "fp1") {
			t.Fatal("expected k1 to remain cached after Prune")
		}
		if !cache.Changed("k2", "fp2") {
			t.Fatal("expected k2 to report changed after being pruned")
		}
	})
}

func TestHashCacheContract(t *testing.T) {
	CacheCheckerContract(t, func() process.CacheChecker {
		return convert.NewHashCache()
	})
}

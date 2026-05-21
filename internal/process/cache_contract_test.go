package process_test

import (
	"os"
	"path/filepath"
	"testing"

	"cert-watcher/internal/convert"
	"cert-watcher/internal/process"
)

// CacheCheckerContract verifies behavioral invariants that any CacheChecker
// implementation must satisfy.
func CacheCheckerContract(t *testing.T, newCache func() process.CacheChecker) {
	t.Helper()

	writeTempFile := func(t *testing.T, dir, name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("Changed_returns_true_on_first_call", func(t *testing.T) {
		cache := newCache()
		dir := t.TempDir()
		crt := writeTempFile(t, dir, "a.crt", "cert-data")
		key := writeTempFile(t, dir, "a.key", "key-data")

		if !cache.Changed(crt, key) {
			t.Fatal("expected Changed to return true on first call")
		}
	})

	t.Run("Changed_returns_false_without_content_change", func(t *testing.T) {
		cache := newCache()
		dir := t.TempDir()
		crt := writeTempFile(t, dir, "a.crt", "cert-data")
		key := writeTempFile(t, dir, "a.key", "key-data")

		cache.Changed(crt, key) // prime
		if cache.Changed(crt, key) {
			t.Fatal("expected Changed to return false on subsequent call without content change")
		}
	})

	t.Run("Invalidate_causes_next_Changed_to_return_true", func(t *testing.T) {
		cache := newCache()
		dir := t.TempDir()
		crt := writeTempFile(t, dir, "a.crt", "cert-data")
		key := writeTempFile(t, dir, "a.key", "key-data")

		cache.Changed(crt, key) // prime
		cache.Invalidate(crt)
		if !cache.Changed(crt, key) {
			t.Fatal("expected Changed to return true after Invalidate")
		}
	})

	t.Run("Prune_removes_entries_not_in_seen", func(t *testing.T) {
		cache := newCache()
		dir := t.TempDir()
		crt1 := writeTempFile(t, dir, "a.crt", "cert-a")
		key1 := writeTempFile(t, dir, "a.key", "key-a")
		crt2 := writeTempFile(t, dir, "b.crt", "cert-b")
		key2 := writeTempFile(t, dir, "b.key", "key-b")

		cache.Changed(crt1, key1)
		cache.Changed(crt2, key2)

		// Only crt1 is in the seen set; crt2 should be pruned.
		seen := map[string]struct{}{crt1: {}}
		cache.Prune(seen)

		// crt1 still cached — unchanged.
		if cache.Changed(crt1, key1) {
			t.Fatal("expected crt1 to remain cached after Prune")
		}
		// crt2 was pruned — should report changed.
		if !cache.Changed(crt2, key2) {
			t.Fatal("expected crt2 to report changed after being pruned")
		}
	})
}

func TestHashCacheContract(t *testing.T) {
	CacheCheckerContract(t, func() process.CacheChecker {
		return convert.NewHashCache()
	})
}

package convert

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// HashCache tracks a content fingerprint per cert/key key so the scanner can
// skip pairs whose inputs have not changed since the last scan. It performs NO
// file I/O: the scanner reads each cert and key once (through a confined
// *os.Root), derives a fingerprint with Fingerprint, and asks Matches whether
// it equals the last recorded value. Keeping the cache I/O-free is what lets
// a scan read each input exactly once.
//
// Query and mutation are deliberately separate: Matches only reads, and Record
// commits a fingerprint at the success boundary (after the conversion it
// describes actually wrote a PFX). A caller therefore cannot leave the cache
// claiming a pair is current on the strength of a conversion that failed, and an
// early exit added between the query and the write is safe by construction — no
// rollback obligation exists to forget.
type HashCache struct {
	fingerprints map[string]string
	mu           sync.Mutex
}

// NewHashCache returns an initialised HashCache.
func NewHashCache() *HashCache {
	return &HashCache{fingerprints: make(map[string]string)}
}

// Fingerprint derives a collision-resistant fingerprint of a cert+key pair from
// their PEM bytes. Each input is hashed separately before the two digests are
// combined, so the boundary between cert and key is unambiguous: a byte moved
// from the key into the cert still changes the fingerprint (a plain
// concatenation would not detect that shift).
func Fingerprint(certPEM, keyPEM []byte) string {
	certSum := sha256.Sum256(certPEM)
	keySum := sha256.Sum256(keyPEM)
	h := sha256.New()
	h.Write(certSum[:])
	h.Write(keySum[:])
	return hex.EncodeToString(h.Sum(nil))
}

// Matches reports whether key's recorded fingerprint equals fingerprint. It is
// a pure query: a key never seen (or one whose recorded fingerprint differs)
// reports false and the cache is left untouched, so a caller that goes on to
// fail — or returns early for any other reason — owes the cache nothing.
func (c *HashCache) Matches(key, fingerprint string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, ok := c.fingerprints[key]
	return ok && prev == fingerprint
}

// Record commits fingerprint as key's current value. Callers must call it only
// after the conversion the fingerprint describes has succeeded, so a later scan
// can trust a Matches hit to mean "the recorded output was actually produced
// from these bytes".
func (c *HashCache) Record(key, fingerprint string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fingerprints[key] = fingerprint
}

// Prune removes fingerprint entries for keys not present in seen.
func (c *HashCache) Prune(seen map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.fingerprints {
		if _, ok := seen[k]; !ok {
			delete(c.fingerprints, k)
		}
	}
}

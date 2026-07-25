package convert

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// HashCache tracks a content fingerprint per cert/key key so the scanner can
// skip pairs whose inputs have not changed since the last scan. It performs NO
// file I/O: the scanner reads each cert and key once (through a confined
// *os.Root), derives a fingerprint with Fingerprint, and asks Changed whether
// it differs from the last seen value. Keeping the cache I/O-free is what lets
// a scan read each input exactly once.
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

// Changed reports whether key's fingerprint differs from the last seen value
// (or was never seen), recording the new fingerprint when it differs. The
// caller MUST Invalidate(key) if the conversion that follows a true result
// fails, so the next scan retries rather than treating the failed pair as
// already current.
func (c *HashCache) Changed(key, fingerprint string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.fingerprints[key]; ok && prev == fingerprint {
		return false
	}
	c.fingerprints[key] = fingerprint
	return true
}

// Invalidate drops the cached fingerprint for key so the next Changed retries.
func (c *HashCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.fingerprints, key)
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

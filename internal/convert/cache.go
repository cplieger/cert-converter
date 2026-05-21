package convert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// fileHash stores the last known hash of a cert+key pair.
type fileHash struct {
	certHash string
	keyHash  string
}

// HashCache tracks file hashes to skip unchanged cert pairs.
type HashCache struct {
	hashes map[string]fileHash
	mu     sync.Mutex
}

// NewHashCache returns an initialised HashCache.
func NewHashCache() *HashCache {
	return &HashCache{hashes: make(map[string]fileHash)}
}

// HashFile returns the hex-encoded SHA-256 of a file's contents.
func (c *HashCache) HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > MaxFileSize {
		return "", fmt.Errorf("file %s exceeds 10 MB size limit (%d bytes)", filepath.Base(path), info.Size())
	}

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxFileSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Changed returns true if the cert or key file has changed since last check.
func (c *HashCache) Changed(crtPath, keyPath string) bool {
	certH, err := c.HashFile(crtPath)
	if err != nil {
		return true
	}
	keyH, err := c.HashFile(keyPath)
	if err != nil {
		return true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	prev, exists := c.hashes[crtPath]
	if !exists || prev.certHash != certH || prev.keyHash != keyH {
		c.hashes[crtPath] = fileHash{certHash: certH, keyHash: keyH}
		return true
	}
	return false
}

// Invalidate removes the cached hash for a cert path so the next scan retries.
func (c *HashCache) Invalidate(crtPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.hashes, crtPath)
}

// Prune removes hash entries for paths not present in seen.
func (c *HashCache) Prune(seen map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.hashes {
		if _, ok := seen[k]; !ok {
			delete(c.hashes, k)
		}
	}
}

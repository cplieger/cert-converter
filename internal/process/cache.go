package process

import "cert-watcher/internal/convert"

// Compile-time assertion: *HashCache satisfies CacheChecker.
var _ CacheChecker = (*convert.HashCache)(nil)

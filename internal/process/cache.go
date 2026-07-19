package process

import "github.com/cplieger/cert-converter/internal/convert"

// Compile-time assertion: *HashCache satisfies CacheChecker.
var _ CacheChecker = (*convert.HashCache)(nil)

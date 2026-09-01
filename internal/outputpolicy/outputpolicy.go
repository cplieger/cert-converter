// Package outputpolicy owns the configured output formats, layout and lifecycle:
// which artifacts are generated, where they land, and what happens when their
// source disappears.
package outputpolicy

import (
	"slices"
	"strings"
)

// Lifecycle decides what happens to an output artifact whose source disappeared.
type Lifecycle string

// The three lifecycle modes.
const (
	// LifecycleWarn reports orphaned outputs and deletes nothing.
	LifecycleWarn Lifecycle = "warn"
	// LifecycleSync makes the output tree mirror the input tree, deleting an
	// artifact whose source is gone.
	LifecycleSync Lifecycle = "sync"
	// LifecycleKeep leaves orphans in place silently.
	LifecycleKeep Lifecycle = "keep"
)

// lifecycleModes is the accepted value domain, stated ONCE: ParseLifecycle
// accepts exactly these and LifecycleModes advertises exactly these, so a mode
// cannot be added, renamed or removed on one side only — accepted but absent
// from the operator warning, or advertised but still rejected.
var lifecycleModes = [...]Lifecycle{LifecycleWarn, LifecycleSync, LifecycleKeep}

// ParseLifecycle normalises a raw OUTPUT_LIFECYCLE value.
func ParseLifecycle(raw string) (mode Lifecycle, known bool) {
	normalized := Lifecycle(strings.ToLower(strings.TrimSpace(raw)))
	if normalized == "" {
		normalized = LifecycleWarn // unset means the default, not an unrecognised value
	}
	if slices.Contains(lifecycleModes[:], normalized) {
		return normalized, true
	}
	return LifecycleWarn, false
}

// LifecycleModes returns the accepted OUTPUT_LIFECYCLE values, so the caller that
// read the environment variable can name them in its warning without re-listing
// the domain ParseLifecycle owns.
func LifecycleModes() []Lifecycle {
	return slices.Clone(lifecycleModes[:])
}

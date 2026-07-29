// Package outputpolicy owns the OUTPUT_LIFECYCLE value domain: what happens to
// an output bundle whose input pair has disappeared.
//
// It is a package of its own rather than three constants inside
// internal/process because the two ends of the knob need the same values for
// different reasons: internal/config parses the operator's raw environment value
// and names an unrecognised one in a warning, while internal/process acts on the
// parsed mode when it reconciles the output tree against the input tree. Holding
// the domain in the orchestrator put the configuration layer ABOVE it — config
// imported process, and so transitively convert, layout and atomicfile, for a
// three-value string enum and a short switch — which also meant nothing in
// process could ever read config without an import cycle.
//
// Neither package sits above this one: both import it, it imports neither of
// them, and like internal/layout it depends on nothing outside the standard
// library, so the knob's normalisation is testable on its own.
package outputpolicy

import (
	"slices"
	"strings"
)

// Lifecycle decides what happens to an output whose input pair has disappeared.
type Lifecycle string

// The three lifecycle modes.
const (
	// LifecycleWarn reports orphaned outputs and deletes nothing. The DEFAULT:
	// deletion is opt-in, so an upgrade cannot remove files on its own.
	LifecycleWarn Lifecycle = "warn"
	// LifecycleSync makes the output tree mirror the input tree, deleting a bundle
	// whose source is gone.
	LifecycleSync Lifecycle = "sync"
	// LifecycleKeep leaves orphans in place silently.
	LifecycleKeep Lifecycle = "keep"
)

// lifecycleModes is the accepted value domain, stated ONCE: ParseLifecycle
// accepts exactly these and LifecycleModes advertises exactly these, so a mode
// cannot be added, renamed or removed on one side only — accepted but absent
// from the operator warning, or advertised but still rejected.
var lifecycleModes = [...]Lifecycle{LifecycleWarn, LifecycleSync, LifecycleKeep}

// ParseLifecycle normalises a raw OUTPUT_LIFECYCLE value. An unrecognised value
// falls back to the default with known false, so the caller that read the
// environment is the one that names it in a warning. An empty or whitespace-only
// value is the UNSET case and is recognised: it returns LifecycleWarn with known
// true, so leaving OUTPUT_LIFECYCLE unset warns about nothing — the same split
// convert.EncoderName documents for PFX_ENCODER.
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
// the domain ParseLifecycle owns. The clone keeps a caller from mutating the
// package's own inventory.
func LifecycleModes() []Lifecycle {
	return slices.Clone(lifecycleModes[:])
}

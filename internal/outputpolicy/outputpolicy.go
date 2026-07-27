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

import "strings"

// Lifecycle decides what happens to an output whose input pair has disappeared.
type Lifecycle string

// The three lifecycle modes.
const (
	// LifecycleWarn reports orphaned outputs and deletes nothing. The DEFAULT:
	// deletion is opt-in, so an upgrade cannot remove files on its own.
	LifecycleWarn Lifecycle = "warn"
	// LifecycleSync makes the output tree mirror the input tree, deleting a bundle
	// whose source is gone. The homelab deployment opts into this explicitly.
	LifecycleSync Lifecycle = "sync"
	// LifecycleKeep leaves orphans in place silently.
	LifecycleKeep Lifecycle = "keep"
)

// ParseLifecycle normalises a raw OUTPUT_LIFECYCLE value. An unrecognised value
// falls back to the default with known false, so the caller that read the
// environment is the one that names it in a warning.
func ParseLifecycle(raw string) (mode Lifecycle, known bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(LifecycleSync):
		return LifecycleSync, true
	case string(LifecycleKeep):
		return LifecycleKeep, true
	case "", string(LifecycleWarn):
		return LifecycleWarn, true
	default:
		return LifecycleWarn, false
	}
}

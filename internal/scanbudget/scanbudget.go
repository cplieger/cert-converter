// Package scanbudget owns the MAX_SCAN_ENTRIES value domain: how many entries one walk
// of a mounted tree this app does not own may enumerate before it stops.
//
// It is a package of its own for the reason internal/outputpolicy is: the two ends of
// the knob need the same values for different reasons — internal/config parses the
// operator's raw value, clamps it and names a repaired one in a warning, while
// internal/process and internal/watch enforce the parsed number — and neither end may
// import the other. Holding the number in either one forced the other to spell it again
// and assert the equality in prose. It depends on nothing outside the standard library,
// so it adds no edge that could cycle.
package scanbudget

// Default is how many entries one walk enumerates when the operator set nothing, and the
// floor under a walk assembled with no budget at all.
//
// A Caddy certificate directory holds a handful of entries per domain, so ten thousand is
// already orders of magnitude above any real deployment while keeping the walk's worst
// case small.
const Default = 10_000

// Ceiling is the highest MAX_SCAN_ENTRIES this app accepts before clamping. It is the
// historical hardcoded bound, kept as the upper limit so raising the setting cannot
// restore an effectively unbounded walk.
const Ceiling = 200_000

// Effective resolves an injected budget: non-positive means Default, so a walk assembled
// field by field without one is bounded rather than unbounded.
func Effective(n int) int {
	if n > 0 {
		return n
	}
	return Default
}

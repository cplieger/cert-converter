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

// AlertedPhrase is the substring the README publishes as CertConverterInputTreeTooLarge's whole
// matcher. It lives with the knob it is about because BOTH walks over /input carry it — the scan
// walk (internal/process) and the watch-set walk (internal/watch) — and the exclusion it implies
// is app-wide: no other condition's message may contain it, or that condition fires the /input rule
// and hands the operator the /input remediation for the wrong mount. Held in either enforcing
// package, the other had to spell it again and each could only assert the invariant over its own
// messages.
const AlertedPhrase = "holds more entries than one scan will enumerate"

// InputTreeTooLarge is the leading clause every /input budget-stop message opens with; each walk
// appends what IT stopped doing.
const InputTreeTooLarge = "the /input tree " + AlertedPhrase

// InputRemediation is the operator action for an /input budget stop, naming both ways out: a mount
// pointed at the wrong tree, or a legitimately large certificate directory. ONE string because both
// /input walks stop for the same reason and ask for the same thing. A walk over a DIFFERENT tree
// words its own (internal/process's /output orphan walk), which is why this one names /input.
const InputRemediation = "check that /input is mounted at the certificate directory and holds nothing else, or raise MAX_SCAN_ENTRIES if the tree is legitimately this large"

// Effective resolves an injected budget: non-positive means Default, so a walk assembled
// field by field without one is bounded rather than unbounded.
func Effective(n int) int {
	if n > 0 {
		return n
	}
	return Default
}

// Counter charges one walk's enumerated entries against a budget. It is the ONE
// implementation of the MAX_SCAN_ENTRIES enforcement rule, so the app's walks cannot
// disagree about what the operator's number means.
//
// Charge exactly once per ENUMERATED path — what the walk TOUCHED, not what it kept —
// and charge AFTER the walk's error arm. A tree walk reports a directory it could not
// finish reading through the callback for that directory's OWN path, which its parent
// already charged, so charging above the error arm counts one path twice and enforces the
// operator's ceiling below its configured value. Every walk in this app honours this:
// internal/process's two walks and internal/watch's two watch-set walks.
//
// The zero value is usable and bounded: a Counter assembled field by field, which this
// repo's focused tests do, resolves its ceiling to Default rather than to zero.
type Counter struct {
	max     int
	entries int
}

// NewCounter builds a Counter over an injected budget. Resolution is Max's: it treats
// non-positive as Default on every read, so a Counter built here and a zero-value one
// are bounded by the same single rule.
func NewCounter(limit int) Counter {
	return Counter{max: limit}
}

// Charge counts one enumerated path and reports whether it is within budget.
func (c *Counter) Charge() bool {
	c.entries++
	return c.entries <= c.Max()
}

// Count is how many paths have been charged so far, for the refusing walk's own
// diagnostic; each walk words that record for its own tree.
func (c *Counter) Count() int { return c.entries }

// Max is the resolved ceiling: non-positive means Default (Effective). It is the ONE
// site that resolves, so a zero-value Counter and a NewCounter one are bounded by the
// same rule.
func (c *Counter) Max() int { return Effective(c.max) }

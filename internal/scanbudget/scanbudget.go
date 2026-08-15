// Package scanbudget owns the MAX_SCAN_ENTRIES value domain: how many entries one walk
// of a mounted tree this app does not own may enumerate before it stops.
package scanbudget

// Default is how many entries one walk enumerates when the operator set nothing, and the
// floor under a walk assembled with no budget at all.
const Default = 10_000

// Ceiling is the highest MAX_SCAN_ENTRIES this app accepts before clamping.
const Ceiling = 200_000

// AlertedPhrase is the substring the README publishes as CertConverterInputTreeTooLarge's whole
// matcher.
const AlertedPhrase = "holds more entries than one scan will enumerate"

// InputTreeTooLarge is the leading clause every /input budget-stop message opens with; each walk
// appends what IT stopped doing.
const InputTreeTooLarge = "the /input tree " + AlertedPhrase

// InputRemediation is the operator action for an /input budget stop, naming both ways out: a mount
// pointed at the wrong tree, or a legitimately large certificate directory.
const InputRemediation = "check that /input is mounted at the certificate directory and holds nothing else, or raise MAX_SCAN_ENTRIES if the tree is legitimately this large"

// Effective resolves an injected budget: non-positive means Default, so a walk assembled
// field by field without one is bounded rather than unbounded.
func Effective(n int) int {
	if n > 0 {
		return n
	}
	return Default
}

// Counter charges one walk's enumerated entries against a budget.
type Counter struct {
	max     int
	entries int
}

// NewCounter builds a Counter over an injected budget.
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

// Max is the resolved ceiling: non-positive means Default (Effective).
func (c *Counter) Max() int { return Effective(c.max) }

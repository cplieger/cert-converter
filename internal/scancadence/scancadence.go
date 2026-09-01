// Package scancadence owns the FALLBACK_SCAN_HOURS value domain: the longest this
// app will go without a full reconciliation of the input tree, the rule that
// resolves one from the operator's configured cadence, and the operator
// vocabulary every cadence-bearing record carries.
package scancadence

import "time"

// Floor is the longest this app will go without a FULL reconciliation of the
// input tree in ANY configuration, including FALLBACK_SCAN_HOURS=0/false.
const Floor = 24 * time.Hour

// Effective reports the periodic safety-net scan's interval for a configured
// fallback value: the operator's cadence when at or below the floor, and the
// floor otherwise (covers the 0/false opt-out, a negative value, and a cadence
// above the floor including the 10-year ceiling internal/config clamps to).
func Effective(fallback time.Duration) time.Duration {
	if fallback > 0 && fallback < Floor {
		return fallback
	}
	return Floor
}

// label renders a periodic-rescan interval for an operator-facing log record.
func label(d time.Duration) string {
	if d <= 0 {
		return "disabled"
	}
	return d.String()
}

// CoverageAttrs renders the coverage pair every cadence-bearing record carries:
// fallback_scan (the operator's own rescan cadence, "disabled" when off) and
// scan_floor (the guaranteed reconciliation cadence health's deadline derives from).
func CoverageAttrs(fallback time.Duration) []any {
	return []any{
		"fallback_scan", label(fallback),
		"scan_floor", Effective(fallback).String(),
	}
}

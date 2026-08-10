// Package scancadence owns the FALLBACK_SCAN_HOURS value domain: the longest this app
// will go without a full reconciliation of the input tree in any configuration, the rule
// that resolves one from the operator's configured cadence, and the operator vocabulary
// every cadence-bearing record carries.
//
// It is a package of its own for the reason internal/scanbudget is: the two ends of the
// knob need the same values for different reasons — internal/config parses the operator's
// cadence, clamps it and warns when the floor overrides it, while internal/watch arms its
// timers from the resolved value and main derives the health marker's freshness deadline
// from it — and neither end may import the other. Holding the domain in internal/watch
// made internal/config import the mechanism it configures and forced watch to export two
// functions no watching consumer needs. It depends on nothing outside the standard
// library, so it adds no edge that could cycle.
package scancadence

import "time"

// Floor is the longest this app will go without a FULL reconciliation of
// the input tree — a whole-tree watch-set re-assert followed by a certificate scan
// — in ANY configuration, including FALLBACK_SCAN_HOURS=0/false.
//
// It is a floor, not a cadence: every scan re-arms the timer that enforces it,
// exactly as the configured fallback interval is re-armed, so a deployment whose
// fsnotify events arrive normally never pays for a reconciliation walk at all. Only
// a process that has gone a whole floor without scanning reaches it.
//
// Why it exists. fsnotify events are a LATENCY optimisation here, not the liveness
// mechanism: one walk's enumeration is deliberately BOUNDED (addWatchDirs caps how many
// paths a walk visits, because the tree it enumerates is one this app does not own), so
// a tree larger than that budget is watched only in part; the kernel refuses a
// registration outright once the per-UID inotify quota is spent; the kernel discards
// watches without emitting an event at all (IN_UNMOUNT/IN_IGNORED); and a descriptor
// the kernel refused is only recovered by a re-assert. An app that notices change
// ONLY through events therefore has states in which it converts nothing indefinitely.
// This floor is what makes eventual convergence a property of the app rather than of
// its configuration, and it is what gives the health marker a guaranteed refresh
// cadence in every mode (Effective), so a wedged loop can be restarted even
// with the routine rescan switched off.
//
// Why 24h and not the documented 6h default. An operator who sets
// FALLBACK_SCAN_HOURS=0 is escaping periodic full walks — usually because /input is a
// network mount where they are expensive — so re-enabling the default cadence under
// another name would overrule the choice this setting exists to offer. The floor costs
// them ONE walk per day of inactivity, a quarter of the default cadence's, and the
// certificate timescale is what makes a day cheap: an ACME issuer renews a 90-day
// certificate about 30 days before it expires (Caddy at two thirds of the lifetime),
// so a renewal whose event was lost has weeks of slack before anything downstream
// serves an expired chain, and a day of added latency spends a rounding error of it.
const Floor = 24 * time.Hour

// Effective reports the periodic safety-net scan's interval for a
// configured fallback value: the operator's cadence while they chose one below the
// floor, and the reconciliation floor otherwise — which covers the 0/false opt-out,
// a negative value, and a cadence above the floor (including the 10-year ceiling
// internal/config clamps to, at which no rescan would ever have arrived).
//
// One timer serves both, because they are the same mechanism — a full re-assert plus
// a full scan — differing only in who chose the number. internal/watch's
// safetyNetTrigger reports which one did, so the two never become indistinguishable in
// the log.
//
// It is also how often the health marker is guaranteed to be refreshed under a given
// FALLBACK_SCAN_HOURS interval (non-positive = the 0/false opt-out): every safety-net
// scan calls the caller's onChange, and that is what writes the marker, so this is the
// cadence a probe staleness deadline must be derived from — the composition root's
// `health` subcommand arms health.WithMaxAge from it. One function rather than two
// names for it, because the marker's guaranteed refresh cadence and the safety-net
// timer's interval are the same number by construction.
func Effective(fallback time.Duration) time.Duration {
	if fallback > 0 && fallback < Floor {
		return fallback
	}
	return Floor
}

// label renders a periodic-rescan interval for an operator-facing log
// record. A non-positive interval is reported as "disabled" rather than as a
// bare "0s": that value is the operator's confirmation that
// FALLBACK_SCAN_HOURS=0/false took effect, i.e. that no ROUTINE rescan runs on
// their cadence. It does NOT mean nothing rescans — the reconciliation floor
// still does, and the probe's staleness deadline is derived from that floor
// (Effective), which is why every record carrying this label also
// carries scan_floor. It is unexported because CoverageAttrs is the one home for
// the pair: the composition root, internal/config and internal/watch's
// degraded-path WARNs all render fallback_scan through that, never by calling
// this directly.
func label(d time.Duration) string {
	if d <= 0 {
		return "disabled"
	}
	return d.String()
}

// CoverageAttrs renders the coverage pair every cadence-bearing record
// carries: fallback_scan (the operator's own rescan cadence, "disabled"
// when switched off) and scan_floor (the guaranteed reconciliation
// cadence the health deadline is derived from). One home for the keys,
// their order and both renderings, so the startup line, config's
// fallback WARNs and internal/watch's degraded-path records cannot drift.
func CoverageAttrs(fallback time.Duration) []any {
	return []any{
		// fallback_scan answers only "is the operator's own cadence running?", so
		// label renders a non-positive interval as "disabled"; scan_floor beside
		// it is what keeps that from reading as "nothing will ever revisit this".
		"fallback_scan", label(fallback),
		"scan_floor", Effective(fallback).String(),
	}
}

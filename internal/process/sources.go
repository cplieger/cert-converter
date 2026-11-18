package process

import (
	"maps"
	"slices"
	"time"

	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

// SourceOutcome is what the latest scan that reached a source made of it.
type SourceOutcome int

// The source outcomes, in the order SourceOutcomeNames lists them.
const (
	SourceConverted SourceOutcome = iota
	SourceUnchanged
	SourceFailed
	SourceOrphan
	SourceUnreadable
	SourceUnwritable
	SourceCollided
	SourceExcluded
	SourceVanished
	sourceOutcomeCount
)

// sourceOutcomeNames spells each SourceOutcome as the last_scan_sources outcome
// label spells the same result, so both metric families share one vocabulary.
var sourceOutcomeNames = [sourceOutcomeCount]string{
	"converted", "unchanged", "failed", "orphan", "unreadable",
	"unwritable", "collided", "excluded", "vanished",
}

// String names the outcome as the metrics label spells it.
func (o SourceOutcome) String() string { return sourceOutcomeNames[o] }

// SourceOutcomeNames returns every outcome's name, in SourceOutcome order, in a
// new slice.
func SourceOutcomeNames() []string { return slices.Clone(sourceOutcomeNames[:]) }

// SourceState is one source's fact as the scanner holds it after a scan.
type SourceState struct {
	// LastConverted is the zero time when no output artifact is known.
	LastConverted time.Time
	// Path is relative to /input, unsanitised.
	Path    string
	Outcome SourceOutcome
}

// sourceFact is the Scanner's memory of one source across scans.
type sourceFact struct {
	convertedAt time.Time
	outcome     SourceOutcome
	// timeRead is whether convertedAt is settled in this process: a conversion set
	// it, or the artifact mtime lookup ran.
	timeRead bool
}

// conversionClock is indirected for the same reason sweepClock is.
var conversionClock = time.Now

// outcomeOfStatus maps a per-source conversion status to its outcome; statusUnset
// resolves none.
func outcomeOfStatus(status conversionStatus) (SourceOutcome, bool) {
	switch status {
	case statusConverted:
		return SourceConverted, true
	case statusUnchanged:
		return SourceUnchanged, true
	case statusFailed:
		return SourceFailed, true
	case statusOrphan:
		return SourceOrphan, true
	case statusUnreadable:
		return SourceUnreadable, true
	case statusVanished:
		return SourceVanished, true
	case statusUnwritable:
		return SourceUnwritable, true
	case statusCollided:
		return SourceCollided, true
	case statusExcluded:
		return SourceExcluded, true
	default:
		return 0, false
	}
}

// resolve counts status for rel and remembers it as rel's outcome this scan.
func (sw *scanWalk) resolve(rel string, status conversionStatus) {
	sw.results = append(sw.results, status)
	if outcome, ok := outcomeOfStatus(status); ok {
		sw.noteOutcome(rel, outcome)
	}
}

// noteOutcome remembers rel's outcome this scan without counting it, for a site
// whose count is kept elsewhere.
func (sw *scanWalk) noteOutcome(rel string, outcome SourceOutcome) {
	if sw.outcomes == nil {
		sw.outcomes = make(map[string]SourceOutcome)
	}
	sw.outcomes[rel] = outcome
}

// artifactsOf returns every artifact path the enabled formats derive from rel.
func (sw *scanWalk) artifactsOf(rel string) []string {
	outStem := layout.SourceStem(rel)
	if sw.layoutMode == outputpolicy.LayoutFlat {
		outStem = layout.FlatStem(outStem)
	}
	return layout.ArtifactsFor(outStem, sw.formats)
}

// ownsArtifacts reports whether rel's artifacts, artifacts, are rel's own output
// and not another source's: an excluded source registers none, so an expected
// one is another source's, and a flat stem belongs to its owner, or to its sole
// claimant while it has none.
func (sw *scanWalk) ownsArtifacts(rel string, outcome SourceOutcome, artifacts []string) bool {
	if outcome == SourceExcluded && slices.ContainsFunc(artifacts, func(a string) bool {
		_, expected := sw.expected[a]
		return expected
	}) {
		return false
	}
	if sw.layoutMode != outputpolicy.LayoutFlat {
		return true
	}
	claim := sw.claims[layout.FlatStem(layout.SourceStem(rel))]
	if claim.Owner != "" {
		return claim.Owner == rel
	}
	return len(claim.Members) == 0 || slices.Equal(claim.Members, []string{rel})
}

// mergeSources folds this scan's outcomes into the Scanner's memory. A source
// leaves only when a scan ended by walkErr == nil reached its path and did not
// resolve it, the proof keepObserved requires; any other unresolved source keeps
// its fact, as carryUnproven keeps the counts.
func (s *Scanner) mergeSources(sw *scanWalk, out *store, walkErr error) {
	for rel, outcome := range sw.outcomes {
		fact := s.sources[rel]
		fact.outcome = outcome
		switch {
		case outcome == SourceConverted:
			fact.convertedAt, fact.timeRead = conversionClock(), true
		case !fact.timeRead:
			// After a restart the artifacts' mtime is the only record of the last
			// conversion that survives.
			if artifacts := sw.artifactsOf(rel); sw.ownsArtifacts(rel, outcome, artifacts) {
				fact.convertedAt, fact.timeRead = out.newestArtifact(artifacts), true
			}
		}
		s.sources[rel] = fact
	}
	if walkErr != nil {
		return
	}
	for rel := range s.sources {
		if _, resolved := sw.outcomes[rel]; !resolved && sw.reach.input(rel) {
			delete(s.sources, rel)
		}
	}
}

// sourceStates returns the Scanner's memory sorted by path, in a new slice.
func (s *Scanner) sourceStates() []SourceState {
	states := make([]SourceState, 0, len(s.sources))
	for _, rel := range slices.Sorted(maps.Keys(s.sources)) {
		fact := s.sources[rel]
		states = append(states, SourceState{Path: rel, Outcome: fact.outcome, LastConverted: fact.convertedAt})
	}
	return states
}

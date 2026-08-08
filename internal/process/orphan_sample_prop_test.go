package process

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cplieger/cert-converter/internal/logtext"
	"pgregory.net/rapid"
)

// TestSampleOrphanPaths_properties pins the BYTE budget of the orphan report's paths
// attribute across the whole input space, which the two table tests cannot: they pin
// three fixed shapes (a realistic sample under the budget, one oversized single path,
// and a sample over BOTH caps), so a byte cut applied only inside the item cap's
// branch -- or applied per path instead of to the joined sample -- satisfies all three
// while letting a sample of fifteen 400-byte paths through whole. reconcile emits that
// record on every scan for as long as an orphan exists, so the bound is what keeps a
// permanent multi-kilobyte line out of the log.
//
// The properties are stated over the JOINED sample rather than by re-deriving the cut,
// so they cannot be satisfied by re-implementing the function under test: the sample
// is a byte-prefix of the join (no name is ever rewritten), it is untouched when the
// join fits the budget, and past the budget it is marked, bounded, and cut no further
// back than one rune.
//
// Lengths are drawn and the paths built from them, deliberately: rapid's own string
// generator is small-biased and never joins to more than maxLoggedOrphanBytes, so a
// property built on rapid.String() alone passes on a build with no byte cap at all.
func TestSampleOrphanPaths_properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		lengths := rapid.SliceOfN(rapid.SampledFrom([]int{1, 12, 137, 205, 240, 400, 900}), 1, 30).
			Draw(rt, "path_lengths")
		// Multi-byte fill runes, so the cut offset lands inside a rune: the partial-rune
		// tail runesafe.CapBytes exists to prevent is invisible to a byte-count bound.
		fill := []rune{'a', 'é', '→'}
		paths := make([]string, 0, len(lengths))
		for i, n := range lengths {
			paths = append(paths, strings.Repeat(string(fill[i%len(fill)]), n))
		}

		got := sampleOrphanPaths(paths)

		named, elided := paths, ""
		if len(paths) > maxLoggedOrphans {
			named = paths[:maxLoggedOrphans]
			elided = fmt.Sprintf(" (+%d more)", len(paths)-maxLoggedOrphans)
		}
		full := strings.Join(named, ",")

		if !strings.HasSuffix(got, elided) {
			rt.Fatalf("sampleOrphanPaths(%d paths) rendered %d bytes not ending in %q: the byte cut dropped the item cap's scale",
				len(paths), len(got), elided)
		}
		if !utf8.ValidString(got) {
			rt.Fatalf("sampleOrphanPaths(%d paths) rendered invalid UTF-8: a cut split a rune", len(paths))
		}
		kept := strings.TrimSuffix(strings.TrimSuffix(got, elided), logtext.Marker)
		if !strings.HasPrefix(full, kept) {
			rt.Fatalf("sampleOrphanPaths(%d paths) kept %d bytes that are not a prefix of the joined sample: a name was rewritten",
				len(paths), len(kept))
		}
		if len(full) <= maxLoggedOrphanBytes {
			if got != full+elided {
				rt.Fatalf("sampleOrphanPaths(%d paths joining to %d bytes) rendered %d bytes, want the sample untouched below the budget",
					len(paths), len(full), len(got))
			}
			return
		}
		if !strings.Contains(got, logtext.Marker) {
			rt.Fatalf("sampleOrphanPaths(%d paths joining to %d bytes) rendered %d bytes with no %q marker: a reader cannot tell the list was cut",
				len(paths), len(full), len(got), logtext.Marker)
		}
		if maxLen := maxLoggedOrphanBytes + len(logtext.Marker) + len(elided); len(got) > maxLen {
			rt.Fatalf("sampleOrphanPaths(%d paths joining to %d bytes) rendered %d bytes, want at most %d",
				len(paths), len(full), len(got), maxLen)
		}
		if minKept := maxLoggedOrphanBytes - (utf8.UTFMax - 1); len(kept) < minKept {
			rt.Fatalf("sampleOrphanPaths(%d paths joining to %d bytes) kept only %d bytes, want at least %d: the rune backoff must not discard more than one rune",
				len(paths), len(full), len(kept), minKept)
		}
	})
}

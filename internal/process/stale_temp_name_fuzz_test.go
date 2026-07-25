package process

import (
	"regexp"
	"testing"
)

// staleTempNameOracle states the temp-name contract declaratively:
// ".atomicfile-" + one or more ASCII digits + ".tmp". It is a deliberately
// different implementation strategy from isStaleTempName's prefix/suffix scan,
// so agreement between the two is evidence rather than a restatement.
var staleTempNameOracle = regexp.MustCompile(`^\.atomicfile-[0-9]+\.tmp$`)

// FuzzIsStaleTempName_matchesOnlyTheExactTempShape drives the deletion gate of
// the /output sweep with arbitrary filesystem-derived names. A false positive
// unlinks an operator-owned file out of the PFX volume, so the matcher must
// agree with the declarative shape on every input, not just the curated table
// cases.
func FuzzIsStaleTempName_matchesOnlyTheExactTempShape(f *testing.F) {
	for _, seed := range []string{
		"", ".", "..", "x", "existing.pfx",
		".atomicfile-0.tmp",
		".atomicfile-109.tmp",
		".atomicfile-123456.tmp",
		".atomicfile-.tmp",
		".atomicfile-notes.tmp",
		".atomicfile-12a3.tmp",
		"atomicfile-123.tmp",
		".atomicfile-123.tmp.bak",
		".atomicfile-123.tmp.tmp",
		".atomicfile-123.TMP",
		".atomicfile-\uff11\uff12\uff13.tmp",
		".atomicfile-1_2.tmp",
		".atomicfile--1.tmp",
		".atomicfile-+1.tmp",
		".atomicfile-1.tmp\n",
		".atomicfile-1.tmp/../evil",
		".atomicfile-\x00123.tmp",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := isStaleTempName(name)
		if want := staleTempNameOracle.MatchString(name); got != want {
			t.Fatalf("isStaleTempName(%q) = %v, want %v (the sweep must match exactly .atomicfile-<digits>.tmp)", name, got, want)
		}
	})
}

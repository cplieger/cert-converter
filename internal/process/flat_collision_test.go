package process

import (
	"slices"
	"testing"
)

func TestSelectFlatSources_collidingStemConvertsNothingRegardlessOfArrival(t *testing.T) {
	t.Parallel()

	unique, collisions := selectFlatSources([]string{
		"issuer-z/shared/site.crt",
		"issuer-y/other/cert.crt",
		"issuer-a/shared/site.crt",
	})
	// The uncontested source converts; NEITHER claimant of the shared stem does.
	wantUnique := []string{"issuer-y/other/cert.crt"}
	if !slices.Equal(unique, wantUnique) {
		t.Errorf("selectFlatSources(reverse arrival) unique = %v, want %v", unique, wantUnique)
	}
	if len(collisions) != 1 {
		t.Fatalf("selectFlatSources(reverse arrival) collisions = %+v, want one group", collisions)
	}
	got := collisions[0]
	if got.stem != "shared/site" {
		t.Errorf("selectFlatSources(reverse arrival) collision stem = %q, want %q", got.stem, "shared/site")
	}
	wantSources := []string{"issuer-a/shared/site.crt", "issuer-z/shared/site.crt"}
	if !slices.Equal(got.sources, wantSources) {
		t.Errorf("selectFlatSources(reverse arrival) collision sources = %v, want %v", got.sources, wantSources)
	}
}

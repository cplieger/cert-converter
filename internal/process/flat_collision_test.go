package process

import (
	"slices"
	"testing"
)

func TestGroupFlatClaims_groupsEachStemsClaimantsRegardlessOfArrival(t *testing.T) {
	t.Parallel()

	claims := groupFlatClaims([]string{
		"issuer-z/shared/site.crt",
		"issuer-y/other/cert.crt",
		"issuer-a/shared/site.crt",
	})
	if len(claims) != 2 {
		t.Fatalf("groupFlatClaims(reverse arrival) = %+v, want two stems", claims)
	}
	if got, want := claims[0], (flatClaim{stem: "shared/site", sources: []string{"issuer-a/shared/site.crt", "issuer-z/shared/site.crt"}}); got.stem != want.stem || !slices.Equal(got.sources, want.sources) {
		t.Errorf("groupFlatClaims(reverse arrival)[0] = %+v, want %+v", got, want)
	}
	if got, want := claims[1], (flatClaim{stem: "other/cert", sources: []string{"issuer-y/other/cert.crt"}}); got.stem != want.stem || !slices.Equal(got.sources, want.sources) {
		t.Errorf("groupFlatClaims(reverse arrival)[1] = %+v, want %+v", got, want)
	}
}

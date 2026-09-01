package layout_test

import (
	"slices"
	"testing"

	"github.com/cplieger/cert-converter/internal/layout"
)

func TestExcludeSet_Excludes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		members []string
		rel     string
		want    bool
	}{
		{name: "empty set excludes nothing", rel: "clients/identity.crt"},
		{name: "exact file match", members: []string{"site.crt"}, rel: "site.crt", want: true},
		{name: "directory covers what is beneath it", members: []string{"clients"}, rel: "clients/identity.crt", want: true},
		{name: "directory covers a deeper descendant", members: []string{"clients"}, rel: "clients/eu/a/id.pfx", want: true},
		{name: "a name prefix is not a path prefix", members: []string{"client"}, rel: "clients/identity.crt"},
		{name: "a sibling is untouched", members: []string{"clients"}, rel: "server/wanted.crt"},
		{name: "the member itself matches as a directory path", members: []string{"clients"}, rel: "clients", want: true},
		{name: "a trailing slash on the member still matches", members: []string{"clients/"}, rel: "clients/identity.crt", want: true},
		{name: "a redundant member spelling still matches", members: []string{"./clients"}, rel: "clients/identity.crt", want: true},
		{name: "a nested member matches only its own branch", members: []string{"a/b"}, rel: "a/c/id.crt"},
		{name: "a nested member matches its branch", members: []string{"a/b"}, rel: "a/b/id.crt", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set := layout.NewExcludeSet(tc.members)
			if got := set.Excludes(tc.rel); got != tc.want {
				t.Errorf("NewExcludeSet(%v).Excludes(%q) = %v, want %v", tc.members, tc.rel, got, tc.want)
			}
		})
	}
}

func TestExcludeSet_normalisesMembers(t *testing.T) {
	t.Parallel()

	set := layout.NewExcludeSet([]string{"z/", "./a", "a", "", ".", "m/n"})
	want := []string{"a", "m/n", "z"}
	if got := set.Paths(); !slices.Equal(got, want) {
		t.Errorf("NewExcludeSet(...).Paths() = %v, want %v: members are cleaned, deduplicated and sorted", got, want)
	}
	if set.Empty() {
		t.Error("NewExcludeSet(...).Empty() = true, want false")
	}
	if empty := layout.NewExcludeSet(nil); !empty.Empty() {
		t.Error("NewExcludeSet(nil).Empty() = false, want true")
	}
	if trivial := layout.NewExcludeSet([]string{".", ""}); !trivial.Empty() {
		t.Errorf("NewExcludeSet([\".\", \"\"]).Empty() = false, want true: neither names a path under the root")
	}
}

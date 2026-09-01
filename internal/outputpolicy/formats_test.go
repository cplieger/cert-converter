package outputpolicy_test

import (
	"slices"
	"testing"

	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

func TestParseFormats(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		raw          string
		want         outputpolicy.Formats
		wantNames    []string
		wantRejected []string
		wantExplicit bool
	}{
		{name: "unset keeps legacy default", want: outputpolicy.Formats{PFX: true}, wantNames: []string{"pfx"}},
		{name: "pfx only", raw: "pfx", want: outputpolicy.Formats{PFX: true}, wantNames: []string{"pfx"}, wantExplicit: true},
		{name: "pem only", raw: "pem", want: outputpolicy.Formats{PEM: true}, wantNames: []string{"pem"}, wantExplicit: true},
		{name: "both are normalized and deduplicated", raw: " PEM, pfx,pem ", want: outputpolicy.Formats{PFX: true, PEM: true}, wantNames: []string{"pfx", "pem"}, wantExplicit: true},
		{name: "known survives unknown", raw: "jks,pem", want: outputpolicy.Formats{PEM: true}, wantNames: []string{"pem"}, wantRejected: []string{"jks"}, wantExplicit: true},
		{name: "all unknown falls back safely", raw: "jks,der", want: outputpolicy.Formats{PFX: true}, wantNames: []string{"pfx"}, wantRejected: []string{"jks", "der"}},
		{name: "empty list members carry no intent", raw: ",pfx,,", want: outputpolicy.Formats{PFX: true}, wantNames: []string{"pfx"}, wantExplicit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, rejected := outputpolicy.ParseFormats(tc.raw)
			if got != tc.want {
				t.Errorf("ParseFormats(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
			if names := got.Names(); !slices.Equal(names, tc.wantNames) {
				t.Errorf("ParseFormats(%q).Names() = %v, want %v", tc.raw, names, tc.wantNames)
			}
			if !slices.Equal(rejected, tc.wantRejected) {
				t.Errorf("ParseFormats(%q) rejected = %v, want %v", tc.raw, rejected, tc.wantRejected)
			}
			if explicit := outputpolicy.FormatsExplicit(tc.raw); explicit != tc.wantExplicit {
				t.Errorf("FormatsExplicit(%q) = %v, want %v", tc.raw, explicit, tc.wantExplicit)
			}
		})
	}
}

func TestParseLayout(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		raw          string
		want         outputpolicy.Layout
		known        bool
		wantExplicit bool
	}{
		{name: "unset resolves to the flat default", want: outputpolicy.LayoutFlat, known: true},
		{name: "mirror", raw: "mirror", want: outputpolicy.LayoutMirror, known: true, wantExplicit: true},
		{name: "flat mixed case", raw: " FLAT ", want: outputpolicy.LayoutFlat, known: true, wantExplicit: true},
		{name: "unknown falls back to the default", raw: "tree", want: outputpolicy.LayoutFlat, known: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, known := outputpolicy.ParseLayout(tc.raw)
			if got != tc.want || known != tc.known {
				t.Errorf("ParseLayout(%q) = (%q, %v), want (%q, %v)", tc.raw, got, known, tc.want, tc.known)
			}
			if explicit := outputpolicy.LayoutExplicit(tc.raw); explicit != tc.wantExplicit {
				t.Errorf("LayoutExplicit(%q) = %v, want %v", tc.raw, explicit, tc.wantExplicit)
			}
		})
	}
}

func FuzzParseFormats_neverReturnsAnEmptySet(f *testing.F) {
	for _, seed := range []string{"", "pfx", "pem", "pfx,pem", "unknown", ",,,", " PFX, PEM "} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		formats, _ := outputpolicy.ParseFormats(raw)
		if !formats.PFX && !formats.PEM {
			t.Fatalf("ParseFormats(%q) returned no enabled format", raw)
		}
	})
}

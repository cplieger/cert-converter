package outputpolicy

import "testing"

// TestParseLifecycle pins the knob's normalisation, including that an
// unrecognised value falls back to the SAFE mode rather than the destructive one.
func TestParseLifecycle(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw       string
		want      Lifecycle
		wantKnown bool
	}{
		{"", LifecycleWarn, true},
		{"warn", LifecycleWarn, true},
		{"  SYNC  ", LifecycleSync, true},
		{"Keep", LifecycleKeep, true},
		{"delete", LifecycleWarn, false},
		{"true", LifecycleWarn, false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, known := ParseLifecycle(tc.raw)
			if got != tc.want || known != tc.wantKnown {
				t.Errorf("ParseLifecycle(%q) = (%q, %v), want (%q, %v)", tc.raw, got, known, tc.want, tc.wantKnown)
			}
		})
	}
}

// TestLifecycleModes_advertises_exactly_what_the_parser_accepts pins the "stated
// once" contract in the direction a test can actually observe: LifecycleModes must
// return the current canonical three-value inventory IN ORDER, and every advertised
// value must round-trip through ParseLifecycle. A mode added to the inventory alone
// is accepted here and rejected by the parser, which is the drift this catches —
// along with a removal, a reordering and a broken clone.
//
// It cannot catch the mirror case (a new Lifecycle constant that is never added to
// the inventory): Go constants are not enumerable at runtime, and the want slice
// below would have to be edited by the same hand that forgot the inventory.
func TestLifecycleModes_advertises_exactly_what_the_parser_accepts(t *testing.T) {
	t.Parallel()

	got := LifecycleModes()
	want := []Lifecycle{LifecycleWarn, LifecycleSync, LifecycleKeep}
	if len(got) != len(want) {
		t.Fatalf("LifecycleModes() = %v, want %v", got, want)
	}
	for i, mode := range want {
		if got[i] != mode {
			t.Errorf("LifecycleModes()[%d] = %q, want %q", i, got[i], mode)
		}
	}
	for _, mode := range got {
		parsed, known := ParseLifecycle(string(mode))
		if parsed != mode || !known {
			t.Errorf("ParseLifecycle(%q) = (%q, %v), want (%q, true): an advertised mode the parser rejects sends the operator in circles",
				mode, parsed, known, mode)
		}
	}
}

// TestLifecycleModes_hands_out_a_copy pins the clone. Without it the returned slice
// aliases the package's own inventory, so a caller that sorts or rewrites the modes
// it advertises silently changes which values ParseLifecycle accepts — including
// making "sync", the one mode authorised to delete a bundle, unrecognised, so an
// operator who asked for it gets the warn default with no explanation.
func TestLifecycleModes_hands_out_a_copy(t *testing.T) {
	t.Parallel()

	first := LifecycleModes()
	first[0] = "clobbered"

	if _, known := ParseLifecycle(string(LifecycleWarn)); !known {
		t.Errorf("ParseLifecycle(%q) reports the default unknown after a caller wrote to the slice LifecycleModes returned",
			LifecycleWarn)
	}
	if second := LifecycleModes(); second[0] != LifecycleWarn {
		t.Errorf("LifecycleModes()[0] = %q after a caller mutated an earlier result, want %q: each call must hand out its own copy",
			second[0], LifecycleWarn)
	}
}

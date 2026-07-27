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

package process

import (
	"strings"
	"testing"
)

// FuzzParseLifecycle_unknownNeverEnablesDeletion pins the safety invariant of the
// only knob in this app that authorises deleting private-key material: whatever
// OUTPUT_LIFECYCLE holds, an unrecognised value must resolve to the
// non-destructive default, never to sync. Three properties, none of which
// re-implements the parser: the result is always one of the three modes (bounded
// output), recognition is decided against the four accepted spellings derived here
// rather than against the parser's own answer (so a value the parser wrongly
// accepts is caught instead of excusing itself), and every canonical mode name
// round-trips to itself as known (so the value the caller logs and the value it
// acts on cannot diverge).
func FuzzParseLifecycle_unknownNeverEnablesDeletion(f *testing.F) {
	for _, seed := range []string{
		"", "warn", "sync", "keep", "  SYNC  ", "Sync\n", "delete", "true", "1",
		"sync sync", "s\x00ync", "SYNC\u00a0", "\uff53\uff59\uff4e\uff43",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		mode, known := ParseLifecycle(raw)

		switch mode {
		case LifecycleWarn, LifecycleSync, LifecycleKeep:
		default:
			t.Fatalf("ParseLifecycle(%q) = %q, want one of warn/sync/keep", raw, mode)
		}
		// The accepted set, spelled out independently of the parser: asking
		// ParseLifecycle whether it recognised the value would let a regression that
		// accepts a non-canonical spelling (and resolves it to sync) satisfy the
		// invariant it is supposed to break.
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "", string(LifecycleWarn), string(LifecycleSync), string(LifecycleKeep):
			if !known {
				t.Fatalf("ParseLifecycle(%q) = (%q, false), want a canonical spelling to be recognised", raw, mode)
			}
		default:
			if known {
				t.Fatalf("ParseLifecycle(%q) = (%q, true), want an unrecognised value to be reported as unknown", raw, mode)
			}
			if mode != LifecycleWarn {
				t.Fatalf("ParseLifecycle(%q) = (%q, false), want the non-destructive default for an unrecognised value", raw, mode)
			}
		}
		again, againKnown := ParseLifecycle(string(mode))
		if again != mode || !againKnown {
			t.Fatalf("ParseLifecycle(%q) = (%q, %v), want (%q, true): a canonical mode name must round-trip as known",
				string(mode), again, againKnown, mode)
		}
	})
}

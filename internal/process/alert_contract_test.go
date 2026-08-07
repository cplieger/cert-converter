package process

import (
	"strings"
	"testing"
)

// TestOperatorLogContract_pins_every_published_message_substring is the only test that
// can fail when one of these messages is reworded.
//
// The README's alerting section keys a Loki rule and two documented operator queries on
// exact substrings of them, while every other assertion in this package compares a
// captured record against the production const ITSELF -- so a reword changes both sides
// together, the whole suite stays green, and CertConverterInputTreeTooLarge silently
// stops matching while the two OUTPUT_LIFECYCLE=sync queries return nothing. The
// substrings are spelled out here deliberately, exactly as the mode-repair tests spell
// theirs out, so renaming one has to be done on purpose.
//
// Each entry is the substring the README publishes rather than the whole message: the
// rules match on a phrase, so widening the message around it stays compatible and only
// the phrase is the contract.
func TestOperatorLogContract_pins_every_published_message_substring(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		message string
		want    string
	}{
		{
			// The README states this rule is the ONLY signal for the condition: health is
			// deliberately unaffected, because no restart shrinks the tree.
			name:    "CertConverterInputTreeTooLarge matches the entry-budget abort",
			message: scanBudgetMsg,
			want:    "holds more entries than one scan will enumerate",
		},
		{
			// The audit record for the only destructive action this app takes.
			name:    "the sync-mode deletion audit is queryable",
			message: reapAuditMsg,
			want:    "removed output bundles whose input certificates are gone",
		},
		{
			// The only trace of a bundle kept indefinitely because its private key is still
			// there; it is counted in nothing, so the message is the whole signal.
			name:    "the retained-lone-key report is queryable",
			message: loneKeyRetainedMsg,
			want:    "keeping an output bundle whose certificate is gone but whose private key is still in /input",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if !strings.Contains(tc.message, tc.want) {
				t.Errorf("this app logs %q, want it to contain %q: the README publishes that substring as the"+
					" operator's match, so rewording it silently stops the documented alert or query from"+
					" ever firing again", tc.message, tc.want)
			}
		})
	}
}

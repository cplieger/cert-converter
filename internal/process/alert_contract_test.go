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

// inputBudgetPhrase is the whole of CertConverterInputTreeTooLarge's matcher, restated
// here for the exclusion below. The inclusion side is the table case above.
const inputBudgetPhrase = "holds more entries than one scan will enumerate"

// TestOperatorLogContract_keeps_the_published_matchers_mutually_exclusive is the other
// half of the contract above, and the half a Contains-only table cannot see.
//
// CertConverterInputTreeTooLarge matches on a PHRASE, not on a whole message, so any
// other message containing that phrase fires it too -- and its remediation ("check that
// /input is mounted at the certificate directory ... or raise MAX_SCAN_ENTRIES") sends
// the operator to the wrong mount for any condition that is not the /input walk. The
// /output entry budget is the near miss: it is a different documented condition with its
// own rule (CertConverterOrphanRemovalDisabled), its own remediation naming /output, and
// a WARN whose own doc comment says the generic /output-ownership diagnosis is the wrong
// one for it. Sharing a matcher with the /input rule would undo exactly that.
//
// So scanBudgetMsg is the phrase's ONLY carrier. This test fails if a reword gives it a
// second one.
func TestOperatorLogContract_keeps_the_published_matchers_mutually_exclusive(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		message string
	}{
		{
			// Same shaped condition, different mount, different remediation: the one
			// message most likely to be worded into a collision.
			name:    "the /output entry budget does not fire the /input rule",
			message: outputBudgetMsg,
		},
		{
			// Also a ceiling condition, also reported through reapDisabledPhrase, so the
			// same wording pull applies to it.
			name:    "the evicted-wholeness abort does not fire the /input rule",
			message: evictedEvidenceMsg,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if strings.Contains(tc.message, inputBudgetPhrase) {
				t.Errorf("this app logs %q, which contains %q -- the substring the README publishes as"+
					" CertConverterInputTreeTooLarge's matcher. This condition would fire the /input rule and"+
					" hand the operator the /input remediation, pointing them at the wrong mount; reword it so"+
					" only scanBudgetMsg carries the phrase", tc.message, inputBudgetPhrase)
			}
		})
	}
}

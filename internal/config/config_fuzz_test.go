package config

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzCheckPasswordEncodable_gate_matches_the_recognizer pins the two contracts
// the startup gate owns over arbitrary secret bytes: it refuses exactly the
// shapes the PKCS#12 UCS-2 password encoding cannot carry (a dropped or reordered
// branch would let a silently-unopenable bundle ship), and its error never
// carries the secret into the startup log every aggregator retains.
func FuzzCheckPasswordEncodable_gate_matches_the_recognizer(f *testing.F) {
	for _, seed := range []string{
		"", " ", "hunter2", "pässwörd-Ünicode", "日本語パスワード",
		string([]byte{0xff}), string([]byte{0xff}) + "pw-\U0001F600",
		"pw-\U0001F600", "sentinel\x00secret", "\uFFFD",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, password string) {
		// Deliberately an INDEPENDENT restatement of the three shapes rather than a
		// call into convert: the gate reaches its verdict through
		// convert.ValidatePasswordEncoding, so deriving this side of the comparison
		// from the same query would make the oracle tautological and a dropped
		// recognition branch would pass. Kept in step with the classifier by this
		// test failing if the two ever disagree.
		unusable := !utf8.ValidString(password) ||
			strings.ContainsRune(password, 0) ||
			strings.ContainsFunc(password, func(r rune) bool { return r > 0xFFFF })

		err := checkPasswordEncodable(password)
		if unusable != (err != nil) {
			t.Fatalf("checkPasswordEncodable(%q) = %v, but the PKCS#12 UCS-2 encoding %s carry it: the gate must refuse exactly the shapes the encoder cannot carry",
				password, err, map[bool]string{true: "cannot", false: "can"}[unusable])
		}
		if err == nil {
			return
		}
		if !errors.Is(err, ErrUnencodablePassword) {
			t.Errorf("checkPasswordEncodable(%q) = %v, want it to wrap ErrUnencodablePassword", password, err)
		}
		if strings.Contains(err.Error(), password) {
			t.Errorf("checkPasswordEncodable leaked the password into %q", err.Error())
		}
	})
}

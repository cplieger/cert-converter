package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
)

// FuzzCheckPasswordEncodable_gate_matches_the_recognizer pins the two contracts
// the startup gate owns over arbitrary secret bytes: it refuses exactly the
// shapes convert.InspectPasswordEncoding recognises (a dropped or reordered
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
		issues := convert.InspectPasswordEncoding(password)
		// Deliberately an independent restatement, NOT issues.Unencodable():
		// checkPasswordEncodable selects on Primary, so deriving this side of
		// the comparison from Primary too would make the oracle tautological
		// and a dropped Primary branch would pass.
		unusable := issues.InvalidUTF8 || issues.NonBMP || issues.EmbeddedNUL

		err := checkPasswordEncodable(password)
		if unusable != (err != nil) {
			t.Fatalf("checkPasswordEncodable(%q) = %v, but InspectPasswordEncoding reports %+v: the gate must refuse exactly the shapes the encoder cannot carry",
				password, err, issues)
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

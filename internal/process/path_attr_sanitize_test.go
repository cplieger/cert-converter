package process

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/slogx/capture"
)

// hostileStem is a certificate name carrying one rune from each of the two classes
// that make an untrusted filename a record-INTEGRITY problem rather than a cosmetic
// one: LF forges a record boundary in the plain-text handler this app configures, so a
// name holding one can inject a whole fabricated log line, and U+202E
// (RIGHT-TO-LEFT OVERRIDE) reorders everything after it in the rendered line, so a
// name holding one can make an operator read a different path than the record names.
//
// Both are legal bytes in a POSIX filename, and BOTH mounted trees are untrusted: this
// is a public image, so /input and /output are whatever a stranger points them at and a
// co-writer on either one chooses the names this app enumerates.
const hostileStem = "hostile\n\u202egone"

// unsafeInAttribute is the set hostileStem is built from, for the batch-wide sweep
// below. Not the whole runesafe policy — that is runesafe's own exhaustive
// every-rune sweep to pin — just the two classes this test injects.
var unsafeInAttribute = []string{"\n", "\r", "\u202e"}

// TestScannerRun_sanitizes_walk_supplied_names_in_log_attributes is the oracle for the
// path-attribute-runesafe-adoption decision: every filesystem-derived string headed for
// a log attribute is sanitized AT THE LOG BOUNDARY, and only there.
//
// It runs the REAL scan over a real /input tree rather than calling logtext.Path
// directly, because the point of the decision is the WIRING: a gate that exists and is
// not reached at the walk's own emit sites leaves the records it was adopted for
// forgeable. So the name under test is supplied by this app's own walk, travels through
// pairing, conversion and the atomic write, and is asserted where it actually reaches an
// operator.
//
// Three properties, and the second two are what stop an over-broad fix passing:
//
//   - A hostile name is REWRITTEN in the attribute: neither injected rune survives
//     anywhere in the batch.
//   - An ordinary name is BYTE-IDENTICAL. Sanitizing is a no-op for every ASCII and
//     domain-derived name, which is why adopting it moved no operator's log query key;
//     a fix that escaped, quoted or truncated instead would fail here.
//   - The bundle is on disk under the RAW name. `rel` stays raw for every filesystem
//     decision, so the gate must sit at the slog call and nowhere upstream of it — a
//     sanitized value used for an open, a join or a map key would publish the bundle at
//     a name no consumer asked for.
//
// Runs serially: it swaps slog.Default().
func TestScannerRun_sanitizes_walk_supplied_names_in_log_attributes(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	// The subject is the FILENAME, so both certificates carry an ordinary CN:
	// certificate-derived text has its own gate (internal/convert's boundLogText) and a
	// hostile subject here would let that gate satisfy this test.
	ordinaryCert, ordinaryKey := testcerts.GenerateSelfSignedCert(t, "ordinary.example.com", "ecdsa")
	writePair(t, certsRoot, "ordinary", ordinaryCert, ordinaryKey)
	hostileCert, hostileKey := testcerts.GenerateSelfSignedCert(t, "hostile.example.com", "ecdsa")
	writePair(t, certsRoot, hostileStem, hostileCert, hostileKey)

	logs := captureLogs(t)
	scanner := New(&Options{
		CertsRoot: certsRoot,
		OutRoot:   outRoot,
		Password:  "pw",
		Encoder:   convert.EncNameModern2023,
	})

	res, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	// Both pairs must actually convert, or the records under test never came from the
	// walk and every assertion below would pass vacuously.
	if res.Converted != 2 || res.Failed != 0 {
		t.Fatalf("Run = %+v, want Converted 2 and Failed 0: an unconverted pair emits no wrote-pfx record", res)
	}

	rawOut := layout.OutputFor(hostileStem + ".crt")
	wantSanitized := logtext.Path(rawOut)
	if wantSanitized == rawOut {
		t.Fatalf("the fixture name %q survives sanitizing unchanged, so this test asserts nothing", rawOut)
	}

	// The hostile name reaches the operator rewritten, and the raw spelling appears in
	// no attribute of the record.
	if !logs.HasAttr("wrote pfx", "path", wantSanitized) {
		t.Errorf("wrote-pfx paths = %q, want the hostile output name sanitized to %q",
			logs.AttrValuesExact("wrote pfx", "path"), wantSanitized)
	}
	// The ordinary name is untouched: same helper, same call site, no rewriting.
	if !logs.HasAttr("wrote pfx", "path", "ordinary.pfx") {
		t.Errorf("wrote-pfx paths = %q, want the ordinary name %q byte-identical",
			logs.AttrValuesExact("wrote pfx", "path"), "ordinary.pfx")
	}

	assertNoUnsafeRunesInAttributes(t, logs)

	// The gate is at the LOG call, not upstream of it: the bundle is published under the
	// raw name the walk supplied, so a consumer resolving <name>.pfx beside <name>.crt
	// still finds it.
	rawPath := filepath.Join(outRoot, rawOut)
	if _, statErr := os.Lstat(rawPath); statErr != nil {
		t.Errorf("Lstat(%q) = %v, want the bundle published under the RAW name: sanitizing must not reach a filesystem decision",
			rawOut, statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(outRoot, wantSanitized)); statErr == nil {
		t.Errorf("a bundle exists at the SANITIZED name %q: the gate leaked past the log boundary into the write path", wantSanitized)
	}
}

// assertNoUnsafeRunesInAttributes sweeps every attribute of every record in the batch.
// It is deliberately wider than the two records asserted above: the decision covers
// EVERY filesystem-derived log attribute, and this app names the same walk-supplied
// path in a dozen places (the pairing lines, the currency lines, the orphan walk, the
// summary's error), so a fix applied to the one site a test names is exactly the
// partial adoption that leaves the rest forgeable.
//
// A clean two-pair scan carries no legitimate CR, LF or bidi control in any attribute,
// so any hit is the fixture's own name arriving raw.
func assertNoUnsafeRunesInAttributes(t *testing.T, logs *capture.Recorder) {
	t.Helper()
	for _, rec := range logs.Records() {
		rec.Attrs(func(a slog.Attr) bool {
			checkAttrValue(t, rec.Message, a.Key, a.Value)
			return true
		})
	}
}

// checkAttrValue reports an unsafe rune in one attribute value, descending into a group
// so a nested attribute cannot hide one.
func checkAttrValue(t *testing.T, msg, key string, v slog.Value) {
	t.Helper()
	if v.Kind() == slog.KindGroup {
		for _, a := range v.Group() {
			checkAttrValue(t, msg, key+"."+a.Key, a.Value)
		}
		return
	}
	rendered := v.String()
	for _, bad := range unsafeInAttribute {
		if strings.Contains(rendered, bad) {
			t.Errorf("record %q attribute %s=%q holds %q: a filesystem-derived value reached the log un-sanitized",
				msg, key, rendered, bad)
		}
	}
}

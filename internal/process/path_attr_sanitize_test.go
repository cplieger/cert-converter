package process

import (
	"context"
	"io/fs"
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

// hostileStem is a certificate name carrying one rune from each class that makes
// an untrusted filename a record-legibility problem: LF splits a logfmt line,
// and U+202E (RIGHT-TO-LEFT OVERRIDE) reorders everything after it. Both are
// legal POSIX filename bytes, and this app's mounted trees are untrusted.
const hostileStem = "hostile\n\u202egone"

// unsafeInAttribute is the set hostileStem is built from, for the batch-wide sweep
// below.
var unsafeInAttribute = []string{"\n", "\r", "\u202e"}

// TestScannerRun_sanitizes_walk_supplied_names_in_log_attributes runs the REAL
// scan over a real /input tree, because the point is the WIRING: a name
// supplied by this app's own walk travels through pairing, conversion and the
// atomic write, and is asserted where it actually reaches an operator. Asserts:
// a hostile name is rewritten in the attribute; an ordinary name is
// byte-identical; and the bundle is on disk under the RAW name (`rel` stays raw
// for every filesystem decision, or a sanitized value would publish the bundle
// at a name no consumer asked for).
//
// Runs serially: it swaps slog.Default().
func TestScannerRun_sanitizes_walk_supplied_names_in_log_attributes(t *testing.T) {
	certsRoot := t.TempDir()
	outRoot := t.TempDir()

	// The subject is the FILENAME: certificate-derived text has its own gate
	// (internal/convert's boundLogText), so both certificates carry an
	// ordinary CN to avoid that gate satisfying this test instead.
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
	// Both pairs must actually convert, or the records under test never came
	// from the walk and every assertion below passes vacuously.
	if res.Converted != 2 || res.Failed != 0 {
		t.Fatalf("Run = %+v, want Converted 2 and Failed 0: an unconverted pair emits no wrote-pfx record", res)
	}

	rawOut := layout.PFXOutFor(hostileStem)
	wantSanitized := logtext.Path(rawOut)
	if wantSanitized == rawOut {
		t.Fatalf("the fixture name %q survives sanitizing unchanged, so this test asserts nothing", rawOut)
	}

	// The hostile name reaches the operator rewritten, and the raw spelling
	// appears in no attribute of the record.
	if !logs.HasAttr("wrote pfx", "path", wantSanitized) {
		t.Errorf("wrote-pfx paths = %q, want the hostile output name sanitized to %q",
			logs.AttrValuesExact("wrote pfx", "path"), wantSanitized)
	}
	// Same helper, same call site, no rewriting for the ordinary name.
	if !logs.HasAttr("wrote pfx", "path", "ordinary.pfx") {
		t.Errorf("wrote-pfx paths = %q, want the ordinary name %q byte-identical",
			logs.AttrValuesExact("wrote pfx", "path"), "ordinary.pfx")
	}

	assertNoUnsafeRunesInAttributes(t, logs)

	// The gate is at the LOG call, not upstream of it: the bundle is published
	// under the raw name the walk supplied, so a consumer resolving
	// <name>.pfx beside <name>.crt still finds it.
	rawPath := filepath.Join(outRoot, rawOut)
	if _, statErr := os.Lstat(rawPath); statErr != nil {
		t.Errorf("Lstat(%q) = %v, want the bundle published under the RAW name: sanitizing must not reach a filesystem decision",
			rawOut, statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(outRoot, wantSanitized)); statErr == nil {
		t.Errorf("a bundle exists at the SANITIZED name %q: the gate leaked past the log boundary into the write path", wantSanitized)
	}
}

// assertNoUnsafeRunesInAttributes sweeps every attribute of every record in the
// batch, deliberately wider than the two asserted above: this app names the same
// walk-supplied path in a dozen places, so a fix applied to one site is exactly
// the partial adoption that leaves the rest ungated.
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

// TestErrorAttributes_are_sanitized_at_the_emit_sites covers the ERROR half of
// the path-attribute gate, which the "path" half above does not reach: the
// filesystem returns *fs.PathError and atomicfile interpolates the name it
// refused, so a hostile filename arrives inside err.Error() even at a site
// whose "path" attribute is already gated. The three records asserted are each
// the ONLY signal for their condition: an unreadable certificate, an unreadable
// prior bundle, and a refused rewrite.
//
// Runs serially: each subtest swaps slog.Default().
func TestErrorAttributes_are_sanitized_at_the_emit_sites(t *testing.T) {
	// Spelled out rather than imported from production: an operator's log
	// query keys on these words, so a silent rewording must fail here.
	const (
		unreadableInputMsg = "cannot read certificate"
		unreadablePriorMsg = "cannot read prior pfx; regenerating"
	)

	t.Run("a certificate /input refuses", func(t *testing.T) {
		// The error, not the path, carries the untrusted name here: os.Root
		// reports the name it refused inside a PathError.
		readErr := &fs.PathError{Op: "openat", Path: hostileStem + ".crt", Err: fs.ErrPermission}
		sw := &scanWalk{}
		logs := captureLogs(t)

		if got := sw.noteUnreadableInput(hostileStem+".crt", hostileStem+".crt", "certificate", readErr); got != statusUnreadable {
			t.Errorf("noteUnreadableInput(permission denied) = %v, want statusUnreadable", got)
		}
		assertErrorAttrSanitized(t, logs, unreadableInputMsg, readErr.Error())
	})

	t.Run("a prior bundle /output refuses", func(t *testing.T) {
		// The read seam is the only way in: no temp directory the suite owns
		// can stage a failure between inspect's classifying Lstat and its
		// read, and chmod-based refusals are no-ops for the root uid CI uses.
		readErr := &fs.PathError{Op: "openat", Path: hostileStem + ".pfx", Err: fs.ErrPermission}
		dir := t.TempDir()
		s := newOutputStore(t, dir)
		if err := s.write(t.Context(), "out.pfx", []byte("prior bundle")); err != nil {
			t.Fatalf("setup: write: %v", err)
		}
		prev := readBoundedInRoot
		readBoundedInRoot = func(context.Context, *os.Root, string, int64) ([]byte, error) {
			return nil, readErr
		}
		t.Cleanup(func() { readBoundedInRoot = prev })
		logs := captureLogs(t)

		state, err := s.inspect(t.Context(), "out.pfx", convert.Analysis{}, convert.EncNameModern2023, "pw")
		if err != nil {
			t.Fatalf("inspect(unreadable prior bundle) = error %v, want nil: a rewrite is the remedy", err)
		}
		if state != contentUnverified {
			t.Errorf("inspect(unreadable prior bundle) = %v, want contentUnverified", state)
		}
		assertErrorAttrSanitized(t, logs, unreadablePriorMsg, readErr.Error())
	})

	t.Run("a rewrite /output refuses for a reason no restart clears", func(t *testing.T) {
		// atomicfile interpolates the output name it refused, so the refusal's
		// own text carries it even though reportWriteFailure's path and
		// output_path are gated. Minted the way store.write mints one.
		refused := refuseWrite(refusalOwnership, "write output: %w",
			&fs.PathError{Op: "rename", Path: hostileStem + ".pfx", Err: fs.ErrPermission})
		logs := captureLogs(t)

		// The health-neutral arm, message taken from the production const
		// rather than spelled out (the shorter records above already pin the
		// rewording guard).
		reportWriteFailure(hostileStem+".crt", hostileStem+".pfx", refused, statusUnwritable)
		assertErrorAttrSanitized(t, logs, unreplaceableArtifactMsg, refused.Error())

		// The loud arm reaches the operator through failEntry, a different
		// emit site with its own gate.
		logs = captureLogs(t)
		reportWriteFailure(hostileStem+".crt", hostileStem+".pfx", refused, statusFailed)
		assertErrorAttrSanitized(t, logs, "conversion failed", refused.Error())
	})
}

// assertErrorAttrSanitized pins one record's "error" attribute to the sanitized
// rendering of raw, then sweeps the whole batch for a stray unsafe rune.
//
// The first check fails an absent gate; the second fails a half-applied one, since
// a record's remediation, output_path or nested group can carry the same name.
func assertErrorAttrSanitized(t *testing.T, logs *capture.Recorder, msgSub, raw string) {
	t.Helper()
	want := logtext.Path(raw)
	if want == raw {
		t.Fatalf("the fixture error text %q survives sanitizing unchanged, so this case asserts nothing", raw)
	}
	got, ok := logs.AttrValue(msgSub, "error")
	if !ok {
		t.Fatalf("record %q carries no error attribute: %q", msgSub, logs.Messages())
	}
	if got != want {
		t.Errorf("record %q error attribute = %q, want the sanitized rendering %q: a filesystem-derived"+
			" error reaches the operator through the same gate its sibling path attribute uses",
			msgSub, got, want)
	}
	assertNoUnsafeRunesInAttributes(t, logs)
}

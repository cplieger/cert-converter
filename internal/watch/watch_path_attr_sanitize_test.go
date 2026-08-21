package watch

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/slogx/capture"
	"github.com/fsnotify/fsnotify"
)

// hostileDirName is a directory name carrying one rune from each of the two classes
// that make an untrusted path a record-INTEGRITY problem rather than a cosmetic one:
// LF ends a record in a single-line sink, and U+202E (RIGHT-TO-LEFT OVERRIDE)
// reorders everything after it in the rendered line, so a name holding one can make
// an operator read a different path than the record names. Both are legal bytes in a
// POSIX directory name, and the watched tree is untrusted: this is a public image, so
// a co-writer on /input chooses the names this walk enumerates.
const hostileDirName = "hostile\n\u202egone"

// unsafeInAttribute is the set hostileDirName is built from, for the batch-wide sweep
// below. Not the whole runesafe policy -- that is runesafe's own to pin -- just the
// two classes this test injects.
var unsafeInAttribute = []string{"\n", "\r", "\u202e"}

// TestWatchRecords_sanitize_walk_supplied_names_in_log_attributes is this package's
// oracle for the rule that every filesystem-derived string headed for a log attribute
// is sanitized at the log boundary, and only there.
//
// It drives the REAL watch-set walk and the REAL event classifier over a tree holding
// a hostile directory name, because what can regress here is the WIRING rather than
// the gate: logtext.Path is pinned in its own package, so the failure mode is an emit
// site in this package that stops calling it. This package's other tests assert
// attribute values built from ordinary t.TempDir() names, for which Path is
// byte-identical, so a site handed the raw value again leaves every one of them green.
//
// Four properties, and the last three are what stop an over-broad fix passing:
//
//   - The hostile name is REWRITTEN wherever it reaches an operator, including the
//     watch-set dump's directories attribute, which is one bounded inventory of many
//     names and so needs the gate applied per element as they accumulate.
//   - An ordinary name is BYTE-IDENTICAL. Sanitizing is a no-op for every ASCII and
//     domain-derived name, which is why the rule moved no operator's log query key; a
//     fix that escaped, quoted or truncated instead would fail here.
//   - No attribute of any record in the batch holds either rune, so a fix applied to
//     the one site a test names cannot pass as adoption across every path-bearing
//     attribute this package emits.
//   - The directory is REGISTERED under the RAW name. Every filesystem decision here
//     (watcher.Add, the membership mirror, the root-vs-descendant equality that picks
//     a refusal's severity) is made on the real bytes, so a sanitized value that
//     leaked upstream of the slog call would watch a path the kernel does not have
//     and leave the real one uncovered.
//
// What the gate buys, stated exactly: production installs slog's TextHandler, which
// QUOTES and escapes both runes in a string attribute and inside an error attribute's
// text, so a hostile name cannot forge a record in this app as deployed. The gate buys
// handler-independence -- a JSON handler escapes the newline but passes a bidi
// override through raw -- and legibility for the operator reading the line.
//
// Serial (no t.Parallel): it swaps the process-global slog default.
func TestWatchRecords_sanitize_walk_supplied_names_in_log_attributes(t *testing.T) {
	root := t.TempDir()
	hostileDir := filepath.Join(root, hostileDirName)
	const ordinaryName = "ordinary.example.com"
	ordinaryDir := filepath.Join(root, ordinaryName)
	for _, dir := range []string{hostileDir, ordinaryDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Skipf("this filesystem will not hold the fixture directory name: %v", err)
		}
	}
	wantSanitized := logtext.Path(hostileDir)
	if wantSanitized == hostileDir {
		t.Fatalf("logtext.Path leaves the fixture name %q unchanged, so every assertion below would pass vacuously", hostileDir)
	}

	watcher := newTestWatcher(t)
	w := New(root, func(context.Context) {})

	logs := capture.Default(t)

	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("addWatchDirs(%q) = %v, want nil: the records under test come from this walk", root, err)
	}
	logWatchSet(t.Context(), watcher)
	st := newWatchState(w)
	t.Cleanup(st.stop)
	w.handleFsEvent(t.Context(), watcher, st, fsnotify.Event{Name: hostileDir, Op: fsnotify.Chmod})

	// The watch-set dump names every registered directory in ONE attribute, which is
	// what an operator diagnosing an incomplete watch set reads.
	dirs, ok := logs.AttrValue("fsnotify watch set", "directories")
	if !ok {
		t.Fatalf("no fsnotify-watch-set record carries a directories attribute; log = %v", logs.Messages())
	}
	if !strings.Contains(dirs, wantSanitized) {
		t.Errorf("watch-set directories = %q, want the hostile directory sanitized to %q", dirs, wantSanitized)
	}
	if !strings.Contains(dirs, ordinaryName) {
		t.Errorf("watch-set directories = %q, want the ordinary name %q byte-identical: sanitizing must not rewrite a name an operator queries on", dirs, ordinaryName)
	}

	// The per-event line names a path an untrusted party chose outright.
	if !logs.HasAttr("fs event", "path", wantSanitized) {
		t.Errorf("fs-event paths = %q, want the hostile event path sanitized to %q",
			logs.AttrValuesExact("fs event", "path"), wantSanitized)
	}

	// One filesystem-ERROR record too. The two records above are success-path ones, so
	// with only those the batch sweep below never sees an `error` attribute: every
	// logtext.Path(err.Error()) in this package could be removed and this test would
	// stay green, which is the one-site-only adoption it exists to prevent. An
	// *fs.PathError carries the walk-supplied path inside its own text, and it is the
	// shape os.Root and the walk actually mint.
	const unwatchableMsg = "skipping unwatchable path; renewals under it require a full rescan"
	walkErr := &fs.PathError{Op: "open", Path: hostileDir, Err: fs.ErrPermission}
	relevant, classifyErr := w.classifyWatchEntry(root, hostileDir, nil, walkErr)
	if classifyErr != nil || relevant {
		t.Fatalf("classifyWatchEntry(path error) = (%v, %v), want (false, nil)", relevant, classifyErr)
	}
	if !logs.HasAttr(unwatchableMsg, "error", logtext.Path(walkErr.Error())) {
		t.Errorf("unwatchable-path error was not sanitized: values = %q",
			logs.AttrValuesExact(unwatchableMsg, "error"))
	}

	assertNoUnsafeRunesInWatchAttributes(t, logs)

	// The gate is at the log call and nowhere upstream of it.
	watched := watcher.WatchList()
	if !slices.Contains(watched, hostileDir) {
		t.Errorf("watch list = %q, want the RAW directory name registered: a sanitized value that reached watcher.Add would watch a path the kernel does not have", watched)
	}
	if slices.Contains(watched, wantSanitized) {
		t.Errorf("watch list = %q holds the SANITIZED name %q: the log-boundary gate leaked into the registration path", watched, wantSanitized)
	}
	if !w.watchSetHas(hostileDir) {
		t.Error("the membership mirror does not hold the RAW directory name; the per-event fast path would read it as unwatched and re-assert the whole watch set on every event")
	}
}

// assertNoUnsafeRunesInWatchAttributes sweeps every attribute of every record in the
// batch. It is deliberately wider than the two records asserted above: this package
// names a walk-supplied or event-supplied path in many attributes, so a fix applied to
// the one site a test names is exactly the partial adoption that leaves the rest
// un-sanitized. A clean walk over this fixture carries no legitimate CR, LF or bidi
// control in any attribute, so any hit is the fixture's own name arriving raw.
func assertNoUnsafeRunesInWatchAttributes(t *testing.T, logs *capture.Recorder) {
	t.Helper()
	for _, rec := range logs.Records() {
		rec.Attrs(func(a slog.Attr) bool {
			assertAttrValueIsSingleLine(t, rec.Message, a.Key, a.Value)
			return true
		})
	}
}

// assertAttrValueIsSingleLine reports an unsafe rune in one attribute value,
// descending into a group so a nested attribute cannot hide one.
func assertAttrValueIsSingleLine(t *testing.T, msg, key string, v slog.Value) {
	t.Helper()
	if v.Kind() == slog.KindGroup {
		for _, a := range v.Group() {
			assertAttrValueIsSingleLine(t, msg, key+"."+a.Key, a.Value)
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

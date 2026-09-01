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

// hostileDirName is a directory name carrying one rune from each class that makes
// an untrusted path a record-INTEGRITY problem rather than a cosmetic one: LF ends
// a record in a single-line sink, and U+202E (RIGHT-TO-LEFT OVERRIDE) reorders
// everything after it in the rendered line. Both are legal bytes in a POSIX
// directory name, and this is a public image, so a co-writer on /input chooses
// the names this walk enumerates.
const hostileDirName = "hostile\n\u202egone"

// unsafeInAttribute is the set hostileDirName is built from, for the batch-wide
// sweep below.
var unsafeInAttribute = []string{"\n", "\r", "\u202e"}

// TestWatchRecords_sanitize_walk_supplied_names_in_log_attributes drives the REAL
// watch-set walk and event classifier over a hostile directory name: the failure
// mode is an emit site that stops calling logtext.Path, not the gate itself.
// Asserts: the hostile name is rewritten wherever it reaches an operator; an
// ordinary name is byte-identical; no attribute in the batch holds the raw
// rune; and the directory is registered under the RAW name (watcher.Add and the
// membership mirror must never see a sanitized path, or the kernel watch and
// this app's idea of what is watched diverge).
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

	// The watch-set dump names every registered directory in ONE attribute.
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

	// One filesystem-ERROR record too: the two above are success-path, so
	// without this the batch sweep below never sees an `error` attribute, and
	// every logtext.Path(err.Error()) call in this package could be removed
	// with the test staying green. *fs.PathError carries the walk-supplied
	// path inside its own text, the shape os.Root and the walk actually mint.
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

// assertNoUnsafeRunesInWatchAttributes sweeps every attribute of every record in
// the batch: deliberately wider than the two records asserted above, so a fix
// applied to only the named sites is the partial adoption this catches.
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

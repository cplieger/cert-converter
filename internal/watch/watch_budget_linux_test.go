package watch

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/fsnotify/fsnotify"
)

// walkErrorBudgetHelper marks the process that runs the assertions. It is a flag, not a
// path: whichever process runs the body builds its own fixture, so no filesystem path
// crosses the process boundary.
const walkErrorBudgetHelper = "CERT_CONVERTER_WALK_ERROR_BUDGET_HELPER"

// TestAddWatchDirs_walk_error_does_not_spend_budget_twice pins the one-charge-per-path
// rule both watch-set walks obey: WalkDir reports a directory it could not read through
// a SECOND callback for that directory's own path, and charging it again would stop the
// walk below the operator's configured MAX_SCAN_ENTRIES.
//
// Directory permissions are ignored for uid 0, so the unreadable directory the fixture
// turns on is only unreadable for an unprivileged uid: when the suite runs as root the
// body re-execs a copy of this binary as uid 65534.
func TestAddWatchDirs_walk_error_does_not_spend_budget_twice(t *testing.T) {
	if os.Geteuid() == 0 && os.Getenv(walkErrorBudgetHelper) == "" {
		runWalkErrorBudgetHelper(t)
		return
	}

	// /tmp rather than t.TempDir(): TMPDIR may name a directory only the invoking user
	// can write, and this body also runs as uid 65534 under the helper above.
	root, err := os.MkdirTemp("/tmp", "cert-converter-watch-budget-")
	if err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(root, "a.example.com")
	t.Cleanup(func() {
		_ = os.Chmod(unreadable, 0o700) // restore traversal so the tree is removable
		_ = os.RemoveAll(root)
	})
	for _, dir := range []string{unreadable, filepath.Join(root, "z.example.com")} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("fsnotify.NewWatcher() = %v", err)
	}
	defer watcher.Close()

	// Three paths of budget: the root, the unreadable directory, and its sibling.
	w := New(root, func(context.Context) {}, WithMaxEntries(3))
	if err := w.addWatchDirs(t.Context(), watcher, root); err != nil {
		t.Fatalf("addWatchDirs(%q) = %v", root, err)
	}
	want := filepath.Join(root, "z.example.com")
	if !slices.Contains(watcher.WatchList(), want) {
		t.Errorf("watch list = %v, want %q: the unreadable directory's walk-error callback must not spend a second entry and exhaust the three-path budget before this sibling", watcher.WatchList(), want)
	}
	desired, err := w.desiredWatchDirs(t.Context(), root)
	if err != nil {
		t.Fatalf("desiredWatchDirs(%q) = %v", root, err)
	}
	if _, ok := desired[want]; !ok {
		t.Errorf("desired watch set = %v, want %q: the preflight walk must apply the same one-charge-per-path budget rule as the registering walk", desired, want)
	}
}

// runWalkErrorBudgetHelper re-runs this one test in a copy of the test binary as uid
// 65534, the uid the kernel actually enforces directory permissions for. The copy lives
// under /tmp so the unprivileged uid can execute it.
func runWalkErrorBudgetHelper(t *testing.T) {
	t.Helper()
	helperDir, err := os.MkdirTemp("/tmp", "cert-converter-watch-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(helperDir) })
	if err := os.Chmod(helperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(helperDir, "watch.test")
	src, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(helperPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(helperPath, "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), walkErrorBudgetHelper+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged helper failed: %v\n%s", err, output)
	}
}

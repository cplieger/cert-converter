package process

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestMain neutralises the orphan-reap deferral for the whole package.
//
// reapDeferral is thirty seconds of real time on every sync-mode reap, so leaving the
// production wait in place would charge it to every test that deletes an orphan, and
// to every future one. Overriding it here rather than per test means no test can
// accidentally pay for it, while the contract the wait itself owns — return the
// context's error when cancellation wins, otherwise wait out the delay — is pinned
// directly in TestWaitForReapDeferral. Tests that need to observe the wait (count it, or
// let something happen inside the window) swap this var again and restore it with
// t.Cleanup, which is why they run serially.
//
// Returning ctx.Err() rather than nil keeps the cancellation half of the contract
// intact for every test that does not care about the delay: a cancelled scan must
// still abandon the reap.
func TestMain(m *testing.M) {
	waitBeforeReap = func(ctx context.Context, _ time.Duration) error {
		return ctx.Err()
	}
	os.Exit(m.Run())
}

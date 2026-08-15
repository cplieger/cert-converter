package watch

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
)

// The mode signal is an operator contract, not an incidental log line: a
// container degraded to poll mode raises renewal latency to FALLBACK_SCAN_HOURS
// while health stays green, so the ONLY way an operator learns about it is these
// records. The tests below pin all three halves of the contract — the two
// transitions, the per-scan state record's level in each mode, and the upgrade
// failure's cause surviving into the WARN — on ATTRIBUTES, because that is what a
// Loki/Alertmanager rule keys on.

// loggedRecord is one captured record reduced to what these tests assert on: its
// level and its top-level attributes by key.
type loggedRecord struct {
	attrs map[string]string
	level slog.Level
}

// recordsFor returns every captured record whose Message is EXACTLY msg, in
// capture order. Exact matching, and a walk of Records() rather than the
// Recorder's msgSub helpers, because the per-scan record shares one message
// across every scan: the helpers answer from the FIRST match, which cannot tell a
// watch-mode scan from a poll-mode one.
func recordsFor(logs *capture.Recorder, msg string) []loggedRecord {
	var out []loggedRecord
	for _, r := range logs.Records() {
		if r.Message != msg {
			continue
		}
		rec := loggedRecord{level: r.Level, attrs: map[string]string{}}
		r.Attrs(func(a slog.Attr) bool {
			rec.attrs[a.Key] = a.Value.String()
			return true
		})
		out = append(out, rec)
	}
	return out
}

// requireOneRecord returns the single record with message msg, failing when the
// count is not exactly one: a mode record that fires twice per scan doubles the
// log volume of the healthy path, and one that never fires is the silent
// degradation this whole model exists to end.
func requireOneRecord(t *testing.T, logs *capture.Recorder, msg string) loggedRecord {
	t.Helper()
	got := recordsFor(logs, msg)
	if len(got) != 1 {
		t.Fatalf("%q logged %d times, want exactly 1; log = %v", msg, len(got), logs.Messages())
	}
	return got[0]
}

// assertAttrs checks each wanted attribute on a record, reporting every mismatch
// rather than stopping at the first: an alert rule keys on the whole set.
func assertAttrs(t *testing.T, what string, rec loggedRecord, want map[string]string) {
	t.Helper()
	for key, wantValue := range want {
		got, ok := rec.attrs[key]
		if !ok {
			t.Errorf("%s carries no %q attribute (attrs = %v); an alert rule cannot key on it", what, key, rec.attrs)
			continue
		}
		if got != wantValue {
			t.Errorf("%s %s = %q, want %q", what, key, got, wantValue)
		}
	}
}

// TestAttachWatchSet_announces_entering_poll_mode_as_a_degradation pins the
// poll-entry transition: whichever half of the attach failed, the record is a
// WARN naming the mode it entered, so an operator running at the documented
// LOG_LEVEL=warn sees the process go degraded, and the cause travels with it.
// Not parallel: it swaps the process-global slog default and the newFSWatcher seam.
func TestAttachWatchSet_announces_entering_poll_mode_as_a_degradation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		msg         string
		unavailable bool
	}{
		{"fsnotify unusable", "fsnotify unavailable, using polling with periodic upgrade attempts", true},
		{"root unwatchable", "failed to watch directories, using polling with periodic upgrade attempts", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unavailable {
				stubFSWatcherUnavailable(t)
			} else {
				newTestWatcher(t) // availability probe: the root, not fsnotify, must fail here
			}
			logs := capture.Default(t)
			w := New(filepath.Join(t.TempDir(), "missing"), func(context.Context) {}, WithFallback(6*time.Hour))

			watcher, stopped := w.attachWatchSet(t.Context())
			if watcher != nil {
				watcher.Close()
				t.Fatal("attachWatchSet returned a watcher, want none so Run selects poll mode")
			}
			if stopped {
				t.Fatal("attachWatchSet stopped = true, want false: an unusable watch set is a degradation, not a shutdown")
			}

			rec := requireOneRecord(t, logs, tc.msg)
			if rec.level != slog.LevelWarn {
				t.Errorf("poll-mode entry logged at %v, want WARN: entering a standing degradation must be visible at LOG_LEVEL=warn", rec.level)
			}
			assertAttrs(t, "the poll-entry transition", rec, map[string]string{
				"mode":          "poll",
				"previous_mode": "startup",
				"fallback_scan": "6h0m0s",
			})
			if rec.attrs["error"] == "" {
				t.Errorf("the poll-entry transition carries no error attribute (attrs = %v); the operator cannot tell why fsnotify is unusable", rec.attrs)
			}
		})
	}
}

// TestAttachWatchSet_announces_watch_mode_at_info pins the other half of the
// startup transition pair: the intended mode is reported at Info with the same
// attribute vocabulary, so one query over the mode attribute answers "which mode
// is this container in" without knowing which message won.
// Not parallel: it swaps the process-global slog default.
func TestAttachWatchSet_announces_watch_mode_at_info(t *testing.T) {
	newTestWatcher(t) // availability probe: skips where inotify is unavailable
	logs := capture.Default(t)
	w := New(t.TempDir(), func(context.Context) {}, WithFallback(6*time.Hour))

	watcher, stopped := w.attachWatchSet(t.Context())
	if watcher == nil || stopped {
		t.Fatalf("attachWatchSet = (%v, stopped=%v), want an attached watcher", watcher, stopped)
	}
	defer watcher.Close()

	rec := requireOneRecord(t, logs, "fsnotify active")
	if rec.level != slog.LevelInfo {
		t.Errorf("watch-mode entry logged at %v, want INFO: the intended mode must add no warnings to a healthy deployment", rec.level)
	}
	assertAttrs(t, "the watch-mode transition", rec, map[string]string{
		"mode":          "watch",
		"previous_mode": "startup",
	})
}

// TestPollTick_announces_the_recovery_transition_at_info pins the recovery
// record: leaving a standing degradation is good news, so it reports at Info and
// names both ends of the transition (previous_mode="poll"), which is what lets an
// operator close an alert on evidence rather than on its absence.
//
// The upgrading tick runs no scan of its own (watch mode's attach-then-scan owns
// that), so it must emit no per-scan record either.
// Not parallel: it swaps the process-global slog default.
func TestPollTick_announces_the_recovery_transition_at_info(t *testing.T) {
	newTestWatcher(t) // availability probe: the tick must be able to upgrade
	logs := capture.Default(t)
	w := New(t.TempDir(), func(context.Context) {}, WithFallback(time.Hour))

	upgraded, stopped := w.pollTick(t.Context())
	if upgraded == nil || stopped {
		t.Fatalf("pollTick = (%v, stopped=%v), want an upgraded watcher", upgraded, stopped)
	}
	defer upgraded.Close()

	rec := requireOneRecord(t, logs, "fsnotify recovered, upgrading from poll to watch")
	if rec.level != slog.LevelInfo {
		t.Errorf("recovery logged at %v, want INFO: recovery is good news, not a degradation", rec.level)
	}
	assertAttrs(t, "the recovery transition", rec, map[string]string{
		"mode":          "watch",
		"previous_mode": "poll",
	})
	if n := len(recordsFor(logs, msgScanState)); n != 0 {
		t.Errorf("the upgrading tick logged %d scan records, want 0: it runs no scan, watch mode's attach-then-scan does", n)
	}
}

// TestPollTick_reports_the_standing_degradation_at_warn_with_its_cause pins the
// record that makes a PERMANENT degradation visible: every poll-mode scan reports
// at WARN with mode="poll", so a container that has been polling for a week keeps
// producing a signal at LOG_LEVEL=warn instead of looking healthy after its one
// startup line. The upgrade failure's cause must survive the level change, which
// is what upgrade_stage and error carry.
// Not parallel: it swaps the process-global slog default and the newFSWatcher seam.
func TestPollTick_reports_the_standing_degradation_at_warn_with_its_cause(t *testing.T) {
	for _, tc := range []struct {
		name        string
		root        string
		wantStage   string
		unavailable bool
	}{
		{name: "fsnotify still unusable", wantStage: "fsnotify_unavailable", unavailable: true},
		{name: "watch set cannot be rebuilt", wantStage: "watch_set_rebuild_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.unavailable {
				stubFSWatcherUnavailable(t)
			} else {
				newTestWatcher(t)                         // availability probe: the root, not fsnotify, must fail here
				root = filepath.Join(t.TempDir(), "gone") // an absent root fails the watch-set walk
			}
			logs := capture.Default(t)
			scans := 0
			w := New(root, func(context.Context) { scans++ }, WithFallback(6*time.Hour))

			upgraded, stopped := w.pollTick(t.Context())
			if upgraded != nil {
				upgraded.Close()
				t.Fatal("pollTick handed back a watcher, want none: this tick must stay in poll mode")
			}
			if stopped {
				t.Fatal("pollTick stopped = true, want false so polling continues")
			}
			if scans != 1 {
				t.Fatalf("pollTick ran %d scans, want 1: the tick's scan is the only live change detection", scans)
			}

			// README's CertConverterChangeDetectionDegraded rule matches the
			// literal line `change detection scan` plus mode=poll, so the message
			// is pinned as a LITERAL rather than via msgScanState: a reword of the
			// shared constant must fail here, not in an operator's Loki rule that
			// silently stops matching. recordsFor matches the message exactly, so
			// this pins the whole line; main_test.go pins its alerted messages the
			// same way.
			rec := requireOneRecord(t, logs, "change detection scan")
			if rec.level != slog.LevelWarn {
				t.Errorf("poll-mode scan logged at %v, want WARN: a standing degradation must stay visible at LOG_LEVEL=warn", rec.level)
			}
			assertAttrs(t, "the poll-mode scan record", rec, map[string]string{
				"mode":          "poll",
				"trigger":       "poll",
				"upgrade_stage": tc.wantStage,
				"fallback_scan": "6h0m0s",
			})
			if rec.attrs["error"] == "" {
				t.Errorf("the poll-mode scan record carries no error attribute (attrs = %v); relevelling the continuation record must not cost the reason the upgrade failed", rec.attrs)
			}
		})
	}
}

// TestPollLoopWithUpgrade_reports_poll_mode_on_its_initial_scan pins the mode
// signal on poll mode's FIRST scan, the one that runs before the ticker exists.
// Without it the disabled-fallback configuration would scan once, report nothing
// about the mode it is in, and exit for a restart.
// Not parallel: it swaps the process-global slog default and the newFSWatcher seam.
func TestPollLoopWithUpgrade_reports_poll_mode_on_its_initial_scan(t *testing.T) {
	stubFSWatcherUnavailable(t)
	logs := capture.Default(t)
	scans := 0
	// No WithFallback: the initial scan is then the only one, so the record
	// asserted below can only be its own.
	w := New(t.TempDir(), func(context.Context) { scans++ })

	if fw, err := w.pollLoopWithUpgrade(t.Context()); fw != nil {
		fw.Close()
		t.Fatal("pollLoopWithUpgrade handed back a watcher, want none")
	} else if err == nil {
		t.Fatal("pollLoopWithUpgrade(no fallback) = nil, want a *LostError")
	}
	if scans != 1 {
		t.Fatalf("pollLoopWithUpgrade ran %d scans, want 1", scans)
	}

	rec := requireOneRecord(t, logs, msgScanState)
	if rec.level != slog.LevelWarn {
		t.Errorf("poll mode's initial scan logged at %v, want WARN", rec.level)
	}
	assertAttrs(t, "poll mode's initial scan record", rec, map[string]string{
		"mode":          "poll",
		"trigger":       "startup",
		"fallback_scan": "disabled",
	})
}

// TestWatchModeScans_report_watch_mode_at_info pins the healthy half of the
// per-scan contract at all three watch-mode scan sites: one record per scan, at
// INFO, naming the mode and which clock or event caused the scan. The zero-WARN
// assertion is the point of the level rule — a healthy deployment must add no
// warning noise, or the poll-mode WARN above stops meaning anything.
// Not parallel: it swaps the process-global slog default.
func TestWatchModeScans_report_watch_mode_at_info(t *testing.T) {
	for _, tc := range []struct {
		scan        func(ctx context.Context, t *testing.T, cancel context.CancelFunc, scans *int)
		name        string
		wantTrigger string
	}{
		{
			name:        "post-attach scan",
			wantTrigger: "attach",
			scan: func(ctx context.Context, t *testing.T, cancel context.CancelFunc, scans *int) {
				watcher := newTestWatcher(t)
				// Cancelling from inside the scan lets watchLoop return immediately
				// afterwards, so the assertion covers exactly the attach scan.
				w := New(t.TempDir(), func(context.Context) { *scans++; cancel() }, WithFallback(time.Hour))
				if err := w.scanThenWatch(ctx, watcher); err != nil {
					t.Fatalf("scanThenWatch = %v, want nil", err)
				}
			},
		},
		{
			name:        "debounced event scan",
			wantTrigger: "event",
			scan: func(ctx context.Context, t *testing.T, _ context.CancelFunc, scans *int) {
				// absentWatchRoot: the scan's watch-set re-assert fails at the root and
				// returns before touching a watcher, so a nil one is safe here (the
				// same trick watch_state_test.go uses for the timer arithmetic).
				st := newWatchState(New(absentWatchRoot, func(context.Context) { *scans++ }, WithDebounce(time.Hour)))
				t.Cleanup(st.stop)
				st.scheduleScan()
				st.runDebouncedScan(ctx, nil)
			},
		},
		{
			name:        "periodic fallback scan",
			wantTrigger: "fallback",
			scan: func(ctx context.Context, t *testing.T, _ context.CancelFunc, scans *int) {
				st := newWatchState(New(absentWatchRoot, func(context.Context) { *scans++ }, WithFallback(6*time.Hour)))
				t.Cleanup(st.stop)
				st.runSafetyNetScan(ctx)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			scans := 0

			tc.scan(ctx, t, cancel, &scans)

			if scans != 1 {
				t.Fatalf("the %s ran %d scans, want 1", tc.name, scans)
			}
			rec := requireOneRecord(t, logs, msgScanState)
			if rec.level != slog.LevelInfo {
				t.Errorf("the %s logged its state record at %v, want INFO", tc.name, rec.level)
			}
			assertAttrs(t, "the "+tc.name+" record", rec, map[string]string{
				"mode":    "watch",
				"trigger": tc.wantTrigger,
			})
			if n := logs.CountLevel(slog.LevelWarn, msgScanState); n != 0 {
				t.Errorf("the %s logged %d WARN state records, want 0: a healthy deployment must add no warning noise; log = %v", tc.name, n, logs.Messages())
			}
			if n := logs.CountLevel(slog.LevelError, ""); n != 0 {
				t.Errorf("the %s logged %d ERROR records, want 0: this package is deliberately silent at ERROR, main owns the one announcement", tc.name, n)
			}
		})
	}
}

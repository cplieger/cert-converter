package process

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLogScanOutcome_levels pins the level and message of the end-of-scan
// summary. The README's Loki alerts key on exactly these: a completed scan must
// emit "scan complete" at Info (its absence for 8h is the stall alert), a
// shutdown-cancelled walk must stay at Debug so a normal restart never pages,
// and any other abort must be a Warn an operator sees.
func TestLogScanOutcome_levels(t *testing.T) {
	result := ScanResult{Total: 2, Converted: 1, Unchanged: 1}
	tests := []struct {
		walkErr   error
		name      string
		wantMsg   string
		wantLevel slog.Level
	}{
		{nil, "completed walk logs scan complete at info", "scan complete", slog.LevelInfo},
		{context.Canceled, "cancelled walk logs at debug", "scan cancelled during shutdown", slog.LevelDebug},
		{context.DeadlineExceeded, "deadline exceeded logs at debug", "scan cancelled during shutdown", slog.LevelDebug},
		{errors.New("permission denied"), "other abort logs at warn", "scan aborted before completion", slog.LevelWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			logScanOutcome(t.Context(), result, tt.walkErr)

			out := buf.String()
			if !strings.Contains(out, tt.wantMsg) {
				t.Errorf("logScanOutcome(walkErr=%v) logged %q, want message %q", tt.walkErr, out, tt.wantMsg)
			}
			if !strings.Contains(out, "level="+tt.wantLevel.String()) {
				t.Errorf("logScanOutcome(walkErr=%v) logged %q, want level %s", tt.walkErr, out, tt.wantLevel)
			}
			if !strings.Contains(out, "converted=1") {
				t.Errorf("logScanOutcome(walkErr=%v) logged %q, want the converted count in the summary", tt.walkErr, out)
			}
		})
	}
}

// TestLogEntryFailure_levels pins the per-entry failure level split: a failure
// caused by shutdown stays at Debug, so stopping the container never emits an
// operator-facing error line, while every real conversion failure is an Error
// the log-based alerting can act on. Both cases keep the cert's relative path.
func TestLogEntryFailure_levels(t *testing.T) {
	tests := []struct {
		err       error
		name      string
		wantMsg   string
		wantLevel slog.Level
	}{
		{errors.New("permission denied"), "real failure logs at error", `msg="conversion failed"`, slog.LevelError},
		{context.Canceled, "cancellation logs at debug", `msg="conversion failed (shutdown)"`, slog.LevelDebug},
		{context.DeadlineExceeded, "deadline exceeded logs at debug", `msg="conversion failed (shutdown)"`, slog.LevelDebug},
		{errors.Join(errors.New("read certificate"), context.Canceled), "wrapped cancellation logs at debug", `msg="conversion failed (shutdown)"`, slog.LevelDebug},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			logEntryFailure("example.com/tls.crt", "conversion failed", tt.err)

			out := buf.String()
			if !strings.Contains(out, tt.wantMsg) {
				t.Errorf("logEntryFailure(%v) logged %q, want %s", tt.err, out, tt.wantMsg)
			}
			if !strings.Contains(out, "level="+tt.wantLevel.String()) {
				t.Errorf("logEntryFailure(%v) logged %q, want level %s", tt.err, out, tt.wantLevel)
			}
			if !strings.Contains(out, "path=example.com/tls.crt") {
				t.Errorf("logEntryFailure(%v) logged %q, want the cert's relative path", tt.err, out)
			}
		})
	}
}

// TestReadPair_distinguishes_a_missing_key_from_an_unstattable_one pins the
// diagnosability split in readPair. Both outcomes are the same health-neutral
// statusOrphan, so the log line is the ONLY observable difference between a
// cert that simply has no sibling key (the normal, quiet steady state, Debug)
// and one whose sibling key exists but cannot be stat-ed through the confined
// root (a symlink escaping /input, or a permission error), which is deliberately
// surfaced at Warn so the misconfiguration is diagnosable rather than hidden
// behind LOG_LEVEL=debug. Collapsing the two arms leaves an operator with no
// default-level evidence of a broken input layout. Runs serially: it swaps
// slog.Default().
func TestReadPair_distinguishes_a_missing_key_from_an_unstattable_one(t *testing.T) {
	base := t.TempDir()
	input := filepath.Join(base, "input")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{input, outside} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "real.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lonely.crt", "escape.crt"} {
		if err := os.WriteFile(filepath.Join(input, name), []byte("pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A sibling key that exists but escapes the input root: the confined Stat
	// refuses it with a non-ENOENT error, which is not a genuine "no key".
	if err := os.Symlink(filepath.Join(outside, "real.key"), filepath.Join(input, "escape.key")); err != nil {
		t.Fatal(err)
	}
	inHandle, err := os.OpenRoot(input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inHandle.Close() })
	sw := &scanWalk{inHandle: inHandle}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for _, tt := range []struct{ certRel, keyRel, wantMsg, wantLevel string }{
		{"lonely.crt", "lonely.key", "skipping cert without matching key", "level=DEBUG"},
		{"escape.crt", "escape.key", "skipping cert: cannot stat sibling key", "level=WARN"},
	} {
		buf.Reset()

		_, outcome, ok := sw.readPair(t.Context(), tt.certRel, tt.keyRel)

		if ok {
			t.Errorf("readPair(%q) ok = true, want false (an unusable sibling key is never a readable pair)", tt.certRel)
		}
		if outcome != statusOrphan {
			t.Errorf("readPair(%q) outcome = %d, want statusOrphan (%d)", tt.certRel, outcome, statusOrphan)
		}
		out := buf.String()
		if !strings.Contains(out, tt.wantMsg) || !strings.Contains(out, tt.wantLevel) {
			t.Errorf("readPair(%q) logged %q, want message %q at %s", tt.certRel, out, tt.wantMsg, tt.wantLevel)
		}
	}
}

// TestLogScanOutcome_flags_an_input_tree_with_no_certificate_pairs pins the
// empty-input notice the README documents (a certbot-style directory of
// fullchain.pem/privkey.pem "produces no output and logs `no certificate pairs
// found under the input root`"). A completed scan that visited no .crt is
// indistinguishable from a healthy steady state in the summary counts -- failed
// is 0, so the marker stays set and none of the README's Loki rules fire -- so
// this line is the only signal of a wrong or vanished /input mount. It must fire
// for exactly that shape: a scan that converted a pair, one whose empty result
// is already explained by an unreadable sub-path, and an aborted scan must all
// stay quiet, or the notice becomes noise on every fsnotify event and every
// fallback tick. Runs serially: it swaps slog.Default().
func TestLogScanOutcome_flags_an_input_tree_with_no_certificate_pairs(t *testing.T) {
	const wantMsg = "no certificate pairs found under the input root"
	tests := []struct {
		walkErr  error
		name     string
		result   ScanResult
		wantWarn bool
	}{
		{nil, "an empty input tree is named", ScanResult{}, true},
		{nil, "a scan that converted a pair stays quiet", ScanResult{Total: 1, Converted: 1}, false},
		{nil, "an unreadable sub-path already explains the empty result", ScanResult{Unreadable: 1}, false},
		{errors.New("permission denied"), "an aborted scan stays quiet", ScanResult{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			logScanOutcome(t.Context(), tt.result, tt.walkErr)

			out := buf.String()
			if got := strings.Contains(out, wantMsg); got != tt.wantWarn {
				t.Errorf("logScanOutcome(%+v, %v) logged %q; empty-input notice present = %v, want %v",
					tt.result, tt.walkErr, out, got, tt.wantWarn)
			}
			if tt.wantWarn && !strings.Contains(out, "level=WARN") {
				t.Errorf("logScanOutcome(%+v, nil) logged %q, want the empty-input notice at level WARN", tt.result, out)
			}
		})
	}
}

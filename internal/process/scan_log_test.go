package process

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
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

// Package scanreport writes each scan's verdict as the end-of-scan record, the one
// log line the shipped log rules read.
package scanreport

import (
	"context"
	"log/slog"

	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/process"
)

// Message is the end-of-scan record's message. The shipped log rules select the
// record by it and read its fields by name, so both are the record's contract
// (TestLogQLRulesUnwrapNumericRecordFields).
const Message = "scan complete"

// Scan is one finished scan: the scanner's verdict, the error it ended with, and
// whether change detection was polling when it ran.
type Scan struct {
	Err     error
	Result  process.ScanResult
	Polling bool
}

// fields is the ONE list of the record's fields, each a number so a log rule can
// unwrap it.
var fields = []struct {
	of   func(*Scan) int
	name string
}{
	{name: "total", of: func(s *Scan) int { return s.Result.Total }},
	{name: "converted", of: func(s *Scan) int { return s.Result.Converted }},
	{name: "unchanged", of: func(s *Scan) int { return s.Result.Unchanged }},
	{name: "orphan", of: func(s *Scan) int { return s.Result.Orphan }},
	{name: "unreadable", of: func(s *Scan) int { return s.Result.Unreadable }},
	{name: "unresolved", of: func(s *Scan) int { return s.Result.Unresolved }},
	{name: "vanished", of: func(s *Scan) int { return s.Result.Vanished }},
	{name: "unwritable", of: func(s *Scan) int { return s.Result.Unwritable }},
	{name: "collided", of: func(s *Scan) int { return s.Result.Collided }},
	{name: "excluded", of: func(s *Scan) int { return s.Result.Excluded }},
	{name: "ignored", of: func(s *Scan) int { return s.Result.Ignored }},
	{name: "removed", of: func(s *Scan) int { return s.Result.Removed }},
	{name: "failed", of: func(s *Scan) int { return s.Result.Failed }},
	{name: "aborted", of: func(s *Scan) int { return flag(s.Result.Outcome == process.OutcomeAborted) }},
	{name: "budget_stopped", of: func(s *Scan) int { return flag(s.Result.Outcome == process.OutcomeBudgetStopped) }},
	{name: "polling", of: func(s *Scan) int { return flag(s.Polling) }},
	{name: "no_sources", of: func(s *Scan) int { return flag(s.Result.NoSources) }},
	{name: "all_excluded", of: func(s *Scan) int { return flag(s.Result.AllExcluded) }},
	{name: "orphan_removal_disabled", of: func(s *Scan) int { return flag(s.Result.OrphanRemovalDisabled) }},
	{name: "previous_layout_retained", of: func(s *Scan) int { return flag(s.Result.PreviousLayoutRetained) }},
	{name: "cleanup_degraded", of: func(s *Scan) int { return flag(s.Result.CleanupDegraded) }},
}

func flag(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Log writes the end-of-scan record: INFO for a scan that covered the tree, WARN
// for one that aborted or stopped at the entry budget. A scan shutdown cut short
// has no verdict, so the caller does not report it.
func Log(ctx context.Context, scan *Scan) {
	level := slog.LevelInfo
	if scan.Result.Outcome != process.OutcomeComplete {
		level = slog.LevelWarn
	}
	attrs := make([]any, 0, 2+2*len(fields))
	if scan.Err != nil {
		attrs = append(attrs, "error", logtext.Path(scan.Err.Error()))
	}
	for _, f := range fields {
		attrs = append(attrs, f.name, f.of(scan))
	}
	slog.Log(ctx, level, Message, attrs...)
}

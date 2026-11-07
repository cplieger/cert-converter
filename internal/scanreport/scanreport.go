// Package scanreport writes each scan's verdict once, to the end-of-scan record the
// shipped log rules read and to the metrics the shipped metric rules read, so the
// two never disagree.
package scanreport

import (
	"context"
	"log/slog"
	"time"

	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/go/measure"
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

// series says which metric a record field also sets.
type series int

const (
	// seriesOwn is a field with its own metric, set by name in Report.
	seriesOwn series = iota
	// seriesSource is one outcome label of last_scan_sources.
	seriesSource
	// seriesCondition is one condition label of the condition gauge.
	seriesCondition
)

// fields is the ONE list of the record's fields, each a number so a log rule can
// unwrap it, and of the metric each one sets.
var fields = []struct {
	of     func(*Scan) int
	name   string
	series series
}{
	{name: "total", of: func(s *Scan) int { return s.Result.Total }},
	{name: "converted", of: func(s *Scan) int { return s.Result.Converted }, series: seriesSource},
	{name: "unchanged", of: func(s *Scan) int { return s.Result.Unchanged }, series: seriesSource},
	{name: "orphan", of: func(s *Scan) int { return s.Result.Orphan }, series: seriesSource},
	{name: "unreadable", of: func(s *Scan) int { return s.Result.Unreadable }, series: seriesSource},
	{name: "unresolved", of: func(s *Scan) int { return s.Result.Unresolved }, series: seriesSource},
	{name: "vanished", of: func(s *Scan) int { return s.Result.Vanished }, series: seriesSource},
	{name: "unwritable", of: func(s *Scan) int { return s.Result.Unwritable }, series: seriesSource},
	{name: "collided", of: func(s *Scan) int { return s.Result.Collided }, series: seriesSource},
	{name: "excluded", of: func(s *Scan) int { return s.Result.Excluded }, series: seriesSource},
	{name: "ignored", of: func(s *Scan) int { return s.Result.Ignored }, series: seriesSource},
	{name: "removed", of: func(s *Scan) int { return s.Result.Removed }},
	{name: "failed", of: func(s *Scan) int { return s.Result.Failed }, series: seriesSource},
	{name: "aborted", of: func(s *Scan) int { return flag(s.Result.Outcome == process.OutcomeAborted) }},
	{name: "budget_stopped", of: func(s *Scan) int { return flag(s.Result.Outcome == process.OutcomeBudgetStopped) }},
	{name: "polling", of: func(s *Scan) int { return flag(s.Polling) }},
	{name: "no_sources", of: func(s *Scan) int { return flag(s.Result.NoSources) }, series: seriesCondition},
	{name: "all_excluded", of: func(s *Scan) int { return flag(s.Result.AllExcluded) }, series: seriesCondition},
	{name: "orphan_removal_disabled", of: func(s *Scan) int { return flag(s.Result.OrphanRemovalDisabled) }, series: seriesCondition},
	{name: "previous_layout_retained", of: func(s *Scan) int { return flag(s.Result.PreviousLayoutRetained) }, series: seriesCondition},
	{name: "cleanup_degraded", of: func(s *Scan) int { return flag(s.Result.CleanupDegraded) }, series: seriesCondition},
}

func flag(b bool) int {
	if b {
		return 1
	}
	return 0
}

// logRecord writes the end-of-scan record; the log rules read it at either level.
func logRecord(ctx context.Context, scan *Scan) {
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

// Reporter writes each scan's verdict to the record and the metrics in one call.
type Reporter struct {
	sources   *measure.LabeledGauge
	found     *measure.Gauge
	finished  *measure.Gauge
	outcome   *measure.LabeledGauge
	mode      *measure.LabeledGauge
	condition *measure.LabeledGauge
	removed   *measure.Counter
}

// reportClock is indirected so a test can pin the last-scan timestamp.
var reportClock = time.Now

var (
	outcomes = []process.Outcome{process.OutcomeComplete, process.OutcomeAborted, process.OutcomeBudgetStopped}
	modes    = []string{"watch", "poll"}
)

// NewReporter registers the scan metrics on reg and seeds every label value at 0,
// so a rule sees each series from the first scrape.
func NewReporter(reg *measure.Registry) *Reporter {
	r := &Reporter{
		sources: measure.NewLabeledGauge("last_scan_sources",
			"Sources the last scan resolved to each outcome.", []string{"outcome"}),
		found: measure.NewGauge("last_scan_sources_found",
			"Certificate sources the last scan found under /input."),
		finished: measure.NewGauge("last_scan_timestamp_seconds",
			"Unix time the last scan ended, 0 before the first one."),
		outcome: measure.NewLabeledGauge("last_scan_outcome",
			"1 for how the last scan ended, 0 for the other outcomes.", []string{"outcome"}),
		mode: measure.NewLabeledGauge("change_detection_mode",
			"1 for the change-detection mode the last scan ran in, 0 for the other.", []string{"mode"}),
		condition: measure.NewLabeledGauge("condition",
			"1 while the last scan reported the standing condition, else 0.", []string{"condition"}),
		removed: measure.NewCounter("removed_artifacts_total",
			"Output artifacts removed because their source is gone."),
	}
	reg.MustRegister(r.sources, r.found, r.finished, r.outcome, r.mode, r.condition, r.removed)
	r.set(&Scan{}, 0)
	for _, o := range outcomes {
		r.outcome.Set(0, o.String())
	}
	for _, m := range modes {
		r.mode.Set(0, m)
	}
	return r
}

// Report writes the end-of-scan record and sets the metrics from the same scan. A
// scan shutdown cut short has no verdict, so the caller does not report it.
func (r *Reporter) Report(ctx context.Context, scan *Scan) {
	logRecord(ctx, scan)
	r.set(scan, float64(reportClock().Unix()))
	r.removed.Add(int64(scan.Result.Removed))
}

func (r *Reporter) set(scan *Scan, finished float64) {
	for _, f := range fields {
		switch f.series {
		case seriesSource:
			r.sources.Set(float64(f.of(scan)), f.name)
		case seriesCondition:
			r.condition.Set(float64(f.of(scan)), f.name)
		case seriesOwn:
		}
	}
	r.found.Set(float64(scan.Result.Total))
	r.finished.Set(finished)
	for _, o := range outcomes {
		r.outcome.Set(float64(flag(scan.Result.Outcome == o)), o.String())
	}
	r.mode.Set(float64(flag(scan.Polling)), "poll")
	r.mode.Set(float64(flag(!scan.Polling)), "watch")
}

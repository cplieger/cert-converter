// Package obs owns cert-converter's metrics registry, prefixed cert_converter_:
// build_info and the scan series. It writes each scan's verdict once, to the
// end-of-scan record the shipped log rules read and to the metrics the shipped
// metric rules read, so the two never disagree.
package obs

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/cplieger/cert-converter/internal/logtext"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/go/measure/v2"
	"github.com/cplieger/go/textsafe"
)

// recordMessage is the end-of-scan record's message. The shipped log rules select
// the record by it and read its fields by name, so both are the record's contract
// (TestLogQLRulesUnwrapNumericRecordFields).
const recordMessage = "scan complete"

// Scan is one finished scan: the scanner's verdict, the error it ended with,
// whether change detection was polling when it ran, and whether it left the
// container healthy.
type Scan struct {
	Err     error
	Result  process.ScanResult
	Polling bool
	Healthy bool
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
	slog.Log(ctx, level, recordMessage, attrs...)
}

// Reporter writes each scan's verdict to the record and the metrics in one call.
type Reporter struct {
	snapshot  atomic.Pointer[[]process.SourceState] // the latest reported scan's Sources
	outcomeOf *measure.Desc
	converted *measure.Desc
	next      *measure.Gauge
	sources   *measure.LabeledGauge
	found     *measure.Gauge
	finished  *measure.Gauge
	outcome   *measure.LabeledGauge
	mode      *measure.LabeledGauge
	condition *measure.LabeledGauge
	removed   *measure.Counter
	deadline  *measure.Gauge
	succeeded *measure.Gauge
	lease     time.Duration
}

// reportClock is indirected so a test can pin the last-scan timestamp and the
// scan deadline.
var reportClock = time.Now

// outcomeLabel names the label of every family keyed by an outcome.
const outcomeLabel = "outcome"

var (
	outcomes = []process.Outcome{process.OutcomeComplete, process.OutcomeAborted, process.OutcomeBudgetStopped}
	modes    = []string{"watch", "poll"}
)

// New builds the registry the metrics listener serves, with build_info set for
// version and the scan series on it. lease is the gap the scan deadline allows
// after the start and after each healthy scan.
func New(version string, lease time.Duration) (*measure.Registry, *Reporter) {
	reg := measure.NewRegistry("cert_converter")
	buildInfo := measure.NewLabeledGauge("build_info",
		"Always 1; the version label is the cert-converter release this process runs.", measure.UnitNone, []string{"version"})
	reg.MustRegister(buildInfo)
	buildInfo.Set(1, version)
	return reg, newReporter(reg, lease)
}

// newReporter registers the scan metrics on reg and seeds every label value at
// 0, so a rule sees each series from the first scrape.
func newReporter(reg *measure.Registry, lease time.Duration) *Reporter {
	r := &Reporter{
		lease: lease,
		sources: measure.NewLabeledGauge("last_scan_sources",
			"Sources at each outcome in the last scan; a scan that did not cover the tree keeps the previous scan's problem counts.", measure.UnitCount, []string{outcomeLabel}),
		found: measure.NewGauge("last_scan_sources_found",
			"Certificate sources the last scan found under /input.", measure.UnitCount),
		finished: measure.NewGauge("last_scan_timestamp_seconds",
			"Unix time the last scan ended, 0 before the first one.", measure.UnitSeconds),
		outcome: measure.NewLabeledGauge("last_scan_outcome",
			"1 for how the last scan ended, 0 for the other outcomes.", measure.UnitNone, []string{outcomeLabel}),
		mode: measure.NewLabeledGauge("change_detection_mode",
			"1 for the change-detection mode the last scan ran in, 0 for the other.", measure.UnitNone, []string{"mode"}),
		condition: measure.NewLabeledGauge("condition",
			"1 while the last scan reported the standing condition, else 0.", measure.UnitNone, []string{"condition"}),
		removed: measure.NewCounter("removed_artifacts_total",
			"Output artifacts removed because their source is gone.", measure.UnitCount),
		deadline: measure.NewGauge("scan_deadline_timestamp_seconds",
			"Unix time by which the next healthy scan is due: the last healthy scan's end, or the start, plus three guaranteed recheck cadences.", measure.UnitSeconds),
		succeeded: measure.NewGauge("last_success_timestamp_seconds",
			"Unix time the last healthy scan ended, 0 before the first one.", measure.UnitSeconds),
		next: measure.NewGauge("next_scan_timestamp_seconds",
			"Unix time of the next guaranteed recheck of every source; a changed file under /input can bring a scan sooner.", measure.UnitSeconds),
		outcomeOf: measure.NewStateSetDesc("source_outcome",
			"1 for the outcome the latest scan that reached the source gave it, 0 for the others; source is a path under /input.",
			[]string{"source", outcomeLabel}, process.SourceOutcomeNames()),
		converted: measure.NewGaugeDesc("source_last_conversion_timestamp_seconds",
			"Unix time the source was last converted, from its newest output artifact after a restart; 0 when it has no output.",
			measure.UnitSeconds, []string{"source"}),
	}
	reg.MustRegister(r.sources, r.found, r.finished, r.outcome, r.mode, r.condition, r.removed, r.deadline, r.succeeded,
		r.next, measure.NewCollector(r.collectSources, r.outcomeOf, r.converted))
	r.set(&Scan{}, 0)
	start := reportClock()
	r.renewDeadline(start)
	// The startup scan is the next guaranteed one, and it is due now.
	r.SetNextScan(start)
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
	now := reportClock()
	r.set(scan, float64(now.Unix()))
	sources := scan.Result.Sources
	r.snapshot.Store(&sources)
	r.removed.Add(int64(scan.Result.Removed))
	if scan.Healthy {
		r.succeeded.Set(float64(now.Unix()))
		r.renewDeadline(now)
	}
}

// SetNextScan records at as the time of the next guaranteed recheck of every
// source.
func (r *Reporter) SetNextScan(at time.Time) {
	r.next.Set(float64(at.Unix()))
}

// collectSources serves one series per source of the latest reported scan, so a
// source that scan no longer holds leaves the page; before the first report it
// serves none.
func (r *Reporter) collectSources(_ context.Context, e *measure.Emitter) {
	sources := r.snapshot.Load()
	if sources == nil {
		return
	}
	for i := range *sources {
		s := &(*sources)[i]
		// The path is a file name from /input; it is sanitised where it leaves the
		// program (textsafe README), as every log line naming it is.
		label := textsafe.SanitizeSingleLine(s.Path)
		e.EmitState(r.outcomeOf, s.Outcome.String(), label)
		e.Emit(r.converted, unixOrZero(s.LastConverted), label)
	}
}

// unixOrZero is at in Unix seconds, and 0 for the zero time, which means none.
func unixOrZero(at time.Time) float64 {
	if at.IsZero() {
		return 0
	}
	return float64(at.Unix())
}

// renewDeadline dates the next healthy scan one lease after at. Only the start
// and a healthy scan call it, so scans that keep failing cross the deadline.
func (r *Reporter) renewDeadline(at time.Time) {
	r.deadline.Set(float64(at.Add(r.lease).Unix()))
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

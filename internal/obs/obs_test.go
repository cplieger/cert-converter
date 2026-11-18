package obs

import (
	"bytes"
	"errors"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/go/measure/v2"
	"github.com/cplieger/go/slogx"
	"github.com/cplieger/go/slogx/capture"
)

// TestRecordCarriesEveryVerdictField sets each ScanResult field in turn, and the
// polling flag, and requires exactly one record field to move from the clean
// scan's value. A field added to ScanResult without a record field fails here
// rather than staying invisible to every rule and reader.
func TestRecordCarriesEveryVerdictField(t *testing.T) {
	clean := renderRecord(t, &Scan{})
	moved := func(scan *Scan) []string {
		var changed []string
		for key, value := range renderRecord(t, scan) {
			if key != "time" && key != "level" && key != "error" && clean[key] != value {
				changed = append(changed, key)
			}
		}
		return changed
	}

	typ := reflect.TypeFor[process.ScanResult]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Name == "Sources" {
			// Sources sets the per-source series, not a record field
			// (TestReportServesEachSourceOnce).
			continue
		}
		var scan Scan
		v := reflect.ValueOf(&scan.Result).Elem().Field(i)
		switch {
		case field.Type == reflect.TypeFor[process.Outcome]():
			for _, outcome := range []process.Outcome{process.OutcomeAborted, process.OutcomeBudgetStopped} {
				scan.Result.Outcome = outcome
				if got := moved(&scan); len(got) != 1 {
					t.Errorf("Outcome=%v moves record fields %v, want exactly one", outcome, got)
				}
			}
			continue
		case field.Type.Kind() == reflect.Bool:
			v.SetBool(true)
		case field.Type.Kind() == reflect.Int:
			v.SetInt(7)
		default:
			t.Errorf("ScanResult.%s has type %s, which this test cannot set", field.Name, field.Type)
			continue
		}
		if got := moved(&scan); len(got) != 1 {
			t.Errorf("ScanResult.%s moves record fields %v, want exactly one", field.Name, got)
		}
	}
	if got := moved(&Scan{Polling: true}); len(got) != 1 || got[0] != "polling" {
		t.Errorf("Polling moves record fields %v, want [polling]", got)
	}
}

// TestLogLevels pins the record's level: INFO for a scan that covered the tree,
// WARN for one that aborted or stopped at the budget, so a reader at
// LOG_LEVEL=warn still sees a scan that did not finish its work.
func TestLogLevels(t *testing.T) {
	for _, tc := range []struct {
		scan  Scan
		name  string
		level slog.Level
	}{
		{name: "complete", scan: Scan{Result: process.ScanResult{Total: 1, Converted: 1}}, level: slog.LevelInfo},
		{name: "aborted", scan: Scan{Result: process.ScanResult{Outcome: process.OutcomeAborted}, Err: errors.New("open input root")}, level: slog.LevelWarn},
		{name: "budget stopped", scan: Scan{Result: process.ScanResult{Outcome: process.OutcomeBudgetStopped}}, level: slog.LevelWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := capture.Default(t)
			logRecord(t.Context(), &tc.scan)
			if got := logs.CountLevel(tc.level, recordMessage); got != 1 {
				t.Errorf("logRecord(%s) wrote %q, want one %s record %q", tc.name, logs.Messages(), tc.level, recordMessage)
			}
			if tc.scan.Err != nil && !logs.HasAttr(recordMessage, "error", tc.scan.Err.Error()) {
				t.Errorf("logRecord(%s) wrote no error attribute naming the cause", tc.name)
			}
		})
	}
}

// TestReportSetsEverySeriesFromTheRecord pins that one Report call sets every
// scan series to the value of the record it writes, both parsed from what they
// emit, so the log rules and the metric rules read the same verdict.
func TestReportSetsEverySeriesFromTheRecord(t *testing.T) {
	const lease = 18 * time.Hour
	at := time.Unix(1_800_000_000, 0)
	pinClock(t, &at)
	reg := measure.NewRegistry("cert_converter")
	reporter := newReporter(reg, lease)

	scan := Scan{Polling: true, Result: process.ScanResult{
		Total: 9, Converted: 1, Unchanged: 2, Orphan: 3, Unreadable: 4, Unresolved: 5, Vanished: 6,
		Unwritable: 7, Collided: 8, Excluded: 10, Ignored: 11, Removed: 12, Failed: 13,
		Outcome: process.OutcomeBudgetStopped, NoSources: true, CleanupDegraded: true,
	}}
	var buf bytes.Buffer
	handler, _ := slogx.NewHandler(slogx.Options{Output: &buf})
	capture.SwapDefault(t, slog.New(handler))
	reporter.Report(t.Context(), &scan)
	record := parseLogfmt(t, strings.TrimSpace(buf.String()))

	families, err := reg.Gather(t.Context())
	if err != nil {
		t.Fatalf("Gather = %v", err)
	}
	got := make(map[string]float64)
	for _, f := range families {
		for _, s := range f.Samples {
			key := f.Name
			for _, l := range s.Labels {
				key += "{" + l.Name + "=" + l.Value + "}"
			}
			got[key] = s.Value
		}
	}
	num := func(field string) float64 {
		v, err := strconv.ParseFloat(record[field], 64)
		if err != nil {
			t.Fatalf("record field %s = %q: %v", field, record[field], err)
		}
		return v
	}
	want := map[string]float64{
		"cert_converter_last_scan_sources_found":                   num("total"),
		"cert_converter_removed_artifacts_total":                   num("removed"),
		"cert_converter_last_scan_timestamp_seconds":               float64(at.Unix()),
		"cert_converter_last_scan_outcome{outcome=complete}":       1 - num("aborted") - num("budget_stopped"),
		"cert_converter_last_scan_outcome{outcome=aborted}":        num("aborted"),
		"cert_converter_last_scan_outcome{outcome=budget_stopped}": num("budget_stopped"),
		"cert_converter_change_detection_mode{mode=poll}":          num("polling"),
		"cert_converter_change_detection_mode{mode=watch}":         1 - num("polling"),
		// Not record fields: the scan is not healthy, so the deadline keeps its
		// start value and no healthy scan has ended (TestScanDeadline).
		"cert_converter_scan_deadline_timestamp_seconds": float64(at.Add(lease).Unix()),
		"cert_converter_last_success_timestamp_seconds":  0,
		// Not a record field: the startup scan is the next guaranteed one, due at
		// the start. The scan holds no Sources, so no per-source series is served.
		"cert_converter_next_scan_timestamp_seconds": float64(at.Unix()),
	}
	for _, outcome := range []string{"converted", "unchanged", "orphan", "unreadable", "unresolved", "vanished", "unwritable", "collided", "excluded", "ignored", "failed"} {
		want["cert_converter_last_scan_sources{outcome="+outcome+"}"] = num(outcome)
	}
	for _, condition := range []string{"no_sources", "all_excluded", "orphan_removal_disabled", "previous_layout_retained", "cleanup_degraded"} {
		want["cert_converter_condition{condition="+condition+"}"] = num(condition)
	}
	for key, w := range want {
		if g, ok := got[key]; !ok || g != w {
			t.Errorf("%s = %v (present %v), want %v from the record", key, g, ok, w)
		}
	}
	for key := range got {
		if strings.HasPrefix(key, "cert_converter_") {
			if _, ok := want[key]; !ok {
				t.Errorf("the registry exports %s, which no record field sets", key)
			}
		}
	}
}

// pinClock makes reportClock read *now until the test ends.
func pinClock(t *testing.T, now *time.Time) {
	t.Helper()
	prev := reportClock
	reportClock = func() time.Time { return *now }
	t.Cleanup(func() { reportClock = prev })
}

// TestScanDeadline pins the stall rule's deadline and the last healthy scan's
// time beside it: the start plus the lease and 0 before any scan, a healthy
// scan's end plus the lease and that end after it, and both unchanged by a scan
// that is not healthy, so scans that keep failing cross the deadline.
func TestScanDeadline(t *testing.T) {
	const lease = 18 * time.Hour
	start := time.Unix(1_800_000_000, 0)
	now := start
	pinClock(t, &now)
	capture.SwapDefault(t, slog.New(slog.DiscardHandler))
	reg := measure.NewRegistry("cert_converter")
	reporter := newReporter(reg, lease)
	gauge := func(name string) float64 {
		t.Helper()
		families, err := reg.Gather(t.Context())
		if err != nil {
			t.Fatalf("Gather = %v", err)
		}
		for _, f := range families {
			if f.Name == name && len(f.Samples) == 1 {
				return f.Samples[0].Value
			}
		}
		t.Fatalf("the registry exports no single %s sample", name)
		return 0
	}
	deadline := func() float64 { return gauge("cert_converter_scan_deadline_timestamp_seconds") }
	succeeded := func() float64 { return gauge("cert_converter_last_success_timestamp_seconds") }
	unix := func(at time.Time) float64 { return float64(at.Unix()) }

	if got, want := deadline(), unix(start.Add(lease)); got != want {
		t.Errorf("deadline before any scan = %v, want the start plus the lease %v", got, want)
	}
	if got := succeeded(); got != 0 {
		t.Errorf("last success before any scan = %v, want 0", got)
	}
	steps := []struct {
		name    string
		scan    Scan
		at      time.Duration
		want    time.Time
		success time.Time
	}{
		{
			name: "a healthy scan moves it", at: time.Hour,
			scan: Scan{Healthy: true, Result: process.ScanResult{Total: 1, Converted: 1}},
			want: start.Add(time.Hour + lease), success: start.Add(time.Hour),
		},
		{
			name: "a failed conversion leaves it", at: 2 * time.Hour,
			scan: Scan{Result: process.ScanResult{Total: 1, Failed: 1}},
			want: start.Add(time.Hour + lease), success: start.Add(time.Hour),
		},
		{
			name: "an aborted scan leaves it", at: 3 * time.Hour,
			scan: Scan{Result: process.ScanResult{Outcome: process.OutcomeAborted}, Err: errors.New("open input root")},
			want: start.Add(time.Hour + lease), success: start.Add(time.Hour),
		},
		{
			name: "the next healthy scan moves it again", at: 4 * time.Hour,
			scan: Scan{Healthy: true},
			want: start.Add(4*time.Hour + lease), success: start.Add(4 * time.Hour),
		},
	}
	for _, step := range steps {
		now = start.Add(step.at)
		reporter.Report(t.Context(), &step.scan)
		if got := deadline(); got != unix(step.want) {
			t.Errorf("%s: deadline = %v, want %v", step.name, got, unix(step.want))
		}
		if got := succeeded(); got != unix(step.success) {
			t.Errorf("%s: last success = %v, want %v", step.name, got, unix(step.success))
		}
	}
}

// gathered returns every cert_converter_ sample reg serves, keyed by its family
// name and labels in the order the family declares them.
func gathered(t *testing.T, reg *measure.Registry) map[string]float64 {
	t.Helper()
	families, err := reg.Gather(t.Context())
	if err != nil {
		t.Fatalf("Gather = %v", err)
	}
	got := make(map[string]float64)
	for _, f := range families {
		for _, s := range f.Samples {
			key := f.Name
			for _, l := range s.Labels {
				key += "{" + l.Name + "=" + l.Value + "}"
			}
			got[key] = s.Value
		}
	}
	return got
}

// sourceKeys returns the keys of got whose family is one of the per-source ones.
func sourceKeys(got map[string]float64) []string {
	var keys []string
	for key := range got {
		if strings.HasPrefix(key, "cert_converter_source_") {
			keys = append(keys, key)
		}
	}
	return keys
}

// outcomeNames is the fixed outcome list the source_outcome family declares.
var outcomeNames = []string{"converted", "unchanged", "failed", "orphan", "unreadable", "unwritable", "collided", "excluded", "vanished"}

func reportSources(t *testing.T, reporter *Reporter, sources ...process.SourceState) {
	t.Helper()
	reporter.Report(t.Context(), &Scan{Result: process.ScanResult{Total: len(sources), Sources: sources}})
}

// TestReportServesEachSourceOnce pins the per-source series: one source_outcome
// state set per source, 1 for its outcome and 0 for the eight others, and its
// last conversion time, 0 when it has none; nothing before the first report.
// Serial: it swaps slog.Default().
func TestReportServesEachSourceOnce(t *testing.T) {
	capture.SwapDefault(t, slog.New(slog.DiscardHandler))
	reg := measure.NewRegistry("cert_converter")
	reporter := newReporter(reg, time.Hour)
	if keys := sourceKeys(gathered(t, reg)); len(keys) != 0 {
		t.Errorf("before any report the registry serves %v, want no per-source sample", keys)
	}

	reportSources(t, reporter,
		process.SourceState{Path: "a/one.crt", Outcome: process.SourceConverted, LastConverted: time.Unix(1_800_000_000, 0)},
		process.SourceState{Path: "b/two.pfx", Outcome: process.SourceFailed},
	)
	got := gathered(t, reg)
	want := map[string]float64{
		"cert_converter_source_last_conversion_timestamp_seconds{source=a/one.crt}": 1.8e9,
		"cert_converter_source_last_conversion_timestamp_seconds{source=b/two.pfx}": 0,
	}
	for source, current := range map[string]string{"a/one.crt": "converted", "b/two.pfx": "failed"} {
		for _, outcome := range outcomeNames {
			value := 0.0
			if outcome == current {
				value = 1
			}
			want["cert_converter_source_outcome{source="+source+"}{outcome="+outcome+"}"] = value
		}
	}
	for key, w := range want {
		if g, ok := got[key]; !ok || g != w {
			t.Errorf("%s = %v (present %v), want %v", key, g, ok, w)
		}
	}
	for _, key := range sourceKeys(got) {
		if _, ok := want[key]; !ok {
			t.Errorf("the registry serves %s, which no reported source sets", key)
		}
	}
}

// TestReportDropsASourceThatGoes pins that each report replaces the served
// sources, so a source the latest scan no longer holds leaves both families.
// Serial: it swaps slog.Default().
func TestReportDropsASourceThatGoes(t *testing.T) {
	capture.SwapDefault(t, slog.New(slog.DiscardHandler))
	reg := measure.NewRegistry("cert_converter")
	reporter := newReporter(reg, time.Hour)
	reportSources(t, reporter,
		process.SourceState{Path: "a/one.crt", Outcome: process.SourceConverted, LastConverted: time.Unix(1_800_000_000, 0)},
		process.SourceState{Path: "b/two.pfx", Outcome: process.SourceFailed},
	)
	reportSources(t, reporter, process.SourceState{Path: "b/two.pfx", Outcome: process.SourceFailed})

	keys := sourceKeys(gathered(t, reg))
	for _, key := range keys {
		if strings.Contains(key, "{source=a/one.crt}") {
			t.Errorf("after a report without a/one.crt the registry still serves %s", key)
		}
	}
	if want := 1 + len(outcomeNames); len(keys) != want {
		t.Errorf("after a report of one source the registry serves %d per-source samples %v, want %d", len(keys), keys, want)
	}
}

// TestReportSanitisesTheSourceLabel pins that a control or bidi rune in a file
// name reaches the label as a space, as textsafe's single-line policy says.
// Serial: it swaps slog.Default().
func TestReportSanitisesTheSourceLabel(t *testing.T) {
	capture.SwapDefault(t, slog.New(slog.DiscardHandler))
	reg := measure.NewRegistry("cert_converter")
	reporter := newReporter(reg, time.Hour)
	reportSources(t, reporter, process.SourceState{Path: "evil\x1b[31m\u202e.crt", Outcome: process.SourceUnchanged})

	got := gathered(t, reg)
	for _, key := range []string{
		"cert_converter_source_last_conversion_timestamp_seconds{source=evil [31m .crt}",
		"cert_converter_source_outcome{source=evil [31m .crt}{outcome=unchanged}",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("the registry serves no %q; per-source samples %q", key, sourceKeys(got))
		}
	}
}

// TestReporterAfterARestart pins a fresh reporter: no per-source sample until a
// scan reports, and the next guaranteed scan due at the start, since the
// startup scan runs now.
func TestReporterAfterARestart(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	pinClock(t, &start)
	reg := measure.NewRegistry("cert_converter")
	newReporter(reg, time.Hour)

	got := gathered(t, reg)
	if keys := sourceKeys(got); len(keys) != 0 {
		t.Errorf("a fresh reporter serves %v, want no per-source sample", keys)
	}
	if g, ok := got["cert_converter_next_scan_timestamp_seconds"]; !ok || g != float64(start.Unix()) {
		t.Errorf("next_scan_timestamp_seconds = %v (present %v), want the start %v", g, ok, start.Unix())
	}
}

// TestSetNextScan pins that the gauge serves the time it was given, in Unix
// seconds.
func TestSetNextScan(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	pinClock(t, &t0)
	reg := measure.NewRegistry("cert_converter")
	reporter := newReporter(reg, time.Hour)
	reporter.SetNextScan(t0.Add(6 * time.Hour))

	want := float64(1_800_000_000 + 6*3600)
	if g, ok := gathered(t, reg)["cert_converter_next_scan_timestamp_seconds"]; !ok || g != want {
		t.Errorf("next_scan_timestamp_seconds after SetNextScan(t0+6h) = %v (present %v), want %v", g, ok, want)
	}
}

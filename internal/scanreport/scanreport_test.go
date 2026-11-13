package scanreport

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
	"github.com/cplieger/go/measure"
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
	reporter := NewReporter(reg, lease)

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
		// Not a record field: the scan is not healthy, so the deadline keeps its
		// start value (TestScanDeadline).
		"cert_converter_scan_deadline_timestamp_seconds": float64(at.Add(lease).Unix()),
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

// TestScanDeadline pins the stall rule's deadline: the start plus the lease
// before any scan, a healthy scan's end plus the lease after it, and unchanged
// by a scan that is not healthy, so scans that keep failing cross it.
func TestScanDeadline(t *testing.T) {
	const lease = 18 * time.Hour
	start := time.Unix(1_800_000_000, 0)
	now := start
	pinClock(t, &now)
	capture.SwapDefault(t, slog.New(slog.DiscardHandler))
	reg := measure.NewRegistry("cert_converter")
	reporter := NewReporter(reg, lease)
	deadline := func() float64 {
		t.Helper()
		families, err := reg.Gather(t.Context())
		if err != nil {
			t.Fatalf("Gather = %v", err)
		}
		for _, f := range families {
			if f.Name == "cert_converter_scan_deadline_timestamp_seconds" && len(f.Samples) == 1 {
				return f.Samples[0].Value
			}
		}
		t.Fatal("the registry exports no single cert_converter_scan_deadline_timestamp_seconds sample")
		return 0
	}
	unix := func(at time.Time) float64 { return float64(at.Unix()) }

	if got, want := deadline(), unix(start.Add(lease)); got != want {
		t.Errorf("deadline before any scan = %v, want the start plus the lease %v", got, want)
	}
	steps := []struct {
		name string
		scan Scan
		at   time.Duration
		want time.Time
	}{
		{
			name: "a healthy scan moves it", at: time.Hour,
			scan: Scan{Healthy: true, Result: process.ScanResult{Total: 1, Converted: 1}},
			want: start.Add(time.Hour + lease),
		},
		{
			name: "a failed conversion leaves it", at: 2 * time.Hour,
			scan: Scan{Result: process.ScanResult{Total: 1, Failed: 1}},
			want: start.Add(time.Hour + lease),
		},
		{
			name: "an aborted scan leaves it", at: 3 * time.Hour,
			scan: Scan{Result: process.ScanResult{Outcome: process.OutcomeAborted}, Err: errors.New("open input root")},
			want: start.Add(time.Hour + lease),
		},
		{
			name: "the next healthy scan moves it again", at: 4 * time.Hour,
			scan: Scan{Healthy: true},
			want: start.Add(4*time.Hour + lease),
		},
	}
	for _, step := range steps {
		now = start.Add(step.at)
		reporter.Report(t.Context(), &step.scan)
		if got := deadline(); got != unix(step.want) {
			t.Errorf("%s: deadline = %v, want %v", step.name, got, unix(step.want))
		}
	}
}

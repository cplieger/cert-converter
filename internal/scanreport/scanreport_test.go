package scanreport

import (
	"errors"
	"log/slog"
	"reflect"
	"testing"

	"github.com/cplieger/cert-converter/internal/process"
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
			Log(t.Context(), &tc.scan)
			if got := logs.CountLevel(tc.level, Message); got != 1 {
				t.Errorf("Log(%s) wrote %q, want one %s record %q", tc.name, logs.Messages(), tc.level, Message)
			}
			if tc.scan.Err != nil && !logs.HasAttr(Message, "error", tc.scan.Err.Error()) {
				t.Errorf("Log(%s) wrote no error attribute naming the cause", tc.name)
			}
		})
	}
}

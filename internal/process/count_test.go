package process

import (
	"reflect"
	"testing"
)

func TestCountResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		results    []conversionStatus
		unreadable int
		unresolved int
		vanished   int
		want       ScanResult
	}{
		{
			name:       "empty results",
			results:    nil,
			unreadable: 0,
			want:       ScanResult{},
		},
		{
			name: "mixed statuses",
			results: []conversionStatus{
				statusConverted,
				statusConverted,
				statusUnchanged,
				statusOrphan,
				statusFailed,
			},
			unreadable: 3,
			unresolved: 2,
			want:       ScanResult{Total: 5, Converted: 2, Unchanged: 1, Orphan: 1, Failed: 1, Unreadable: 3, Unresolved: 2},
		},
		{
			name:       "unreadable not counted in total",
			results:    []conversionStatus{statusConverted},
			unreadable: 7,
			want:       ScanResult{Total: 1, Converted: 1, Unreadable: 7},
		},
		{
			name: "a vanished entry gets its own count, never Unreadable",
			results: []conversionStatus{
				statusConverted,
				statusVanished,
				statusVanished,
				statusUnreadable,
			},
			want: ScanResult{Total: 4, Converted: 1, Unreadable: 1, Vanished: 2},
		},
		{
			name:       "a walk-level vanished path lands in Vanished, never Unreadable",
			results:    []conversionStatus{statusConverted},
			unreadable: 1,
			vanished:   2,
			want:       ScanResult{Total: 1, Converted: 1, Unreadable: 1, Vanished: 2},
		},
		{
			name: "all converted",
			results: []conversionStatus{
				statusConverted,
				statusConverted,
			},
			unreadable: 0,
			want:       ScanResult{Total: 2, Converted: 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := countResults(tt.results, tt.unreadable, tt.unresolved, tt.vanished)
			if got != tt.want {
				t.Errorf("countResults(%d results, unreadable=%d, unresolved=%d, vanished=%d) = %+v, want %+v",
					len(tt.results), tt.unreadable, tt.unresolved, tt.vanished, got, tt.want)
			}
		})
	}
}

// TestCountResults_counts_every_outcome_in_the_enum is the guard that makes adding a
// conversionStatus a one-line change instead of a silent zero. countResults indexes a
// [statusCount]int by the status itself, so a member added above the statusCount
// sentinel is accumulated by construction — but nothing stops a new member from being
// accumulated into a slot no ScanResult field reads. Every outcome must land in
// exactly one counter, and the case table above only covers the members that exist
// today, so it cannot fail for a future one.
//
// statusUnset is excluded deliberately: it is the "no outcome resolved" zero value and
// never reaches countResults (see its doc comment in types.go).
func TestCountResults_counts_every_outcome_in_the_enum(t *testing.T) {
	t.Parallel()
	for status := statusUnset + 1; status < statusCount; status++ {
		got := countResults([]conversionStatus{status}, 0, 0, 0)
		if got.Total != 1 {
			t.Errorf("countResults([status %d]).Total = %d, want 1", status, got.Total)
		}
		counted := got.Converted + got.Unchanged + got.Orphan + got.Failed +
			got.Unreadable + got.Unresolved + got.Vanished + got.Unwritable
		if counted != 1 {
			t.Errorf("countResults([status %d]) = %+v, want the outcome in exactly one counter, got %d",
				status, got, counted)
		}
	}
}

// TestSummaryAttrs_names_every_scan_result_counter is the reporting half of the same
// guard. logScanOutcome renders the ONE operator-visible scan summary from
// summaryAttrs, and the README's Loki rules key on those attribute names, so a counter
// added to ScanResult without a row here is invisible in production with no compile
// error to say so. Reflection is what makes the assertion cover a field that does not
// exist yet.
func TestSummaryAttrs_names_every_scan_result_counter(t *testing.T) {
	t.Parallel()
	fields := reflect.TypeFor[ScanResult]().NumField()
	if len(summaryAttrs) != fields {
		t.Errorf("len(summaryAttrs) = %d, want %d (one row per ScanResult counter)", len(summaryAttrs), fields)
	}
	for i := range fields {
		var result ScanResult
		reflect.ValueOf(&result).Elem().Field(i).SetInt(1)
		name := reflect.TypeFor[ScanResult]().Field(i).Name
		reporting := make([]string, 0, 1)
		for _, a := range summaryAttrs {
			if a.of(&result) == 1 {
				reporting = append(reporting, a.name)
			}
		}
		if len(reporting) != 1 {
			t.Errorf("ScanResult.%s is reported by summaryAttrs rows %v, want exactly one", name, reporting)
		}
	}
}

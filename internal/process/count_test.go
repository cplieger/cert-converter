package process

import (
	"reflect"
	"strings"
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
			got.Unreadable + got.Unresolved + got.Vanished + got.Unwritable + got.Collided + got.Excluded
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
			continue
		}
		// The attribute NAME is the operator-visible half of the contract: the
		// README's Loki rules match on `orphan=`, `unreadable=` and the rest, so a
		// row whose func reads the wrong counter must fail here even though the
		// bijection above still holds.
		if want := strings.ToLower(name); reporting[0] != want {
			t.Errorf("ScanResult.%s is reported as %q, want %q", name, reporting[0], want)
		}
	}
}

// The reap-gate role a ScanResult counter plays. Every counter has exactly one, and the
// table below is the ONE place that classification is written down.
const (
	// vetoNone: an outcome count that reports and nothing more.
	vetoNone = "none"
	// vetoDurable: a coverage hole a restart cannot clear, so it must veto every claim
	// about the input tree (durablyEnumerated, and therefore inputFullyEnumerated too).
	vetoDurable = "durable"
	// vetoTransient: a mid-scan replacement, so it must veto the whole-tree claim while
	// leaving the durable one intact.
	vetoTransient = "transient"
	// vetoConversion: output work this app is still trying to repair, so it must veto
	// conversionsClean.
	vetoConversion = "conversion"
)

// TestScanResultVetoes_every_counter_is_classified_and_honoured is the reap-gate half of
// the structural guard TestSummaryAttrs_names_every_scan_result_counter already gives the
// reporting half.
//
// The three veto predicates on ScanResult are spelled once each so their two askers
// cannot drift, but nothing makes a NEW counter reach them: adding an /input coverage
// dimension compiles, is forced into the summary by the reporting guard, and is then
// simply absent from durablyEnumerated -- so a scan that could not enumerate /input passes
// the gate and reap deletes bundles it cannot prove orphaned, silently, over private key
// material the documented deployment replicates onward. The case tables that exercise the
// vetoes name today's fields, so none of them can fail for a field that does not exist
// yet; reflection is what closes that.
//
// It asserts two things per counter: that the counter is classified at all, and that a
// non-zero value makes exactly the predicates its class owns answer false.
func TestScanResultVetoes_every_counter_is_classified_and_honoured(t *testing.T) {
	t.Parallel()

	classes := map[string]string{
		"Removed":    vetoNone,
		"Total":      vetoNone,
		"Converted":  vetoNone,
		"Unchanged":  vetoNone,
		"Orphan":     vetoNone,
		"Failed":     vetoConversion,
		"Unwritable": vetoConversion,
		"Unreadable": vetoDurable,
		"Unresolved": vetoDurable,
		"Vanished":   vetoTransient,
		"Collided":   vetoConversion,
		"Excluded":   vetoNone,
		"Ignored":    vetoNone,
	}

	typ := reflect.TypeFor[ScanResult]()
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		class, classified := classes[name]
		if !classified {
			t.Errorf("ScanResult.%s is not classified here: wire a new counter into the reap gate"+
				" (durablyEnumerated for a coverage hole a restart cannot clear, inputFullyEnumerated for a"+
				" mid-scan replacement, conversionsClean for output work still being repaired) or classify it"+
				" %q, or a scan that could not enumerate /input will delete bundles it cannot prove orphaned",
				name, vetoNone)
			continue
		}
		var result ScanResult
		reflect.ValueOf(&result).Elem().Field(i).SetInt(1)

		for _, check := range []struct {
			predicate string
			got       bool
			want      bool
		}{
			{"durablyEnumerated", result.durablyEnumerated(), class != vetoDurable},
			{"inputFullyEnumerated", result.inputFullyEnumerated(), class != vetoDurable && class != vetoTransient},
			{"conversionsClean", result.conversionsClean(), class != vetoConversion},
		} {
			if check.got != check.want {
				t.Errorf("ScanResult{%s: 1}.%s() = %v, want %v: %s is classified %q, and that class decides"+
					" which reap claims the counter must refuse",
					name, check.predicate, check.got, check.want, name, class)
			}
		}
	}
}

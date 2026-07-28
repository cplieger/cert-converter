package process

import (
	"testing"
)

func TestCountResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		results    []conversionStatus
		unreadable int
		unresolved int
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
			got := countResults(tt.results, tt.unreadable, tt.unresolved)
			if got != tt.want {
				t.Errorf("countResults(%d results, unreadable=%d, unresolved=%d) = %+v, want %+v",
					len(tt.results), tt.unreadable, tt.unresolved, got, tt.want)
			}
		})
	}
}

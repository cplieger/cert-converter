package process

import (
	"testing"
)

func TestCountResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		results    []ConversionStatus
		unreadable int
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
			results: []ConversionStatus{
				StatusConverted,
				StatusConverted,
				StatusUnchanged,
				StatusOrphan,
				StatusFailed,
			},
			unreadable: 3,
			want:       ScanResult{Total: 5, Converted: 2, Unchanged: 1, Orphan: 1, Failed: 1, Unreadable: 3},
		},
		{
			name:       "unreadable not counted in total",
			results:    []ConversionStatus{StatusConverted},
			unreadable: 7,
			want:       ScanResult{Total: 1, Converted: 1, Unreadable: 7},
		},
		{
			name: "all converted",
			results: []ConversionStatus{
				StatusConverted,
				StatusConverted,
			},
			unreadable: 0,
			want:       ScanResult{Total: 2, Converted: 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := countResults(tt.results, tt.unreadable)
			if got != tt.want {
				t.Errorf("countResults(%d results, unreadable=%d) = %+v, want %+v",
					len(tt.results), tt.unreadable, got, tt.want)
			}
		})
	}
}

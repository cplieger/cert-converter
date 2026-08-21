package scancadence

import (
	"testing"
	"time"
)

// TestFloor_is_the_documented_reconciliation_cadence pins the one number three
// operator promises are derived from: the README states the guarantee as 24 hours
// (config table, Healthcheck section) and the health lease as 72 (3*Floor,
// main.go), and the CertConverterChangeDetectionDegraded alert description says
// "capped at the 24h reconciliation floor". Every other assertion in this repo
// compares against Floor itself, so without a literal here the constant can move
// and only the docs become wrong.
func TestFloor_is_the_documented_reconciliation_cadence(t *testing.T) {
	t.Parallel()
	if Floor != 24*time.Hour {
		t.Errorf("Floor = %v, want 24h: README.md's config table, Healthcheck section and alerting section all publish 24h, and the health lease main.go arms is 3*Floor = 72h", Floor)
	}
}

// TestEffective pins the resolution rule against literals rather than against
// Floor, so a moved floor fails HERE, naming the cadence, instead of surfacing as
// an unrelated fixture in internal/watch.
func TestEffective(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		fallback time.Duration
		want     time.Duration
	}{
		{"the 0/false opt-out falls to the floor", 0, 24 * time.Hour},
		{"a negative cadence falls to the floor", -time.Second, 24 * time.Hour},
		{"the deployed default is the operator's", 6 * time.Hour, 6 * time.Hour},
		{"a cadence at the floor is the floor", 24 * time.Hour, 24 * time.Hour},
		{"a cadence above the floor is capped", 48 * time.Hour, 24 * time.Hour},
		{"the config ceiling is capped", 87600 * time.Hour, 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Effective(tc.fallback); got != tc.want {
				t.Errorf("Effective(%v) = %v, want %v", tc.fallback, got, tc.want)
			}
		})
	}
}

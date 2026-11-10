package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/watch"
	"github.com/cplieger/go/slogx/capture"
)

// logqlLineFilter returns the one backticked line filter of a LogQL event rule
// in alerts/logql.yaml, compiled as Loki compiles it (RE2).
func logqlLineFilter(t *testing.T, alert string) *regexp.Regexp {
	t.Helper()
	raw, err := os.ReadFile("alerts/logql.yaml")
	if err != nil {
		t.Fatalf("reading the shipped LogQL rules: %v", err)
	}
	_, rule, found := strings.Cut(string(raw), "- alert: "+alert+"\n")
	if !found {
		t.Fatalf("alerts/logql.yaml defines no %s rule", alert)
	}
	rule, _, _ = strings.Cut(rule, "for:")
	m := regexp.MustCompile("\\|[=~] `([^`]+)`").FindAllStringSubmatch(rule, -1)
	if len(m) != 1 {
		t.Fatalf("%s has %d line filters, want exactly one", alert, len(m))
	}
	if strings.Contains(rule, "|= `") {
		return regexp.MustCompile(regexp.QuoteMeta(m[0][1]))
	}
	return regexp.MustCompile(m[0][1])
}

// TestChangeDetectionDeadMatchesTheExitLine binds the event rule to the line
// reportWatchExit writes: the process exits after it, so no record follows.
func TestChangeDetectionDeadMatchesTheExitLine(t *testing.T) {
	filter := logqlLineFilter(t, "CertConverterChangeDetectionDead")
	logs := capture.Default(t)
	reportWatchExit(t.Context(), &watch.LostError{Cause: "the fsnotify events channel closed"})
	msgs := logs.Messages()
	if len(msgs) != 1 || !filter.MatchString(msgs[0]) {
		t.Errorf("reportWatchExit logged %q, want one line the rule's filter %q matches", msgs, filter)
	}
}

// TestStartupRefusedMatchesEveryRefusal binds the startup-refusal rule to the
// lines run writes before it exits 1: an invalid setting, a missing volume and a
// METRICS_LISTEN_ADDR it cannot bind.
func TestStartupRefusedMatchesEveryRefusal(t *testing.T) {
	filter := logqlLineFilter(t, "CertConverterStartupRefused")
	for name, out := range map[string]string{
		"invalid configuration": startupFailureOutput(t),
		"missing volume":        missingVolumeOutput(t),
		"metrics bind failure":  bindFailureOutput(t),
	} {
		var refusal string
		for line := range strings.Lines(out) {
			if strings.Contains(line, "level=ERROR") {
				refusal = line
			}
		}
		if refusal == "" {
			t.Errorf("%s: run wrote no ERROR line; stderr %q", name, out)
			continue
		}
		if !filter.MatchString(refusal) {
			t.Errorf("%s: the refusal %q does not match the rule's filter %q", name, refusal, filter)
		}
	}
}

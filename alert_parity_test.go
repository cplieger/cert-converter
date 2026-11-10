package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// promqlWords are the PromQL keywords and functions the shipped rules may use;
// every other identifier in an expression is a series name.
var promqlWords = []string{
	"and", "or", "unless", "on", "ignoring", "group_left", "group_right", "by", "without", "bool",
	"sum", "min", "max", "avg", "count", "absent", "time", "rate", "increase", "changes", "resets",
	"min_over_time", "max_over_time", "avg_over_time", "sum_over_time", "count_over_time",
	"last_over_time", "present_over_time", "absent_over_time",
}

// seriesOutsideTheApp are names a rule may read that no app registry exports:
// `up` is written by the scrape itself.
var seriesOutsideTheApp = []string{"up"}

var (
	labelMatchersRe = regexp.MustCompile(`\{[^}]*\}`)
	groupingRe      = regexp.MustCompile(`\b(by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)`)
	rangeRe         = regexp.MustCompile(`\[[^\]]*\]`)
	identRe         = regexp.MustCompile(`[a-zA-Z_:][a-zA-Z0-9_:]*`)
)

// ruleExprs returns each alert of a shipped rule file with its expression.
func ruleExprs(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	rules := make(map[string]string)
	for _, block := range strings.Split(string(raw), "- alert: ")[1:] {
		name, rest, _ := strings.Cut(block, "\n")
		_, expr, found := strings.Cut(rest, "expr: ")
		if !found {
			t.Fatalf("%s: %s has no expr", path, name)
		}
		expr, _, _ = strings.Cut(expr, "for:")
		rules[strings.TrimSpace(name)] = strings.TrimPrefix(strings.TrimSpace(expr), "|")
	}
	return rules
}

// seriesNames returns the series an expression reads.
func seriesNames(expr string) []string {
	expr = labelMatchersRe.ReplaceAllString(expr, " ")
	expr = groupingRe.ReplaceAllString(expr, " ")
	expr = rangeRe.ReplaceAllString(expr, " ")
	var names []string
	for _, word := range identRe.FindAllString(expr, -1) {
		if !slices.Contains(promqlWords, word) && !slices.Contains(names, word) {
			names = append(names, word)
		}
	}
	return names
}

// TestPromQLRulesReadOnlyExportedSeries builds the registry the way run does and
// fails when a shipped PromQL rule reads a series that registry does not export,
// so a renamed or dropped series fails the build instead of silencing an alert.
func TestPromQLRulesReadOnlyExportedSeries(t *testing.T) {
	reg, _ := newMetrics()
	families, err := reg.Gather(t.Context())
	if err != nil {
		t.Fatalf("Gather = %v", err)
	}
	exported := slices.Clone(seriesOutsideTheApp)
	for _, f := range families {
		exported = append(exported, f.Name)
	}
	for alert, expr := range ruleExprs(t, "alerts/promql.yaml") {
		names := seriesNames(expr)
		if len(names) == 0 {
			t.Errorf("%s reads no series: %s", alert, expr)
		}
		for _, name := range names {
			if !slices.Contains(exported, name) {
				t.Errorf("%s reads %s, which the registry run serves does not export", alert, name)
			}
		}
	}
}

// oneSided names the alerts that exist in one rule file only, with the alert that
// covers the same problem in the other file.
var oneSided = map[string]string{
	"CertConverterStartupRefused":      "CertConverterDown",
	"CertConverterChangeDetectionDead": "CertConverterDown",
	"CertConverterDown":                "CertConverterScanStalled",
}

// releasedAlerts are the alert names an earlier release shipped, each with the
// name that carries it now, so dropping or renaming one is a decision in the diff.
var releasedAlerts = map[string]string{
	"CertConverterConversionFailed":        "CertConverterConversionFailed",
	"CertConverterOutputNameCollision":     "CertConverterOutputNameCollision",
	"CertConverterOutputWriteRefused":      "CertConverterOutputWriteRefused",
	"CertConverterScanAborted":             "CertConverterScanAborted",
	"CertConverterInputTreeTooLarge":       "CertConverterInputTreeTooLarge",
	"CertConverterChangeDetectionDegraded": "CertConverterChangeDetectionDegraded",
	"CertConverterChangeDetectionDead":     "CertConverterChangeDetectionDead",
	"CertConverterScanStalled":             "CertConverterScanStalled",
	"CertConverterInputPathUnreachable":    "CertConverterInputPathUnreachable",
	"CertConverterNoCertificateSources":    "CertConverterNoCertificateSources",
	"CertConverterEverySourceExcluded":     "CertConverterEverySourceExcluded",
	"CertConverterOutputCleanupDegraded":   "CertConverterOutputCleanupDegraded",
	"CertConverterOrphanRemovalDisabled":   "CertConverterOrphanRemovalDisabled",
	"CertConverterPreviousLayoutRetained":  "CertConverterPreviousLayoutRetained",
}

// TestAlertFilesHoldTheSameAlerts keeps the two alternative files in parity: an
// alert in one has a partner of the same name in the other, except the one-sided
// alerts named with their cover, and every released alert name still exists.
func TestAlertFilesHoldTheSameAlerts(t *testing.T) {
	promql := ruleExprs(t, "alerts/promql.yaml")
	logql := ruleExprs(t, "alerts/logql.yaml")
	for _, pair := range []struct {
		name        string
		rules, peer map[string]string
	}{
		{name: "alerts/promql.yaml", rules: promql, peer: logql},
		{name: "alerts/logql.yaml", rules: logql, peer: promql},
	} {
		for alert := range pair.rules {
			if _, ok := pair.peer[alert]; ok {
				continue
			}
			cover, named := oneSided[alert]
			if !named {
				t.Errorf("%s holds %s, which the other file lacks and oneSided does not name", pair.name, alert)
				continue
			}
			if _, ok := pair.peer[cover]; !ok {
				t.Errorf("%s exists only in %s, and its cover %s is missing from the other file", alert, pair.name, cover)
			}
		}
	}
	for released, now := range releasedAlerts {
		_, inProm := promql[now]
		_, inLog := logql[now]
		if !inProm && !inLog {
			t.Errorf("released alert %s maps to %s, which neither file defines", released, now)
		}
	}
}

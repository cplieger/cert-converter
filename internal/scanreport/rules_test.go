package scanreport

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/go/slogx"
)

// logqlRule is one rule of alerts/logql.yaml, read as text: the repo carries no
// YAML parser and the file's shape is fixed by its own header.
type logqlRule struct {
	name   string
	expr   string
	fields []string
	window time.Duration
}

var (
	unwrapRe = regexp.MustCompile(`\| unwrap (\w+)`)
	rangeRe  = regexp.MustCompile(`\[(\d+)h\]`)
	filterRe = regexp.MustCompile("\\|= `([^`]+)`")
)

func readLogQLRules(t *testing.T) []logqlRule {
	t.Helper()
	raw, err := os.ReadFile("../../alerts/logql.yaml")
	if err != nil {
		t.Fatalf("reading the shipped LogQL rules: %v", err)
	}
	var rules []logqlRule
	for _, block := range strings.Split(string(raw), "- alert: ")[1:] {
		name, rest, _ := strings.Cut(block, "\n")
		_, expr, found := strings.Cut(rest, "expr: |\n")
		if !found {
			t.Fatalf("%s has no block expr", name)
		}
		expr, _, _ = strings.Cut(expr, "for:")
		rule := logqlRule{name: strings.TrimSpace(name), expr: expr}
		for _, m := range unwrapRe.FindAllStringSubmatch(expr, -1) {
			rule.fields = append(rule.fields, m[1])
		}
		if m := rangeRe.FindStringSubmatch(expr); m != nil {
			hours, _ := strconv.Atoi(m[1])
			rule.window = time.Duration(hours) * time.Hour
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		t.Fatal("alerts/logql.yaml defines no rule")
	}
	return rules
}

// stateRules are the rules that read a field of the end-of-scan record.
func stateRules(t *testing.T) []logqlRule {
	t.Helper()
	var state []logqlRule
	for _, r := range readLogQLRules(t) {
		if len(r.fields) > 0 {
			state = append(state, r)
		}
	}
	if len(state) == 0 {
		t.Fatal("alerts/logql.yaml unwraps no field of the end-of-scan record")
	}
	return state
}

// renderRecord writes scan's record through the production text handler and
// returns its logfmt fields.
func renderRecord(t *testing.T, scan *Scan) map[string]string {
	t.Helper()
	var buf bytes.Buffer
	handler, _ := slogx.NewHandler(slogx.Options{Output: &buf})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })
	logRecord(t.Context(), scan)
	slog.SetDefault(prev)
	line := strings.TrimSpace(buf.String())
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("logRecord wrote %q, want exactly one line", line)
	}
	return parseLogfmt(t, line)
}

// parseLogfmt splits one slog text line into its keys and values.
func parseLogfmt(t *testing.T, line string) map[string]string {
	t.Helper()
	fields := make(map[string]string)
	for line != "" {
		key, rest, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("malformed logfmt near %q", line)
		}
		var value string
		if strings.HasPrefix(rest, `"`) {
			end := 1
			for end < len(rest) && (rest[end] != '"' || rest[end-1] == '\\') {
				end++
			}
			unquoted, err := strconv.Unquote(rest[:end+1])
			if err != nil {
				t.Fatalf("unquoting %q: %v", rest[:end+1], err)
			}
			value, rest = unquoted, rest[end+1:]
		} else {
			value, rest, _ = strings.Cut(rest, " ")
		}
		fields[key] = value
		line = strings.TrimLeft(rest, " ")
	}
	return fields
}

// TestLogQLRulesUnwrapNumericRecordFields binds every LogQL state rule to the
// record: each selects the record by its message and unwraps a field the record
// carries as a number, so a renamed or dropped field fails here instead of
// leaving a rule that never fires.
func TestLogQLRulesUnwrapNumericRecordFields(t *testing.T) {
	record := renderRecord(t, &Scan{Result: process.ScanResult{Total: 1, Converted: 1}})
	if record["msg"] != Message {
		t.Fatalf("logRecord wrote msg=%q, want %q", record["msg"], Message)
	}
	for _, rule := range stateRules(t) {
		t.Run(rule.name, func(t *testing.T) {
			for _, m := range filterRe.FindAllStringSubmatch(rule.expr, -1) {
				if m[1] != Message {
					t.Errorf("%s filters on %q, want the record's message %q", rule.name, m[1], Message)
				}
			}
			for _, field := range rule.fields {
				value, ok := record[field]
				if !ok {
					t.Errorf("%s unwraps %q, which the end-of-scan record does not carry", rule.name, field)
					continue
				}
				if _, err := strconv.ParseFloat(value, 64); err != nil {
					t.Errorf("%s unwraps %q, which the record carries as %q, not a number", rule.name, field, value)
				}
			}
		})
	}
}

// badScans holds, per unwrapped field, a scan whose record carries the problem
// that field reports.
var badScans = map[string]Scan{
	"failed":                   {Result: process.ScanResult{Total: 1, Failed: 1}},
	"collided":                 {Result: process.ScanResult{Total: 2, Collided: 2}},
	"unwritable":               {Result: process.ScanResult{Total: 1, Unwritable: 1}},
	"aborted":                  {Result: process.ScanResult{Outcome: process.OutcomeAborted}, Err: errors.New("open input root")},
	"budget_stopped":           {Result: process.ScanResult{Outcome: process.OutcomeBudgetStopped}},
	"polling":                  {Result: process.ScanResult{Total: 1, Converted: 1}, Polling: true},
	"unreadable":               {Result: process.ScanResult{Total: 1, Unreadable: 1}},
	"unresolved":               {Result: process.ScanResult{Total: 1, Unresolved: 1}},
	"no_sources":               {Result: process.ScanResult{NoSources: true}},
	"all_excluded":             {Result: process.ScanResult{Total: 1, Excluded: 1, AllExcluded: true}},
	"cleanup_degraded":         {Result: process.ScanResult{Total: 1, CleanupDegraded: true}},
	"orphan_removal_disabled":  {Result: process.ScanResult{Total: 1, OrphanRemovalDisabled: true}},
	"previous_layout_retained": {Result: process.ScanResult{Total: 1, PreviousLayoutRetained: true}},
}

type timedRecord struct {
	fields map[string]string
	at     time.Duration
}

// firing evaluates a state rule at `at` the way Loki's last_over_time does over
// one stream: the latest record inside the window supplies every unwrapped
// field, and the rule fires when their sum is above 0.
func firing(t *testing.T, rule logqlRule, records []timedRecord, at time.Duration) bool {
	t.Helper()
	var latest map[string]string
	for _, r := range records {
		if r.at <= at && at-r.at < rule.window {
			latest = r.fields
		}
	}
	if latest == nil {
		return false
	}
	sum := 0.0
	for _, field := range rule.fields {
		v, err := strconv.ParseFloat(latest[field], 64)
		if err != nil {
			t.Fatalf("%s: field %q = %q: %v", rule.name, field, latest[field], err)
		}
		sum += v
	}
	return sum > 0
}

// TestLogQLStateRulesResolveOnTheNextGoodRecord is each state rule's fixture: a
// record with the problem fires the rule, and a good record after it inside the
// window resolves it, so the rule holds while the problem lasts and clears at the
// next clean scan.
func TestLogQLStateRulesResolveOnTheNextGoodRecord(t *testing.T) {
	good := renderRecord(t, &Scan{Result: process.ScanResult{Total: 1, Converted: 1}})
	for _, rule := range stateRules(t) {
		t.Run(rule.name, func(t *testing.T) {
			if !strings.HasSuffix(strings.TrimSpace(rule.expr), "> 0") {
				t.Fatalf("%s does not end in `> 0`, so this fixture cannot evaluate it: %s", rule.name, rule.expr)
			}
			if rule.window <= 0 {
				t.Fatalf("%s has no range in hours: %s", rule.name, rule.expr)
			}
			for _, field := range rule.fields {
				scan, ok := badScans[field]
				if !ok {
					t.Fatalf("no fixture scan for field %q: add one to badScans", field)
				}
				bad := renderRecord(t, &scan)
				onlyBad := []timedRecord{{fields: bad, at: 0}}
				if !firing(t, rule, onlyBad, time.Hour) {
					t.Errorf("%s does not fire one hour after a record with %s=%s", rule.name, field, bad[field])
				}
				badThenGood := []timedRecord{{fields: bad, at: 0}, {fields: good, at: time.Hour}}
				if firing(t, rule, badThenGood, 2*time.Hour) {
					t.Errorf("%s still fires after a good record followed the bad one inside the window", rule.name)
				}
			}
		})
	}
}

// TestLogQLStateRangesEqualTheDeadmanWindow keeps every state rule's range equal
// to the deadman's window: a shorter range would resolve a standing problem into
// silence before the deadman fires.
func TestLogQLStateRangesEqualTheDeadmanWindow(t *testing.T) {
	var deadman time.Duration
	for _, r := range readLogQLRules(t) {
		if strings.Contains(r.expr, "absent_over_time") {
			deadman = r.window
		}
	}
	if deadman == 0 {
		t.Fatal("alerts/logql.yaml has no absent_over_time deadman with a range in hours")
	}
	for _, rule := range stateRules(t) {
		if rule.window != deadman {
			t.Errorf("%s ranges over %s, want the deadman's %s", rule.name, rule.window, deadman)
		}
	}
}

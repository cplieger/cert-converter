package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/cert-converter/internal/obs"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/go/measure/v2"
	"github.com/cplieger/go/slogx/capture"
)

const (
	dashboardFile = "grafana-dashboard.json"
	promqlRules   = "alerts/promql.yaml"
)

type dashQuery struct {
	Spec struct {
		RefID string `json:"refId"`
		Query struct {
			Spec struct {
				Expr         string `json:"expr"`
				LegendFormat string `json:"legendFormat"`
			} `json:"spec"`
		} `json:"query"`
	} `json:"spec"`
}

type dashMapping struct {
	Options map[string]struct {
		Text  string `json:"text"`
		Color string `json:"color"`
	} `json:"options"`
	Type string `json:"type"`
}

type dashThresholds struct {
	Steps []struct {
		Value *float64 `json:"value"`
		Color string   `json:"color"`
	} `json:"steps"`
}

type dashOverride struct {
	Matcher struct {
		Options any    `json:"options"`
		ID      string `json:"id"`
	} `json:"matcher"`
	Properties []struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	} `json:"properties"`
}

type dashTransformation struct {
	Group string `json:"group"`
	Spec  struct {
		Options json.RawMessage `json:"options"`
	} `json:"spec"`
}

type dashPanel struct {
	Spec struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Data        struct {
			Spec struct {
				Queries         []dashQuery          `json:"queries"`
				Transformations []dashTransformation `json:"transformations"`
				QueryOptions    struct {
					MaxDataPoints int `json:"maxDataPoints"`
				} `json:"queryOptions"`
			} `json:"spec"`
		} `json:"data"`
		VizConfig struct {
			Group string `json:"group"`
			Spec  struct {
				Options struct {
					Text struct {
						TitleSize int `json:"titleSize"`
						ValueSize int `json:"valueSize"`
					} `json:"text"`
				} `json:"options"`
				FieldConfig struct {
					Overrides []dashOverride `json:"overrides"`
					Defaults  struct {
						NoValue    string         `json:"noValue"`
						Mappings   []dashMapping  `json:"mappings"`
						Thresholds dashThresholds `json:"thresholds"`
					} `json:"defaults"`
				} `json:"fieldConfig"`
			} `json:"spec"`
		} `json:"vizConfig"`
	} `json:"spec"`
}

type conditionRule struct {
	Kind string `json:"kind"`
	Spec struct {
		Value    any    `json:"value"`
		Variable string `json:"variable"`
		Operator string `json:"operator"`
	} `json:"spec"`
}

type conditionGroup struct {
	Spec struct {
		Visibility string          `json:"visibility"`
		Condition  string          `json:"condition"`
		Items      []conditionRule `json:"items"`
	} `json:"spec"`
}

type gridItem struct {
	Spec struct {
		ConditionalRendering *conditionGroup `json:"conditionalRendering"`
		Element              struct {
			Name string `json:"name"`
		} `json:"element"`
	} `json:"spec"`
}

type layoutNode struct {
	Kind string `json:"kind"`
	Spec struct {
		Layout               *layoutNode     `json:"layout"`
		ConditionalRendering *conditionGroup `json:"conditionalRendering"`
		Title                string          `json:"title"`
		Rows                 []layoutNode    `json:"rows"`
		Items                []gridItem      `json:"items"`
		HideHeader           bool            `json:"hideHeader"`
		Collapse             bool            `json:"collapse"`
	} `json:"spec"`
}

type dashVariable struct {
	Kind string `json:"kind"`
	Spec struct {
		Current struct {
			Text  any `json:"text"`
			Value any `json:"value"`
		} `json:"current"`
		Name    string `json:"name"`
		Hide    string `json:"hide"`
		Refresh string `json:"refresh"`
		Sort    string `json:"sort"`
		// Query is a data query on a QueryVariable, a string on a
		// CustomVariable and absent on a DatasourceVariable.
		Query json.RawMessage `json:"query"`
	} `json:"spec"`
}

type dashboard struct {
	Metadata   map[string]any `json:"metadata"`
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Spec       struct {
		Elements  map[string]dashPanel `json:"elements"`
		Layout    layoutNode           `json:"layout"`
		Variables []dashVariable       `json:"variables"`
		Preload   bool                 `json:"preload"`
	} `json:"spec"`
}

func loadDashboard(t *testing.T) dashboard {
	t.Helper()
	raw, err := os.ReadFile(dashboardFile)
	if err != nil {
		t.Fatalf("reading %s: %v", dashboardFile, err)
	}
	var d dashboard
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("decoding %s: %v", dashboardFile, err)
	}
	if len(d.Spec.Elements) == 0 {
		t.Fatalf("%s holds no panel", dashboardFile)
	}
	return d
}

func panelExprs(p *dashPanel) []string {
	var out []string
	for _, q := range p.Spec.Data.Spec.Queries {
		out = append(out, q.Spec.Query.Spec.Expr)
	}
	return out
}

func (d *dashboard) variables() map[string]dashVariable {
	out := map[string]dashVariable{}
	for _, v := range d.Spec.Variables {
		out[v.Spec.Name] = v
	}
	return out
}

// variableQuery is a query variable's PromQL, or "" for any other variable.
// Grafana runs the query's __legacyStringValue, null as "", when that key is
// present (getDataQueryForVariable), and its query field otherwise.
func variableQuery(v *dashVariable) string {
	var q struct {
		Spec map[string]json.RawMessage `json:"spec"`
	}
	if v.Kind != "QueryVariable" || json.Unmarshal(v.Spec.Query, &q) != nil {
		return ""
	}
	raw, ok := q.Spec["__legacyStringValue"]
	if !ok {
		raw = q.Spec["query"]
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// TestVariableQueryReadsTheQueryGrafanaRuns pins variableQuery to the query
// Grafana runs, so a pin on query cannot pass while __legacyStringValue holds
// another one.
func TestVariableQueryReadsTheQueryGrafanaRuns(t *testing.T) {
	for _, tc := range []struct{ name, spec, want string }{
		{"query only", `{"query":"up"}`, "up"},
		{"legacy wins", `{"query":"up","__legacyStringValue":"down"}`, "down"},
		{"legacy null is empty", `{"query":"up","__legacyStringValue":null}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := dashVariable{Kind: "QueryVariable"}
			v.Spec.Query = json.RawMessage(`{"spec":` + tc.spec + `}`)
			if got := variableQuery(&v); got != tc.want {
				t.Errorf("variableQuery = %q, want %q", got, tc.want)
			}
		})
	}
}

// dashboardQueries is every variable and panel query, keyed by where it sits,
// with its PromQL comments removed so no check reads a comment as a query.
func dashboardQueries(d *dashboard) map[string]string {
	queries := map[string]string{}
	for name, v := range d.variables() {
		if q := variableQuery(&v); q != "" {
			queries["variable "+name] = withoutComments(q)
		}
	}
	for name, p := range d.Spec.Elements {
		for i, e := range panelExprs(&p) {
			queries[fmt.Sprintf("%s %s query %d", name, p.Spec.Title, i)] = withoutComments(e)
		}
	}
	return queries
}

func row(t *testing.T, d *dashboard, title string) *layoutNode {
	t.Helper()
	for i := range d.Spec.Layout.Spec.Rows {
		if r := &d.Spec.Layout.Spec.Rows[i]; r.Spec.Title == title {
			return r
		}
	}
	t.Fatalf("no row titled %q", title)
	return nil
}

// gatherWithOneSource reports a scan holding one source before it gathers,
// since the per-source families serve nothing before one.
func gatherWithOneSource(t *testing.T) []measure.Family {
	t.Helper()
	capture.SwapDefault(t, slog.New(slog.DiscardHandler))
	reg, reporter := newMetrics(0)
	reporter.Report(t.Context(), &obs.Scan{Result: process.ScanResult{Total: 1, Sources: []process.SourceState{
		{Path: "a/one.crt", Outcome: process.SourceConverted, LastConverted: time.Unix(1_800_000_000, 0)},
	}}})
	families, err := reg.Gather(t.Context())
	if err != nil {
		t.Fatalf("Gather = %v", err)
	}
	return families
}

func servedSeries(t *testing.T) map[string][]string {
	t.Helper()
	served := map[string][]string{}
	for _, f := range gatherWithOneSource(t) {
		labels := []string{}
		for _, s := range f.Samples {
			for _, l := range s.Labels {
				if !slices.Contains(labels, l.Name) {
					labels = append(labels, l.Name)
				}
			}
		}
		if len(f.Samples) > 0 {
			served[f.Name] = labels
		}
	}
	for _, name := range []string{"cert_converter_last_scan_outcome", "cert_converter_source_outcome"} {
		if _, ok := served[name]; !ok {
			t.Fatalf("Setup: the registry serves no %s: %v", name, served)
		}
	}
	return served
}

var (
	dashQuotedRe   = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	dashSelectorRe = regexp.MustCompile(`([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}`)
	dashMatcherRe  = regexp.MustCompile(`([a-zA-Z_]\w*)\s*(?:=~|!~|!=|=)`)
	dashMatchersRe = regexp.MustCompile(`\{[^}]*\}`)
	dashGroupingRe = regexp.MustCompile(`\b(by|without|on|ignoring|group_left|group_right)\s*\(([^)]*)\)`)
	dashRangeRe    = regexp.MustCompile(`\[[^\]]*\]`)
	dashVariableRe = regexp.MustCompile(`\$\{?\w+(?::\w+)?\}?`)
	labelValuesRe  = regexp.MustCompile(`label_values\(([^,]+),\s*\w+\)`)
	dashFunctionRe = regexp.MustCompile(`\b[a-z_]+\s*\(`)
	dashIdentRe    = regexp.MustCompile(`\b[a-zA-Z_:][a-zA-Z0-9_:]*\b`)
	alertsRe       = regexp.MustCompile(`ALERTS\{alertname="([A-Za-z]+)"`)
	// madeLabelRe matches the label a label_replace or label_join call writes:
	// the first of the strings that close the call.
	madeLabelRe = regexp.MustCompile(`,\s*"(\w+)"(?:\s*,\s*"(?:[^"\\]|\\.)*"){2,}\s*\)`)
	// bracedVariableRe matches ${name}, whose braces are no selector.
	bracedVariableRe = regexp.MustCompile(`\$\{\w+(?::\w+)?\}`)
	dashKeywords     = []string{"and", "or", "unless", "bool", "offset"}
	userNamedLabels  = []string{"job", "hostname", "container"}
)

// skipString returns the index just past the string literal opening at s[i].
func skipString(s string, i int) int {
	q := s[i]
	for i++; i < len(s); i++ {
		switch {
		case s[i] == '\\' && q != '`':
			i++
		case s[i] == q:
			return i + 1
		}
	}
	return len(s)
}

// withoutComments drops each # comment from expr, up to its newline. A # inside
// a string literal opens no comment, and a quote inside a comment opens no
// string.
func withoutComments(expr string) string {
	var b strings.Builder
	for i := 0; i < len(expr); {
		switch expr[i] {
		case '#':
			if j := strings.IndexByte(expr[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(expr)
			}
		case '"', '\'', '`':
			j := skipString(expr, i)
			b.WriteString(expr[i:j])
			i = j
		default:
			b.WriteByte(expr[i])
			i++
		}
	}
	return b.String()
}

type selectorBlock struct {
	name, text string
}

// selectors returns each {...} block of expr with the series name written
// before it, empty when none, a keyword (x or {...}) or a variable ($v{...})
// is. Quoted strings are skipped, so a brace inside a label value ends no
// block.
func selectors(expr string) []selectorBlock {
	var out []selectorBlock
	start := -1
	for i := 0; i < len(expr); i++ {
		switch c := expr[i]; {
		case c == '"' || c == '\'' || c == '`':
			i = skipString(expr, i) - 1
		case c == '{':
			start = i
		case c == '}' && start >= 0:
			before := strings.TrimRight(expr[:start], " ")
			name := before[len(strings.TrimRightFunc(before, func(r rune) bool {
				return r == '_' || r == ':' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
			})):]
			if slices.Contains(dashKeywords, name) || strings.HasSuffix(before[:len(before)-len(name)], "$") {
				name = ""
			}
			out = append(out, selectorBlock{name: name, text: name + expr[start:i+1]})
			start = -1
		}
	}
	return out
}

func madeLabels(expr string) []string {
	var out []string
	for _, m := range madeLabelRe.FindAllStringSubmatch(expr, -1) {
		out = append(out, m[1])
	}
	return out
}

// dashboardSeries returns the series names a panel or variable query reads;
// label_values names a label after its series, which is no series.
func dashboardSeries(expr string) []string {
	expr = labelValuesRe.ReplaceAllString(expr, "$1")
	for _, re := range []*regexp.Regexp{dashMatchersRe, dashQuotedRe, dashGroupingRe, dashRangeRe, dashVariableRe, dashFunctionRe} {
		expr = re.ReplaceAllString(expr, " ")
	}
	var names []string
	for _, id := range dashIdentRe.FindAllString(expr, -1) {
		if !slices.Contains(dashKeywords, id) && !slices.Contains(names, id) {
			names = append(names, id)
		}
	}
	return names
}

// TestDashboardIsAV2ResourceUnderItsName fails when the file stops being a
// schema v2 resource Grafana provisions as is, or when metadata.name changes,
// which would import as a second dashboard beside every user's existing one.
func TestDashboardIsAV2ResourceUnderItsName(t *testing.T) {
	d := loadDashboard(t)
	if d.APIVersion != "dashboard.grafana.app/v2" || d.Kind != "Dashboard" {
		t.Errorf("apiVersion %q kind %q, want dashboard.grafana.app/v2 Dashboard", d.APIVersion, d.Kind)
	}
	if len(d.Metadata) != 1 || d.Metadata["name"] != "cert-converter" {
		t.Errorf("metadata = %v, want only name cert-converter", d.Metadata)
	}
}

// TestDashboardReadsOnlySeriesCertConverterServes fails when a panel or a
// variable reads a series or a label the image does not serve, so a renamed
// series fails the build instead of blanking a panel. ALERTS is the ruler's
// series; instance is the scrape's label.
func TestDashboardReadsOnlySeriesCertConverterServes(t *testing.T) {
	served := servedSeries(t)
	d := loadDashboard(t)
	scrape := []string{"instance"}
	read := 0
	for where, expr := range dashboardQueries(&d) {
		for _, sel := range selectors(bracedVariableRe.ReplaceAllString(expr, "$$v")) {
			if sel.name == "" {
				t.Errorf("%s has a selector with no series name before its braces, which this check cannot read: %s", where, sel.text)
			}
		}
		var labels []string
		for _, name := range dashboardSeries(expr) {
			switch have, ok := served[name]; {
			case name == "ALERTS":
			case !ok:
				t.Errorf("%s reads %s, which cert-converter does not serve", where, name)
			default:
				read++
				labels = append(labels, have...)
			}
		}
		for _, sel := range dashSelectorRe.FindAllStringSubmatch(dashQuotedRe.ReplaceAllString(expr, `""`), -1) {
			have, ok := served[sel[1]]
			if !ok {
				continue
			}
			for _, m := range dashMatcherRe.FindAllStringSubmatch(sel[2], -1) {
				if !slices.Contains(have, m[1]) && !slices.Contains(scrape, m[1]) {
					t.Errorf("%s matches %s on %s, which carries no such label", where, m[1], sel[1])
				}
			}
		}
		for _, g := range dashGroupingRe.FindAllStringSubmatch(expr, -1) {
			for l := range strings.SplitSeq(g[2], ",") {
				l = strings.TrimSpace(l)
				computed := slices.Contains(madeLabels(expr), l)
				if l != "" && !computed && !slices.Contains(labels, l) && !slices.Contains(scrape, l) {
					t.Errorf("%s groups by %s, which no series it reads carries", where, l)
				}
			}
		}
	}
	if read == 0 {
		t.Error("no query reads a cert-converter series; the check no longer reads the dashboard")
	}
}

// TestDashboardInstancePickerListsEveryTarget fails when the instance picker
// stops listing every target that serves cert-converter with no setup, or a
// legend shows instance, job, hostname or container, which never vary inside
// one instance.
func TestDashboardInstancePickerListsEveryTarget(t *testing.T) {
	d := loadDashboard(t)
	inst, ok := d.variables()["instance"]
	if !ok {
		t.Fatal("no instance variable")
	}
	if got, want := variableQuery(&inst), "label_values(cert_converter_build_info, instance)"; got != want {
		t.Errorf("instance variable query = %q, want %q", got, want)
	}
	if s := inst.Spec; s.Sort != "alphabeticalAsc" || s.Refresh != "onTimeRangeChanged" ||
		s.Current.Text != "" || s.Current.Value != "" || s.Hide != "dontHide" {
		t.Errorf("instance variable is sort %q refresh %q current %v/%v hide %q, "+
			"want a shown pick sorted alphabeticalAsc, refreshed onTimeRangeChanged and saved empty so Grafana picks the first",
			s.Sort, s.Refresh, s.Current.Text, s.Current.Value, s.Hide)
	}
	for name, p := range d.Spec.Elements {
		for _, q := range p.Spec.Data.Spec.Queries {
			for _, l := range append([]string{"instance"}, userNamedLabels...) {
				if strings.Contains(q.Spec.Query.Spec.LegendFormat, "{{"+l+"}}") {
					t.Errorf("%s %q legend shows %s, which never varies inside one instance", name, p.Spec.Title, l)
				}
			}
		}
	}
}

// TestDashboardQueriesAreTheTestedOnes fails when a panel query differs from
// the one alerts/promql_test.yaml evaluates under its anchor with $instance
// and a 1m slot filled in, so a change to the query runs through promtool in
// CI.
func TestDashboardQueriesAreTheTestedOnes(t *testing.T) {
	d := loadDashboard(t)
	raw, err := os.ReadFile("alerts/promql_test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fill := strings.NewReplacer(`$instance`, "[::1]:9468", `${__interval_ms}`, "60000", `$__interval`, "1m")
	for _, tc := range []struct{ title, anchor string }{
		{"cert-converter scrape", "scrape_down"},
		{"Outputs match inputs", "outputs_match"},
		{"Each certificate", "certificate_table"},
	} {
		t.Run(tc.anchor, func(t *testing.T) {
			var exprs []string
			for _, p := range d.Spec.Elements {
				if p.Spec.Title == tc.title {
					exprs = append(exprs, panelExprs(&p)...)
				}
			}
			if len(exprs) != 1 {
				t.Fatalf("found %d %q queries, want 1", len(exprs), tc.title)
			}
			m := regexp.MustCompile(`(?m)expr: &` + tc.anchor + ` '([^']*)'$`).FindSubmatch(raw)
			if m == nil {
				t.Fatalf("alerts/promql_test.yaml has no expr anchored as %s", tc.anchor)
			}
			if want := fill.Replace(exprs[0]); string(m[1]) != want {
				t.Errorf("alerts/promql_test.yaml tests\n%s\nthe dashboard reads, with its variables filled in,\n%s", m[1], want)
			}
		})
	}
}

// attentionReads is every ALERTS selector a query may read the rule name's
// firing alerts with, for the rule expression expr. absent() and
// absent_over_time() label their alert with only the selector's equality
// matchers, and a shipped rule's selector names no instance, so only such a
// rule's alert is also read with instance="":
// https://prometheus.io/docs/prometheus/latest/querying/functions/#absent
func attentionReads(name, expr string) []string {
	read := `ALERTS{alertname="` + name + `", alertstate="firing", instance=`
	if strings.Contains(expr, "absent(") || strings.Contains(expr, "absent_over_time(") {
		return []string{read + `"$instance"}`, read + `""}`}
	}
	return []string{read + `"$instance"}`}
}

// attentionTile is the query of the Needs attention tile for the rule name
// with expression expr, which answers 0 while any of its reads does.
func attentionTile(name, expr string) string {
	reads := attentionReads(name, expr)
	if len(reads) == 2 {
		return `0 * max((` + reads[0] + ` or ` + reads[1] + `))`
	}
	return `0 * max(` + reads[0] + `)`
}

// TestDashboardAttentionTilesMirrorEveryShippedRule fails when a rule in
// alerts/promql.yaml has no Needs attention tile or spells an absent call in a
// form attentionReads does not read, a tile names a rule the file does not
// hold or does not name it in its description, a tile's query is not exactly
// attentionTile's for its rule, the row's variable does not count exactly
// those tiles in layout order, a tile is not hidden until its query answers,
// or any query reads an ALERTS selector that is not one of attentionReads'
// for a shipped rule, or a query reads a rule with instance="" but not with
// instance="$instance".
func TestDashboardAttentionTilesMirrorEveryShippedRule(t *testing.T) {
	d := loadDashboard(t)
	rules := ruleExprs(t, promqlRules)
	for name, expr := range rules {
		// PromQL function names are case-sensitive, so every absent call
		// holds the word, and these two are the spellings attentionReads reads.
		if strings.Count(expr, "absent") != strings.Count(expr, "absent(")+strings.Count(expr, "absent_over_time(") {
			t.Errorf("%s spells an absent call other than absent( or absent_over_time(, which attentionReads reads: %s", name, expr)
		}
	}
	for where, expr := range dashboardQueries(&d) {
		sels := selectors(bracedVariableRe.ReplaceAllString(expr, "$$v"))
		var texts []string
		for _, sel := range sels {
			texts = append(texts, sel.text)
		}
		for _, sel := range sels {
			if sel.name != "ALERTS" {
				continue
			}
			name := ""
			if m := alertsRe.FindStringSubmatch(sel.text); m != nil {
				name = m[1]
			}
			rule, ok := rules[name]
			if !ok || !slices.Contains(attentionReads(name, rule), sel.text) {
				t.Errorf("%s reads %s, which is none of the reads attentionReads gives a rule in %s, so it reads another instance's alerts, an unshipped alert or, with instance=\"\" on a rule with no absent arm, nothing", where, sel.text, promqlRules)
				continue
			}
			if reads := attentionReads(name, rule); strings.HasSuffix(sel.text, `instance=""}`) && !slices.Contains(texts, reads[0]) {
				t.Errorf("%s reads %s without %s in the same query: a read of only instance=\"\" misses the rule's alerts for the picked target", where, sel.text, reads[0])
			}
		}
	}
	attention := row(t, &d, "Needs attention")
	gate := attention.Spec.ConditionalRendering
	if gate == nil || gate.Spec.Visibility != "show" || len(gate.Spec.Items) != 1 ||
		gate.Spec.Items[0].Kind != "ConditionalRenderingVariable" ||
		gate.Spec.Items[0].Spec.Operator != "matches" || gate.Spec.Items[0].Spec.Value != "^[1-9]" {
		t.Fatal("Needs attention is not shown by a variable matching ^[1-9]")
	}
	var mirrored, counts []string
	for i, it := range attention.Spec.Layout.Spec.Items {
		p := d.Spec.Elements[it.Spec.Element.Name]
		cr := it.Spec.ConditionalRendering
		var conds []string
		if cr != nil {
			for _, c := range cr.Spec.Items {
				conds = append(conds, c.Kind)
			}
		}
		slices.Sort(conds)
		if cr == nil || cr.Spec.Visibility != "show" || cr.Spec.Condition != "or" ||
			!slices.Equal(conds, []string{"ConditionalRenderingData", "ConditionalRenderingTimeRangeSize"}) ||
			p.Spec.Data.Spec.QueryOptions.MaxDataPoints <= 0 {
			t.Errorf("%q does not show exactly while its query answers: want a shown group or'ing a has-data rule with a 0s range rule, and a maxDataPoints pin", p.Spec.Title)
		}
		exprs := panelExprs(&p)
		if len(exprs) != 1 {
			t.Errorf("%q holds %d queries, want 1", p.Spec.Title, len(exprs))
			continue
		}
		m := alertsRe.FindStringSubmatch(exprs[0])
		if m == nil {
			t.Errorf("%q reads no ALERTS series by alertname: %s", p.Spec.Title, exprs[0])
			continue
		}
		name := m[1]
		mirrored = append(mirrored, name)
		counts = append(counts, fmt.Sprintf(`label_replace(count(%s), "tile", "%d", "", "")`, exprs[0], i+1))
		if !strings.Contains(p.Spec.Description, name) {
			t.Errorf("%q reads %s, which its description does not name", p.Spec.Title, name)
		}
		expr, ok := rules[name]
		if !ok {
			t.Errorf("a tile mirrors %s, which %s does not hold", name, promqlRules)
			continue
		}
		if want := attentionTile(name, expr); exprs[0] != want {
			t.Errorf("%q must read exactly\n%s\nso it shows only the picked instance's firing %s alerts; it reads\n%s",
				p.Spec.Title, want, name, exprs[0])
		}
	}
	gateVar := d.variables()[gate.Spec.Items[0].Spec.Variable]
	if got, want := variableQuery(&gateVar), "query_result(count("+strings.Join(counts, " or ")+") or vector(0))"; got != want {
		t.Errorf("the row's variable must count exactly its tiles in layout order:\n%s\nit reads\n%s", want, got)
	}
	for name := range rules {
		if !slices.Contains(mirrored, name) {
			t.Errorf("%s has no Needs attention tile reading its firing alerts", name)
		}
	}
}

// TestDashboardRowHeadersFoldTwoPanels fails when a row shows a header over
// fewer than two always-shown panels, unless it holds only tiles shown with
// data, which light several.
func TestDashboardRowHeadersFoldTwoPanels(t *testing.T) {
	d := loadDashboard(t)
	for _, r := range d.Spec.Layout.Spec.Rows {
		if r.Spec.HideHeader {
			continue
		}
		shown, gated := 0, 0
		for _, it := range r.Spec.Layout.Spec.Items {
			if it.Spec.ConditionalRendering == nil {
				shown++
			} else {
				gated++
			}
		}
		if shown < 2 && (shown > 0 || gated < 2) {
			t.Errorf("row %q shows a header over %d always-shown panels and %d shown only with data, want two of one kind or hideHeader",
				r.Spec.Title, shown, gated)
		}
	}
}

func TestDashboardPanelsExplainThemselves(t *testing.T) {
	d := loadDashboard(t)
	if !d.Spec.Preload {
		t.Error("spec.preload = false, want true so a hidden tile below the fold still queries")
	}
	if d.Spec.Layout.Kind != "RowsLayout" || len(d.Spec.Layout.Spec.Rows) == 0 {
		t.Errorf("layout is %s, want one RowsLayout", d.Spec.Layout.Kind)
	}
	for name, p := range d.Spec.Elements {
		if strings.TrimSpace(p.Spec.Description) == "" {
			t.Errorf("%s %q has no description", name, p.Spec.Title)
		}
		switch p.Spec.VizConfig.Group {
		case "stat", "gauge", "bargauge", "table":
			if strings.TrimSpace(p.Spec.VizConfig.Spec.FieldConfig.Defaults.NoValue) == "" {
				t.Errorf("%s %q has no no-value text", name, p.Spec.Title)
			}
		}
	}
}

// panelTitled fails the test unless exactly one panel is titled title.
func panelTitled(t *testing.T, d *dashboard, title string) *dashPanel {
	t.Helper()
	var found []dashPanel
	for _, p := range d.Spec.Elements {
		if p.Spec.Title == title {
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d panels titled %q, want 1", len(found), title)
	}
	return &found[0]
}

// onlyExpr fails the test unless p holds exactly one query.
func onlyExpr(t *testing.T, p *dashPanel) string {
	t.Helper()
	exprs := panelExprs(p)
	if len(exprs) != 1 {
		t.Fatalf("%q holds %d queries, want 1", p.Spec.Title, len(exprs))
	}
	return withoutComments(exprs[0])
}

func servedValues(t *testing.T, family, label string) []string {
	t.Helper()
	var out []string
	for _, f := range gatherWithOneSource(t) {
		if f.Name != family {
			continue
		}
		for _, s := range f.Samples {
			for _, l := range s.Labels {
				if l.Name == label && !slices.Contains(out, l.Value) {
					out = append(out, l.Value)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

var fixedLengthRe = regexp.MustCompile(`(?i)\b\d+(?:\.\d+)?\s*(?:s|m|h|d|w|seconds?|minutes?|hours?|days?|weeks?)\b`)

// TestDashboardNamesNoFixedLength fails when a title names a fixed length or a
// query writes a fixed window or offset, since every figure follows the time
// picker. A panel that reads $__range must also put the range words back.
func TestDashboardNamesNoFixedLength(t *testing.T) {
	d := loadDashboard(t)
	for name, p := range d.Spec.Elements {
		if fixedLengthRe.MatchString(p.Spec.Title) {
			t.Errorf("%s %q names a fixed length, want none", name, p.Spec.Title)
		}
		if slices.ContainsFunc(panelExprs(&p), func(e string) bool { return strings.Contains(e, "$__range") }) {
			t.Errorf("%s %q reads $__range, which this dashboard's titles have no range words for", name, p.Spec.Title)
		}
	}
	offsetRe := regexp.MustCompile(`\boffset\s+(\S+)`)
	for where, expr := range dashboardQueries(&d) {
		expr = dashQuotedRe.ReplaceAllString(expr, `""`)
		windows := dashRangeRe.FindAllString(expr, -1)
		for _, m := range offsetRe.FindAllStringSubmatch(expr, -1) {
			windows = append(windows, m[1])
		}
		for _, w := range windows {
			if !strings.Contains(w, "$") {
				t.Errorf("%s writes the fixed window %s, want one that follows the time picker", where, w)
			}
		}
	}
}

// outputsMatchReason is one answer of Outputs match inputs: the series and
// matcher that raise it, and the text and colour the tile shows.
type outputsMatchReason struct {
	series, matcher, text, color string
}

// outputsMatchSpec is every Outputs match inputs answer by value, the more
// urgent the higher. Red marks what makes the container unhealthy. Removal
// turned off ranks above the outputs it kept, because it says why they stay.
var outputsMatchSpec = map[string]outputsMatchReason{
	"0":  {text: "Yes", color: "green"},
	"13": {"cert_converter_last_scan_outcome", `outcome="aborted"`, "No: scan aborted", "red"},
	"12": {"cert_converter_last_scan_sources", `outcome="failed"`, "No: conversion failed", "red"},
	"11": {"cert_converter_last_scan_sources", `outcome="collided"`, "No: name collision", "red"},
	"10": {"cert_converter_last_scan_sources", `outcome="unwritable"`, "No: write refused", "yellow"},
	"9":  {"cert_converter_last_scan_outcome", `outcome="budget_stopped"`, "No: input too large", "yellow"},
	"8":  {"cert_converter_last_scan_sources", `outcome=~"unreadable|unresolved|vanished"`, "No: input unreadable", "yellow"},
	"7":  {"cert_converter_condition", `condition="no_sources"`, "No: no certificates", "yellow"},
	"6":  {"cert_converter_condition", `condition="all_excluded"`, "No: all excluded", "yellow"},
	"5":  {"cert_converter_last_scan_sources", `outcome="orphan"`, "No: key missing", "yellow"},
	"4":  {"cert_converter_condition", `condition="orphan_removal_disabled"`, "No: old outputs kept", "yellow"},
	"3":  {"cert_converter_last_scan_unmatched_outputs", "", "No: outputs without input", "yellow"},
	"2":  {"cert_converter_condition", `condition="previous_layout_retained"`, "No: old layout kept", "yellow"},
	"1":  {"cert_converter_last_scan_sources", `outcome="ignored"`, "No: PFX input off", "yellow"},
}

// TestDashboardOutputsMatchNamesEveryReason fails when Outputs match inputs
// reads a reason other than its spec, at another rank, tests a count or a flag
// the wrong way, shows another text or colour for it, or misses an outcome or
// condition a shipped rule alerts on, except cleanup_degraded, whose leftover
// temporary files leave every output matching its input.
func TestDashboardOutputsMatchNamesEveryReason(t *testing.T) {
	d := loadDashboard(t)
	p := panelTitled(t, &d, "Outputs match inputs")
	expr := onlyExpr(t, p)
	// A count is above 0 and a flag is 1 when its reason holds.
	test := map[string]string{
		"cert_converter_last_scan_sources":           "> bool 0",
		"cert_converter_last_scan_unmatched_outputs": "> bool 0",
		"cert_converter_last_scan_outcome":           "== bool 1",
		"cert_converter_condition":                   "== bool 1",
	}
	operandRe := regexp.MustCompile(`\((\w+)\{instance="\$instance"(?:, ((?:outcome|condition)=~?"[^"]*"))?\} ((?:==|>) bool [01])\) \* (\d+)`)
	operands := operandRe.FindAllStringSubmatch(expr, -1)
	if n := strings.Count(expr, " bool "); len(operands) != n {
		t.Errorf("read %d reasons of the %d bool comparisons in %s", len(operands), n, expr)
	}
	got := map[string]outputsMatchReason{}
	for _, m := range operands {
		if _, dup := got[m[4]]; dup {
			t.Errorf("value %s is raised by two reasons", m[4])
		}
		if m[3] != test[m[1]] {
			t.Errorf("%s{%s} is tested %q, want %q", m[1], m[2], m[3], test[m[1]])
		}
		got[m[4]] = outputsMatchReason{series: m[1], matcher: m[2]}
	}
	got["0"] = outputsMatchReason{}
	mappings := p.Spec.VizConfig.Spec.FieldConfig.Defaults.Mappings
	if len(mappings) != 1 || mappings[0].Type != "value" {
		t.Fatalf("Outputs match inputs has mappings %+v, want one value mapping", mappings)
	}
	for value, o := range mappings[0].Options {
		r := got[value]
		r.text, r.color = o.Text, o.Color
		got[value] = r
	}
	values := slices.Collect(maps.Keys(got))
	for v := range outputsMatchSpec {
		if !slices.Contains(values, v) {
			values = append(values, v)
		}
	}
	slices.Sort(values)
	for _, value := range values {
		if got[value] != outputsMatchSpec[value] {
			t.Errorf("value %s is %+v, want %+v", value, got[value], outputsMatchSpec[value])
		}
	}
	read := map[string]bool{"cleanup_degraded": true}
	for _, r := range outputsMatchSpec {
		_, values, _ := strings.Cut(r.matcher, `"`)
		for v := range strings.SplitSeq(strings.TrimSuffix(values, `"`), "|") {
			read[v] = true
		}
	}
	ruleValueRe := regexp.MustCompile(`(?:outcome|condition)=~?"([^"]+)"`)
	for name, rule := range ruleExprs(t, promqlRules) {
		for _, m := range ruleValueRe.FindAllStringSubmatch(rule, -1) {
			for v := range strings.SplitSeq(m[1], "|") {
				if !read[v] {
					t.Errorf("%s alerts on %s, which Outputs match inputs gives no reason for", name, v)
				}
			}
		}
	}
}

// sourceProblems are the per-source outcomes that leave a certificate without
// a current output: the table ranks them first and Errors now counts them.
var sourceProblems = []string{"collided", "failed", "orphan", "unreadable", "unwritable", "vanished"}

// TestDashboardCertificateTableRanksProblemsFirst fails when an outcome the
// per-source series serve falls in no rank or in both, the problems ranked
// first differ from sourceProblems or from what Errors now counts, an outcome
// has no State text or a problem is not shown red or yellow, Errors now or
// Outputs match inputs colours a problem otherwise than the table, or the table
// drops its sort key before sorting on it.
func TestDashboardCertificateTableRanksProblemsFirst(t *testing.T) {
	served := servedValues(t, "cert_converter_source_outcome", "outcome")
	if len(served) == 0 {
		t.Fatal("Setup: cert_converter_source_outcome serves no outcome")
	}
	d := loadDashboard(t)
	table := panelTitled(t, &d, "Each certificate")
	rankRe := regexp.MustCompile(`"rank", "(\d)", "outcome", "([^"]+)"`)
	ranks := map[string]*regexp.Regexp{}
	for _, m := range rankRe.FindAllStringSubmatch(onlyExpr(t, table), -1) {
		// label_replace anchors its regex at both ends:
		// https://prometheus.io/docs/prometheus/latest/querying/functions/#label_replace
		ranks[m[1]] = regexp.MustCompile("^(?:" + m[2] + ")$")
	}
	if len(ranks) != 2 || ranks["0"] == nil || ranks["1"] == nil {
		t.Fatalf("the table ranks %v, want ranks 0 and 1", ranks)
	}
	var first []string
	for _, o := range served {
		in := slices.DeleteFunc(slices.Sorted(maps.Keys(ranks)), func(r string) bool { return !ranks[r].MatchString(o) })
		if len(in) != 1 {
			t.Errorf("outcome %s falls in ranks %v, want exactly one", o, in)
		}
		if ranks["0"].MatchString(o) {
			first = append(first, o)
		}
	}
	if !slices.Equal(first, sourceProblems) {
		t.Errorf("the table ranks %v first, want %v", first, sourceProblems)
	}
	var states []dashMapping
	for _, o := range table.Spec.VizConfig.Spec.FieldConfig.Overrides {
		for _, prop := range o.Properties {
			if o.Matcher.ID == "byName" && o.Matcher.Options == "State" && prop.ID == "mappings" {
				if err := json.Unmarshal(prop.Value, &states); err != nil {
					t.Fatalf("State mappings: %v", err)
				}
			}
		}
	}
	if len(states) != 1 {
		t.Fatalf("State has %d mappings, want one value mapping", len(states))
	}
	for _, o := range served {
		shown, ok := states[0].Options[o]
		warns := shown.Color == "red" || shown.Color == "yellow"
		switch {
		case !ok || shown.Text == "":
			t.Errorf("outcome %s has no State text", o)
		case warns != slices.Contains(sourceProblems, o):
			t.Errorf("outcome %s shows %s, want red or yellow for exactly the problems", o, shown.Color)
		}
	}
	countedRe := regexp.MustCompile(`outcome=~"([^"]+)"`)
	var counted []string
	for _, title := range []string{"Errors", "Warnings"} {
		p := panelTitled(t, &d, title)
		queries := p.Spec.Data.Spec.Queries
		if len(queries) != 1 {
			t.Errorf("%s holds %d queries, want 1", title, len(queries))
			continue
		}
		m := countedRe.FindStringSubmatch(queries[0].Spec.Query.Spec.Expr)
		if m == nil {
			t.Errorf("%s matches no outcome list", title)
			continue
		}
		color := colorAtOne(t, p, queries[0].Spec.RefID)
		for o := range strings.SplitSeq(m[1], "|") {
			counted = append(counted, o)
			if shown := states[0].Options[o].Color; shown != color {
				t.Errorf("%s shows %s %s from 1, the table %s", title, o, color, shown)
			}
		}
	}
	slices.Sort(counted)
	if !slices.Equal(counted, sourceProblems) {
		t.Errorf("Errors and Warnings count %v, want %v", counted, sourceProblems)
	}
	for _, o := range sourceProblems {
		for value, r := range outputsMatchSpec {
			_, matched, _ := strings.Cut(r.matcher, `"`)
			if r.series == "cert_converter_last_scan_sources" && slices.Contains(strings.Split(strings.TrimSuffix(matched, `"`), "|"), o) &&
				r.color != states[0].Options[o].Color {
				t.Errorf("Outputs match inputs shows %s %s at %s, the table %s", o, r.color, value, states[0].Options[o].Color)
			}
		}
	}
	sorted, filtered := -1, -1
	for i, tr := range table.Spec.Data.Spec.Transformations {
		switch tr.Group {
		case "sortBy":
			var opts struct {
				Sort []struct {
					Field string `json:"field"`
					Desc  bool   `json:"desc"`
				} `json:"sort"`
			}
			if err := json.Unmarshal(tr.Spec.Options, &opts); err != nil || len(opts.Sort) != 1 || opts.Sort[0].Field != "order" || opts.Sort[0].Desc {
				t.Errorf("the table sorts by %+v (%v), want order ascending", opts.Sort, err)
			}
			sorted = i
		case "filterFieldsByName":
			filtered = i
		}
	}
	if sorted < 0 || filtered < 0 || sorted > filtered {
		t.Errorf("the table sorts at step %d and filters at step %d, want a sort before the filter drops order", sorted, filtered)
	}
}

// colorAtOne is the colour p shows the query refID's value 1 in: its own
// thresholds override, else the defaults.
func colorAtOne(t *testing.T, p *dashPanel, refID string) string {
	t.Helper()
	th := p.Spec.VizConfig.Spec.FieldConfig.Defaults.Thresholds
	for _, o := range p.Spec.VizConfig.Spec.FieldConfig.Overrides {
		for _, prop := range o.Properties {
			if o.Matcher.ID == "byFrameRefID" && o.Matcher.Options == refID && prop.ID == "thresholds" {
				var own dashThresholds
				if err := json.Unmarshal(prop.Value, &own); err != nil {
					t.Fatalf("%q thresholds for %s: %v", p.Spec.Title, refID, err)
				}
				th = own
			}
		}
	}
	color := ""
	for _, st := range th.Steps {
		if st.Value == nil || *st.Value <= 1 {
			color = st.Color
		}
	}
	return color
}

// TestDashboardRowsAreAttentionThenNow fails when the rows stop reading
// attention, then the answers, with the answers open.
func TestDashboardRowsAreAttentionThenNow(t *testing.T) {
	d := loadDashboard(t)
	var titles []string
	for _, r := range d.Spec.Layout.Spec.Rows {
		titles = append(titles, r.Spec.Title)
	}
	if want := []string{"Needs attention", "Now"}; !slices.Equal(titles, want) {
		t.Errorf("rows are %q, want %q", titles, want)
	}
	if row(t, &d, "Now").Spec.Collapse {
		t.Error("Now starts collapsed, want it open")
	}
}

// TestDashboardStatTextIsFixed fails when a stat leaves its text to auto sizing
// or sizes it off the fleet's fixed sizes: 14 and 28, or 14 and 18 for a stat
// that stacks several values in one tile (grafana/panels.md "Draw options").
func TestDashboardStatTextIsFixed(t *testing.T) {
	d := loadDashboard(t)
	for name, p := range d.Spec.Elements {
		if p.Spec.VizConfig.Group != "stat" {
			continue
		}
		want := 28
		if len(p.Spec.Data.Spec.Queries) > 1 {
			want = 18
		}
		if got := p.Spec.VizConfig.Spec.Options.Text; got.TitleSize != 14 || got.ValueSize != want {
			t.Errorf("%s %q text is %d/%d, want 14/%d", name, p.Spec.Title, got.TitleSize, got.ValueSize, want)
		}
	}
}

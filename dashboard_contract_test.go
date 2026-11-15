package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	dashboardFile = "grafana-dashboard.json"
	promqlRules   = "alerts/promql.yaml"
)

type dashQuery struct {
	Spec struct {
		Query struct {
			Spec struct {
				Expr         string `json:"expr"`
				LegendFormat string `json:"legendFormat"`
			} `json:"spec"`
		} `json:"query"`
	} `json:"spec"`
}

type dashPanel struct {
	Spec struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Data        struct {
			Spec struct {
				Queries      []dashQuery `json:"queries"`
				QueryOptions struct {
					MaxDataPoints int `json:"maxDataPoints"`
				} `json:"queryOptions"`
			} `json:"spec"`
		} `json:"data"`
		VizConfig struct {
			Group string `json:"group"`
			Spec  struct {
				FieldConfig struct {
					Defaults struct {
						NoValue string `json:"noValue"`
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
	} `json:"spec"`
}

type dashVariable struct {
	Kind string `json:"kind"`
	Spec struct {
		Current struct {
			Text  any `json:"text"`
			Value any `json:"value"`
		} `json:"current"`
		Name             string `json:"name"`
		Hide             string `json:"hide"`
		Refresh          string `json:"refresh"`
		Sort             string `json:"sort"`
		Multi            bool   `json:"multi"`
		IncludeAll       bool   `json:"includeAll"`
		AllowCustomValue bool   `json:"allowCustomValue"`
		// Query is a data query on a QueryVariable and absent on a
		// DatasourceVariable.
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
func variableQuery(v *dashVariable) string {
	var q struct {
		Spec struct {
			Query string `json:"query"`
		} `json:"spec"`
	}
	if v.Kind != "QueryVariable" || json.Unmarshal(v.Spec.Query, &q) != nil {
		return ""
	}
	return q.Spec.Query
}

// dashboardQueries is every variable and panel query, keyed by where it sits.
func dashboardQueries(d *dashboard) map[string]string {
	queries := map[string]string{}
	for name, v := range d.variables() {
		if q := variableQuery(&v); q != "" {
			queries["variable "+name] = q
		}
	}
	for name, p := range d.Spec.Elements {
		for i, e := range panelExprs(&p) {
			queries[fmt.Sprintf("%s %s query %d", name, p.Spec.Title, i)] = e
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

// servedSeries builds the registry the way run does and returns each series
// name it serves with its label names.
func servedSeries(t *testing.T) map[string][]string {
	t.Helper()
	reg, _ := newMetrics(0)
	families, err := reg.Gather(t.Context())
	if err != nil {
		t.Fatalf("Gather = %v", err)
	}
	served := map[string][]string{}
	for _, f := range families {
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
	if _, ok := served["cert_converter_last_scan_outcome"]; !ok {
		t.Fatalf("Setup: the registry serves no cert_converter_last_scan_outcome: %v", served)
	}
	return served
}

var (
	dashQuotedRe    = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	dashSelectorRe  = regexp.MustCompile(`([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}`)
	dashMatcherRe   = regexp.MustCompile(`([a-zA-Z_]\w*)\s*(?:=~|!~|!=|=)`)
	dashMatchersRe  = regexp.MustCompile(`\{[^}]*\}`)
	dashGroupingRe  = regexp.MustCompile(`\b(by|without|on|ignoring|group_left|group_right)\s*\(([^)]*)\)`)
	dashRangeRe     = regexp.MustCompile(`\[[^\]]*\]`)
	dashVariableRe  = regexp.MustCompile(`\$\{?\w+(?::\w+)?\}?`)
	labelValuesRe   = regexp.MustCompile(`label_values\(([^,]+),\s*\w+\)`)
	dashFunctionRe  = regexp.MustCompile(`\b[a-z_]+\s*\(`)
	dashIdentRe     = regexp.MustCompile(`\b[a-zA-Z_:][a-zA-Z0-9_:]*\b`)
	alertsRe        = regexp.MustCompile(`ALERTS\{alertname="([A-Za-z]+)"([^}]*)\}`)
	selectorAtRe    = regexp.MustCompile(`([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(\{(?:[^{}"]|"(?:[^"\\]|\\.)*")*\})?`)
	instanceRe      = regexp.MustCompile(`\binstance\s*=\s*"\$instance"`)
	instanceOrNone  = regexp.MustCompile(`\binstance\s*=~\s*"\$instance\|"`)
	alertNameRe     = regexp.MustCompile(`\balertname\s*=\s*"(\w+)"`)
	dashKeywords    = []string{"and", "or", "unless", "bool", "offset"}
	userNamedLabels = []string{"job", "hostname", "container"}
)

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
				// A label the query names as a string is one label_replace makes.
				computed := strings.Contains(expr, `"`+l+`"`)
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

// TestDashboardMatchesOnlyTheSelectedInstance fails when the instance picker
// stops working with no setup, when a series a query reads is not narrowed to
// instance="$instance", or when a query or a legend uses job, hostname or
// container, labels each user names in their own scrape config. An absent()
// rule's alert carries no instance label, because absent() keeps only its
// equality matchers' labels, so its tile also matches the empty instance:
// https://prometheus.io/docs/prometheus/latest/querying/functions/#absent
func TestDashboardMatchesOnlyTheSelectedInstance(t *testing.T) {
	d := loadDashboard(t)
	inst, ok := d.variables()["instance"]
	if !ok {
		t.Fatal("no instance variable")
	}
	if got, want := variableQuery(&inst), "label_values(cert_converter_build_info, instance)"; got != want {
		t.Errorf("instance variable query = %q, want %q", got, want)
	}
	if s := inst.Spec; s.Sort != "alphabeticalAsc" || s.Refresh != "onTimeRangeChanged" ||
		s.Current.Text != "" || s.Current.Value != "" || s.Multi || s.IncludeAll || s.AllowCustomValue || s.Hide != "dontHide" {
		t.Errorf("instance variable is sort %q refresh %q current %v/%v multi %v includeAll %v allowCustomValue %v hide %q, "+
			"want a shown single pick sorted alphabeticalAsc, refreshed onTimeRangeChanged, saved empty so Grafana picks the first, and closed",
			s.Sort, s.Refresh, s.Current.Text, s.Current.Value, s.Multi, s.IncludeAll, s.AllowCustomValue, s.Hide)
	}

	instanceless := map[string]bool{}
	for alert, expr := range ruleExprs(t, promqlRules) {
		instanceless[alert] = strings.Contains(expr, "absent(")
	}
	checked := 0
	for where, expr := range dashboardQueries(&d) {
		for _, group := range dashMatchersRe.FindAllString(dashQuotedRe.ReplaceAllString(expr, `""`), -1) {
			for _, mm := range dashMatcherRe.FindAllStringSubmatch(group, -1) {
				if slices.Contains(userNamedLabels, mm[1]) {
					t.Errorf("%s matches on %s, a label each user names: %s", where, mm[1], expr)
				}
			}
		}
		if where == "variable instance" {
			continue
		}
		series := dashboardSeries(expr)
		named := 0
		for _, m := range selectorAtRe.FindAllStringSubmatch(expr, -1) {
			if !slices.Contains(series, m[1]) {
				continue
			}
			if m[2] != "" {
				named++
			}
			checked++
			a := alertNameRe.FindStringSubmatch(m[2])
			switch {
			case m[1] == "ALERTS" && a != nil && instanceless[a[1]]:
				if !instanceOrNone.MatchString(m[2]) {
					t.Errorf("%s reads %s alerts without instance=~\"$instance|\", so a missing target never shows: %s", where, a[1], expr)
				}
			case !instanceRe.MatchString(m[2]):
				t.Errorf("%s reads %s without instance=\"$instance\": %s", where, m[1], expr)
			}
		}
		if groups := len(dashMatchersRe.FindAllString(dashQuotedRe.ReplaceAllString(expr, `""`), -1)); groups != named {
			t.Errorf("%s has a selector with no series name before its braces, which these checks cannot read: %s", where, expr)
		}
	}
	if checked == 0 {
		t.Error("no query reads a series; the check no longer reads the dashboard")
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

// TestDashboardAttentionTilesMirrorEveryShippedRule fails when a rule in
// alerts/promql.yaml has no Needs attention tile, or a tile names a rule the
// file does not hold. Each tile reads its rule's firing ALERTS series and
// names the rule, and starts hidden until its query answers.
func TestDashboardAttentionTilesMirrorEveryShippedRule(t *testing.T) {
	d := loadDashboard(t)
	rules := ruleExprs(t, promqlRules)
	attention := row(t, &d, "Needs attention")
	gate := attention.Spec.ConditionalRendering
	if gate == nil || gate.Spec.Visibility != "show" || len(gate.Spec.Items) != 1 ||
		gate.Spec.Items[0].Kind != "ConditionalRenderingVariable" ||
		gate.Spec.Items[0].Spec.Operator != "matches" || gate.Spec.Items[0].Spec.Value != "^[1-9]" {
		t.Fatal("Needs attention is not shown by a variable matching ^[1-9]")
	}
	gateVar := d.variables()[gate.Spec.Items[0].Spec.Variable]
	counted := variableQuery(&gateVar)
	var mirrored []string
	for _, it := range attention.Spec.Layout.Spec.Items {
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
		for _, e := range panelExprs(&p) {
			if !strings.Contains(counted, "count("+e+")") {
				t.Errorf("%q query is not counted by the row's variable", p.Spec.Title)
			}
			for _, m := range alertsRe.FindAllStringSubmatch(e, -1) {
				if !strings.Contains(m[2], `alertstate="firing"`) {
					t.Errorf("%q reads %s alerts in any state, want only firing ones", p.Spec.Title, m[1])
				}
				if !strings.Contains(p.Spec.Description, m[1]) {
					t.Errorf("%q reads %s, which its description does not name", p.Spec.Title, m[1])
				}
				if !slices.Contains(mirrored, m[1]) {
					mirrored = append(mirrored, m[1])
				}
			}
		}
	}
	for name := range rules {
		if !slices.Contains(mirrored, name) {
			t.Errorf("%s has no Needs attention tile reading its firing alerts", name)
		}
	}
	for _, name := range mirrored {
		if _, ok := rules[name]; !ok {
			t.Errorf("a tile mirrors %s, which %s does not hold", name, promqlRules)
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

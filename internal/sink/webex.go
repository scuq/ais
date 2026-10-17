package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/secret"
)

// webex posts a formatted message to a Webex space, either through an
// incoming webhook (url only) or as a bot (url https://webexapis.com/v1/
// messages, tokenSecret and roomId). The body is Markdown shaped per
// finding; card: true adds an Adaptive Card with the same content.
type webex struct {
	name     string
	url      string
	token    string
	roomID   string
	maxItems int
	card     bool
	title    *template.Template
	client   *http.Client
}

// Webex limits a message's markdown to 7439 characters.
const webexMaxMarkdown = 7000

func newWebex(name string, cfg config.SinkConfig, secrets secret.Store) (Sink, error) {
	url, err := secret.Expand(cfg.URL, secrets)
	if err != nil {
		return nil, fmt.Errorf("sink %q: %w", name, err)
	}
	w := &webex{name: name, url: url, roomID: cfg.RoomID, maxItems: cfg.MaxItems, card: cfg.Card, client: httpClient(cfg)}
	if cfg.TokenSecret != "" {
		if w.token, err = secrets.Get(cfg.TokenSecret); err != nil {
			return nil, fmt.Errorf("sink %q: %w", name, err)
		}
	}
	if w.token != "" && w.roomID == "" {
		return nil, fmt.Errorf("sink %q: webex bot mode (tokenSecret) needs roomId", name)
	}
	if w.token == "" && !strings.Contains(url, "/webhooks/incoming/") {
		return nil, fmt.Errorf("sink %q: url is not a Webex incoming webhook; for a bot set tokenSecret and roomId", name)
	}
	if w.maxItems <= 0 {
		w.maxItems = 10
	}
	w.title, err = template.New("title").Funcs(tmplFuncs).Parse(orDefault(cfg.Title, "ais {{ .Task }}"))
	if err != nil {
		return nil, fmt.Errorf("sink %q: title: %w", name, err)
	}
	return w, nil
}

func (w *webex) Name() string { return w.name }
func (w *webex) Type() string { return "webex" }

func (w *webex) Deliver(ctx context.Context, ev Event) error {
	title, err := render(w.title, ev)
	if err != nil {
		return Permanent{err}
	}
	md := WebexMarkdown(title, ev, w.maxItems)
	body := map[string]any{"markdown": md}
	if w.roomID != "" {
		body["roomId"] = w.roomID
	}
	if w.card {
		body["attachments"] = []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     WebexCard(title, ev, w.maxItems),
		}}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return Permanent{err}
	}
	headers := map[string]string{}
	if w.token != "" {
		headers["Authorization"] = "Bearer " + w.token
	}
	return post(ctx, w.client, w.url, headers, "application/json", raw)
}

// finding is the subset of a vuln-watch finding the formatter knows; other
// result shapes fall back to a JSON block. Only the first line of fields is
// required by the template schema; the rest render when present.
type finding struct {
	Vendor, Product, Installed, AffectedRange, Fixed, Severity, Summary string
	CVEs, URLs, Devices                                                 []string
	Title, CVSS, Affected, Action, Published                            string
	Exploited, PreviouslyReported                                       *bool
	// Update says what changed since an earlier report; with
	// PreviouslyReported it turns the block into a short update. IoCs are
	// indicators of compromise, one per entry.
	Update string
	IoCs   []string
}

// isUpdate reports whether the finding is a short update to an earlier
// report rather than a new finding.
func (f finding) isUpdate() bool {
	return f.PreviouslyReported != nil && *f.PreviouslyReported && strings.TrimSpace(f.Update) != ""
}

// iocLine renders the indicators as code spans, so that Webex does not
// make links of them and nobody clicks one by accident.
func (f finding) iocLine() string {
	out := make([]string, 0, len(f.IoCs))
	for i, ioc := range f.IoCs {
		if i >= 10 {
			out = append(out, fmt.Sprintf("+%d more", len(f.IoCs)-10))
			break
		}
		out = append(out, "`"+strings.TrimSpace(ioc)+"`")
	}
	return strings.Join(out, ", ")
}

func boolPtr(m map[string]any, k string) *bool {
	if v, ok := m[k].(bool); ok {
		return &v
	}
	return nil
}

func cvss(m map[string]any) string {
	v, ok := m["cvss"].(float64)
	if !ok {
		return ""
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", v), "0"), ".")
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func strs(m map[string]any, k string) []string {
	arr, _ := m[k].([]any)
	out := make([]string, 0, len(arr))
	for _, a := range arr {
		out = append(out, fmt.Sprint(a))
	}
	return out
}

// findings extracts a findings array from a result, if it has one.
func findings(result any) ([]finding, bool) {
	m, ok := result.(map[string]any)
	if !ok {
		return nil, false
	}
	arr, ok := m["findings"].([]any)
	if !ok {
		return nil, false
	}
	var out []finding
	for _, el := range arr {
		fm, ok := el.(map[string]any)
		if !ok {
			continue
		}
		f := finding{
			Vendor: str(fm, "vendor"), Product: str(fm, "product"), Installed: str(fm, "installed_version"),
			AffectedRange: str(fm, "affected_version_range"), Fixed: str(fm, "fixed_version"),
			Severity: strings.ToLower(str(fm, "severity")), Summary: str(fm, "summary"),
			CVEs: strs(fm, "cve_ids"), URLs: strs(fm, "source_urls"),
			Title: str(fm, "title"), CVSS: cvss(fm), Affected: str(fm, "affected"), Action: str(fm, "action"),
			Published: str(fm, "published"), Exploited: boolPtr(fm, "exploited"), PreviouslyReported: boolPtr(fm, "previously_reported"),
			Update: str(fm, "update"), IoCs: strs(fm, "iocs"),
		}
		if devs, ok := fm["devices"].([]any); ok {
			for _, d := range devs {
				if dm, ok := d.(map[string]any); ok {
					if name := deviceName(dm); name != "" {
						f.Devices = append(f.Devices, name)
					}
				}
			}
		}
		out = append(out, f)
	}
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(out, func(i, j int) bool {
		oi, oki := severityOrder[out[i].Severity]
		oj, okj := severityOrder[out[j].Severity]
		if !oki {
			oi = 9
		}
		if !okj {
			oj = 9
		}
		return oi < oj
	})
	return out, true
}

// deviceName names an attached inventory entry: its hostname, else its
// address, else its title (a role such as "Internet edge firewalls"), with
// the install count when the entry stands for more than one.
func deviceName(dm map[string]any) string {
	name := str(dm, "hostname")
	if name == "" {
		name = str(dm, "ip")
	}
	if name == "" {
		name = str(dm, "title")
	}
	if name == "" {
		return ""
	}
	if c := str(dm, "count"); c != "" && c != "1" {
		name += " (×" + c + ")"
	}
	return name
}

var severityMark = map[string]string{"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "unknown": "⚪"}

func mark(sev string) string {
	if m, ok := severityMark[sev]; ok {
		return m
	}
	return "⚪"
}

func joinMax(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" (+%d more)", len(items)-n)
}

// WebexMarkdown renders an event as Webex Markdown (bold, lists, links).
func WebexMarkdown(title string, ev Event, maxItems int) string {
	if maxItems <= 0 {
		maxItems = 10
	}
	var b strings.Builder
	when := ev.FinishedAt.Local().Format("2006-01-02 15:04")
	switch ev.Kind {
	case "digest":
		return digestMarkdown(title, ev, when)
	case "alert":
		fmt.Fprintf(&b, "⚠️ **%s**: run `%s` %s", title, ev.RunID, ev.State)
		if ev.Reason != "" {
			fmt.Fprintf(&b, " (%s)", ev.Reason)
		}
		b.WriteString("\n")
		if ev.Error != "" {
			fmt.Fprintf(&b, "> %s\n", strings.TrimSpace(ev.Error))
		}
		if len(ev.Leaks) > 0 {
			fmt.Fprintf(&b, "Leaked fields: %s. The result was not delivered.\n", strings.Join(ev.Leaks, ", "))
		}
		fmt.Fprintf(&b, "_%s · %s_", when, ev.Meta.Host)
		return b.String()
	}
	fs, ok := findings(ev.Result)
	if !ok {
		raw, _ := json.MarshalIndent(ev.Result, "", "  ")
		fmt.Fprintf(&b, "**%s**: run `%s` finished (%d turns, %s)\n```\n%s\n```", title, ev.RunID, ev.Meta.NumTurns, costLine(ev), truncateTo(string(raw), 3000))
		return b.String()
	}
	if len(fs) == 0 {
		fmt.Fprintf(&b, "✅ **%s**: no new findings\n_%s · %d turns · %s_", title, when, ev.Meta.NumTurns, costLine(ev))
		return b.String()
	}
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "unknown"} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	summary := strings.Join(parts, ", ")
	if n := countUpdates(fs); n > 0 {
		summary += fmt.Sprintf("; %d update(s)", n)
	}
	fmt.Fprintf(&b, "%s **%s**: %d finding(s) (%s)\n\n", mark(fs[0].Severity), title, len(fs), summary)
	for i, f := range fs {
		if i >= maxItems {
			fmt.Fprintf(&b, "… and %d more; see `ais runs show %s --clear`\n\n", len(fs)-maxItems, ev.RunID)
			break
		}
		b.WriteString(findingMarkdown(f))
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "_%s · run %s · %d turns · %s_", when, ev.RunID, ev.Meta.NumTurns, costLine(ev))
	return truncateTo(b.String(), webexMaxMarkdown)
}

// digestMarkdown renders a digest event: the headline says whether the
// window had findings, the second line says what the runs did, the footer
// gives the summed usage and the next run.
func digestMarkdown(title string, ev Event, when string) string {
	dg := ev.Digest
	if dg == nil {
		return fmt.Sprintf("**%s**: digest without data", title)
	}
	var b strings.Builder
	if dg.Findings == 0 {
		fmt.Fprintf(&b, "✅ **%s**: nothing found in the last %s\n", title, dg.WindowLabel())
	} else {
		fmt.Fprintf(&b, "🔎 **%s**: %d finding(s) in the last %s\n", title, dg.Findings, dg.WindowLabel())
	}
	b.WriteString(digestStats(dg, ev))
	fmt.Fprintf(&b, "\n_%s · %s", when, costLine(ev))
	if dg.NextRun != nil {
		fmt.Fprintf(&b, " · next run %s", dg.NextRun.Local().Format("2006-01-02 15:04"))
	}
	b.WriteString("_")
	return b.String()
}

// digestStats is the middle line of a digest: runs, turns, checked items.
func digestStats(dg *Digest, ev Event) string {
	parts := []string{dg.RunsLine(), fmt.Sprintf("%d turns", ev.Meta.NumTurns)}
	if dg.Checked != nil {
		parts = append(parts, fmt.Sprintf("%d items checked", *dg.Checked))
	}
	return strings.Join(parts, " · ")
}

// headline is "Vendor Product — Title", or the CVE list when the finding
// has no title.
func (f finding) headline() string {
	name := strings.TrimSpace(f.Vendor + " " + f.Product)
	tail := strings.TrimSpace(f.Title)
	if tail == "" {
		tail = strings.Join(f.CVEs, ", ")
	}
	switch {
	case name == "":
		return tail
	case tail == "":
		return name
	}
	return name + " — " + tail
}

// criticality is "CRITICAL / CVSS 9.8 / Exploited in the wild"; the CVSS
// and exploitation parts appear when the finding has them.
func (f finding) criticality() string {
	parts := []string{strings.ToUpper(f.Severity)}
	if f.CVSS != "" {
		parts = append(parts, "CVSS "+f.CVSS)
	}
	if f.Exploited != nil {
		if *f.Exploited {
			parts = append(parts, "Exploited in the wild")
		} else {
			parts = append(parts, "No known exploitation")
		}
	}
	return strings.Join(parts, " / ")
}

// yourVersion is the installed version with the affected range, when known.
func (f finding) yourVersion() string {
	v := f.Installed
	if v == "" {
		v = "unknown"
	}
	if f.AffectedRange != "" {
		v += " — affected: " + f.AffectedRange
	}
	return v
}

func (f finding) newVersion() string {
	if f.Fixed == "" {
		return "none yet"
	}
	return f.Fixed
}

func (f finding) cveLine() string {
	if len(f.CVEs) == 0 {
		return "none assigned"
	}
	return strings.Join(f.CVEs, ", ")
}

// publishedLine adds the watch history to the publication date.
func (f finding) publishedLine() string {
	p := strings.TrimSpace(f.Published)
	if f.PreviouslyReported == nil {
		return p
	}
	note := "Previously unreported in this watch."
	if *f.PreviouslyReported {
		note = "Previously reported in this watch; new information."
	}
	if p == "" {
		return note
	}
	return strings.TrimRight(p, ".") + ". " + note
}

// linkLabel names a source link by its host, as a reader scans for the
// vendor advisory among the links.
func linkLabel(raw string, i int) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return strings.TrimPrefix(u.Host, "www.")
	}
	return fmt.Sprintf("source %d", i+1)
}

// maxLinks is the number of source links shown per finding.
const maxLinks = 3

func (f finding) links() string {
	links := make([]string, 0, maxLinks)
	for i, u := range f.URLs {
		if i >= maxLinks {
			break
		}
		links = append(links, fmt.Sprintf("[%s](%s)", linkLabel(u, i), u))
	}
	if len(f.URLs) > maxLinks {
		links = append(links, fmt.Sprintf("+%d", len(f.URLs)-maxLinks))
	}
	return strings.Join(links, " · ")
}

// countUpdates counts the findings that are updates to earlier reports.
func countUpdates(fs []finding) int {
	n := 0
	for _, f := range fs {
		if f.isUpdate() {
			n++
		}
	}
	return n
}

// updateMarkdown renders a repeated finding as a short update: what is
// new, the identity and criticality, the fix if there is one, the
// indicators, the links, and the devices. The rest was reported before.
func updateMarkdown(f finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🔁 **Update: %s**\n", f.headline())
	fmt.Fprintf(&b, "**What's new:** %s\n", codeSpans(truncateTo(strings.TrimSpace(f.Update), 400)))
	fmt.Fprintf(&b, "**CVE:** %s\n", f.cveLine())
	fmt.Fprintf(&b, "**Criticality:** %s\n", f.criticality())
	if f.Fixed != "" {
		fmt.Fprintf(&b, "**New version:** %s\n", f.Fixed)
	}
	if len(f.IoCs) > 0 {
		fmt.Fprintf(&b, "**IoCs:** %s\n", f.iocLine())
	}
	if len(f.URLs) > 0 {
		fmt.Fprintf(&b, "**Links:** %s\n", f.links())
	}
	if len(f.Devices) > 0 {
		fmt.Fprintf(&b, "**Devices (%d):** %s\n", len(f.Devices), joinMax(f.Devices, 5))
	}
	return b.String()
}

// findingMarkdown renders one finding as labelled lines, one fact per line.
// A repeated finding with an update text is rendered short.
func findingMarkdown(f finding) string {
	if f.isUpdate() {
		return updateMarkdown(f)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s **%s**\n", mark(f.Severity), f.headline())
	fmt.Fprintf(&b, "**Your version:** %s\n", f.yourVersion())
	fmt.Fprintf(&b, "**New version:** %s\n", f.newVersion())
	fmt.Fprintf(&b, "**CVE:** %s\n", f.cveLine())
	fmt.Fprintf(&b, "**Criticality:** %s\n", f.criticality())
	if f.Summary != "" {
		fmt.Fprintf(&b, "**Summary:** %s\n", codeSpans(truncateTo(strings.TrimSpace(f.Summary), 400)))
	}
	if len(f.IoCs) > 0 {
		fmt.Fprintf(&b, "**IoCs:** %s\n", f.iocLine())
	}
	if len(f.URLs) > 0 {
		fmt.Fprintf(&b, "**Links:** %s\n", f.links())
	}
	if f.Affected != "" {
		fmt.Fprintf(&b, "**Affected:** %s\n", codeSpans(truncateTo(strings.TrimSpace(f.Affected), 300)))
	}
	if len(f.Devices) > 0 {
		fmt.Fprintf(&b, "**Devices (%d):** %s\n", len(f.Devices), joinMax(f.Devices, 5))
	}
	if f.Action != "" {
		fmt.Fprintf(&b, "**Action:** %s\n", codeSpans(truncateTo(strings.TrimSpace(f.Action), 300)))
	}
	if p := f.publishedLine(); p != "" {
		fmt.Fprintf(&b, "**Published:** %s\n", p)
	}
	return b.String()
}

// WebexCard renders the same content as an Adaptive Card (version 1.3).
func WebexCard(title string, ev Event, maxItems int) map[string]any {
	if maxItems <= 0 {
		maxItems = 10
	}
	body := []any{map[string]any{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title, "wrap": true}}
	fs, ok := findings(ev.Result)
	switch {
	case ev.Kind == "digest" && ev.Digest != nil:
		head, color := fmt.Sprintf("Nothing found in the last %s", ev.Digest.WindowLabel()), "Good"
		if ev.Digest.Findings > 0 {
			head, color = fmt.Sprintf("%d finding(s) in the last %s", ev.Digest.Findings, ev.Digest.WindowLabel()), "Accent"
		}
		body = append(body, map[string]any{"type": "TextBlock", "text": head, "wrap": true, "color": color},
			map[string]any{"type": "TextBlock", "text": digestStats(ev.Digest, ev), "wrap": true})
	case ev.Kind == "alert":
		body = append(body, map[string]any{"type": "TextBlock", "text": fmt.Sprintf("Run %s %s (%s)", ev.RunID, ev.State, ev.Reason), "wrap": true, "color": "Attention"})
		if ev.Error != "" {
			body = append(body, map[string]any{"type": "TextBlock", "text": ev.Error, "wrap": true, "isSubtle": true})
		}
	case !ok:
		raw, _ := json.Marshal(ev.Result)
		body = append(body, map[string]any{"type": "TextBlock", "text": truncateTo(string(raw), 2000), "wrap": true, "fontType": "Monospace"})
	case len(fs) == 0:
		body = append(body, map[string]any{"type": "TextBlock", "text": "No new findings", "wrap": true, "color": "Good"})
	default:
		for i, f := range fs {
			if i >= maxItems {
				body = append(body, map[string]any{"type": "TextBlock", "text": fmt.Sprintf("… and %d more", len(fs)-maxItems), "wrap": true, "isSubtle": true})
				break
			}
			color := map[string]string{"critical": "Attention", "high": "Warning", "medium": "Accent", "low": "Good"}[f.Severity]
			if color == "" {
				color = "Default"
			}
			head := f.headline()
			if f.isUpdate() {
				head = "Update: " + head
			}
			body = append(body, map[string]any{"type": "TextBlock", "weight": "Bolder", "color": color, "wrap": true, "text": head})
			if f.isUpdate() {
				body = append(body, map[string]any{"type": "TextBlock", "text": "What's new: " + truncateTo(strings.TrimSpace(f.Update), 400), "wrap": true})
			}
			facts := []any{
				map[string]any{"title": "CVE", "value": f.cveLine()},
				map[string]any{"title": "Criticality", "value": f.criticality()},
			}
			if !f.isUpdate() {
				facts = append([]any{
					map[string]any{"title": "Your version", "value": f.yourVersion()},
					map[string]any{"title": "New version", "value": f.newVersion()},
				}, facts...)
			} else if f.Fixed != "" {
				facts = append(facts, map[string]any{"title": "New version", "value": f.Fixed})
			}
			if len(f.IoCs) > 0 {
				facts = append(facts, map[string]any{"title": "IoCs", "value": strings.Join(f.IoCs, ", ")})
			}
			if f.Affected != "" && !f.isUpdate() {
				facts = append(facts, map[string]any{"title": "Affected", "value": truncateTo(f.Affected, 300)})
			}
			if len(f.Devices) > 0 {
				facts = append(facts, map[string]any{"title": fmt.Sprintf("Devices (%d)", len(f.Devices)), "value": joinMax(f.Devices, 5)})
			}
			if p := f.publishedLine(); p != "" && !f.isUpdate() {
				facts = append(facts, map[string]any{"title": "Published", "value": p})
			}
			body = append(body, map[string]any{"type": "FactSet", "facts": facts})
			if f.Summary != "" && !f.isUpdate() {
				body = append(body, map[string]any{"type": "TextBlock", "text": truncateTo(f.Summary, 400), "wrap": true})
			}
			if f.Action != "" && !f.isUpdate() {
				body = append(body, map[string]any{"type": "TextBlock", "text": "Action: " + truncateTo(f.Action, 300), "wrap": true})
			}
		}
	}
	footer := fmt.Sprintf("%s · run %s · %d turns · %s", ev.FinishedAt.Local().Format("2006-01-02 15:04"), ev.RunID, ev.Meta.NumTurns, costLine(ev))
	if ev.Kind == "digest" && ev.Digest != nil {
		footer = fmt.Sprintf("%s · %s", ev.FinishedAt.Local().Format("2006-01-02 15:04"), costLine(ev))
		if ev.Digest.NextRun != nil {
			footer += " · next run " + ev.Digest.NextRun.Local().Format("2006-01-02 15:04")
		}
	}
	body = append(body, map[string]any{"type": "TextBlock", "isSubtle": true, "size": "Small", "wrap": true, "text": footer})
	card := map[string]any{
		"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.3", "body": body,
	}
	var actions []any
	for i, f := range fs {
		if i >= 3 || len(f.URLs) == 0 {
			continue
		}
		actions = append(actions, map[string]any{"type": "Action.OpenUrl", "title": truncateTo(strings.TrimSpace(f.Product+" "+strings.Join(f.CVEs, ",")), 40), "url": f.URLs[0]})
	}
	if len(actions) > 0 {
		card["actions"] = actions
	}
	return card
}

// RenderTitle renders a sink title template (default "ais {{ .Task }}").
func RenderTitle(tmpl string, ev Event) (string, error) {
	t, err := template.New("title").Funcs(tmplFuncs).Parse(orDefault(tmpl, "ais {{ .Task }}"))
	if err != nil {
		return "", err
	}
	return render(t, ev)
}

// costLine returns the usage and billing segment of a footer, for example
// "claude-opus-5-5 · 92k in / 6k out · subscription (est. $0.42)".
// If the run has no model or no tokens, costLine leaves out that part.
// Old rows and failed runs can have none.
func costLine(ev Event) string {
	var parts []string
	switch {
	case len(ev.Meta.Models) > 0:
		parts = append(parts, strings.Join(ev.Meta.Models, ", "))
	case ev.Meta.Model != "":
		parts = append(parts, ev.Meta.Model)
	}
	if t := ev.Meta.Tokens; t.In()+t.Out() > 0 {
		parts = append(parts, fmt.Sprintf("%s in / %s out", humanTokens(t.In()), humanTokens(t.Out())))
	}
	if ev.Meta.Billing == "" || ev.Meta.Billing == config.Billing {
		parts = append(parts, fmt.Sprintf("subscription (est. $%.2f)", ev.Meta.CostUSD))
	} else {
		parts = append(parts, fmt.Sprintf("$%.2f", ev.Meta.CostUSD))
	}
	return strings.Join(parts, " · ")
}

// humanTokens returns the token count n in short form for a footer, for
// example 999, 1.2k, 12k, or 1.2M.
func humanTokens(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d", n)
	case n < 10_000:
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	case n < 1_000_000:
		return fmt.Sprintf("%dk", n/1000)
	case n < 10_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	return fmt.Sprintf("%dM", n/1_000_000)
}

// iocPattern matches a URL or an IPv4 address, with an optional prefix
// length or port, in free text.
var iocPattern = regexp.MustCompile("https?://[^\\s<>()\\[\\]`\"']+|" + `\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2}|:\d{1,5})?\b`)

// codeSpans puts each URL and IPv4 address in s in a Markdown code span,
// so that an indicator of compromise is shown as code and Webex does not
// make it a link. Text that is already in a code span is unchanged. A
// trailing sentence mark is left outside the span.
func codeSpans(s string) string {
	if !strings.ContainsAny(s, ":.") {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range iocPattern.FindAllStringIndex(s, -1) {
		start, end := m[0], m[1]
		match := s[start:end]
		trimmed := strings.TrimRight(match, ".,;:!?")
		end = start + len(trimmed)
		b.WriteString(s[last:start])
		if (start > 0 && s[start-1] == '`') || (end < len(s) && s[end] == '`') {
			b.WriteString(trimmed)
		} else {
			b.WriteString("`" + trimmed + "`")
		}
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

func truncateTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// SampleEvent is a representative result event for `ais sinks test`.
func SampleEvent(task string) Event {
	return Event{
		Kind: "result", Task: task, RunID: "sample-" + time.Now().UTC().Format("20060102T150405Z"), State: "succeeded", FinishedAt: time.Now(),
		Result: map[string]any{"findings": []any{
			map[string]any{"vendor": "Palo Alto Networks", "product": "PAN-OS", "installed_version": "11.1.4", "affected_version_range": "< 11.1.5", "fixed_version": "11.1.5",
				"cve_ids": []any{"CVE-2026-0001"}, "severity": "critical", "source_urls": []any{"https://security.paloaltonetworks.com/"},
				"summary": "Sample finding: authentication bypass on the management interface. This is a test message from ais.",
				"title":   "Authentication bypass on the management interface", "cvss": 9.8, "exploited": true,
				"affected":  "PAN-OS 11.1 before 11.1.5 with the management interface reachable from the internet.",
				"action":    "Upgrade to 11.1.5. Until then restrict the management interface to the jump host.",
				"published": "2026-10-07; updated 2026-10-08", "previously_reported": false,
				"devices": []any{map[string]any{"hostname": "fw01.example", "ip": "10.0.0.1"}, map[string]any{"hostname": "fw02.example", "ip": "10.0.0.2"}}},
			map[string]any{"vendor": "Fortinet", "product": "FortiOS", "installed_version": "7.4.5", "affected_version_range": "7.4.0-7.4.6", "fixed_version": "7.4.7",
				"cve_ids": []any{"CVE-2026-0002"}, "severity": "high", "source_urls": []any{"https://fortiguard.fortinet.com/psirt"},
				"summary": "Sample finding: SSL VPN heap overflow.", "devices": []any{map[string]any{"hostname": "vpn01.example"}}},
		}},
		Meta: Meta{Model: "claude-opus-5-5", Models: []string{"claude-opus-5-5"}, Billing: config.Billing, CostUSD: 0.42, NumTurns: 7, Host: "ais-sample",
			Tokens: Tokens{Input: 13862, Output: 5996, CacheRead: 55694, CacheCreation: 16542}},
	}
}

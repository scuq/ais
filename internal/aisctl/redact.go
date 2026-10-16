package aisctl

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/inventory"
	"github.com/scuq/ais/internal/pseudo"
	"github.com/scuq/ais/internal/task"
)

// RedactTestOptions control RedactTest.
type RedactTestOptions struct {
	// Text is extra text to run through the redactor (empty: samples only).
	Text string
	// Stdin reads text from standard input.
	Stdin io.Reader
	// Inventory overrides the configured inventory file; Format its format.
	Inventory string
	Format    string
	// Task applies that task's field policy; empty uses a generic one.
	Task string
	// JSON prints the report as JSON.
	JSON bool
}

// RedactReport is the result of a policy test.
type RedactReport struct {
	Policy   pseudo.Redaction `json:"policy"`
	Hash     string           `json:"hash"`
	Approved bool             `json:"approved"`
	Samples  [][2]string      `json:"samples"`
	Coverage pseudo.Coverage  `json:"coverage"`
	Records  int              `json:"records"`
	// Diffs show every inventory record before and after the field policy.
	Diffs []RecordDiff `json:"diffs,omitempty"`
	// Fields is the field policy that was applied.
	Fields map[string]string `json:"fields,omitempty"`
	// Text shows every free-text inventory line before and after the redactor.
	Text [][2]string `json:"text,omitempty"`
}

// RecordDiff is one record's before/after view.
type RecordDiff struct {
	Before map[string]string `json:"before"`
	After  map[string]string `json:"after"`
}

// GenericPolicy guesses a field policy from column names: hostname-like
// and address-like fields are pseudonymized, comment-like fields scrubbed,
// owner-like fields dropped, everything else passes clear. A task's own
// fields: block is used instead when --task names one.
func GenericPolicy(fields []string) pseudo.Policy {
	p := pseudo.Policy{}
	for _, f := range fields {
		switch l := strings.ToLower(f); {
		case pseudo.DefaultLabels[l] == "host" || pseudo.DefaultLabels[l] == "ip":
			p[f] = pseudo.Pseudonym
		case strings.Contains(l, "comment") || strings.Contains(l, "note") || strings.Contains(l, "remark"):
			p[f] = pseudo.Scrub
		case strings.Contains(l, "mail") || strings.Contains(l, "owner") || strings.Contains(l, "user"):
			p[f] = pseudo.Drop
		default:
			p[f] = pseudo.Clear
		}
	}
	return p
}

// Samples are texts that a run's tool output could plausibly contain.
var sampleTexts = []string{
	"Advisory affects fw01.cyberdyne.systems (10.1.0.1) and vpn01.cyberdyne.systems; see https://vendor.example/advisory",
	"Ticket: host app01.cyberdyne.systems at 172.16.1.20, gateway 192.168.1.1, public mirror 93.184.216.34",
	"Unrelated: news.ycombinator.com and 8.8.8.8 stay as they are; fe80::1 and fc00::1234 are local",
}

// RunRedactTest evaluates the policy against samples, optional text and
// the configured inventory.
func RunRedactTest(ctx context.Context, cfg *config.Config, o RedactTestOptions) (*RedactReport, error) {
	pol := cfg.Redaction()
	if err := pol.Validate(); err != nil {
		return nil, fmt.Errorf("pii: %w", err)
	}
	rep := &RedactReport{Policy: pol, Hash: pol.ApprovalHash(), Approved: cfg.RedactionApproved() == nil}
	rules := pol.Rules()
	rules.Key = hex.EncodeToString([]byte("aisctl-redact-test-key-0123456789ab"))
	rd, err := pseudo.NewRedactor(rules)
	if err != nil {
		return nil, err
	}
	texts := append([]string(nil), sampleTexts...)
	if o.Text != "" {
		texts = append(texts, o.Text)
	}
	if o.Stdin != nil {
		if data, err := io.ReadAll(o.Stdin); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			texts = append(texts, strings.TrimSpace(string(data)))
		}
	}
	for _, t := range texts {
		rep.Samples = append(rep.Samples, [2]string{t, rd.Redact(t)})
	}
	invFile, invFormat := config.ExpandPath(cfg.Inventory.File), cfg.Inventory.Format
	if o.Inventory != "" {
		invFile, invFormat = o.Inventory, o.Format
	}
	if invFile != "" {
		src, err := inventory.Open(inventory.SourceConfig{File: invFile, Format: invFormat})
		if err != nil {
			return nil, err
		}
		{
			recs, err := src.Load(ctx)
			if err != nil {
				return nil, err
			}
			rep.Records = len(recs)
			fieldPolicy := GenericPolicy(inventory.Fields(recs))
			if o.Task != "" {
				tasks, err := task.LoadDir(cfg.TasksDir(), taskDefaults(cfg), nil)
				if err != nil {
					return nil, err
				}
				t, ok := task.Find(tasks, o.Task)
				if !ok {
					return nil, fmt.Errorf("no task named %q", o.Task)
				}
				fieldPolicy = t.Policy()
			}
			rep.Fields = map[string]string{}
			for f, m := range fieldPolicy {
				rep.Fields[f] = string(m)
			}
			salt, err := pseudo.NewSalt()
			if err != nil {
				return nil, err
			}
			tok := pseudo.NewTokenizer(salt, nil)
			tok.HostnameMode, tok.IPMode = pol.HostnameMode, pol.IPMode
			scrubRules := pol.Rules()
			scrubRules.Key = hex.EncodeToString(salt)
			scrub, err := pseudo.NewRedactor(scrubRules)
			if err != nil {
				return nil, err
			}
			after := pseudo.Apply(fieldPolicy, tok, pseudo.NewMap("test", "ephemeral"), scrub, recs)
			for i := range recs {
				rep.Diffs = append(rep.Diffs, RecordDiff{Before: recs[i].Fields, After: after[i].Fields})
			}
			var hosts, ips []string
			for _, r := range recs {
				for f, v := range r.Fields {
					switch pseudo.DefaultLabels[strings.ToLower(f)] {
					case "host":
						hosts = append(hosts, v)
					case "ip":
						ips = append(ips, v)
					}
				}
			}
			rep.Coverage = pol.Check(hosts, ips)
		}
	}
	if tf := config.ExpandPath(cfg.Inventory.TextFile); tf != "" && o.Inventory == "" {
		lines, err := inventory.LoadText(tf)
		if err != nil {
			return nil, err
		}
		for _, l := range lines {
			rep.Text = append(rep.Text, [2]string{l, rd.Redact(l)})
		}
	}
	return rep, nil
}

// Uncovered reports whether the inventory holds values the policy misses.
func (r *RedactReport) Uncovered() int {
	return len(r.Coverage.UncoveredHosts) + len(r.Coverage.UncoveredIPs)
}

func (r *RedactReport) print(e *Env) {
	e.headline("redaction policy (hash %s, approved=%v)", r.Hash, r.Approved)
	e.logf("domains:   %s", strings.Join(r.Policy.Domains, ", "))
	e.logf("ranges:    %s", strings.Join(r.Policy.CIDRs, ", "))
	if len(r.Policy.Literals) > 0 {
		e.logf("literals:  %d", len(r.Policy.Literals))
	}
	e.logf("hostnames: %s   ips: %s", r.Policy.HostnameMode, r.Policy.IPMode)
	e.headline("samples (before -> after)")
	for _, s := range r.Samples {
		e.logf("- %s", s[0])
		e.logf("  %s", s[1])
	}
	if r.Records > 0 {
		e.headline("inventory: %d record(s), field policy: %s", r.Records, policyLine(r.Fields))
		for i, d := range r.Diffs {
			e.logf("record %d", i+1)
			keys := make([]string, 0, len(d.Before))
			for k := range d.Before {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				after, ok := d.After[k]
				switch {
				case !ok:
					e.logf("  %-12s %-40s -> (dropped)", k, trunc(d.Before[k], 40))
				case after == d.Before[k]:
					e.logf("  %-12s %s", k, trunc(after, 60))
				default:
					e.logf("  %-12s %-40s -> %s", k, trunc(d.Before[k], 40), trunc(after, 60))
				}
			}
		}
		if r.Uncovered() == 0 {
			e.logf("every hostname is under a configured domain and every address is inside a configured range")
		}
		for _, h := range r.Coverage.UncoveredHosts {
			e.logf("NOT COVERED hostname %s (add its domain to pii.domains)", h)
		}
		for _, ip := range r.Coverage.UncoveredIPs {
			e.logf("NOT COVERED address %s (add its range to pii.cidrs)", ip)
		}
	}
	if len(r.Text) > 0 {
		e.headline("free-text inventory: %d line(s) (before -> after)", len(r.Text))
		for _, l := range r.Text {
			if l[0] == l[1] {
				e.logf("- %s", trunc(l[0], 80))
				continue
			}
			e.logf("- %s", trunc(l[0], 80))
			e.logf("  %s", trunc(l[1], 80))
		}
	}
}

func policyLine(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + fields[k]
	}
	return strings.Join(parts, " ")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// RedactTest prints the report.
func RedactTest(ctx context.Context, e *Env, o RedactTestOptions) error {
	p := UserPaths(e.Home)
	cfg, err := loadConfig(p.ConfigFile)
	if err != nil {
		return err
	}
	rep, err := RunRedactTest(ctx, cfg, o)
	if err != nil {
		return err
	}
	if o.JSON {
		return json.NewEncoder(e.Out).Encode(rep)
	}
	rep.print(e)
	if !rep.Approved {
		e.headline("not approved: nothing runs until 'aisctl redact approve'")
	}
	return nil
}

// RedactApproveOptions control RedactApprove.
type RedactApproveOptions struct {
	// Force approves although the inventory has uncovered values.
	Force bool
	// Start starts the unit afterwards when it is installed but inactive.
	Start bool
}

// RedactApprove records the policy hash in config.yaml.
func RedactApprove(ctx context.Context, e *Env, o RedactApproveOptions) error {
	p := UserPaths(e.Home)
	cfg, err := loadConfig(p.ConfigFile)
	if err != nil {
		return err
	}
	rep, err := RunRedactTest(ctx, cfg, RedactTestOptions{})
	if err != nil {
		return err
	}
	rep.print(e)
	if n := rep.Uncovered(); n > 0 && !o.Force {
		return fmt.Errorf("%d inventory value(s) are not covered by the policy; fix pii.domains / pii.cidrs, or pass --force to approve anyway", n)
	}
	if err := setConfigKey(p.ConfigFile, "pii", "approvedHash", rep.Hash); err != nil {
		return err
	}
	e.headline("approved policy %s in %s", rep.Hash, p.ConfigFile)
	if o.Start {
		active, _ := e.Exec(ctx, "systemctl", "--user", "is-active", UnitName)
		enabled, _ := e.Exec(ctx, "systemctl", "--user", "is-enabled", UnitName)
		if strings.TrimSpace(enabled) == "enabled" && strings.TrimSpace(active) != "active" {
			if _, err := e.Exec(ctx, "systemctl", "--user", "start", UnitName); err != nil {
				return err
			}
			e.logf("started %s", UnitName)
			if err := waitHealth(ctx, cfg.BackendSocket(), 60e9); err != nil {
				return err
			}
			e.logf("daemon healthy")
		} else if strings.TrimSpace(active) == "active" {
			_, _ = e.Exec(ctx, "systemctl", "--user", "kill", "-s", "HUP", UnitName)
			e.logf("daemon reloaded")
		}
	}
	return nil
}

var _ = os.Getenv

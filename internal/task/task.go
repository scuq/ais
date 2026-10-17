// Package task defines what a scheduled job is: its schedule, inputs, data
// policy, tool surface, output contract and sinks. Tasks are YAML files in
// the tasks directory; one file is one task.
package task

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/adhocore/gronx"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/scuq/ais/internal/pseudo"
)

// Version is the task schema version.
const Version = 1

// Task is one task definition after defaults and validation.
type Task struct {
	Version     int    `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Enabled     *bool  `yaml:"enabled"`

	Schedule string         `yaml:"schedule"`
	Jitter   *time.Duration `yaml:"jitter"`
	Overlap  string         `yaml:"overlap"` // skip
	Timeout  time.Duration  `yaml:"timeout"`

	Model        string  `yaml:"model"`
	Effort       string  `yaml:"effort"`
	MaxTurns     int     `yaml:"maxTurns"`
	MaxBudgetUSD float64 `yaml:"maxBudgetUsd"`

	Inventory *InventoryRef     `yaml:"inventory"`
	Fields    map[string]string `yaml:"fields"`
	Expose    Expose            `yaml:"expose"`

	Tools        []string             `yaml:"tools"`
	AllowedTools []string             `yaml:"allowedTools"`
	MCPServers   map[string]MCPServer `yaml:"mcpServers"`
	Egress       Egress               `yaml:"egress"`
	PII          PII                  `yaml:"pii"`

	Prompt             string `yaml:"prompt"`
	AppendSystemPrompt string `yaml:"appendSystemPrompt"`

	OutputSchema     map[string]any `yaml:"outputSchema"`
	OutputSchemaFile string         `yaml:"outputSchemaFile"`

	Enrich []EnrichRule `yaml:"enrich"`
	Sinks  []string     `yaml:"sinks"`
	Digest *Digest      `yaml:"digest"`

	// Derived, not from YAML.
	Path   string `yaml:"-"`
	Hash   string `yaml:"-"`
	schema []byte
}

// Digest is the periodic summary of a task: how many runs, turns, tokens
// and dollars a window took. The daemon sends it to the task's sinks on
// Schedule when the window had no finding, so a quiet day is visible as
// work done, not as silence. Always sends it also when there were findings.
type Digest struct {
	Schedule string        `yaml:"schedule"`
	Window   time.Duration `yaml:"window"` // default 24h
	Always   bool          `yaml:"always"`
}

// DefaultDigestWindow is the window of a digest that sets none.
const DefaultDigestWindow = 24 * time.Hour

// InventoryRef overrides the configured inventory sources. Each key that
// is set replaces the global one; an empty key keeps the global value.
type InventoryRef struct {
	File     string `yaml:"file"`
	Format   string `yaml:"format"`
	TextFile string `yaml:"textFile"`
}

type Expose struct {
	Prompt ExposePrompt `yaml:"prompt"`
	MCP    ExposeMCP    `yaml:"mcp"`
}

type ExposePrompt struct {
	// GroupBy lists the fields whose distinct tuples the prompt sees. Every
	// field must be "clear" in the policy.
	GroupBy []string `yaml:"groupBy"`
	// Collect lists fields whose distinct values are gathered per group
	// (operator comments). Each must be "clear" or "scrub".
	Collect []string `yaml:"collect"`
}

type ExposeMCP struct {
	// Tools is the subset of the built-in inventory MCP tools offered to
	// this task. Empty means all of them.
	Tools []string `yaml:"tools"`
}

// MCPServer is a user-defined MCP server passed through to mcp.json.
type MCPServer struct {
	Type    string            `yaml:"type"` // http | stdio
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	Env     map[string]string `yaml:"env"`
}

type Egress struct {
	Allow []string `yaml:"allow"`
}

type PII struct {
	Redact pseudo.Rules `yaml:"redact"`
}

// EnrichRule attaches inventory identity to result elements on the host,
// after the model is done. Path selects elements ("findings[]"), Match maps
// a result field to an inventory field, Attach names the result field to
// add and the inventory fields to copy into it.
type EnrichRule struct {
	Path   string              `yaml:"path"`
	Match  map[string]string   `yaml:"match"`
	Attach map[string][]string `yaml:"attach"`
}

// BuiltinMCPTools are the tools the inventory server offers.
var BuiltinMCPTools = []string{"inventory_products", "inventory_list", "results_recent"}

// BuiltinTools are the Claude Code built-in tools a task may enable. Bash
// and the file tools are deliberately absent: a run container has no
// workspace and must not get a shell.
var BuiltinTools = map[string]bool{"WebFetch": true, "WebSearch": true}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// IsEnabled reports whether the task is scheduled.
func (t *Task) IsEnabled() bool { return t.Enabled == nil || *t.Enabled }

// JitterOr returns the task jitter or the given default.
func (t *Task) JitterOr(d time.Duration) time.Duration {
	if t.Jitter != nil {
		return *t.Jitter
	}
	return d
}

// Policy returns the field policy.
func (t *Task) Policy() pseudo.Policy {
	p := pseudo.Policy{}
	for f, m := range t.Fields {
		p[f] = pseudo.Mode(m)
	}
	return p
}

// SchemaJSON returns the output schema as compact JSON.
func (t *Task) SchemaJSON() []byte { return t.schema }

// MCPTools returns the built-in tools exposed to this task.
func (t *Task) MCPTools() []string {
	if len(t.Expose.MCP.Tools) == 0 {
		return append([]string(nil), BuiltinMCPTools...)
	}
	return append([]string(nil), t.Expose.MCP.Tools...)
}

// Defaults are the values filled in before validation.
type Defaults struct {
	Model        string
	Effort       string
	MaxTurns     int
	MaxBudgetUSD float64
	Timeout      time.Duration
}

// LoadFile parses one task file.
func LoadFile(path string, d Defaults) (*Task, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t, err := Parse(data, d)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	t.Path = path
	if t.OutputSchemaFile != "" {
		sp := t.OutputSchemaFile
		if !filepath.IsAbs(sp) {
			sp = filepath.Join(filepath.Dir(path), sp)
		}
		raw, err := os.ReadFile(sp)
		if err != nil {
			return nil, fmt.Errorf("%s: outputSchemaFile: %w", path, err)
		}
		if err := t.setSchema(raw); err != nil {
			return nil, fmt.Errorf("%s: outputSchemaFile: %w", path, err)
		}
	}
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

// Parse decodes a task document and applies defaults. Validate is separate
// so LoadFile can resolve a schema file first.
func Parse(data []byte, d Defaults) (*Task, error) {
	t := &Task{Version: Version}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(t); err != nil && err != io.EOF {
		return nil, err
	}
	if t.Model == "" {
		t.Model = d.Model
	}
	if t.Effort == "" {
		t.Effort = d.Effort
	}
	if t.MaxTurns == 0 {
		t.MaxTurns = d.MaxTurns
	}
	if t.MaxBudgetUSD == 0 {
		t.MaxBudgetUSD = d.MaxBudgetUSD
	}
	if t.Digest != nil && t.Digest.Window == 0 {
		t.Digest.Window = DefaultDigestWindow
	}
	if t.Timeout == 0 {
		t.Timeout = d.Timeout
	}
	if t.Overlap == "" {
		t.Overlap = "skip"
	}
	if len(t.Tools) == 0 {
		t.Tools = []string{"WebFetch", "WebSearch"}
	}
	if len(t.AllowedTools) == 0 {
		t.AllowedTools = append(append([]string(nil), t.Tools...), "mcp__inventory__*")
	}
	sum := sha256.Sum256(data)
	t.Hash = hex.EncodeToString(sum[:])[:16]
	if t.OutputSchema != nil && t.OutputSchemaFile != "" {
		return nil, errors.New("set either outputSchema or outputSchemaFile, not both")
	}
	if t.OutputSchema != nil {
		raw, err := json.Marshal(normalize(t.OutputSchema))
		if err != nil {
			return nil, fmt.Errorf("outputSchema: %w", err)
		}
		if err := t.setSchema(raw); err != nil {
			return nil, fmt.Errorf("outputSchema: %w", err)
		}
	}
	return t, nil
}

func (t *Task) setSchema(raw []byte) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}
	if _, err := CompileSchema(raw); err != nil {
		return err
	}
	compact, err := json.Marshal(v)
	if err != nil {
		return err
	}
	t.schema = compact
	return nil
}

// CompileSchema compiles a JSON schema so a bad task fails at load time, not
// after a paid model run.
func CompileSchema(raw []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("task.json", doc); err != nil {
		return nil, err
	}
	s, err := c.Compile("task.json")
	if err != nil {
		return nil, fmt.Errorf("schema does not compile: %w", err)
	}
	return s, nil
}

// normalize converts yaml.v3's map[string]any/[]any trees (which can contain
// map[any]any on older decoders) into JSON-marshalable values.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalize(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = normalize(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = normalize(val)
		}
		return out
	}
	return v
}

// Validate checks the task against ais's contract.
func (t *Task) Validate() error {
	if t.Version != Version {
		return fmt.Errorf("unsupported task version %d (this ais understands version %d)", t.Version, Version)
	}
	if !nameRE.MatchString(t.Name) {
		return fmt.Errorf("name %q must match %s", t.Name, nameRE)
	}
	if t.Schedule == "" {
		return errors.New("schedule is required")
	}
	if !gronx.IsValid(t.Schedule) {
		return fmt.Errorf("schedule %q is not a valid cron expression", t.Schedule)
	}
	if fields := strings.Fields(t.Schedule); !strings.HasPrefix(t.Schedule, "@") && len(fields) != 5 {
		return fmt.Errorf("schedule %q must have 5 fields (minute hour day month weekday) or be @hourly/@daily", t.Schedule)
	}
	if t.Overlap != "skip" {
		return fmt.Errorf("overlap %q is not supported (use: skip)", t.Overlap)
	}
	if t.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if t.Jitter != nil && *t.Jitter < 0 {
		return errors.New("jitter must not be negative")
	}
	if d := t.Digest; d != nil {
		if d.Schedule == "" {
			return errors.New("digest.schedule is required")
		}
		if !gronx.IsValid(d.Schedule) {
			return fmt.Errorf("digest.schedule %q is not a valid cron expression", d.Schedule)
		}
		if fields := strings.Fields(d.Schedule); !strings.HasPrefix(d.Schedule, "@") && len(fields) != 5 {
			return fmt.Errorf("digest.schedule %q must have 5 fields (minute hour day month weekday) or be @daily", d.Schedule)
		}
		if d.Window <= 0 {
			return errors.New("digest.window must be positive")
		}
	}
	if t.MaxTurns <= 0 {
		return errors.New("maxTurns must be positive")
	}
	switch t.Effort {
	case "", "low", "medium", "high", "xhigh", "max":
	default:
		return fmt.Errorf("effort %q (use: low, medium, high, xhigh, max)", t.Effort)
	}
	if t.MaxBudgetUSD <= 0 {
		return errors.New("maxBudgetUsd must be positive")
	}
	if strings.TrimSpace(t.Prompt) == "" {
		return errors.New("prompt is required")
	}
	if t.schema == nil {
		return errors.New("outputSchema or outputSchemaFile is required")
	}
	for f, m := range t.Fields {
		if _, err := pseudo.ParseMode(m); err != nil {
			return fmt.Errorf("fields.%s: %w", f, err)
		}
	}
	for _, g := range t.Expose.Prompt.GroupBy {
		if pseudo.Mode(t.Fields[g]) != pseudo.Clear {
			return fmt.Errorf("expose.prompt.groupBy field %q must be declared clear in fields", g)
		}
	}
	for _, c := range t.Expose.Prompt.Collect {
		if m := pseudo.Mode(t.Fields[c]); m != pseudo.Clear && m != pseudo.Scrub {
			return fmt.Errorf("expose.prompt.collect field %q must be declared clear or scrub in fields", c)
		}
	}
	for _, name := range t.Expose.MCP.Tools {
		if !contains(BuiltinMCPTools, name) {
			return fmt.Errorf("expose.mcp.tools: unknown tool %q (use: %s)", name, strings.Join(BuiltinMCPTools, ", "))
		}
	}
	for _, tool := range t.Tools {
		if !BuiltinTools[tool] {
			return fmt.Errorf("tools: %q is not permitted in a run container (use: WebFetch, WebSearch)", tool)
		}
	}
	for name, s := range t.MCPServers {
		if name == "inventory" {
			return errors.New("mcpServers: \"inventory\" is the built-in server and cannot be redefined")
		}
		switch s.Type {
		case "http":
			if s.URL == "" {
				return fmt.Errorf("mcpServers.%s: http server needs url", name)
			}
		case "stdio":
			return fmt.Errorf("mcpServers.%s: stdio servers are not supported (the run container has no toolchain)", name)
		default:
			return fmt.Errorf("mcpServers.%s: unknown type %q (use: http)", name, s.Type)
		}
	}
	for i, r := range t.Enrich {
		if r.Path == "" || len(r.Match) == 0 || len(r.Attach) == 0 {
			return fmt.Errorf("enrich[%d]: path, match and attach are required", i)
		}
		for rf, inv := range r.Match {
			if pseudo.Mode(t.Fields[inv]) != pseudo.Clear {
				return fmt.Errorf("enrich[%d]: match %s → %q: inventory field must be clear", i, rf, inv)
			}
		}
		for _, fields := range r.Attach {
			for _, f := range fields {
				if _, ok := t.Fields[f]; !ok {
					return fmt.Errorf("enrich[%d]: attach field %q is not in fields", i, f)
				}
			}
		}
	}
	for _, d := range t.Egress.Allow {
		if strings.ContainsAny(d, " /:") {
			return fmt.Errorf("egress.allow: %q is not a bare domain", d)
		}
	}
	if _, err := pseudo.NewRedactor(t.PII.Redact); err != nil {
		return fmt.Errorf("pii.redact: %w", err)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// LoadDir loads every *.yaml in dir, sorted by name. Sinks are checked
// against knownSinks when it is non-nil.
func LoadDir(dir string, d Defaults, knownSinks map[string]bool) ([]*Task, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tasks []*Task
	seen := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		t, err := LoadFile(filepath.Join(dir, e.Name()), d)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[t.Name]; dup {
			return nil, fmt.Errorf("%s: task name %q already defined in %s", t.Path, t.Name, prev)
		}
		seen[t.Name] = t.Path
		if knownSinks != nil {
			for _, s := range t.Sinks {
				if !knownSinks[s] {
					return nil, fmt.Errorf("%s: sinks: unknown sink %q", t.Path, s)
				}
			}
		}
		tasks = append(tasks, t)
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].Name < tasks[j].Name })
	return tasks, nil
}

// Find returns the task with the given name.
func Find(tasks []*Task, name string) (*Task, bool) {
	for _, t := range tasks {
		if t.Name == name {
			return t, true
		}
	}
	return nil, false
}

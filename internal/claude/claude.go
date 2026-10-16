// Package claude knows the headless Claude Code contract: the argv that
// makes a run non-interactive, restricted and structured, and the JSON
// envelope it prints at the end.
package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Container paths shared by the argv, the generated files and the image.
// ConfigDir and HomeDir sit one level below their tmpfs mounts
// (ConfigTmpfs, HomeTmpfs): the tmpfs root belongs to root, and the
// entrypoint, running as an arbitrary uid, must own the directories it
// chmods.
const (
	InDir       = "/run/ais/in"
	OutDir      = "/run/ais/out"
	ConfigTmpfs = "/run/ais/cfg"
	ConfigDir   = ConfigTmpfs + "/claude"
	HomeTmpfs   = "/run/ais/home"
	HomeDir     = HomeTmpfs + "/ais"
	WorkDir     = "/run/ais/work"
	BinDir      = "/run/ais/bin"
	BinPath     = BinDir + "/ais"
	PromptFile  = InDir + "/prompt.md"
	SystemFile  = InDir + "/system.md"
	MCPFile     = InDir + "/mcp.json"
	Settings    = InDir + "/settings.json"
	RedactFile  = InDir + "/redact.json"
	ArgvFile    = InDir + "/argv.json"
)

// ArgsInput is what the argv depends on.
type ArgsInput struct {
	Model        string
	Effort       string
	MaxTurns     int
	MaxBudgetUSD float64
	Tools        []string
	AllowedTools []string
	Schema       []byte
	HasMCP       bool
	HasSystem    bool
	// Stream switches to stream-json (one event per line) for a live view;
	// the final result line carries the same envelope.
	Stream bool
}

// Args renders the claude argv for one run. The prompt arrives on stdin, so
// it is not here. Every flag has a reason:
//
//	-p / --output-format json   headless, one JSON envelope on stdout
//	--json-schema               the result must validate; retried by claude
//	--tools                     which built-ins exist at all (not MCP)
//	--allowedTools              what runs without a prompt
//	--permission-mode dontAsk   anything that would prompt is denied
//	--mcp-config/--strict       only our servers, nothing discovered
//	--settings/--setting-sources only the generated settings file
//	--no-session-persistence    nothing written to the config dir survives
//	--max-turns/--max-budget-usd  hard stops on cost
//	--restricted                removes the command/code tools and ignores
//	                            local settings; refuses bypassPermissions
//	--permission-prompts none   whatever would ask is denied
func Args(in ArgsInput) []string {
	format := "json"
	if in.Stream {
		format = "stream-json"
	}
	args := []string{
		"-p",
		"--output-format", format,
		"--json-schema", string(in.Schema),
		"--model", in.Model,
		"--max-turns", fmt.Sprint(in.MaxTurns),
		"--max-budget-usd", fmt.Sprintf("%.2f", in.MaxBudgetUSD),
		"--tools", strings.Join(in.Tools, ","),
		"--allowedTools", strings.Join(in.AllowedTools, ","),
		"--permission-mode", "dontAsk",
		"--permission-prompts", "none",
		"--restricted",
		"--settings", Settings,
		"--setting-sources", "user",
		"--no-session-persistence",
	}
	if in.Effort != "" {
		args = append(args, "--effort", in.Effort)
	}
	if in.Stream {
		args = append(args, "--verbose")
	}
	if in.HasMCP {
		args = append(args, "--mcp-config", MCPFile, "--strict-mcp-config")
	}
	if in.HasSystem {
		args = append(args, "--append-system-prompt-file", SystemFile)
	}
	return args
}

// VisibleFlags are the flags the image's claude must advertise in --help;
// `ais image build` fails on drift. Unknown flags are accepted silently by
// the CLI, so help text is the only drift signal there is.
var VisibleFlags = []string{
	"--output-format", "--json-schema", "--tools", "--allowedTools", "--permission-mode",
	"--permission-prompts", "--restricted", "--settings", "--setting-sources",
	"--no-session-persistence", "--mcp-config", "--strict-mcp-config",
	"--append-system-prompt", "--max-budget-usd", "--effort",
}

// HiddenFlags are used but not listed in --help as of 2.1.301; they cannot
// be checked. --max-turns has the CLAUDE_CODE_MAX_TURNS environment fallback,
// which the run container also sets.
var HiddenFlags = []string{"--max-turns", "--append-system-prompt-file"}

// MaxTurnsEnv is the environment fallback for --max-turns.
const MaxTurnsEnv = "CLAUDE_CODE_MAX_TURNS"

// Envelope is the final `type: result` message of a headless run.
type Envelope struct {
	Type             string                `json:"type"`
	Subtype          string                `json:"subtype"`
	IsError          bool                  `json:"is_error"`
	Result           string                `json:"result"`
	SessionID        string                `json:"session_id"`
	TotalCostUSD     float64               `json:"total_cost_usd"`
	NumTurns         int                   `json:"num_turns"`
	DurationMS       int64                 `json:"duration_ms"`
	Usage            Usage                 `json:"usage"`
	ModelUsage       map[string]ModelUsage `json:"modelUsage"`
	StructuredOutput json.RawMessage       `json:"structured_output,omitempty"`
	// APIErrorStatus is the HTTP status of a terminal API error (observed:
	// 401 with subtype "success" and is_error true on 2.1.301).
	APIErrorStatus int    `json:"api_error_status,omitempty"`
	APIError       string `json:"api_error,omitempty"`
	TerminalReason string `json:"terminal_reason,omitempty"`
}

// A Usage is the top-level token usage of a result message. It counts the
// main agent only. It does not include subagent turns (modelUsage), so
// [Envelope.Tokens] uses the per-model counts when they exist.
type Usage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
}

// In returns the tokens that the model consumed as context: the input tokens
// plus the cache read tokens and the cache creation tokens.
func (u Usage) In() int64 { return u.InputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens }

// Out returns the output tokens.
func (u Usage) Out() int64 { return u.OutputTokens }

// A ModelUsage is one entry of modelUsage. It holds the token counts and the
// cost of one model. The key of the entry is the model ID.
type ModelUsage struct {
	InputTokens              int64   `json:"inputTokens"`
	OutputTokens             int64   `json:"outputTokens"`
	CacheReadInputTokens     int64   `json:"cacheReadInputTokens"`
	CacheCreationInputTokens int64   `json:"cacheCreationInputTokens"`
	CostUSD                  float64 `json:"costUSD"`
}

// Tokens returns the usage summed over all models. If modelUsage is empty,
// Tokens returns the top-level usage block. Failed runs can have an empty
// modelUsage.
func (e *Envelope) Tokens() Usage {
	if len(e.ModelUsage) == 0 {
		return e.Usage
	}
	var u Usage
	for _, m := range e.ModelUsage {
		u.InputTokens += m.InputTokens
		u.OutputTokens += m.OutputTokens
		u.CacheReadInputTokens += m.CacheReadInputTokens
		u.CacheCreationInputTokens += m.CacheCreationInputTokens
	}
	return u
}

// Models returns the models that the run used, with the highest cost first.
// Models with the same cost are in alphabetical order. If the envelope has no
// modelUsage, Models returns an empty list.
func (e *Envelope) Models() []string {
	ms := make([]string, 0, len(e.ModelUsage))
	for k := range e.ModelUsage {
		ms = append(ms, k)
	}
	sort.Slice(ms, func(i, j int) bool {
		ci, cj := e.ModelUsage[ms[i]].CostUSD, e.ModelUsage[ms[j]].CostUSD
		if ci != cj {
			return ci > cj
		}
		return ms[i] < ms[j]
	})
	return ms
}

// Known result subtypes.
const (
	SubtypeSuccess               = "success"
	SubtypeErrorMaxTurns         = "error_max_turns"
	SubtypeErrorMaxBudget        = "error_max_budget_usd"
	SubtypeErrorStructuredOutput = "error_max_structured_output_retries"
	SubtypeErrorDuringExecution  = "error_during_execution"
)

// ErrNoEnvelope means stdout held no result message.
var ErrNoEnvelope = errors.New("claude: no result envelope in output")

// ParseEnvelope finds the result envelope in stdout. With --output-format
// json the whole stdout is one object, but anything printed before it (a
// stray warning) must not break parsing, so the scan also accepts the last
// line that decodes to a result message.
func ParseEnvelope(stdout []byte) (*Envelope, error) {
	trimmed := bytes.TrimSpace(stdout)
	if len(trimmed) == 0 {
		return nil, ErrNoEnvelope
	}
	var env Envelope
	if err := json.Unmarshal(trimmed, &env); err == nil && env.Type == "result" {
		return &env, nil
	}
	lines := bytes.Split(trimmed, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		l := bytes.TrimSpace(lines[i])
		if len(l) == 0 || l[0] != '{' {
			continue
		}
		var e Envelope
		if err := json.Unmarshal(l, &e); err == nil && e.Type == "result" {
			return &e, nil
		}
	}
	return nil, ErrNoEnvelope
}

// IsAuthFailure guesses from the envelope and stderr whether the run failed
// because the token was rejected. Used to pause a task instead of alerting
// every hour.
func IsAuthFailure(env *Envelope, stderr []byte) bool {
	text := strings.ToLower(string(stderr))
	if env != nil {
		if env.APIErrorStatus == 401 || env.APIErrorStatus == 403 {
			return true
		}
		if e := strings.ToLower(env.APIError); strings.Contains(e, "credential") || strings.Contains(e, "auth") {
			return true
		}
		text += " " + strings.ToLower(env.Result)
	}
	for _, needle := range []string{"authentication_error", "invalid api key", "not logged in", "oauth token", "401", "invalid authentication", "token has expired", "please run /login"} {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

// ValidateOutput decodes structured_output and validates it against the
// compiled schema. The CLI validates too; this is the host's own check so a
// malformed result never reaches a sink.
func ValidateOutput(schema *jsonschema.Schema, raw json.RawMessage) (any, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("claude: envelope has no structured_output")
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("claude: structured_output is not JSON: %w", err)
	}
	if err := schema.Validate(doc); err != nil {
		return nil, fmt.Errorf("claude: structured_output does not match the task schema: %w", err)
	}
	return doc, nil
}

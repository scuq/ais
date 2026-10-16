package claude

import (
	"strings"
	"testing"
)

func TestParseEnvelope(t *testing.T) {
	raw := []byte("warning: something\n" + `{"type":"result","subtype":"success","is_error":false,"result":"ok","total_cost_usd":0.5,"num_turns":3,"structured_output":{"findings":[]}}` + "\n")
	env, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.Subtype != SubtypeSuccess || env.TotalCostUSD != 0.5 || string(env.StructuredOutput) != `{"findings":[]}` {
		t.Errorf("%+v", env)
	}
	if _, err := ParseEnvelope([]byte("nothing here")); err == nil {
		t.Error("expected ErrNoEnvelope")
	}
}

func TestEnvelopeTokensAndModels(t *testing.T) {
	// Numbers from a real run: the top-level usage block counts the main
	// agent only, modelUsage also has the haiku subagents.
	raw := []byte(`{"type":"result","subtype":"success","total_cost_usd":0.3472,"num_turns":14,
	"usage":{"input_tokens":12,"cache_creation_input_tokens":16542,"cache_read_input_tokens":55694,"output_tokens":4733,"service_tier":"standard"},
	"modelUsage":{
	 "claude-haiku-5-5":{"inputTokens":108849,"outputTokens":14950,"cacheReadInputTokens":0,"cacheCreationInputTokens":0,"costUSD":0.0183599,"contextWindow":1000000},
	 "claude-opus-5-5":{"inputTokens":13862,"outputTokens":5996,"cacheReadInputTokens":55694,"cacheCreationInputTokens":16542,"costUSD":0.3288428,"contextWindow":1000000}}}`)
	env, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	u := env.Tokens()
	if u.InputTokens != 108849+13862 || u.OutputTokens != 14950+5996 || u.CacheReadInputTokens != 55694 || u.CacheCreationInputTokens != 16542 {
		t.Errorf("tokens %+v", u)
	}
	if u.In() != 108849+13862+55694+16542 || u.Out() != 14950+5996 {
		t.Errorf("in %d out %d", u.In(), u.Out())
	}
	if got := env.Models(); len(got) != 2 || got[0] != "claude-opus-5-5" || got[1] != "claude-haiku-5-5" {
		t.Errorf("models %v", got)
	}

	// Without modelUsage (failed runs) the top-level block is used.
	env, err = ParseEnvelope([]byte(`{"type":"result","subtype":"success","usage":{"input_tokens":12,"output_tokens":4,"cache_read_input_tokens":100},"modelUsage":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if u := env.Tokens(); u.In() != 112 || u.Out() != 4 {
		t.Errorf("fallback tokens %+v", u)
	}
	if ms := env.Models(); len(ms) != 0 {
		t.Errorf("models %v", ms)
	}
}

func TestArgsFlagsAreRequired(t *testing.T) {
	args := Args(ArgsInput{Model: "m", Effort: "high", MaxTurns: 1, MaxBudgetUSD: 1, Tools: []string{"WebFetch"}, AllowedTools: []string{"WebFetch"}, Schema: []byte("{}"), HasMCP: true, HasSystem: true})
	joined := strings.Join(args, " ")
	for _, f := range append(append([]string(nil), VisibleFlags...), HiddenFlags...) {
		if !strings.Contains(joined, f) {
			t.Errorf("flag %s is listed but Args does not use it", f)
		}
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--") && !strings.Contains(strings.Join(append(VisibleFlags, HiddenFlags...), " "), a) && a != "--model" {
			t.Errorf("flag %s is used by Args but not listed for the drift check", a)
		}
	}
	if strings.Contains(joined, "--bare") || strings.Contains(joined, "bypassPermissions") {
		t.Error("forbidden flags present")
	}
}

func TestIsAuthFailure(t *testing.T) {
	if !IsAuthFailure(nil, []byte("Error: authentication_error: OAuth token has expired")) {
		t.Error("expected auth failure")
	}
	if IsAuthFailure(&Envelope{Result: "all good"}, nil) {
		t.Error("false positive")
	}
}

func TestRenderStreamLine(t *testing.T) {
	cases := map[string]string{
		`{"type":"system","subtype":"init","model":"claude-opus-5-5","tools":["WebFetch"],"mcp_servers":[{"name":"inventory","status":"connected"}]}`:                                                  "▶ session started · model claude-opus-5-5 · tools WebFetch · mcp inventory:connected",
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Checking CISA KEV."},{"type":"tool_use","name":"WebFetch","input":{"url":"https://www.cisa.gov/kev"}}]}}`: "💬 Checking CISA KEV.\n🔧 WebFetch {\"url\":\"https://www.cisa.gov/kev\"}",
		`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"page text here","is_error":false}]}}`:                                                                     "↩ page text here",
		`{"type":"result","subtype":"success","num_turns":5,"total_cost_usd":0.4,"is_error":false}`:                                                                                                    "■ result success · 5 turns · est. $0.40",
	}
	for line, want := range cases {
		got, ok := RenderStreamLine([]byte(line))
		if !ok || got != want {
			t.Errorf("line %s\n got: %q\nwant: %q", line, got, want)
		}
	}
	if _, ok := RenderStreamLine([]byte(`{"type":"rate_limit_event"}`)); ok {
		t.Error("noise rendered")
	}
	args := Args(ArgsInput{Model: "m", MaxTurns: 1, MaxBudgetUSD: 1, Schema: []byte("{}"), Stream: true})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--output-format stream-json") || !strings.Contains(joined, "--verbose") {
		t.Errorf("stream args: %s", joined)
	}
}

package task

import (
	"strings"
	"testing"
	"time"

	"github.com/scuq/ais/assets"
)

var defs = Defaults{Model: "claude-sonnet-5-5", MaxTurns: 10, MaxBudgetUSD: 1, Timeout: 10 * time.Minute}

func TestExampleTaskParses(t *testing.T) {
	raw := assets.Read("templates/vuln-watch/task.yaml")
	tk, err := Parse(raw, defs)
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.Validate(); err != nil {
		t.Fatal(err)
	}
	if tk.Model != "claude-opus-5-5" || tk.MaxTurns != 40 {
		t.Errorf("task values not applied: %+v", tk)
	}
	if !strings.HasPrefix(string(tk.SchemaJSON()), `{"additionalProperties":false`) {
		t.Errorf("schema not compact JSON: %s", tk.SchemaJSON())
	}
	if len(tk.Hash) != 16 {
		t.Errorf("hash: %s", tk.Hash)
	}
}

const minimal = `
version: 1
name: t
schedule: "@hourly"
prompt: hi
fields: {product: clear, hostname: pseudonym}
outputSchema: {type: object}
`

func mustParse(t *testing.T, doc string) *Task {
	t.Helper()
	tk, err := Parse([]byte(doc), defs)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func TestDefaultsApplied(t *testing.T) {
	tk := mustParse(t, minimal)
	if err := tk.Validate(); err != nil {
		t.Fatal(err)
	}
	if tk.Model != defs.Model || tk.MaxTurns != 10 || tk.Timeout != 10*time.Minute || tk.Overlap != "skip" {
		t.Errorf("defaults missing: %+v", tk)
	}
	if strings.Join(tk.AllowedTools, ",") != "WebFetch,WebSearch,mcp__inventory__*" {
		t.Errorf("allowedTools default: %v", tk.AllowedTools)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"bad cron":        strings.Replace(minimal, `"@hourly"`, `"99 * * * *"`, 1),
		"six fields":      strings.Replace(minimal, `"@hourly"`, `"0 0 * * * *"`, 1),
		"bad mode":        strings.Replace(minimal, "hostname: pseudonym", "hostname: hidden", 1),
		"bash tool":       minimal + "tools: [Bash]\n",
		"groupBy pseudo":  minimal + "expose: {prompt: {groupBy: [hostname]}}\n",
		"stdio mcp":       minimal + "mcpServers: {x: {type: stdio, command: foo}}\n",
		"inventory redef": minimal + "mcpServers: {inventory: {type: http, url: http://x}}\n",
		"bad schema":      strings.Replace(minimal, "{type: object}", "{type: nonsense}", 1),
		"unknown key":     minimal + "bogus: 1\n",
		"bad name":        strings.Replace(minimal, "name: t", "name: Bad_Name", 1),
	}
	for name, doc := range cases {
		tk, err := Parse([]byte(doc), defs)
		if err == nil {
			err = tk.Validate()
		}
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

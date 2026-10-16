package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/output"
)

func TestHookRedact(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "redact.json")
	_ = os.WriteFile(rules, []byte(`{"domains":[".corp.example"],"cidrs":["10.0.0.0/8"],"literals":["Falcon"]}`), 0o600)
	in := `{"tool_name":"WebFetch","tool_input":{"url":"x"},"tool_response":{"result":"fw01.corp.example 10.1.2.3 Falcon 8.8.8.8","bytes":12}}`
	var out bytes.Buffer
	if err := hookRedact(rules, strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var doc map[string]map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	upd := doc["hookSpecificOutput"]["updatedToolOutput"].(map[string]any)
	if upd["result"] != "[redacted] [redacted] [redacted] 8.8.8.8" || upd["bytes"].(float64) != 12 {
		t.Errorf("got %v", upd)
	}
	if doc["hookSpecificOutput"]["hookEventName"] != "PostToolUse" {
		t.Error("event name")
	}
}

func TestHookNoResponseIsSilent(t *testing.T) {
	var out bytes.Buffer
	if err := hookRedact("", strings.NewReader(`{"tool_name":"WebFetch"}`), &out); err != nil || out.Len() != 0 {
		t.Errorf("err=%v out=%q", err, out.String())
	}
}

func TestTasksSetRewritesKeys(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Paths.TasksDir = dir
	_ = os.WriteFile(filepath.Join(dir, "t.yaml"), []byte("version: 1\nname: t\n# keep me\nschedule: \"@hourly\"\nprompt: p\noutputSchema: {type: object}\nsinks: []\n"), 0o600)
	p := output.NewStderr()
	if err := cmdTasksSet(p, &cfg, []string{"t", "model=claude-sonnet-5-5", "effort=max", "sinks=webex, splunk", "maxBudgetUsd=1.5", "schedule=7 * * * *"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "t.yaml"))
	s := string(data)
	for _, want := range []string{"# keep me", "model: claude-sonnet-5-5", "effort: max", "sinks: [webex, splunk]", "maxBudgetUsd: 1.5", `schedule: "7 * * * *"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if err := cmdTasksSet(p, &cfg, []string{"t", "effort=turbo"}); err == nil {
		t.Error("invalid effort accepted")
	}
	if err := cmdTasksSet(p, &cfg, []string{"t", "prompt=x"}); err == nil {
		t.Error("non-settable key accepted")
	}
}

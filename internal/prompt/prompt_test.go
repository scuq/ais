package prompt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/scuq/ais/assets"
	"github.com/scuq/ais/internal/inventory"
	"github.com/scuq/ais/internal/pseudo"
	"github.com/scuq/ais/internal/task"
)

func TestGenerate(t *testing.T) {
	tk, err := task.Parse(assets.Read("templates/vuln-watch/task.yaml"), task.Defaults{Model: "m", MaxTurns: 1, MaxBudgetUSD: 1, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	d := Data{
		Task:   tk,
		Run:    RunMeta{ID: "r1", Task: tk.Name, StartedAt: time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)},
		Now:    time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC),
		Groups: []inventory.Group{{Fields: map[string]string{"vendor": "V", "product": "P", "version": "1"}, Count: 2}},
		Text:   []string{"Keycloak 26.1"},
	}
	files, err := Generate(tk, d, Env{BackendURL: "http://10.199.0.4:8080/mcp", RedactRules: pseudo.Rules{Domains: []string{".x"}}, HookEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	p := string(files[PromptFile])
	if !strings.Contains(p, "2026-10-13") || !strings.Contains(p, "- V P 1 (2 installs)") || !strings.Contains(p, "- Keycloak 26.1") {
		t.Errorf("prompt: %s", p)
	}
	if !strings.Contains(string(files[SystemFile]), "free-text product list") || !strings.Contains(string(files[InventoryFile]), `"Keycloak 26.1"`) {
		t.Errorf("text inventory missing from system or view: %s", files[SystemFile])
	}
	d2 := d
	d2.Text = nil
	noText, _ := Generate(tk, d2, Env{})
	if strings.Contains(string(noText[PromptFile]), "Free-text") || strings.Contains(string(noText[SystemFile]), "free-text") {
		t.Error("text section rendered without text lines")
	}
	var mcp MCPConfig
	if err := json.Unmarshal(files[MCPFile], &mcp); err != nil {
		t.Fatal(err)
	}
	if mcp.Servers["inventory"].Headers["Authorization"] != "Bearer ${AIS_RUN_TOKEN}" {
		t.Errorf("mcp: %+v", mcp)
	}
	var argv []string
	if err := json.Unmarshal(files[ArgvFile], &argv); err != nil {
		t.Fatal(err)
	}
	if argv[0] != "-p" || !strings.Contains(strings.Join(argv, " "), "--strict-mcp-config") {
		t.Errorf("argv: %v", argv)
	}
	if !strings.Contains(string(files[SettingsFile]), "hook redact") || !strings.Contains(string(files[SettingsFile]), `"Bash"`) {
		t.Errorf("settings: %s", files[SettingsFile])
	}
	if !strings.Contains(string(files[SystemFile]), "opaque pseudonyms") || !strings.Contains(string(files[SystemFile]), "This run is isolated") {
		t.Errorf("system: %s", files[SystemFile])
	}
	// Without a backend the isolation notice is still there.
	files2, _ := Generate(tk, d, Env{})
	if !strings.Contains(string(files2[SystemFile]), "This run is isolated") {
		t.Error("isolation notice missing without backend")
	}
	// Open egress: no host list. Proxy egress: the reachable hosts are listed.
	if strings.Contains(string(files2[SystemFile]), "allowlist proxy") {
		t.Error("egress notice rendered for open egress")
	}
	files3, _ := Generate(tk, d, Env{EgressRestricted: true, EgressAllow: []string{".cert.at", "msrc.microsoft.com"}})
	sys3 := string(files3[SystemFile])
	if !strings.Contains(sys3, "allowlist proxy") || !strings.Contains(sys3, "\n- .cert.at\n- msrc.microsoft.com\n") || !strings.Contains(sys3, "WebSearch") {
		t.Errorf("egress notice: %s", sys3)
	}
	files4, _ := Generate(tk, d, Env{EgressRestricted: true})
	if !strings.Contains(string(files4[SystemFile]), "(none)") {
		t.Error("empty allowlist should say (none)")
	}
}

func TestMissingKeyIsError(t *testing.T) {
	if _, err := RenderPrompt("{{ .Nope }}", Data{}); err == nil {
		t.Error("expected error for unknown field")
	}
}

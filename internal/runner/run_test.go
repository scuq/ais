package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scuq/ais/assets"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/secret"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

func fixture(t *testing.T) (*Runner, *runtime.Fake, *task.Task) {
	t.Helper()
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.mdj")
	_ = os.WriteFile(inv, assets.Read("examples/inventory.mdj"), 0o600)
	cfg := config.Defaults()
	cfg.Paths.StateDir = dir
	cfg.Inventory.File = inv
	cfg.Egress.Mode = "open"
	cfg.PII.ApprovedHash = cfg.Redaction().ApprovalHash()
	txt := filepath.Join(dir, "inventory.txt")
	_ = os.WriteFile(txt, []byte("# watch list\nKeycloak 26.1\nGlobalProtect portal on vpn01.cyberdyne.systems (10.1.0.5)\n"), 0o600)
	cfg.Inventory.TextFile = txt
	doc := strings.Replace(string(assets.Read("templates/vuln-watch/task.yaml")), "~/.config/ais/inventory.mdj", inv, 1)
	doc = strings.Replace(doc, "sinks: []", "sinks: [splunk]", 1)
	tk, err := task.Parse([]byte(doc), task.Defaults{Model: "m", MaxTurns: 1, MaxBudgetUSD: 1, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.Validate(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fake := runtime.NewFakeDocker()
	r := &Runner{Cfg: &cfg, RT: fake, Store: st, Secrets: secret.Memory{"claude-oauth-token": "tok"}, Opts: Options{Engine: "docker", UID: 1001, GID: 1001}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return r, fake, tk
}

const okEnvelope = `{"type":"result","subtype":"success","is_error":false,"result":"done","total_cost_usd":0.42,"num_turns":5,"duration_ms":1234,"usage":{"input_tokens":12,"output_tokens":40,"cache_read_input_tokens":500,"cache_creation_input_tokens":100},"modelUsage":{"claude-haiku-5-5":{"inputTokens":1000,"outputTokens":200,"costUSD":0.02},"claude-opus-5-5":{"inputTokens":100,"outputTokens":60,"cacheReadInputTokens":500,"cacheCreationInputTokens":100,"costUSD":0.40}},"structured_output":{"checked":[{"url":"https://example","product":"PAN-OS","verdict":"reported"}],"findings":[{"vendor":"Palo Alto Networks","product":"PAN-OS","affected_version_range":"<11.1.5","installed_version":"11.1.4","fixed_version":"11.1.5","cve_ids":["CVE-2026-1234"],"severity":"critical","source_urls":["https://example"],"summary":"bad","confidence":0.9,"title":"Auth bypass","cvss":9.8,"exploited":true,"affected":"all","action":"upgrade","published":"2026-10-07","previously_reported":false}]}}`

func TestRunSucceedsAndEnriches(t *testing.T) {
	r, fake, tk := fixture(t)
	fake.Stdout = okEnvelope
	out, err := r.Run(context.Background(), tk, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if out.Run.State != store.StateSucceeded || out.Run.CostUSD != 0.42 || out.Run.NumTurns != 5 {
		t.Fatalf("%+v", out.Run)
	}
	// Usage is summed over modelUsage, and the model that cost most replaces
	// the configured name.
	if out.Run.Model != "claude-opus-5-5" || out.Run.Models != "claude-opus-5-5,claude-haiku-5-5" ||
		out.Run.InputTokens != 1100 || out.Run.OutputTokens != 260 || out.Run.CacheReadTokens != 500 || out.Run.CacheCreationTokens != 100 {
		t.Errorf("usage: %+v", out.Run)
	}
	stored, err := r.Store.GetRun(context.Background(), out.Run.ID)
	if err != nil || stored.InputTokens != 1100 || stored.Models != out.Run.Models {
		t.Errorf("stored usage: %+v err %v", stored, err)
	}
	clear := out.Clear.(map[string]any)
	f := clear["findings"].([]any)[0].(map[string]any)
	devices := f["devices"].([]any)
	if len(devices) != 2 {
		t.Fatalf("expected 2 PAN-OS devices attached, got %v", devices)
	}
	if devices[0].(map[string]any)["hostname"] != "fw01.cyberdyne.systems" {
		t.Errorf("enrich: %v", devices[0])
	}
	// The engine saw the token in env, never in argv.
	if !strings.Contains(strings.Join(fake.LastEnv, " "), "CLAUDE_CODE_OAUTH_TOKEN=tok") {
		t.Error("token not passed via env")
	}
	if strings.Contains(fake.Calls[0], "tok") {
		t.Error("token leaked into argv")
	}
	if _, err := os.Stat(filepath.Join(out.Dir, "result.clear.json")); err != nil {
		t.Error("clear result file missing")
	}
	dels, _ := r.Store.DeliveriesOf(context.Background(), out.Run.ID)
	if len(dels) != 1 || dels[0].Sink != "splunk" {
		t.Errorf("deliveries: %+v", dels)
	}
	if _, err := os.Stat(filepath.Join(r.Cfg.RunsDir(), tk.Name, "runs.ndjson")); err != nil {
		t.Error("ndjson missing")
	}
	pl, err := r.Store.GetPrompt(context.Background(), out.Run.ID)
	if err != nil || !strings.Contains(pl.Prompt, "PAN-OS") || !strings.Contains(pl.System, "This run is isolated") || len(pl.SHA256) != 64 {
		t.Errorf("prompt log: %+v %v", pl, err)
	}
	if strings.Contains(pl.Prompt, "cyberdyne") || strings.Contains(pl.Prompt, "10.1.0.1") {
		t.Errorf("real values in the logged prompt: %s", pl.Prompt)
	}
	if !strings.Contains(pl.Prompt, "usage:") || !strings.Contains(pl.Prompt, "Authentication with SAML") ||
		!strings.Contains(pl.Prompt, "interest: Only critical and high findings with an unauthenticated remote attack vector") {
		t.Errorf("mdj sections not collected into the prompt: %s", pl.Prompt)
	}
	if !strings.Contains(pl.Prompt, "- Palo Alto Networks GlobalProtect (no version given) (1 entries)") {
		t.Errorf("product without a version not in the prompt: %s", pl.Prompt)
	}
	ndjson, _ := os.ReadFile(filepath.Join(r.Cfg.RunsDir(), tk.Name, "prompts.ndjson"))
	if !strings.Contains(string(ndjson), pl.SHA256) {
		t.Error("prompts.ndjson missing the entry")
	}
}

func TestRunLeakBlocksDispatch(t *testing.T) {
	r, fake, tk := fixture(t)
	fake.Stdout = strings.Replace(okEnvelope, `"summary":"bad"`, `"summary":"fw01.cyberdyne.systems is bad"`, 1)
	out, err := r.Run(context.Background(), tk, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if out.Run.State != store.StateLeaked || len(out.Leaks) == 0 {
		t.Fatalf("%+v", out.Run)
	}
	if out.Clear != nil {
		t.Error("clear result produced for a leaked run")
	}
	if _, err := os.Stat(filepath.Join(out.Dir, "result.clear.json")); err == nil {
		t.Error("clear file written for a leaked run")
	}
	if dels, _ := r.Store.DeliveriesOf(context.Background(), out.Run.ID); len(dels) != 0 {
		t.Error("leaked run was queued for delivery")
	}
}

func TestRunClassifiesFailures(t *testing.T) {
	cases := []struct {
		name, stdout, stderr string
		code                 int
		state, reason        string
	}{
		{"budget", `{"type":"result","subtype":"error_max_budget_usd","is_error":true,"result":"over"}`, "", 1, store.StateFailed, ReasonBudget},
		{"schema", `{"type":"result","subtype":"success","is_error":false,"result":"x","structured_output":{"nope":1}}`, "", 0, store.StateFailed, ReasonSchema},
		{"auth", "", "Error: authentication_error: OAuth token has expired", 1, store.StateFailed, ReasonAuth},
		{"credheader", `{"type":"result","subtype":"success","is_error":true,"api_error":"invalid_credential_header","result":"Invalid auth token"}`, "", 0, store.StateFailed, ReasonAuth},
		{"config", "", "[entrypoint] CLAUDE_CODE_OAUTH_TOKEN is not set", 78, store.StateFailed, ReasonConfig},
		{"noenvelope", "garbage", "boom", 2, store.StateFailed, ReasonExit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, fake, tk := fixture(t)
			fake.Stdout, fake.Stderr, fake.ExitCode = c.stdout, c.stderr, c.code
			out, err := r.Run(context.Background(), tk, "manual")
			if err != nil {
				t.Fatal(err)
			}
			if out.Run.State != c.state || out.Run.Reason != c.reason {
				t.Errorf("got %s/%s want %s/%s (%s)", out.Run.State, out.Run.Reason, c.state, c.reason, out.Run.Error)
			}
		})
	}
}

func TestRunSkipsOnOverlap(t *testing.T) {
	r, fake, tk := fixture(t)
	fake.Stdout = okEnvelope
	_ = r.Store.InsertRun(context.Background(), store.Run{ID: "busy", Task: tk.Name, State: store.StateRunning, StartedAt: time.Now()})
	out, err := r.Run(context.Background(), tk, "schedule")
	if err != nil {
		t.Fatal(err)
	}
	if out.Run.State != store.StateSkipped || out.Run.Reason != ReasonOverlap {
		t.Errorf("%+v", out.Run)
	}
	if len(fake.CallsMatching("run")) != 0 {
		t.Error("container started despite overlap")
	}
}

func TestRunTimeoutStopsContainer(t *testing.T) {
	r, fake, tk := fixture(t)
	fake.BlockUntilCancel = true
	tk.Timeout = 50 * time.Millisecond
	out, err := r.Run(context.Background(), tk, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if out.Run.State != store.StateTimeout || out.Run.Reason != ReasonTimeout {
		t.Fatalf("%+v", out.Run)
	}
	calls := strings.Join(fake.Calls, "\n")
	if !strings.Contains(calls, "stop ais-run-vuln-watch-") || !strings.Contains(calls, "remove ais-run-vuln-watch-") {
		t.Errorf("container not stopped and removed: %s", calls)
	}
}

func TestRunCancelled(t *testing.T) {
	r, fake, tk := fixture(t)
	fake.BlockUntilCancel = true
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	out, err := r.Run(ctx, tk, "schedule")
	if err != nil {
		t.Fatal(err)
	}
	if out.Run.State != store.StateCancelled {
		t.Errorf("%+v", out.Run)
	}
}

func TestPrepareUsesRot13AndCGNAT(t *testing.T) {
	r, _, tk := fixture(t)
	prep, err := Prepare(context.Background(), r.Cfg, tk, r.Store, r.Opts)
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Records []struct {
			Fields map[string]string `json:"fields"`
		} `json:"records"`
	}
	if err := json.Unmarshal(prep.Files["inventory.pseudo.json"], &inv); err != nil {
		t.Fatal(err)
	}
	var sawHost, sawIP bool
	for _, rec := range inv.Records {
		if h := rec.Fields["hostname"]; h == "sj01.ploreqlar.flfgrzf" {
			sawHost = true
		}
		if ip := rec.Fields["ip"]; strings.HasPrefix(ip, "100.") {
			sawIP = true
		}
		if strings.Contains(rec.Fields["hostname"], "cyberdyne") || strings.HasPrefix(rec.Fields["ip"], "10.") || strings.HasPrefix(rec.Fields["ip"], "192.168.") {
			t.Errorf("real value leaked into the view: %v", rec.Fields)
		}
	}
	if !sawHost || !sawIP {
		t.Errorf("expected rot13 hostnames and cgnat ips, got %+v", inv.Records)
	}
	// Free-text lines are scrubbed like a comment field and reach the prompt.
	var view struct {
		Text []string `json:"text"`
	}
	_ = json.Unmarshal(prep.Files["inventory.pseudo.json"], &view)
	if len(view.Text) != 2 || view.Text[0] != "Keycloak 26.1" {
		t.Errorf("text view: %v", view.Text)
	}
	if strings.Contains(view.Text[1], "cyberdyne") || strings.Contains(view.Text[1], "10.1.0.5") {
		t.Errorf("real value leaked through the text inventory: %q", view.Text[1])
	}
	if !strings.Contains(view.Text[1], "ica01.ploreqlar.flfgrzf") || !strings.Contains(view.Text[1], "(100.") {
		t.Errorf("text line not scrubbed with the task salt: %q", view.Text[1])
	}
	promptMD := string(prep.Files["prompt.md"])
	if !strings.Contains(promptMD, "- Keycloak 26.1") || !strings.Contains(promptMD, "Free-text product list") {
		t.Errorf("prompt lacks the text inventory:\n%s", promptMD)
	}
	if !strings.Contains(string(prep.Files["system.md"]), "free-text product list") {
		t.Error("system prompt lacks the free-text notice")
	}
	if prep.Map.Tokens["sj01.ploreqlar.ploreqlar"] != "" && prep.Map.Tokens["sj01.ploreqlar.flfgrzf"] != "fw01.cyberdyne.systems" {
		t.Errorf("map does not resolve the rot13 token: %v", prep.Map.Tokens)
	}
	var rules map[string]any
	_ = json.Unmarshal(prep.Files["redact.json"], &rules)
	if rules["ipMode"] != "cgnat" || rules["hostnameMode"] != "rot13" || len(rules["key"].(string)) != 64 {
		t.Errorf("redact rules: %v", rules)
	}
}

func TestRunRefusesBrokenToken(t *testing.T) {
	r, fake, tk := fixture(t)
	r.Secrets = secret.Memory{"claude-oauth-token": "sk-ant\nbroken"}
	out, err := r.Run(context.Background(), tk, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if out.Run.State != store.StateSkipped || out.Run.Reason != ReasonConfig || len(fake.CallsMatching("run")) != 0 {
		t.Errorf("%+v calls=%v", out.Run, fake.Calls)
	}
}

func TestLiveRunRendersStream(t *testing.T) {
	r, fake, tk := fixture(t)
	var live bytes.Buffer
	r.Opts.Live = &live
	fake.Stdout = `{"type":"system","subtype":"init","model":"m","tools":["WebFetch"]}` + "\n" +
		`{"type":"assistant","message":{"content":[{"type":"text","text":"Looking."}]}}` + "\n" + okEnvelope + "\n"
	out, err := r.Run(context.Background(), tk, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if out.Run.State != store.StateSucceeded {
		t.Fatalf("%+v", out.Run)
	}
	s := live.String()
	for _, want := range []string{"▶ run", "▶ session started", "💬 Looking.", "■ result success"} {
		if !strings.Contains(s, want) {
			t.Errorf("live output missing %q:\n%s", want, s)
		}
	}
	argv, _ := os.ReadFile(filepath.Join(out.Dir, "in", "argv.json"))
	if !strings.Contains(string(argv), "stream-json") || !strings.Contains(string(argv), "--verbose") {
		t.Errorf("stream-json not requested: %s", argv)
	}
}

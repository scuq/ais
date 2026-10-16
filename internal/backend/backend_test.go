package backend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/inventory"
	"github.com/scuq/ais/internal/prompt"
	"github.com/scuq/ais/internal/scheduler"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

func fixture(t *testing.T) (*Backend, *task.Task, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Paths.StateDir = dir
	st, err := store.Open(filepath.Join(dir, "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tk, err := task.Parse([]byte(`
version: 1
name: vw
schedule: "@hourly"
prompt: p
fields: {hostname: pseudonym, product: clear, version: clear}
expose: {prompt: {groupBy: [product, version]}, mcp: {tools: [inventory_products, results_recent]}}
outputSchema: {type: object}
`), task.Defaults{Model: "m", MaxTurns: 1, MaxBudgetUSD: 1, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := task.Parse([]byte("version: 1\nname: other\nschedule: '@hourly'\nprompt: p\noutputSchema: {type: object}\n"), task.Defaults{Model: "m", MaxTurns: 1, MaxBudgetUSD: 1, Timeout: time.Minute})
	ctx := context.Background()
	now := time.Now()
	_ = st.InsertRun(ctx, store.Run{ID: "r1", Task: "vw", State: store.StateRunning, StartedAt: now})
	inDir := filepath.Join(cfg.RunsDir(), "vw", "r1", "in")
	_ = os.MkdirAll(inDir, 0o700)
	view := View{Records: []inventory.Record{
		{Fields: map[string]string{"hostname": "host-aaaaaaaa", "product": "PAN-OS", "version": "11.1.4"}},
		{Fields: map[string]string{"hostname": "host-bbbbbbbb", "product": "PAN-OS", "version": "11.1.4"}},
		{Fields: map[string]string{"hostname": "host-cccccccc", "product": "FortiOS", "version": "7.4.5"}},
	}, Text: []string{"Keycloak 26.1", "PAN-OS lab unit"}}
	vb, _ := json.Marshal(view)
	_ = os.WriteFile(filepath.Join(inDir, prompt.InventoryFile), vb, 0o600)
	_ = st.InsertRun(ctx, store.Run{ID: "r0", Task: "vw", State: store.StateRunning, StartedAt: now.Add(-time.Hour)})
	_ = st.FinishRun(ctx, store.Run{ID: "r0", State: store.StateSucceeded, FinishedAt: now.Add(-time.Hour)})
	_ = st.SaveResult(ctx, "r0", "vw", now.Add(-time.Hour), []byte(`{"findings":[{"product":"PAN-OS"}]}`), []byte(`{"findings":[]}`))

	b := &Backend{Cfg: &cfg, Store: st, Tasks: func() []*task.Task { return []*task.Task{tk, other} }, Version: "test"}
	tok, err := Minter{Store: st}.MintRunToken(ctx, "vw", "r1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return b, tk, tok
}

func TestRunHandlerAuth(t *testing.T) {
	b, _, tok := fixture(t)
	srv := httptest.NewServer(b.RunHandler())
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/healthz")
	if resp.StatusCode != 200 {
		t.Errorf("healthz %d", resp.StatusCode)
	}
	post := func(auth string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(""); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code := post("Bearer nope"); code != 401 {
		t.Errorf("bad token: %d", code)
	}
	_ = b.Store.RevokeRunTokens(context.Background(), "r1")
	if code := post("Bearer " + tok); code != 401 {
		t.Errorf("revoked token: %d", code)
	}
}

func TestMCPToolsScoped(t *testing.T) {
	b, _, tok := fixture(t)
	srv := httptest.NewServer(b.RunHandler())
	defer srv.Close()
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   srv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{tok}},
		MaxRetries: -1,
	}
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "inventory_products,results_recent" {
		t.Errorf("tools %v (inventory_list must be absent for this task)", names)
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "inventory_products", Arguments: map[string]any{"filter": "pan"}})
	if err != nil || res.IsError {
		t.Fatalf("call: %v %+v", err, res)
	}
	out, _ := json.Marshal(res.StructuredContent)
	if !strings.Contains(string(out), `"PAN-OS"`) || strings.Contains(string(out), "FortiOS") || !strings.Contains(string(out), `"count":2`) || strings.Contains(string(out), "host-") {
		t.Errorf("products: %s", out)
	}
	if !strings.Contains(string(out), `"text":["PAN-OS lab unit"]`) {
		t.Errorf("products must filter the free-text lines too: %s", out)
	}
	res, err = sess.CallTool(ctx, &mcp.CallToolParams{Name: "results_recent", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("recent: %v %+v", err, res)
	}
	out, _ = json.Marshal(res.StructuredContent)
	if !strings.Contains(string(out), `"run_id":"r0"`) || !strings.Contains(string(out), "PAN-OS") || strings.Contains(string(out), `"findings":[]`) {
		t.Errorf("recent must return the pseudonymized view only: %s", out)
	}
}

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func TestOperatorAPI(t *testing.T) {
	b, _, _ := fixture(t)
	srv := httptest.NewServer(b.OperatorHandler())
	defer srv.Close()
	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(body))
	}
	if code, body := get("/api/v1/tasks"); code != 200 || !strings.Contains(body, `"vw"`) {
		t.Errorf("tasks %d %s", code, body)
	}
	if code, body := get("/api/v1/runs?task=vw"); code != 200 || !strings.Contains(body, `"r1"`) {
		t.Errorf("runs %d %s", code, body)
	}
	if code, body := get("/api/v1/runs/r0/result?view=clear"); code != 200 || body != `{"findings":[]}` {
		t.Errorf("clear result %d %s", code, body)
	}
	if code, body := get("/api/v1/runs/r0/result"); code != 200 || !strings.Contains(body, "PAN-OS") {
		t.Errorf("pseudo result %d %s", code, body)
	}
	if code, _ := get("/api/v1/runs/nope"); code != 404 {
		t.Errorf("missing run %d", code)
	}
	if code, body := get("/api/v1/inventory?task=vw"); code != 200 || !strings.Contains(body, "host-aaaaaaaa") {
		t.Errorf("inventory %d %s", code, body)
	}
}

func TestProxyHandler(t *testing.T) {
	b, _, _ := fixture(t)
	sock := filepath.Join(t.TempDir(), "mcp.sock")
	l, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, l, b.RunHandler()) }()
	front := httptest.NewServer(ProxyHandler(sock))
	defer front.Close()
	resp, err := http.Get(front.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("via proxy: %v %v", err, resp)
	}
	resp, _ = http.Post(front.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != 401 {
		t.Errorf("proxy must not add authority: %d", resp.StatusCode)
	}
}

func TestTasksAPIReportsNext(t *testing.T) {
	b, _, _ := fixture(t)
	at := time.Date(2026, 10, 16, 12, 7, 44, 0, time.UTC)
	b.Next = func() []scheduler.Upcoming {
		return []scheduler.Upcoming{{Task: "vw", At: at}, {Task: "other", At: at, Paused: "auth"}}
	}
	srv := httptest.NewServer(b.OperatorHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/tasks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rows []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&rows)
	if len(rows) != 2 || !strings.HasPrefix(rows[0]["next"].(string), "2026-10-16T12:07:44") || rows[1]["paused"] != "auth" {
		t.Errorf("rows %v", rows)
	}
}

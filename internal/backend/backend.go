// Package backend is the host-side service that run containers and
// operators talk to. Operators get an HTTP API over a private unix socket.
// Run containers get an MCP server, reachable only through the sidecar on
// the internal network and only with the bearer token minted for their run,
// which scopes every call to that run's task and its pseudonymized view.
package backend

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/inventory"
	"github.com/scuq/ais/internal/prompt"
	"github.com/scuq/ais/internal/scheduler"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

// Minter issues run tokens into the store. It implements
// runner.TokenMinter and is usable without a running backend, because the
// backend validates tokens from the same database.
type Minter struct{ Store *store.Store }

// HashToken returns the stored form of a token.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// MintRunToken creates a token valid for ttl.
func (m Minter) MintRunToken(ctx context.Context, taskName, runID string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	err := m.Store.InsertRunToken(ctx, HashToken(tok), store.RunToken{RunID: runID, Task: taskName, ExpiresAt: time.Now().Add(ttl)})
	return tok, err
}

// Scope is who is calling.
type Scope struct {
	Operator bool
	Task     string
	RunID    string
}

type scopeKey struct{}

// ScopeFrom returns the request scope.
func ScopeFrom(ctx context.Context) Scope {
	s, _ := ctx.Value(scopeKey{}).(Scope)
	return s
}

// Backend serves both surfaces.
type Backend struct {
	Cfg   *config.Config
	Store *store.Store
	// Tasks returns the current task set (the daemon reloads it on SIGHUP).
	Tasks func() []*task.Task
	// Next returns the scheduler's upcoming fire times; nil outside the daemon.
	Next    func() []scheduler.Upcoming
	Log     *slog.Logger
	Version string
	Now     func() time.Time

	mu      sync.Mutex
	servers map[string]*mcp.Server
}

func (b *Backend) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Backend) log() *slog.Logger {
	if b.Log != nil {
		return b.Log
	}
	return slog.Default()
}

func (b *Backend) findTask(name string) (*task.Task, bool) {
	if b.Tasks == nil {
		return nil, false
	}
	return task.Find(b.Tasks(), name)
}

// authenticate resolves a bearer token to a run scope.
func (b *Backend) authenticate(r *http.Request) (Scope, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return Scope{}, false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if tok == "" {
		return Scope{}, false
	}
	rt, ok, err := b.Store.LookupRunToken(r.Context(), HashToken(tok), b.now())
	if err != nil || !ok {
		return Scope{}, false
	}
	return Scope{Task: rt.Task, RunID: rt.RunID}, true
}

// RunHandler is the surface the sidecar exposes to run containers: MCP
// only, bearer required.
func (b *Backend) RunHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		sc := ScopeFrom(r.Context())
		if sc.Task == "" {
			return nil
		}
		return b.serverFor(sc.Task)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/mcp/", mcpHandler)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			mux.ServeHTTP(w, r)
			return
		}
		sc, ok := b.authenticate(r)
		if !ok {
			h := r.Header.Get("Authorization")
			b.log().Warn("mcp: rejected request without a valid run token", "remote", r.RemoteAddr, "path", r.URL.Path,
				"auth_header_len", len(h), "bearer", strings.HasPrefix(h, "Bearer "), "unexpanded", strings.Contains(h, "$"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		b.log().Info("mcp: request", "task", sc.Task, "run", sc.RunID, "method", r.Method, "path", r.URL.Path)
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), scopeKey{}, sc)))
	})
}

// OperatorHandler is the private API over the unix socket.
func (b *Backend) OperatorHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "version": b.Version})
	})
	mux.HandleFunc("GET /api/v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		type row struct {
			Name     string    `json:"name"`
			Enabled  bool      `json:"enabled"`
			Schedule string    `json:"schedule"`
			Model    string    `json:"model"`
			Effort   string    `json:"effort"`
			Hash     string    `json:"hash"`
			Sinks    []string  `json:"sinks"`
			Next     time.Time `json:"next,omitempty"`
			Paused   string    `json:"paused,omitempty"`
		}
		next := map[string]scheduler.Upcoming{}
		if b.Next != nil {
			for _, u := range b.Next() {
				next[u.Task] = u
			}
		}
		out := []row{}
		for _, t := range b.Tasks() {
			r := row{Name: t.Name, Enabled: t.IsEnabled(), Schedule: t.Schedule, Model: t.Model, Effort: t.Effort, Hash: t.Hash, Sinks: t.Sinks}
			if u, ok := next[t.Name]; ok {
				r.Next, r.Paused = u.At, u.Paused
			}
			out = append(out, r)
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("GET /api/v1/runs", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		runs, err := b.Store.ListRuns(r.Context(), r.URL.Query().Get("task"), r.URL.Query().Get("state"), limit)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, runs)
	})
	mux.HandleFunc("GET /api/v1/runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		run, err := b.Store.GetRun(r.Context(), r.PathValue("id"))
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "no such run", 404)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		leaks, _ := b.Store.Leaks(r.Context(), run.ID)
		dels, _ := b.Store.DeliveriesOf(r.Context(), run.ID)
		writeJSON(w, 200, map[string]any{"run": run, "leaks": leaks, "deliveries": dels})
	})
	mux.HandleFunc("GET /api/v1/runs/{id}/result", func(w http.ResponseWriter, r *http.Request) {
		res, err := b.Store.GetResult(r.Context(), r.PathValue("id"))
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "no result", 404)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		body := res.PseudoJSON
		if r.URL.Query().Get("view") == "clear" {
			if res.ClearJSON == nil {
				http.Error(w, "no clear result for this run", 404)
				return
			}
			body = res.ClearJSON
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("POST /api/v1/runs/{id}/redeliver", func(w http.ResponseWriter, r *http.Request) {
		n, err := b.Store.ResetDeliveries(r.Context(), r.PathValue("id"), r.URL.Query().Get("sink"), b.now())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, map[string]any{"queued": n})
	})
	mux.HandleFunc("GET /api/v1/inventory", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("task")
		t, ok := b.findTask(name)
		if !ok {
			http.Error(w, "unknown task", 404)
			return
		}
		view, err := b.latestView(r.Context(), t)
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		writeJSON(w, 200, view)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// View is the pseudonymized inventory snapshot a run was given. It is read
// back from the run's input directory so the MCP view and the prompt are
// the same data.
type View struct {
	Groups  []inventory.Group  `json:"groups"`
	Records []inventory.Record `json:"records"`
	// Text holds the scrubbed lines of the free-text inventory.
	Text []string `json:"text,omitempty"`
}

func (b *Backend) viewForRun(t *task.Task, runID string) (*View, error) {
	path := filepath.Join(b.Cfg.RunsDir(), t.Name, runID, "in", prompt.InventoryFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no inventory view for run %s", runID)
	}
	var v View
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (b *Backend) latestView(ctx context.Context, t *task.Task) (*View, error) {
	runs, err := b.Store.ListRuns(ctx, t.Name, "", 5)
	if err != nil {
		return nil, err
	}
	for _, r := range runs {
		if v, err := b.viewForRun(t, r.ID); err == nil {
			return v, nil
		}
	}
	return nil, errors.New("no run with an inventory view yet")
}

// --- MCP ------------------------------------------------------------------

const instructions = `This server exposes a pseudonymized inventory for the current task. Identifiers of the form host-xxxxxxxx, ip-xxxxxxxx (label-hex tokens) are opaque pseudonyms: copy them verbatim where a reference is needed and never try to resolve them. results_recent returns what earlier runs of this task reported, so you can avoid repeating findings.`

func (b *Backend) serverFor(taskName string) *mcp.Server {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.servers == nil {
		b.servers = map[string]*mcp.Server{}
	}
	t, ok := b.findTask(taskName)
	if !ok {
		return nil
	}
	key := taskName + "@" + t.Hash
	if s, ok := b.servers[key]; ok {
		return s
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "ais-inventory", Version: b.Version}, &mcp.ServerOptions{Instructions: instructions})
	tools := map[string]bool{}
	for _, name := range t.MCPTools() {
		tools[name] = true
	}
	if tools["inventory_products"] {
		mcp.AddTool(s, &mcp.Tool{Name: "inventory_products", Description: "Distinct product tuples in the inventory with install counts. No device identity. Optional case-insensitive substring filter on any field."},
			func(ctx context.Context, req *mcp.CallToolRequest, in ProductsIn) (*mcp.CallToolResult, ProductsOut, error) {
				return b.toolProducts(ctx, t, in)
			})
	}
	if tools["inventory_list"] {
		mcp.AddTool(s, &mcp.Tool{Name: "inventory_list", Description: "Inventory records in the task's pseudonymized view, optionally filtered by product and version. Pseudonym fields are opaque tokens."},
			func(ctx context.Context, req *mcp.CallToolRequest, in ListIn) (*mcp.CallToolResult, ListOut, error) {
				return b.toolList(ctx, t, in)
			})
	}
	if tools["results_recent"] {
		mcp.AddTool(s, &mcp.Tool{Name: "results_recent", Description: "Results reported by earlier runs of this task (pseudonymized view), newest first."},
			func(ctx context.Context, req *mcp.CallToolRequest, in RecentIn) (*mcp.CallToolResult, RecentOut, error) {
				return b.toolRecent(ctx, t, in)
			})
	}
	b.servers[key] = s
	return s
}

// ProductsIn is the input of inventory_products.
type ProductsIn struct {
	Filter string `json:"filter,omitempty" jsonschema:"case-insensitive substring matched against every field"`
}

// ProductsOut is the output of inventory_products.
type ProductsOut struct {
	Products []inventory.Group `json:"products"`
	// Text lists products the operator wrote as free text, without device
	// records: one line each, version only where the line gives one.
	Text []string `json:"text,omitempty" jsonschema:"free-text product lines without device records"`
}

// ListIn is the input of inventory_list.
type ListIn struct {
	Product string `json:"product,omitempty" jsonschema:"exact product name"`
	Version string `json:"version,omitempty" jsonschema:"exact version"`
	Limit   int    `json:"limit,omitempty" jsonschema:"maximum records to return (default 100, max 500)"`
}

// ListOut is the output of inventory_list.
type ListOut struct {
	Records []inventory.Record `json:"records"`
	Total   int                `json:"total"`
}

// RecentIn is the input of results_recent.
type RecentIn struct {
	Since string `json:"since,omitempty" jsonschema:"RFC3339 timestamp; default 7 days ago"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum results (default 10, max 50)"`
}

// RecentResult is one earlier result.
type RecentResult struct {
	RunID      string    `json:"run_id"`
	FinishedAt time.Time `json:"finished_at"`
	Result     any       `json:"result"`
}

// RecentOut is the output of results_recent.
type RecentOut struct {
	Results []RecentResult `json:"results"`
}

func (b *Backend) view(ctx context.Context, t *task.Task) (*View, error) {
	sc := ScopeFrom(ctx)
	if sc.RunID != "" {
		return b.viewForRun(t, sc.RunID)
	}
	return b.latestView(ctx, t)
}

func (b *Backend) toolProducts(ctx context.Context, t *task.Task, in ProductsIn) (*mcp.CallToolResult, ProductsOut, error) {
	v, err := b.view(ctx, t)
	if err != nil {
		return nil, ProductsOut{}, err
	}
	by := t.Expose.Prompt.GroupBy
	if len(by) == 0 {
		by = t.Policy().ClearFields()
	}
	groups := inventory.Minimize(v.Records, by, t.Expose.Prompt.Collect)
	if f := strings.ToLower(strings.TrimSpace(in.Filter)); f != "" {
		var kept []inventory.Group
		for _, g := range groups {
			for _, val := range g.Fields {
				if strings.Contains(strings.ToLower(val), f) {
					kept = append(kept, g)
					break
				}
			}
		}
		groups = kept
	}
	if groups == nil {
		groups = []inventory.Group{}
	}
	text := v.Text
	if f := strings.ToLower(strings.TrimSpace(in.Filter)); f != "" {
		text = nil
		for _, line := range v.Text {
			if strings.Contains(strings.ToLower(line), f) {
				text = append(text, line)
			}
		}
	}
	return nil, ProductsOut{Products: groups, Text: text}, nil
}

func (b *Backend) toolList(ctx context.Context, t *task.Task, in ListIn) (*mcp.CallToolResult, ListOut, error) {
	v, err := b.view(ctx, t)
	if err != nil {
		return nil, ListOut{}, err
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	out := ListOut{Records: []inventory.Record{}}
	for _, r := range v.Records {
		if in.Product != "" && !strings.EqualFold(r.Fields["product"], in.Product) {
			continue
		}
		if in.Version != "" && r.Fields["version"] != in.Version {
			continue
		}
		out.Total++
		if len(out.Records) < limit {
			out.Records = append(out.Records, r)
		}
	}
	return nil, out, nil
}

func (b *Backend) toolRecent(ctx context.Context, t *task.Task, in RecentIn) (*mcp.CallToolResult, RecentOut, error) {
	since := b.now().Add(-7 * 24 * time.Hour)
	if in.Since != "" {
		ts, err := time.Parse(time.RFC3339, in.Since)
		if err != nil {
			return nil, RecentOut{}, fmt.Errorf("since: %w", err)
		}
		since = ts
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}
	rows, err := b.Store.RecentResults(ctx, t.Name, since, limit)
	if err != nil {
		return nil, RecentOut{}, err
	}
	out := RecentOut{Results: []RecentResult{}}
	for _, r := range rows {
		var doc any
		_ = json.Unmarshal(r.PseudoJSON, &doc)
		out.Results = append(out.Results, RecentResult{RunID: r.RunID, FinishedAt: r.FinishedAt, Result: doc})
	}
	return nil, out, nil
}

// --- listeners --------------------------------------------------------------

// ListenUnix serves h on a unix socket with the given mode, replacing a
// stale socket file.
func ListenUnix(path string, mode os.FileMode) (net.Listener, error) {
	// sun_path is 108 bytes including the terminator on Linux.
	if len(path) > 107 {
		return nil, fmt.Errorf("unix socket path %q is longer than 107 bytes; set backend.socket to a shorter path", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve runs an http.Server on l until ctx ends.
func Serve(ctx context.Context, l net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	err := srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// MCPSocket is the socket the sidecar proxies to.
func MCPSocket(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.BackendSocket()), "mcp.sock")
}

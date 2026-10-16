package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/scuq/ais/internal/pseudo"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRunLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	r := Run{ID: "r1", Task: "t", State: StateRunning, Trigger: "manual", StartedAt: now, Model: "m"}
	if err := s.InsertRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ActiveRun(ctx, "t"); !ok {
		t.Error("active run not found")
	}
	r.State, r.FinishedAt, r.CostUSD, r.NumTurns = StateSucceeded, now.Add(time.Minute), 0.5, 3
	r.Model, r.Models = "claude-opus-5-5", "claude-opus-5-5,claude-haiku-5-5"
	r.InputTokens, r.OutputTokens, r.CacheReadTokens, r.CacheCreationTokens = 100, 20, 300, 40
	if err := s.FinishRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, r); err == nil {
		t.Error("finishing twice must fail")
	}
	got, err := s.GetRun(ctx, "r1")
	if err != nil || got.State != StateSucceeded || got.CostUSD != 0.5 || got.FinishedAt.IsZero() {
		t.Errorf("got %+v err %v", got, err)
	}
	if got.Model != "claude-opus-5-5" || got.Models != "claude-opus-5-5,claude-haiku-5-5" ||
		got.InputTokens != 100 || got.OutputTokens != 20 || got.CacheReadTokens != 300 || got.CacheCreationTokens != 40 {
		t.Errorf("usage not round-tripped: %+v", got)
	}
	if _, ok, _ := s.ActiveRun(ctx, "t"); ok {
		t.Error("finished run still active")
	}
	runs, _ := s.ListRuns(ctx, "t", "", 10)
	if len(runs) != 1 {
		t.Errorf("list: %d", len(runs))
	}
	cost, _ := s.CostSince(ctx, "t", now.Add(-time.Hour))
	if cost != 0.5 {
		t.Errorf("cost %v", cost)
	}
}

func TestSaltStableAndRotates(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id1, salt1, err := s.TaskSalt(ctx, "t")
	if err != nil || len(salt1) != pseudo.SaltSize {
		t.Fatal(err)
	}
	id2, salt2, _ := s.TaskSalt(ctx, "t")
	if id1 != id2 || string(salt1) != string(salt2) {
		t.Error("salt not stable")
	}
	id3, salt3, _ := s.RotateSalt(ctx, "t")
	if id3 == id1 || string(salt3) == string(salt1) {
		t.Error("rotate did not change the salt")
	}
	idOther, _, _ := s.TaskSalt(ctx, "other")
	if idOther == id3 {
		t.Error("tasks share a salt")
	}
}

func TestPseudonymsAndResults(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	m := pseudo.NewMap("t", "s1")
	m.Add("host-aaaaaaaa", "hostname", "fw01")
	if err := s.SavePseudonyms(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadPseudonyms(ctx, "t")
	if err != nil || got.Tokens["host-aaaaaaaa"] != "fw01" || got.Field("host-aaaaaaaa") != "hostname" {
		t.Errorf("%+v %v", got, err)
	}
	_ = s.InsertRun(ctx, Run{ID: "r1", Task: "t", State: StateRunning, StartedAt: time.Now()})
	if err := s.SaveResult(ctx, "r1", "t", time.Now(), []byte(`{"a":1}`), []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	res, err := s.GetResult(ctx, "r1")
	if err != nil || string(res.PseudoJSON) != `{"a":1}` || string(res.ClearJSON) != `{"a":2}` {
		t.Errorf("%+v %v", res, err)
	}
	recent, _ := s.RecentResults(ctx, "t", time.Now().Add(-time.Hour), 10)
	if len(recent) != 1 {
		t.Errorf("recent %d", len(recent))
	}
	_ = s.SaveLeaks(ctx, "r1", []pseudo.Finding{{Value: "fw01", Field: "hostname", Snippet: "x", Offset: 3}})
	leaks, _ := s.Leaks(ctx, "r1")
	if len(leaks) != 1 || leaks[0].Value != "fw01" {
		t.Errorf("leaks %+v", leaks)
	}
}

func TestRunTokensAndDeliveries(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now()
	_ = s.InsertRun(ctx, Run{ID: "r1", Task: "t", State: StateRunning, StartedAt: now})
	if err := s.InsertRunToken(ctx, "h1", RunToken{RunID: "r1", Task: "t", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if tk, ok, _ := s.LookupRunToken(ctx, "h1", now); !ok || tk.Task != "t" {
		t.Error("token lookup failed")
	}
	if _, ok, _ := s.LookupRunToken(ctx, "h1", now.Add(2*time.Hour)); ok {
		t.Error("expired token accepted")
	}
	_ = s.RevokeRunTokens(ctx, "r1")
	if _, ok, _ := s.LookupRunToken(ctx, "h1", now); ok {
		t.Error("revoked token accepted")
	}

	_ = s.EnqueueDelivery(ctx, "r1", "splunk", "result", now)
	due, _ := s.DueDeliveries(ctx, now, 10)
	if len(due) != 1 || due[0].Sink != "splunk" {
		t.Fatalf("due %+v", due)
	}
	_ = s.UpdateDelivery(ctx, due[0].ID, DeliveryPending, 1, now.Add(time.Minute), "503", now)
	if d, _ := s.DueDeliveries(ctx, now, 10); len(d) != 0 {
		t.Error("backed-off delivery still due")
	}
	if d, _ := s.DueDeliveries(ctx, now.Add(2*time.Minute), 10); len(d) != 1 || d[0].Attempt != 1 {
		t.Error("delivery not due after backoff")
	}
	n, _ := s.ResetDeliveries(ctx, "r1", "", now)
	if n != 1 {
		t.Errorf("reset %d", n)
	}
}

// TestMigrateAddsRunColumns opens a database created by the first release,
// whose runs table has no token columns, and checks that Open adds them.
func TestMigrateAddsRunColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE runs (
  id TEXT PRIMARY KEY, task TEXT NOT NULL, task_hash TEXT NOT NULL DEFAULT '', state TEXT NOT NULL,
  trigger TEXT NOT NULL DEFAULT 'manual', engine TEXT NOT NULL DEFAULT '', dir TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL, finished_at TEXT, exit_code INTEGER NOT NULL DEFAULT 0, subtype TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '', cost_usd REAL NOT NULL DEFAULT 0, num_turns INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '');
  INSERT INTO runs (id, task, state, started_at, model, cost_usd) VALUES ('old', 't', 'succeeded', '2026-10-16T09:00:00Z', 'm', 0.35);`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.GetRun(context.Background(), "old")
	if err != nil || got.CostUSD != 0.35 || got.InputTokens != 0 || got.Models != "" {
		t.Errorf("old row after migration: %+v err %v", got, err)
	}
	// A second open must be a no-op.
	if _, err := Open(path); err != nil {
		t.Errorf("reopen: %v", err)
	}
}

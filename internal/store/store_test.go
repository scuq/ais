package store

import (
	"context"
	"database/sql"
	"fmt"
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
	r.ModelUsage = map[string]ModelTokens{
		"claude-opus-5-5":  {Input: 10, Output: 15, CacheRead: 300, CacheCreation: 40, CostUSD: 0.45},
		"claude-haiku-5-5": {Input: 90, Output: 5, CostUSD: 0.05},
	}
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
	if len(got.ModelUsage) != 2 || got.ModelUsage["claude-haiku-5-5"] != r.ModelUsage["claude-haiku-5-5"] || got.ModelUsage["claude-opus-5-5"] != r.ModelUsage["claude-opus-5-5"] {
		t.Errorf("model usage not round-tripped: %+v", got.ModelUsage)
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
  INSERT INTO runs (id, task, state, started_at, model, cost_usd) VALUES ('old', 't', 'succeeded', '2026-10-16T09:00:00Z', 'm', 0.35);
  CREATE TABLE deliveries (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, sink TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'result', state TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 0, next_at TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL);
  INSERT INTO deliveries (run_id, sink, state, next_at, updated_at) VALUES ('old', 'w', 'delivered', '2026-10-16T09:01:00Z', '2026-10-16T09:01:00Z');`)
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
	dels, err := s.DeliveriesOf(context.Background(), "old")
	if err != nil || len(dels) != 1 || dels[0].Payload != "" || dels[0].State != "delivered" {
		t.Errorf("old delivery after migration: %+v err %v", dels, err)
	}
	// A second open must be a no-op.
	if _, err := Open(path); err != nil {
		t.Errorf("reopen: %v", err)
	}
}

func TestRunsBetweenAndPayload(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	base := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for i, st := range []string{StateSucceeded, StateFailed, StateRunning, StateSucceeded} {
		id := fmt.Sprintf("r%d", i)
		_ = s.InsertRun(ctx, Run{ID: id, Task: "t", State: StateRunning, StartedAt: base.Add(time.Duration(i) * time.Hour)})
		if st != StateRunning {
			_ = s.FinishRun(ctx, Run{ID: id, State: st, FinishedAt: base.Add(time.Duration(i)*time.Hour + time.Minute)})
		}
	}
	runs, err := s.RunsBetween(ctx, "t", base, base.Add(3*time.Hour))
	if err != nil || len(runs) != 2 || runs[0].ID != "r0" || runs[1].ID != "r1" {
		t.Errorf("runs between: %+v err %v", runs, err)
	}
	if runs, _ := s.RunsBetween(ctx, "t", base, base.Add(4*time.Hour)); len(runs) != 3 {
		t.Errorf("r3 missing: %+v", runs)
	}
	if err := s.EnqueueDeliveryPayload(ctx, "r3", "w", "digest", `{"window_end":"x"}`, base); err != nil {
		t.Fatal(err)
	}
	dels, _ := s.DeliveriesOf(ctx, "r3")
	if len(dels) != 1 || dels[0].Kind != "digest" || dels[0].Payload != `{"window_end":"x"}` {
		t.Errorf("payload: %+v", dels)
	}
	due, _ := s.DueDeliveries(ctx, base, 10)
	if len(due) != 1 || due[0].Payload == "" {
		t.Errorf("due payload: %+v", due)
	}
}

func TestFeedItems(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	items := []FeedItem{{Key: "a", Title: "A", Published: now.Add(-time.Hour)}, {Key: "b", Title: "B", Published: now.Add(-2 * time.Hour)}, {Key: "c", Title: "C", Published: now.Add(-3 * time.Hour)}}
	// A peek reports without claiming.
	peek, err := s.ClaimFeedItems(ctx, "t", "", items, 0, now)
	if err != nil || len(peek) != 3 || peek[0].State != FeedNew {
		t.Fatalf("peek: %+v %v", peek, err)
	}
	// A run claims at most limit items, newest first.
	got, err := s.ClaimFeedItems(ctx, "t", "r1", items, 2, now)
	if err != nil || len(got) != 2 || got[0].Key != "a" || got[1].Key != "b" || got[0].State != FeedHanded {
		t.Fatalf("claim: %+v %v", got, err)
	}
	// A failed run gives its items back; the next run gets them plus the rest.
	if err := s.SettleFeedItems(ctx, "r1", false); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ClaimFeedItems(ctx, "t", "r2", items, 10, now)
	if len(got) != 3 {
		t.Fatalf("after failure: %+v", got)
	}
	_ = s.SettleFeedItems(ctx, "r2", true)
	// Seen items do not come back, a new one does; another task has its own view.
	got, _ = s.ClaimFeedItems(ctx, "t", "r3", append(items, FeedItem{Key: "d", Title: "D", Published: now}), 10, now)
	if len(got) != 1 || got[0].Key != "d" {
		t.Errorf("new only: %+v", got)
	}
	other, _ := s.ClaimFeedItems(ctx, "u", "", items, 10, now)
	if len(other) != 3 {
		t.Errorf("per task: %+v", other)
	}
	of, _ := s.FeedItemsOf(ctx, "r2")
	if len(of) != 3 || of[0].State != FeedSeen {
		t.Errorf("items of r2: %+v", of)
	}
	n, err := s.PruneFeedItems(ctx, now.Add(time.Minute))
	if err != nil || n != 3 {
		t.Errorf("prune: %d %v", n, err)
	}
}

func TestFeedItemsPrefilter(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	items := []FeedItem{
		{Key: "a", Title: "PAN-OS flaw", Link: "https://x/a", Summary: "sum a", Published: now.Add(-time.Hour), Decision: DecisionKeep, Reason: "keyword", Match: "PAN-OS"},
		{Key: "b", Title: "Bakery", Link: "https://x/b", Published: now.Add(-2 * time.Hour), State: FeedFiltered, Decision: DecisionDrop, Reason: "model", Score: 0.1, Scored: true, Model: "m"},
		{Key: "c", Title: "VPN", Link: "https://x/c", Published: now.Add(-3 * time.Hour), Decision: DecisionKeep, Reason: "model", Score: 0.7, Scored: true, Model: "m"},
		{Key: "d", Title: "Unscored", Published: now.Add(-4 * time.Hour)},
	}
	got, err := s.ClaimFeedItems(ctx, "t", "r1", items, 0, now)
	if err != nil || len(got) != 3 {
		t.Fatalf("claim: %+v %v", got, err)
	}
	for _, it := range got {
		if it.Key == "b" {
			t.Error("a filtered item was handed")
		}
		if it.Key == "a" && (it.Summary != "sum a" || it.Decision != DecisionKeep || it.Reason != "keyword" || it.Scored) {
			t.Errorf("a: %+v", it)
		}
		if it.Key == "c" && (!it.Scored || it.Score != 0.7 || it.Model != "m") {
			t.Errorf("c: %+v", it)
		}
		if it.Key == "d" && (it.Decision != "" || it.Scored) {
			t.Errorf("d: %+v", it)
		}
	}
	states, err := s.FeedItemStates(ctx, "t", []string{"a", "b", "d", "zz"})
	if err != nil || len(states) != 3 || states["b"].State != FeedFiltered || states["a"].State != FeedHanded || states["d"].Decision != "" {
		t.Errorf("states: %+v %v", states, err)
	}
	// A later tick refreshes the decision columns of a known item and
	// keeps its state.
	_ = s.SettleFeedItems(ctx, "r1", true)
	_, _ = s.ClaimFeedItems(ctx, "t", "", []FeedItem{{Key: "d", Title: "Unscored", Decision: DecisionDrop, Reason: "model", Score: 0.2, Scored: true, State: FeedFiltered}}, 0, now)
	states, _ = s.FeedItemStates(ctx, "t", []string{"d"})
	if states["d"].State != FeedSeen || states["d"].Decision != DecisionDrop || states["d"].Score != 0.2 {
		t.Errorf("refresh: %+v", states["d"])
	}
	// A row that waits as new and is dropped now becomes filtered.
	_, _ = s.ClaimFeedItems(ctx, "t", "", []FeedItem{{Key: "e", Title: "Waiting", Published: now}}, 0, now)
	_, _ = s.ClaimFeedItems(ctx, "t", "", []FeedItem{{Key: "e", Title: "Waiting", Published: now, Decision: DecisionDrop, Reason: "model", Score: 0.1, Scored: true, State: FeedFiltered}}, 0, now)
	states, _ = s.FeedItemStates(ctx, "t", []string{"e"})
	if states["e"].State != FeedFiltered {
		t.Errorf("waiting row not filtered: %+v", states["e"])
	}
	scores, err := s.FeedItemScores(ctx, "t", now.Add(-time.Minute))
	if err != nil || len(scores) != 5 || scores[0].Key != "c" {
		t.Errorf("scores: %+v %v", scores, err)
	}
	n, err := s.PruneFeedItems(ctx, now.Add(time.Minute))
	if err != nil || n != 5 {
		t.Errorf("prune filtered too: %d %v", n, err)
	}
}

// TestMigrateAddsFeedItemColumns opens a v0.6.0 database, whose feed_items
// table has no prefilter columns, and checks that Open adds them.
func TestMigrateAddsFeedItemColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE feed_items (task TEXT NOT NULL, key TEXT NOT NULL, title TEXT NOT NULL DEFAULT '', link TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '', published TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new',
  run_id TEXT NOT NULL DEFAULT '', PRIMARY KEY (task, key));
  INSERT INTO feed_items (task, key, title, first_seen, state) VALUES ('t', 'old', 'Old', '2026-10-17T09:00:00Z', 'new');`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.ClaimFeedItems(context.Background(), "t", "", nil, 0, time.Now())
	if err != nil || len(got) != 1 || got[0].Key != "old" || got[0].Scored || got[0].Decision != "" || got[0].Summary != "" {
		t.Errorf("old row after migration: %+v %v", got, err)
	}
	if _, err := Open(path); err != nil {
		t.Errorf("reopen: %v", err)
	}
}

func TestRunUsageColumns(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	quiet := Run{ID: "q", Task: "t", State: StateSkipped, Reason: "quiet", Error: "22 feed(s), 900 item(s), none new", StartedAt: now, FinishedAt: now.Add(time.Second), Mode: "feed",
		Feeds: 22, FeedsFailed: 1, FeedItems: 900, FeedFiltered: 3, FetchMS: 2500, PrefilterMS: 6000, PrefilterScored: 3, PrefilterKeyword: 1, PrefilterDropped: 3, PrefilterCPUMS: 9000, PrefilterMemPeak: 1 << 30, PrefilterError: "x"}
	if err := s.InsertRun(ctx, quiet); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRun(ctx, "q")
	if err != nil || got.Error != quiet.Error || !got.FinishedAt.Equal(quiet.FinishedAt) || got.Feeds != 22 || got.FeedsFailed != 1 || got.FeedItems != 900 || got.FeedFiltered != 3 || got.FetchMS != 2500 ||
		got.PrefilterMS != 6000 || got.PrefilterScored != 3 || got.PrefilterKeyword != 1 || got.PrefilterDropped != 3 || got.PrefilterCPUMS != 9000 || got.PrefilterMemPeak != 1<<30 || got.PrefilterError != "x" {
		t.Errorf("quiet row: %+v %v", got, err)
	}
	run := Run{ID: "m", Task: "u", State: StateRunning, StartedAt: now.Add(time.Minute), Mode: "feed", FeedNew: 2}
	_ = s.InsertRun(ctx, run)
	if r, _ := s.GetRun(ctx, "m"); !r.FinishedAt.IsZero() {
		t.Errorf("a running row has a finish time: %v", r.FinishedAt)
	}
	run.State, run.FinishedAt, run.CPUMS, run.MemPeak = StateSucceeded, now.Add(2*time.Minute), 3100, 300<<20
	if err := s.FinishRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.GetRun(ctx, "m"); r.CPUMS != 3100 || r.MemPeak != 300<<20 || r.FeedNew != 2 {
		t.Errorf("finished row: %+v", r)
	}
	all, err := s.RunsSince(ctx, "", now.Add(-time.Hour))
	if err != nil || len(all) != 2 || all[0].ID != "q" {
		t.Errorf("all tasks: %+v %v", all, err)
	}
	one, _ := s.RunsSince(ctx, "u", now.Add(-time.Hour))
	if len(one) != 1 || one[0].ID != "m" {
		t.Errorf("one task: %+v", one)
	}
	_ = s.SaveResult(ctx, "m", "u", now.Add(2*time.Minute), []byte(`{"findings":[]}`), nil)
	res, err := s.ResultsSince(ctx, "", now)
	if err != nil || len(res) != 1 || res[0].ClearJSON != nil || string(res[0].PseudoJSON) != `{"findings":[]}` {
		t.Errorf("results: %+v %v", res, err)
	}
}

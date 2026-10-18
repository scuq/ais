package sink

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

// digestStore seeds a store with a day of runs: two succeeded, one failed,
// one skipped, and one run before the window. The two results of the
// window have no findings and seven checked items together.
func digestStore(t *testing.T, findings string) (*store.Store, time.Time) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	end := time.Date(2026, 10, 17, 20, 30, 0, 0, time.UTC)
	add := func(id string, at time.Time, state string, cost float64, turns int, in, out int64, models string) {
		model := strings.Split(models, ",")[0]
		_ = st.InsertRun(ctx, store.Run{ID: id, Task: "t", State: store.StateRunning, StartedAt: at, Model: model})
		_ = st.FinishRun(ctx, store.Run{ID: id, State: state, FinishedAt: at.Add(2 * time.Minute), CostUSD: cost, NumTurns: turns, InputTokens: in, OutputTokens: out, Models: models, Model: model})
	}
	add("old", end.Add(-30*time.Hour), store.StateSucceeded, 9, 99, 1, 1, "x")
	add("r1", end.Add(-20*time.Hour), store.StateSucceeded, 1.5, 20, 500_000, 40_000, "claude-opus-5-5,claude-haiku-5-5")
	add("r2", end.Add(-10*time.Hour), store.StateFailed, 0, 1, 0, 0, "")
	add("r3", end.Add(-5*time.Hour), store.StateSkipped, 0, 0, 0, 0, "")
	add("r4", end.Add(-1*time.Hour), store.StateSucceeded, 1.0, 15, 300_000, 20_000, "claude-opus-5-5")
	_ = st.SaveResult(ctx, "r1", "t", end.Add(-20*time.Hour), []byte(`{"findings":[],"checked":[{},{},{}]}`), []byte(`{"findings":[],"checked":[{},{},{}]}`))
	_ = st.SaveResult(ctx, "r4", "t", end.Add(-1*time.Hour), []byte(`{"findings":[`+findings+`],"checked":[{},{},{},{}]}`), nil)
	return st, end
}

func TestBuildDigestCounts(t *testing.T) {
	st, end := digestStore(t, "")
	p := DigestPayload{WindowStart: end.Add(-24 * time.Hour), WindowEnd: end}
	dg, meta, anchor, err := BuildDigest(context.Background(), st, "t", p)
	if err != nil {
		t.Fatal(err)
	}
	if anchor != "r4" || dg.Runs != 4 || dg.Succeeded != 2 || dg.Failed != 1 || dg.Skipped != 1 || dg.Findings != 0 {
		t.Errorf("digest: anchor %s %+v", anchor, dg)
	}
	if dg.Checked == nil || *dg.Checked != 7 {
		t.Errorf("checked: %v", dg.Checked)
	}
	if meta.CostUSD != 2.5 || meta.NumTurns != 36 || meta.Tokens.Input != 800_000 || meta.Tokens.Output != 60_000 {
		t.Errorf("meta: %+v", meta)
	}
	if strings.Join(meta.Models, ",") != "claude-opus-5-5,claude-haiku-5-5" || meta.Model != "claude-opus-5-5" {
		t.Errorf("models: %v", meta.Models)
	}
	// An empty window hangs on the newest run of the task.
	dg, _, anchor, err = BuildDigest(context.Background(), st, "t", DigestPayload{WindowStart: end.Add(time.Hour), WindowEnd: end.Add(2 * time.Hour)})
	if err != nil || anchor != "r4" || dg.Runs != 0 || dg.Checked != nil {
		t.Errorf("empty window: anchor %s %+v err %v", anchor, dg, err)
	}
	if _, _, _, err := BuildDigest(context.Background(), st, "nope", p); err != ErrNoRun {
		t.Errorf("unknown task: %v", err)
	}
}

func TestQueueDigestAndRender(t *testing.T) {
	st, end := digestStore(t, "")
	ctx := context.Background()
	tk := &task.Task{Name: "t", Sinks: []string{"webex", "hec"}, Digest: &task.Digest{Schedule: "30 22 * * *", Window: 24 * time.Hour}}
	next := end.Add(10 * time.Hour)
	reason, err := QueueDigest(ctx, st, tk, end, &next, end)
	if err != nil || reason != "" {
		t.Fatalf("queue: %q %v", reason, err)
	}
	dels, _ := st.DeliveriesOf(ctx, "r4")
	if len(dels) != 2 || dels[0].Kind != "digest" || !strings.Contains(dels[0].Payload, `"window_end"`) {
		t.Fatalf("deliveries: %+v", dels)
	}
	d := &Dispatcher{Store: st, Version: "test"}
	ev, err := d.LoadDelivery(ctx, dels[0])
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != "digest" || ev.Task != "t" || ev.Digest == nil || ev.Digest.NextRun == nil || !ev.FinishedAt.Equal(end) {
		t.Fatalf("event: %+v", ev)
	}
	md := WebexMarkdown("ais t", ev, 10)
	for _, want := range []string{
		"✅ **ais t**: nothing found in the last 24 h\n",
		"**Runs** 4 tick(s) · 3 model run(s) (2 ok, 1 failed) · 1 skipped\n",
		"**Model** opus-5-5, haiku-5-5 · 36 turns · 7 items checked\n",
		"**Tokens** 800k in / 60k out\n",
		"**Cost** est. $2.50 · $0.83/run (subscription)\n",
		"_" + end.Local().Format("2006-01-02 15:04") + " · next run " + next.Local().Format("2006-01-02 15:04") + "_",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	// No feed or prefilter figures in the window: no such lines.
	if strings.Contains(md, "**Feeds**") || strings.Contains(md, "**Prefilter**") {
		t.Errorf("empty lines rendered:\n%s", md)
	}
	card := WebexCard("ais t", ev, 10)
	body := card["body"].([]any)
	if len(body) != 7 || !strings.Contains(body[1].(map[string]any)["text"].(string), "Nothing found") {
		t.Errorf("card body: %v", body)
	}
	// skipEmpty leaves a digest alone.
	if r := (skipEmpty{}).Skip(ev); r != "" {
		t.Errorf("digest skipped: %s", r)
	}
	// A payload without a window is a permanent error, not a crash.
	if _, err := d.LoadDelivery(ctx, store.Delivery{ID: 9, RunID: "r4", Kind: "digest"}); err == nil {
		t.Error("missing payload accepted")
	}
}

func TestQueueDigestQuietOnly(t *testing.T) {
	st, end := digestStore(t, `{"severity":"high"}`)
	ctx := context.Background()
	tk := &task.Task{Name: "t", Sinks: []string{"webex"}, Digest: &task.Digest{Schedule: "30 22 * * *", Window: 24 * time.Hour}}
	reason, err := QueueDigest(ctx, st, tk, end, nil, end)
	if err != nil || reason != "1 finding(s) in the window" {
		t.Errorf("findings must hold the digest back: %q %v", reason, err)
	}
	if dels, _ := st.DeliveriesOf(ctx, "r4"); len(dels) != 0 {
		t.Errorf("queued anyway: %+v", dels)
	}
	tk.Digest.Always = true
	if reason, err := QueueDigest(ctx, st, tk, end, nil, end); err != nil || reason != "" {
		t.Errorf("always: %q %v", reason, err)
	}
	dels, _ := st.DeliveriesOf(ctx, "r4")
	d := &Dispatcher{Store: st}
	ev, err := d.LoadDelivery(ctx, dels[0])
	if err != nil {
		t.Fatal(err)
	}
	if md := WebexMarkdown("ais t", ev, 10); !strings.Contains(md, "🔎 **ais t**: 1 finding(s) in the last 24 h\n**Runs**") {
		t.Errorf("markdown: %s", md)
	}
	// Without sinks nothing is queued, with a reason.
	tk.Sinks = nil
	if reason, _ := QueueDigest(ctx, st, tk, end, nil, end); reason != "task has no sinks" {
		t.Errorf("no sinks: %q", reason)
	}
}

// TestDigestStatsLines checks the lines of a feed task: ticks, feeds,
// prefilter, model, tokens, and the cost split by model.
func TestDigestStatsLines(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	end := time.Date(2026, 10, 18, 20, 30, 0, 0, time.UTC)
	add := func(r store.Run, fin store.Run) {
		r.Task, r.State, r.Mode = "t", store.StateRunning, "feed"
		if err := st.InsertRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		fin.ID, fin.FinishedAt = r.ID, r.StartedAt.Add(time.Minute)
		if err := st.FinishRun(ctx, fin); err != nil {
			t.Fatal(err)
		}
	}
	add(store.Run{ID: "q1", StartedAt: end.Add(-5 * time.Hour), Feeds: 25, FeedItems: 1000, FeedsFailed: 1, FetchMS: 2000},
		store.Run{State: store.StateSkipped, Reason: "quiet"})
	add(store.Run{ID: "c1", StartedAt: end.Add(-4 * time.Hour)}, store.Run{State: store.StateSkipped, Reason: "ratelimit"})
	add(store.Run{ID: "m1", StartedAt: end.Add(-3 * time.Hour), Feeds: 25, FeedItems: 1010, FeedNew: 10, FetchMS: 2000,
		PrefilterMS: 5000, PrefilterScored: 9, PrefilterKeyword: 1, PrefilterKept: 6, PrefilterDropped: 4},
		store.Run{State: store.StateSucceeded, NumTurns: 12, DurationMS: 130_000, InputTokens: 100_000, CacheReadTokens: 900_000, OutputTokens: 50_000, CostUSD: 1.20,
			Models: "claude-opus-5-5,claude-haiku-5-5", Model: "claude-opus-5-5",
			ModelUsage: map[string]store.ModelTokens{"claude-opus-5-5": {CostUSD: 1.00}, "claude-haiku-5-5": {CostUSD: 0.20}}})
	_ = st.SaveResult(ctx, "m1", "t", end.Add(-3*time.Hour), []byte(`{"findings":[{"previously_reported":true},{}],"checked":[{},{}]}`), nil)
	d := &Dispatcher{Store: st}
	ev, err := d.LoadDigest(ctx, "t", DigestPayload{WindowStart: end.Add(-24 * time.Hour), WindowEnd: end})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Digest.Findings != 2 || ev.Digest.Updates != 1 || ev.Digest.Stats == nil {
		t.Fatalf("digest: %+v", ev.Digest)
	}
	md := WebexMarkdown("ais t", ev, 10)
	for _, want := range []string{
		"🔎 **ais t**: 1 finding(s), 1 update(s) in the last 24 h\n",
		"**Runs** 3 tick(s) · 1 model run(s) (1 ok) · 1 quiet · 1 capped\n",
		"**Feeds** 3 fetches · 2.0k items · 10 new · 1 feed error(s)\n",
		"**Prefilter** 9 scored · 6 kept / 4 dropped (40 %) · 1 keyword hit(s)\n",
		"**Model** opus-5-5, haiku-5-5 · 12 turns · 2 items checked · avg 2m10s/run\n",
		"**Tokens** 1.0M in (90 % cache read) / 50k out\n",
		"**Cost** est. $1.20 · $1.20/run · opus-5-5 $1.00 · haiku-5-5 $0.20 (subscription)\n",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	// A digest without stats (an older payload) keeps the old line.
	ev.Digest.Stats = nil
	if md := WebexMarkdown("ais t", ev, 10); !strings.Contains(md, "3 run(s) (1 succeeded, 1 skipped, 1 quiet) · 12 turns · 2 items checked") || !strings.Contains(md, "subscription (est. $1.20)") {
		t.Errorf("fallback:\n%s", md)
	}
}

func TestDigestLabels(t *testing.T) {
	base := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	for w, want := range map[time.Duration]string{24 * time.Hour: "24 h", 72 * time.Hour: "3 days", 90 * time.Minute: "90 min", 6 * time.Hour: "6 h"} {
		if got := (Digest{WindowStart: base, WindowEnd: base.Add(w)}).WindowLabel(); got != want {
			t.Errorf("%v: %q", w, got)
		}
	}
	if got := (Digest{Runs: 1, Succeeded: 1}).RunsLine(); got != "1 run(s) (1 succeeded)" {
		t.Errorf("runs line: %q", got)
	}
	if got := (Digest{}).RunsLine(); got != "0 run(s)" {
		t.Errorf("empty runs line: %q", got)
	}
}

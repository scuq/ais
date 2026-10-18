package report

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/scuq/ais/internal/store"
)

func TestParseWindows(t *testing.T) {
	ws, err := ParseWindows("24h, 7d,1.5d")
	if err != nil || len(ws) != 3 || ws[0].Span != 24*time.Hour || ws[1].Span != 7*24*time.Hour || ws[2].Span != 36*time.Hour || ws[1].Name != "7d" {
		t.Fatalf("%+v %v", ws, err)
	}
	for _, bad := range []string{"", "x", "-1d", "0h"} {
		if _, err := ParseWindows(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBuild(t *testing.T) {
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	runs := []store.Run{
		// 3 days ago: an old full run without a mode, no usage figures.
		{ID: "old", Task: "t", State: store.StateSucceeded, StartedAt: at.Add(-72 * time.Hour), NumTurns: 15, InputTokens: 1000, CacheReadTokens: 500, OutputTokens: 100, CostUSD: 0.5, DurationMS: 60000, Models: "claude-opus-5-5,claude-haiku-5-5"},
		// Today: a quiet feed tick with the prefilter.
		{ID: "q", Task: "t", Mode: "feed", State: store.StateSkipped, Reason: "quiet", StartedAt: at.Add(-2 * time.Hour),
			Feeds: 22, FeedsFailed: 1, FeedItems: 900, FeedFiltered: 3, FetchMS: 2500,
			PrefilterMS: 6000, PrefilterScored: 3, PrefilterKept: 0, PrefilterDropped: 3, PrefilterCPUMS: 9000, PrefilterMemPeak: 900 << 20},
		// Today: a feed check that ran the model.
		{ID: "f", Task: "t", Mode: "feed", State: store.StateSucceeded, StartedAt: at.Add(-time.Hour),
			Feeds: 22, FeedItems: 905, FeedNew: 2, FetchMS: 1500,
			PrefilterMS: 4000, PrefilterScored: 1, PrefilterKeyword: 1, PrefilterKept: 2, PrefilterCPUMS: 5000, PrefilterMemPeak: 800 << 20,
			NumTurns: 3, InputTokens: 200, CacheCreationTokens: 50, OutputTokens: 20, CostUSD: 0.18, DurationMS: 12000, CPUMS: 3000, MemPeak: 300 << 20, Models: "claude-opus-5-5"},
		// Today: held back by the cap, and a prefilter error.
		{ID: "r", Task: "t", Mode: "feed", State: store.StateSkipped, Reason: "ratelimit", StartedAt: at.Add(-30 * time.Minute), Feeds: 22, FeedItems: 905, PrefilterKept: 4, PrefilterError: "image missing"},
		// Today: a config failure before any container.
		{ID: "c", Task: "t", State: store.StateFailed, Reason: "config", StartedAt: at.Add(-10 * time.Minute)},
	}
	results := []store.Result{
		{RunID: "old", FinishedAt: at.Add(-71 * time.Hour), PseudoJSON: []byte(`{"findings":[{"previously_reported":false},{"previously_reported":true}],"checked":[{},{},{}]}`)},
		{RunID: "f", FinishedAt: at.Add(-59 * time.Minute), PseudoJSON: []byte(`{"findings":[],"checked":[{}]}`)},
	}
	ws, _ := ParseWindows("24h,7d")
	rep := Build("t", at, "subscription", ws, runs, results)
	day, week := rep.Windows[0].Stats, rep.Windows[1].Stats
	if day.Ticks.Total != 4 || day.Ticks.FeedChecks != 3 || day.Ticks.Quiet != 1 || day.Ticks.RateLimit != 1 || day.Ticks.Failed != 1 || day.Ticks.Succeeded != 1 || week.Ticks.NoMode != 2 {
		t.Errorf("ticks: %+v / %+v", day.Ticks, week.Ticks)
	}
	if f := day.Feeds; f.Fetches != 3 || f.Measured != 3 || f.Feeds != 66 || f.Failed != 1 || f.Items != 2710 || f.New != 2 || f.Filtered != 3 || f.Wall != 4*time.Second || f.WallMax != 2500*time.Millisecond {
		t.Errorf("feeds: %+v", f)
	}
	if p := day.Prefilter; p.Runs != 3 || p.Errors != 1 || p.Scored != 4 || p.Keyword != 1 || p.Kept != 6 || p.Dropped != 3 || p.CPU != 14*time.Second || p.MemPeak != 900<<20 || p.Measured != 2 || p.Wall != 10*time.Second {
		t.Errorf("prefilter: %+v", p)
	}
	if m := day.Model; m.Runs != 1 || m.Turns != 3 || m.In() != 250 || m.Output != 20 || m.CostUSD != 0.18 || m.CPU != 3*time.Second || m.MemPeak != 300<<20 || m.Measured != 1 {
		t.Errorf("model day: %+v", m)
	}
	if m := week.Model; m.Runs != 2 || m.Turns != 18 || m.In() != 1750 || math.Abs(m.CostUSD-0.68) > 1e-9 || m.Measured != 1 || strings.Join(m.Models, ",") != "claude-opus-5-5,claude-haiku-5-5" {
		t.Errorf("model week: %+v", m)
	}
	if r := week.Results; r.Runs != 2 || r.Findings != 1 || r.Updates != 1 || r.Checked != 4 {
		t.Errorf("results: %+v", r)
	}
	if day.CPU != 17*time.Second || day.Wall != 4*time.Second+10*time.Second+12*time.Second {
		t.Errorf("totals: %v %v", day.CPU, day.Wall)
	}
	rep.Runs = runs
	var buf bytes.Buffer
	if err := Render(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"last 24h", "last 7d", "new items to model", "$0.18", "$0.68", "1 of 2", "900 MiB", "905/22", "subscription", "RUNS (last 24h)", "skipped (quiet)"} {
		if !strings.Contains(out, want) {
			t.Errorf("render lacks %q:\n%s", want, out)
		}
	}
}

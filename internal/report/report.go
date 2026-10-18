// Package report sums up what ais ran in a time window and what it cost:
// feed ticks and what they fetched, the local prefilter and its
// decisions, the model runs with their tokens, turns and estimated price,
// the CPU time and peak memory of every container, and what the results
// contained. The numbers come from the runs and results tables only.
package report

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/scuq/ais/internal/store"
)

// Window is one period of the report, ending at the report's time.
type Window struct {
	Name  string        `json:"name"`
	Span  time.Duration `json:"span"`
	Since time.Time     `json:"since"`
	Stats Stats         `json:"stats"`
}

// Stats is what ran in a window.
type Stats struct {
	Ticks     Ticks     `json:"ticks"`
	Feeds     Feeds     `json:"feeds"`
	Prefilter Prefilter `json:"prefilter"`
	Model     Model     `json:"model"`
	Results   Results   `json:"results"`
	// CPU and Wall are the totals over the prefilter and model containers
	// (CPU) and over fetch, prefilter and model (wall time).
	CPU  time.Duration `json:"cpu"`
	Wall time.Duration `json:"wall"`
}

// Ticks counts the run rows by outcome.
type Ticks struct {
	Total      int `json:"total"`
	FeedChecks int `json:"feedChecks"`
	FullChecks int `json:"fullChecks"`
	Succeeded  int `json:"succeeded"`
	Failed     int `json:"failed"`
	Quiet      int `json:"quiet"`
	RateLimit  int `json:"rateLimit"`
	Skipped    int `json:"skipped"` // overlap, config and other skips
	Running    int `json:"running"`
	// NoMode counts rows from before feed checks recorded a mode.
	NoMode int `json:"noMode"`
}

// Feeds is what the feed ticks fetched.
type Feeds struct {
	Fetches  int           `json:"fetches"`
	Feeds    int           `json:"feeds"`
	Failed   int           `json:"failed"`
	Items    int           `json:"items"`
	New      int           `json:"new"`
	Filtered int           `json:"filtered"`
	Wall     time.Duration `json:"wall"`
	WallMax  time.Duration `json:"wallMax"`
	// Measured counts the fetches that recorded these numbers; ticks from
	// before the recording have none.
	Measured int `json:"measured"`
}

// Prefilter is what the local model did.
type Prefilter struct {
	Runs    int           `json:"runs"`
	Errors  int           `json:"errors"`
	Scored  int           `json:"scored"`
	Keyword int           `json:"keyword"`
	Kept    int           `json:"kept"`
	Dropped int           `json:"dropped"`
	Wall    time.Duration `json:"wall"`
	WallMax time.Duration `json:"wallMax"`
	CPU     time.Duration `json:"cpu"`
	MemPeak int64         `json:"memPeak"`
	// Measured counts the runs whose container reported CPU and memory.
	Measured int `json:"measured"`
}

// Model is what the online model runs used.
type Model struct {
	Runs          int           `json:"runs"`
	Turns         int           `json:"turns"`
	Input         int64         `json:"input"`
	CacheRead     int64         `json:"cacheRead"`
	CacheCreation int64         `json:"cacheCreation"`
	Output        int64         `json:"output"`
	CostUSD       float64       `json:"costUsd"`
	Wall          time.Duration `json:"wall"`
	WallMax       time.Duration `json:"wallMax"`
	CPU           time.Duration `json:"cpu"`
	MemPeak       int64         `json:"memPeak"`
	Measured      int           `json:"measured"`
	Models        []string      `json:"models,omitempty"`
	// ByModel splits the tokens and the cost by model. Unsplit holds the
	// runs that recorded no split (older runs without a saved envelope),
	// so that ByModel plus Unsplit adds up to the totals above.
	ByModel map[string]store.ModelTokens `json:"byModel,omitempty"`
	Unsplit store.ModelTokens            `json:"unsplit"`
}

// In is every input token: uncached input, cache reads and cache writes.
func (m Model) In() int64 { return m.Input + m.CacheRead + m.CacheCreation }

// Results is what the successful runs reported.
type Results struct {
	Runs     int `json:"runs"`
	Findings int `json:"findings"`
	Updates  int `json:"updates"`
	Checked  int `json:"checked"`
}

// Report is the whole report.
type Report struct {
	Task    string    `json:"task,omitempty"`
	At      time.Time `json:"at"`
	Billing string    `json:"billing"`
	Windows []Window  `json:"windows"`
	// Runs lists the runs of the first window, oldest first, when asked.
	Runs []store.Run `json:"runs,omitempty"`
}

// ParseWindows parses "24h,7d,30d": Go durations plus a d suffix for days.
func ParseWindows(spec string) ([]Window, error) {
	var out []Window
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		d, err := ParseSpan(part)
		if err != nil {
			return nil, err
		}
		out = append(out, Window{Name: part, Span: d})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no window given")
	}
	return out, nil
}

// ParseSpan parses a duration with an optional d (days) suffix.
func ParseSpan(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseFloat(n, 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("window %q: want a number of days, for example 7d", s)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("window %q: want a duration such as 24h or 7d", s)
	}
	return d, nil
}

// Build fills the windows from runs and results; both must cover the
// longest window. A run counts in a window when it started in it, a
// result when it finished in it.
func Build(task string, at time.Time, billing string, windows []Window, runs []store.Run, results []store.Result) Report {
	rep := Report{Task: task, At: at, Billing: billing}
	verdicts := map[string]resultCounts{}
	for _, r := range results {
		verdicts[r.RunID] = countResult(r.PseudoJSON)
	}
	for _, w := range windows {
		w.Since = at.Add(-w.Span)
		seen := map[string]bool{}
		for _, r := range runs {
			if r.StartedAt.Before(w.Since) || r.StartedAt.After(at) {
				continue
			}
			add(&w.Stats, r, seen)
		}
		for _, res := range results {
			if res.FinishedAt.Before(w.Since) || res.FinishedAt.After(at) {
				continue
			}
			c := verdicts[res.RunID]
			w.Stats.Results.Runs++
			w.Stats.Results.Findings += c.findings
			w.Stats.Results.Updates += c.updates
			w.Stats.Results.Checked += c.checked
		}
		w.Stats.CPU = w.Stats.Prefilter.CPU + w.Stats.Model.CPU
		w.Stats.Wall = w.Stats.Feeds.Wall + w.Stats.Prefilter.Wall + w.Stats.Model.Wall
		rep.Windows = append(rep.Windows, w)
	}
	return rep
}

func add(s *Stats, r store.Run, seenModels map[string]bool) {
	t := &s.Ticks
	t.Total++
	switch r.Mode {
	case "feed":
		t.FeedChecks++
	case "full":
		t.FullChecks++
	default:
		t.NoMode++
	}
	switch r.State {
	case store.StateSucceeded:
		t.Succeeded++
	case store.StateSkipped, store.StateCancelled:
		switch r.Reason {
		case "quiet":
			t.Quiet++
		case "ratelimit":
			t.RateLimit++
		default:
			t.Skipped++
		}
	case store.StateQueued, store.StateRunning:
		t.Running++
	default:
		t.Failed++
	}
	if r.Mode == "feed" && r.Reason != "overlap" {
		f := &s.Feeds
		f.Fetches++
		if r.Feeds > 0 {
			f.Measured++
			f.Feeds += r.Feeds
			f.Failed += r.FeedsFailed
			f.Items += r.FeedItems
			f.New += r.FeedNew
			f.Filtered += r.FeedFiltered
			d := ms(r.FetchMS)
			f.Wall += d
			f.WallMax = max(f.WallMax, d)
		}
	}
	if r.PrefilterKept+r.PrefilterDropped > 0 || r.PrefilterError != "" {
		p := &s.Prefilter
		p.Runs++
		if r.PrefilterError != "" {
			p.Errors++
		}
		p.Scored += r.PrefilterScored
		p.Keyword += r.PrefilterKeyword
		p.Kept += r.PrefilterKept
		p.Dropped += r.PrefilterDropped
		d := ms(r.PrefilterMS)
		p.Wall += d
		p.WallMax = max(p.WallMax, d)
		if r.PrefilterCPUMS > 0 || r.PrefilterMemPeak > 0 {
			p.Measured++
			p.CPU += ms(r.PrefilterCPUMS)
			p.MemPeak = max(p.MemPeak, r.PrefilterMemPeak)
		}
	}
	// A model run is a row whose container started: it has turns, a
	// cost, a duration or a terminal state other than skipped.
	if startedModel(r) {
		m := &s.Model
		m.Runs++
		m.Turns += r.NumTurns
		m.Input += r.InputTokens
		m.CacheRead += r.CacheReadTokens
		m.CacheCreation += r.CacheCreationTokens
		m.Output += r.OutputTokens
		m.CostUSD += r.CostUSD
		d := ms(r.DurationMS)
		m.Wall += d
		m.WallMax = max(m.WallMax, d)
		if r.CPUMS > 0 || r.MemPeak > 0 {
			m.Measured++
			m.CPU += ms(r.CPUMS)
			m.MemPeak = max(m.MemPeak, r.MemPeak)
		}
		if len(r.ModelUsage) == 0 {
			addTokens(&m.Unsplit, store.ModelTokens{Input: r.InputTokens, Output: r.OutputTokens, CacheRead: r.CacheReadTokens, CacheCreation: r.CacheCreationTokens, CostUSD: r.CostUSD})
		}
		for name, u := range r.ModelUsage {
			if m.ByModel == nil {
				m.ByModel = map[string]store.ModelTokens{}
			}
			t := m.ByModel[name]
			addTokens(&t, u)
			m.ByModel[name] = t
		}
		names := strings.Split(r.Models, ",")
		if r.Models == "" && r.Model != "" {
			names = []string{r.Model}
		}
		for _, n := range names {
			if n = strings.TrimSpace(n); n != "" && !seenModels[n] {
				seenModels[n] = true
				m.Models = append(m.Models, n)
			}
		}
	}
}

func addTokens(t *store.ModelTokens, u store.ModelTokens) {
	t.Input += u.Input
	t.Output += u.Output
	t.CacheRead += u.CacheRead
	t.CacheCreation += u.CacheCreation
	t.CostUSD += u.CostUSD
}

func startedModel(r store.Run) bool {
	switch r.State {
	case store.StateSkipped:
		return false
	case store.StateQueued:
		return false
	}
	if r.State == store.StateFailed && r.NumTurns == 0 && r.CostUSD == 0 && r.DurationMS == 0 {
		// Failed before the container (engine missing, config): no model.
		return r.Reason != "config" && r.Reason != "engine"
	}
	return true
}

func ms(v int64) time.Duration { return time.Duration(v) * time.Millisecond }

type resultCounts struct{ findings, updates, checked int }

func countResult(raw []byte) resultCounts {
	var doc struct {
		Findings []struct {
			PreviouslyReported bool `json:"previously_reported"`
		} `json:"findings"`
		Checked []json.RawMessage `json:"checked"`
	}
	var c resultCounts
	if json.Unmarshal(raw, &doc) != nil {
		return c
	}
	for _, f := range doc.Findings {
		if f.PreviouslyReported {
			c.updates++
		} else {
			c.findings++
		}
	}
	c.checked = len(doc.Checked)
	return c
}

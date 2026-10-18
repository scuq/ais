package sink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

// Digest summarises the runs of one task in a window. It is the body of a
// "digest" event: what a quiet day cost, so that silence from a sink with
// skipEmpty is distinguishable from a daemon that did not run.
type Digest struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Runs        int       `json:"runs"`
	Succeeded   int       `json:"succeeded"`
	// Failed counts failed, leaked and timed-out runs; Skipped counts
	// overlap skips and cancellations; Quiet counts feed checks that found
	// nothing new and started no container.
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
	Quiet    int `json:"quiet"`
	Findings int `json:"findings"`
	// Checked is the number of items in the checked lists of the results,
	// when the task's output has such a list (vuln-watch does).
	Checked *int       `json:"checked,omitempty"`
	NextRun *time.Time `json:"next_run,omitempty"`
}

// DigestPayload is what a digest delivery stores: its window, and the next
// scheduled run at the time it was queued.
type DigestPayload struct {
	WindowStart time.Time  `json:"window_start"`
	WindowEnd   time.Time  `json:"window_end"`
	NextRun     *time.Time `json:"next_run,omitempty"`
}

// ErrNoRun means the task has no finished run to attach a digest to.
var ErrNoRun = errors.New("digest: the task has no finished run")

// maxDigestResults bounds the results read for one digest; the store caps
// a larger limit anyway.
const maxDigestResults = 200

// BuildDigest reads the runs and results of task in the window and returns
// the digest, the summed run metadata, and the id of the newest run in the
// window. A delivery hangs on that run. Without a run in the window the
// anchor is the newest run of the task of any age; with none, ErrNoRun.
func BuildDigest(ctx context.Context, st *store.Store, taskName string, p DigestPayload) (Digest, Meta, string, error) {
	dg := Digest{WindowStart: p.WindowStart, WindowEnd: p.WindowEnd, NextRun: p.NextRun}
	meta := Meta{Billing: config.Billing}
	runs, err := st.RunsBetween(ctx, taskName, p.WindowStart, p.WindowEnd)
	if err != nil {
		return dg, meta, "", err
	}
	anchor := ""
	seen := map[string]bool{}
	for _, r := range runs {
		dg.Runs++
		switch r.State {
		case store.StateSucceeded:
			dg.Succeeded++
		case store.StateSkipped, store.StateCancelled:
			if r.Reason == "quiet" {
				dg.Quiet++
			} else {
				dg.Skipped++
			}
		default:
			dg.Failed++
		}
		meta.CostUSD += r.CostUSD
		meta.NumTurns += r.NumTurns
		meta.DurationMS += r.DurationMS
		meta.Tokens.Input += r.InputTokens
		meta.Tokens.Output += r.OutputTokens
		meta.Tokens.CacheRead += r.CacheReadTokens
		meta.Tokens.CacheCreation += r.CacheCreationTokens
		models := splitModels(r.Models)
		if len(models) == 0 && r.Model != "" {
			models = []string{r.Model}
		}
		for _, m := range models {
			if !seen[m] {
				seen[m] = true
				meta.Models = append(meta.Models, m)
			}
		}
		anchor = r.ID
		meta.TaskHash, meta.Engine = r.TaskHash, r.Engine
	}
	if len(meta.Models) > 0 {
		meta.Model = meta.Models[0]
	}
	if anchor == "" {
		latest, err := st.ListRuns(ctx, taskName, "", 1)
		if err != nil {
			return dg, meta, "", err
		}
		if len(latest) == 0 || !store.Terminal(latest[0].State) {
			return dg, meta, "", ErrNoRun
		}
		anchor = latest[0].ID
	}
	results, err := st.RecentResults(ctx, taskName, p.WindowStart, maxDigestResults)
	if err != nil {
		return dg, meta, "", err
	}
	var checked int
	hasChecked := false
	for _, res := range results {
		if !res.FinishedAt.Before(p.WindowEnd) {
			continue
		}
		raw := res.ClearJSON
		if raw == nil {
			raw = res.PseudoJSON
		}
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			continue
		}
		if arr, ok := doc["findings"].([]any); ok {
			dg.Findings += len(arr)
		}
		if arr, ok := doc["checked"].([]any); ok {
			hasChecked = true
			checked += len(arr)
		}
	}
	if hasChecked {
		dg.Checked = &checked
	}
	return dg, meta, anchor, nil
}

// QueueDigest queues a digest delivery for each sink of t, for the window
// of t.Digest that ends at end. It returns the reason when nothing is
// queued: the window had findings and the digest is not always sent, or
// the task has no run yet.
func QueueDigest(ctx context.Context, st *store.Store, t *task.Task, end time.Time, nextRun *time.Time, now time.Time) (string, error) {
	if t.Digest == nil {
		return "task has no digest", nil
	}
	p := DigestPayload{WindowStart: end.Add(-t.Digest.Window), WindowEnd: end, NextRun: nextRun}
	dg, _, anchor, err := BuildDigest(ctx, st, t.Name, p)
	if errors.Is(err, ErrNoRun) {
		return "no finished run", nil
	}
	if err != nil {
		return "", err
	}
	if dg.Findings > 0 && !t.Digest.Always {
		return fmt.Sprintf("%d finding(s) in the window", dg.Findings), nil
	}
	if len(t.Sinks) == 0 {
		return "task has no sinks", nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	for _, s := range t.Sinks {
		if err := st.EnqueueDeliveryPayload(ctx, anchor, s, "digest", string(raw), now); err != nil {
			return "", err
		}
	}
	return "", nil
}

// LoadDigest builds the digest event of a task for a payload.
func (d *Dispatcher) LoadDigest(ctx context.Context, taskName string, p DigestPayload) (Event, error) {
	dg, meta, anchor, err := BuildDigest(ctx, d.Store, taskName, p)
	if err != nil {
		return Event{}, err
	}
	meta.AISVersion = d.Version
	meta.Host, _ = os.Hostname()
	return Event{Kind: "digest", Task: taskName, RunID: anchor, State: "digest", FinishedAt: p.WindowEnd, Digest: &dg, Meta: meta}, nil
}

// WindowLabel renders the length of the window for a footer: "24 h",
// "3 days", "90 min".
func (dg Digest) WindowLabel() string {
	w := dg.WindowEnd.Sub(dg.WindowStart)
	switch {
	case w >= 48*time.Hour && w%(24*time.Hour) == 0:
		return fmt.Sprintf("%d days", int(w/(24*time.Hour)))
	case w >= time.Hour && w%time.Hour == 0:
		return fmt.Sprintf("%d h", int(w/time.Hour))
	}
	return fmt.Sprintf("%d min", int(w/time.Minute))
}

// RunsLine renders the run counts: "12 runs (11 succeeded, 1 failed)".
func (dg Digest) RunsLine() string {
	var parts []string
	if dg.Succeeded > 0 {
		parts = append(parts, fmt.Sprintf("%d succeeded", dg.Succeeded))
	}
	if dg.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", dg.Failed))
	}
	if dg.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", dg.Skipped))
	}
	if dg.Quiet > 0 {
		parts = append(parts, fmt.Sprintf("%d quiet", dg.Quiet))
	}
	line := fmt.Sprintf("%d run(s)", dg.Runs)
	if len(parts) > 0 {
		line += " (" + strings.Join(parts, ", ") + ")"
	}
	return line
}

package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/store"
)

// Dispatcher drains the delivery queue.
type Dispatcher struct {
	Store   *store.Store
	Sinks   map[string]Sink
	Cfg     config.DeliveryConfig
	Version string
	Log     *slog.Logger
	// Poll is the queue polling interval; zero means 5s.
	Poll time.Duration
	Now  func() time.Time
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Dispatcher) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// Start polls until ctx ends.
func (d *Dispatcher) Start(ctx context.Context) {
	poll := d.Poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		if _, err := d.Once(ctx); err != nil && ctx.Err() == nil {
			d.log().Error("dispatch", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Backoff returns the delay before attempt n (1-based) with jitter.
func Backoff(cfg config.BackoffConfig, attempt int) time.Duration {
	initial, maxd := cfg.Initial, cfg.Max
	if initial <= 0 {
		initial = 30 * time.Second
	}
	if maxd <= 0 {
		maxd = time.Hour
	}
	d := initial
	for i := 1; i < attempt && d < maxd; i++ {
		d *= 2
	}
	if d > maxd {
		d = maxd
	}
	return d + time.Duration(rand.Int63n(int64(d)/4+1))
}

// Once processes every due delivery and returns how many it handled.
func (d *Dispatcher) Once(ctx context.Context) (int, error) {
	now := d.now()
	due, err := d.Store.DueDeliveries(ctx, now, 50)
	if err != nil {
		return 0, err
	}
	for _, del := range due {
		d.deliver(ctx, del)
	}
	return len(due), nil
}

func (d *Dispatcher) deliver(ctx context.Context, del store.Delivery) {
	now := d.now()
	log := d.log().With("run", del.RunID, "sink", del.Sink, "kind", del.Kind, "attempt", del.Attempt+1)
	fail := func(err error, permanent bool) {
		attempt := del.Attempt + 1
		if permanent || attempt >= d.Cfg.MaxAttempts {
			log.Error("delivery dead", "error", err)
			_ = d.Store.UpdateDelivery(ctx, del.ID, store.DeliveryDead, attempt, now, err.Error(), now)
			return
		}
		next := now.Add(Backoff(d.Cfg.Backoff, attempt))
		log.Warn("delivery failed, will retry", "error", err, "next", next.Format(time.RFC3339))
		_ = d.Store.UpdateDelivery(ctx, del.ID, store.DeliveryPending, attempt, next, err.Error(), now)
	}
	s, ok := d.Sinks[del.Sink]
	if !ok {
		fail(fmt.Errorf("sink %q is not configured", del.Sink), true)
		return
	}
	ev, err := d.LoadEvent(ctx, del.RunID, del.Kind)
	if err != nil {
		fail(err, true)
		return
	}
	if sk, ok := s.(Skipper); ok {
		if reason := sk.Skip(ev); reason != "" {
			log.Info("delivery skipped", "reason", reason)
			_ = d.Store.UpdateDelivery(ctx, del.ID, store.DeliverySkipped, del.Attempt+1, now, reason, now)
			return
		}
	}
	if err := s.Deliver(ctx, ev); err != nil {
		fail(err, IsPermanent(err))
		return
	}
	log.Info("delivered")
	_ = d.Store.UpdateDelivery(ctx, del.ID, store.DeliveryDelivered, del.Attempt+1, now, "", now)
}

// LoadEvent builds the event for a run from the store.
func (d *Dispatcher) LoadEvent(ctx context.Context, runID, kind string) (Event, error) {
	r, err := d.Store.GetRun(ctx, runID)
	if err != nil {
		return Event{}, err
	}
	host, _ := os.Hostname()
	ev := Event{
		Kind: kind, Task: r.Task, RunID: r.ID, State: r.State, Reason: r.Reason, Error: r.Error, FinishedAt: r.FinishedAt,
		Meta: Meta{Model: r.Model, Models: splitModels(r.Models), Billing: config.Billing, CostUSD: r.CostUSD, NumTurns: r.NumTurns, DurationMS: r.DurationMS,
			Tokens:   Tokens{Input: r.InputTokens, Output: r.OutputTokens, CacheRead: r.CacheReadTokens, CacheCreation: r.CacheCreationTokens},
			TaskHash: r.TaskHash, Engine: r.Engine, AISVersion: d.Version, Host: host},
	}
	switch kind {
	case "result":
		res, err := d.Store.GetResult(ctx, runID)
		if err != nil {
			return ev, err
		}
		if res.ClearJSON == nil {
			return ev, fmt.Errorf("run %s has no clear result", runID)
		}
		var doc any
		if err := json.Unmarshal(res.ClearJSON, &doc); err != nil {
			return ev, err
		}
		ev.Result = doc
	case "alert":
		leaks, _ := d.Store.Leaks(ctx, runID)
		seen := map[string]bool{}
		for _, l := range leaks {
			f := l.Field
			if f == "" {
				f = "unknown"
			}
			if !seen[f] {
				seen[f] = true
				ev.Leaks = append(ev.Leaks, f)
			}
		}
	default:
		return ev, fmt.Errorf("unknown delivery kind %q", kind)
	}
	return ev, nil
}

// splitModels returns the models in s, which is a comma-separated list.
// If s is empty, splitModels returns nil.
func splitModels(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

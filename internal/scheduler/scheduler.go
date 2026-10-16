// Package scheduler fires tasks on their cron schedules. One goroutine per
// enabled task computes the next tick, adds jitter, waits, and hands the run
// to the Runner under a global parallelism cap. Overlap is the Runner's
// business (it skips when a run of the same task is active); missed ticks
// while the daemon was down are not replayed.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/adhocore/gronx"

	"github.com/scuq/ais/internal/task"
)

// Runner executes one scheduled run.
type Runner interface {
	Run(ctx context.Context, t *task.Task, trigger string) error
}

// Options configure a Scheduler.
type Options struct {
	Location      *time.Location
	DefaultJitter time.Duration
	MaxParallel   int
	Log           *slog.Logger
	// Now and Timer are the clock; nil means the real one. Tests inject
	// both.
	Now   func() time.Time
	Timer func(d time.Duration) <-chan time.Time
}

// Scheduler owns the per-task loops.
type Scheduler struct {
	opts   Options
	runner Runner
	sem    chan struct{}

	mu      sync.Mutex
	tasks   map[string]*task.Task
	cancels map[string]context.CancelFunc
	next    map[string]time.Time
	paused  map[string]string
	wg      sync.WaitGroup
	ctx     context.Context
}

// New returns a scheduler for the given tasks.
func New(tasks []*task.Task, r Runner, opts Options) *Scheduler {
	if opts.Location == nil {
		opts.Location = time.Local
	}
	if opts.MaxParallel < 1 {
		opts.MaxParallel = 1
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Timer == nil {
		opts.Timer = func(d time.Duration) <-chan time.Time { return time.After(d) }
	}
	s := &Scheduler{
		opts:    opts,
		runner:  r,
		sem:     make(chan struct{}, opts.MaxParallel),
		tasks:   map[string]*task.Task{},
		cancels: map[string]context.CancelFunc{},
		next:    map[string]time.Time{},
		paused:  map[string]string{},
	}
	for _, t := range tasks {
		s.tasks[t.Name] = t
	}
	return s
}

// NextRun returns the next tick strictly after t, in loc.
func NextRun(expr string, after time.Time, loc *time.Location) (time.Time, error) {
	return gronx.NextTickAfter(expr, after.In(loc), false)
}

// Start launches the loops. It returns immediately; Wait blocks until they
// end after ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = ctx
	for _, t := range s.tasks {
		s.startLocked(t)
	}
}

func (s *Scheduler) startLocked(t *task.Task) {
	if !t.IsEnabled() {
		s.opts.Log.Info("task disabled", "task", t.Name)
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.cancels[t.Name] = cancel
	s.wg.Add(1)
	go s.loop(ctx, t)
}

// Wait blocks until every loop has exited.
func (s *Scheduler) Wait() { s.wg.Wait() }

func (s *Scheduler) loop(ctx context.Context, t *task.Task) {
	defer s.wg.Done()
	log := s.opts.Log.With("task", t.Name)
	for {
		now := s.opts.Now()
		next, err := NextRun(t.Schedule, now, s.opts.Location)
		if err != nil {
			log.Error("schedule", "error", err)
			return
		}
		if j := t.JitterOr(s.opts.DefaultJitter); j > 0 {
			next = next.Add(time.Duration(rand.Int63n(int64(j))))
		}
		s.mu.Lock()
		s.next[t.Name] = next
		s.mu.Unlock()
		log.Info("next run", "at", next.Format(time.RFC3339))
		select {
		case <-ctx.Done():
			return
		case <-s.opts.Timer(next.Sub(now)):
		}
		if reason := s.pausedReason(t.Name); reason != "" {
			log.Warn("paused, tick skipped", "reason", reason)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case s.sem <- struct{}{}:
		}
		if err := s.runner.Run(ctx, t, "schedule"); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("run", "error", err)
		}
		<-s.sem
	}
}

func (s *Scheduler) pausedReason(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.paused[name]
}

// Pause stops a task from firing until Resume; the loop keeps ticking.
func (s *Scheduler) Pause(name, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paused[name] = reason
}

// Resume clears a pause.
func (s *Scheduler) Resume(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.paused, name)
}

// Reload replaces the task set: unchanged tasks (same hash) keep their
// loop, changed ones are restarted, removed ones are stopped. Every pause
// is cleared: a reload is the operator saying the cause (a rotated token)
// is fixed.
func (s *Scheduler) Reload(tasks []*task.Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.paused {
		s.opts.Log.Info("pause cleared by reload", "task", name)
	}
	s.paused = map[string]string{}
	incoming := map[string]*task.Task{}
	for _, t := range tasks {
		incoming[t.Name] = t
	}
	for name, old := range s.tasks {
		nw, ok := incoming[name]
		if ok && nw.Hash == old.Hash && nw.IsEnabled() == old.IsEnabled() {
			continue
		}
		if cancel := s.cancels[name]; cancel != nil {
			cancel()
			delete(s.cancels, name)
		}
		delete(s.next, name)
		if !ok {
			s.opts.Log.Info("task removed", "task", name)
			delete(s.tasks, name)
		}
	}
	for name, t := range incoming {
		old, existed := s.tasks[name]
		if existed && old.Hash == t.Hash && old.IsEnabled() == t.IsEnabled() {
			continue
		}
		s.tasks[name] = t
		if s.ctx != nil {
			s.startLocked(t)
			s.opts.Log.Info("task (re)loaded", "task", name, "hash", t.Hash)
		}
	}
}

// Upcoming lists the next fire time per task, sorted by time.
type Upcoming struct {
	Task   string    `json:"task"`
	At     time.Time `json:"at"`
	Paused string    `json:"paused,omitempty"`
}

// Next returns the upcoming fire times.
func (s *Scheduler) Next() []Upcoming {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Upcoming, 0, len(s.next))
	for name, at := range s.next {
		out = append(out, Upcoming{Task: name, At: at, Paused: s.paused[name]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// Describe renders the schedule of a task for humans.
func Describe(t *task.Task, loc *time.Location, now time.Time) string {
	next, err := NextRun(t.Schedule, now, loc)
	if err != nil {
		return fmt.Sprintf("%s (invalid: %v)", t.Schedule, err)
	}
	return fmt.Sprintf("%s (next %s)", t.Schedule, next.Format("2006-01-02 15:04 MST"))
}

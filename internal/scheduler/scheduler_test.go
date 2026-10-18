package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/scuq/ais/internal/task"
)

type fakeRunner struct {
	mu    sync.Mutex
	runs  []string
	block chan struct{}
}

func (f *fakeRunner) Run(ctx context.Context, t *task.Task, trigger string) error {
	f.mu.Lock()
	f.runs = append(f.runs, t.Name+":"+trigger)
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
		}
	}
	return nil
}

func (f *fakeRunner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

func mkTask(name, schedule string) *task.Task {
	t, err := task.Parse([]byte("version: 1\nname: "+name+"\nschedule: '"+schedule+"'\nprompt: p\noutputSchema: {type: object}\njitter: 0s\n"), task.Defaults{Model: "m", MaxTurns: 1, MaxBudgetUSD: 1, Timeout: time.Minute})
	if err != nil {
		panic(err)
	}
	return t
}

func TestNextRun(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 10, 13, 10, 30, 0, 0, loc)
	next, err := NextRun("7 * * * *", now, loc)
	if err != nil || !next.Equal(time.Date(2026, 10, 13, 11, 7, 0, 0, loc)) {
		t.Errorf("next %v err %v", next, err)
	}
	next, _ = NextRun("@hourly", now, loc)
	if !next.Equal(time.Date(2026, 10, 13, 11, 0, 0, 0, loc)) {
		t.Errorf("hourly %v", next)
	}
}

// fakeClock fires the timer immediately and advances the clock past the
// tick, so a loop iteration happens per Timer call.
func fakeClock(start time.Time) (func() time.Time, func(time.Duration) <-chan time.Time, *sync.Mutex, *time.Time) {
	var mu sync.Mutex
	now := start
	nowFn := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	timer := func(d time.Duration) <-chan time.Time {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
		ch := make(chan time.Time, 1)
		ch <- now
		return ch
	}
	return nowFn, timer, &mu, &now
}

func TestLoopFiresAndRespectsPause(t *testing.T) {
	nowFn, timer, _, _ := fakeClock(time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC))
	r := &fakeRunner{block: make(chan struct{})}
	s := New([]*task.Task{mkTask("a", "@hourly")}, r, Options{Location: time.UTC, Now: nowFn, Timer: timer, MaxParallel: 1})
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for r.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if r.count() != 1 {
		t.Fatalf("expected one run, got %d", r.count())
	}
	if up := s.Next(); len(up) != 1 || up[0].Task != "a" {
		t.Errorf("upcoming %+v", up)
	}
	s.Pause("a", "auth")
	r.block <- struct{}{} // let the first run finish; the next tick is paused
	time.Sleep(20 * time.Millisecond)
	cancel()
	s.Wait()
	if r.count() != 1 {
		t.Errorf("paused task ran: %d", r.count())
	}
}

func TestMaxParallel(t *testing.T) {
	nowFn, timer, _, _ := fakeClock(time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC))
	r := &fakeRunner{block: make(chan struct{})}
	s := New([]*task.Task{mkTask("a", "@hourly"), mkTask("b", "@hourly"), mkTask("c", "@hourly")}, r, Options{Location: time.UTC, Now: nowFn, Timer: timer, MaxParallel: 2})
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	if r.count() != 2 {
		t.Errorf("expected 2 concurrent runs under MaxParallel=2, got %d", r.count())
	}
	cancel()
	s.Wait()
}

func TestReloadRestartsChanged(t *testing.T) {
	nowFn, timer, _, _ := fakeClock(time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC))
	r := &fakeRunner{block: make(chan struct{})}
	a := mkTask("a", "@hourly")
	s := New([]*task.Task{a}, r, Options{Location: time.UTC, Now: nowFn, Timer: timer, MaxParallel: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	time.Sleep(20 * time.Millisecond)
	a2 := mkTask("a", "@daily")
	s.Reload([]*task.Task{a2, mkTask("b", "@hourly")})
	time.Sleep(30 * time.Millisecond)
	s.mu.Lock()
	_, hasB := s.cancels["b"]
	_, hasA := s.cancels["a"]
	s.mu.Unlock()
	if !hasA || !hasB {
		t.Errorf("loops after reload: a=%v b=%v", hasA, hasB)
	}
	s.Reload(nil)
	s.mu.Lock()
	n := len(s.cancels)
	s.mu.Unlock()
	if n != 0 {
		t.Errorf("loops left after removing all tasks: %d", n)
	}
	cancel()
	s.Wait()
}

func TestFullRunTrigger(t *testing.T) {
	for trig, want := range map[string]bool{TriggerSchedule: false, TriggerScheduleFull: true, TriggerManual: false, TriggerManualFull: true, "": false} {
		if FullRun(trig) != want {
			t.Errorf("%q: %v", trig, FullRun(trig))
		}
	}
}

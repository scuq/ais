package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/runner"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

func TestGuardedRunnerRedactionGate(t *testing.T) {
	cfg := config.Defaults()
	st, err := store.Open(filepath.Join(t.TempDir(), "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tk, _ := task.Parse([]byte("version: 1\nname: t\nschedule: '@hourly'\nprompt: p\noutputSchema: {type: object}\n"), task.Defaults{Model: "m", MaxTurns: 1, MaxBudgetUSD: 1, Timeout: time.Minute})
	ran := 0
	r := &runner.Runner{Cfg: &cfg, Store: st}
	g := &guardedRunner{r: r, cfg: &cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil)), loc: time.UTC, pii: cfg.PII,
		run: func(ctx context.Context, t *task.Task, trigger string) (*runner.Outcome, error) {
			ran++
			return &runner.Outcome{Run: store.Run{State: store.StateSucceeded}}, nil
		}}
	if err := g.Run(context.Background(), tk, "schedule"); err != nil {
		t.Fatal(err)
	}
	runs, _ := st.ListRuns(context.Background(), "t", "", 5)
	if ran != 0 || len(runs) != 1 || runs[0].State != store.StateSkipped || runs[0].Reason != runner.ReasonRedaction {
		t.Fatalf("unapproved policy must skip: ran=%d runs=%+v", ran, runs)
	}
	approved := cfg.PII
	approved.ApprovedHash = cfg.Redaction().ApprovalHash()
	g.setPolicy(approved)
	if err := g.Run(context.Background(), tk, "schedule"); err != nil {
		t.Fatal(err)
	}
	if ran != 1 || r.Cfg.PII.ApprovedHash != approved.ApprovedHash {
		t.Errorf("approved policy must run and reach the runner config: ran=%d", ran)
	}
	// A policy edit after approval closes the gate again.
	edited := approved
	edited.Literals = []string{"secret-project"}
	g.setPolicy(edited)
	_ = g.Run(context.Background(), tk, "schedule")
	if ran != 1 {
		t.Error("edited policy must not run")
	}
}

func TestConfigOutsidePIIChanged(t *testing.T) {
	a := config.Defaults()
	b := config.Defaults()
	b.PII.Literals = []string{"x"}
	if configOutsidePIIChanged(&a, &b) {
		t.Error("pii-only change must not count")
	}
	b.Runtime.Memory = "4g"
	if !configOutsidePIIChanged(&a, &b) {
		t.Error("runtime change must count")
	}
}

func TestDigestDue(t *testing.T) {
	loc := time.UTC
	since := time.Date(2026, 10, 17, 22, 0, 0, 0, loc)
	if _, ok := digestDue("30 22 * * *", since, since.Add(29*time.Minute), loc); ok {
		t.Error("due before the minute")
	}
	at, ok := digestDue("30 22 * * *", since, since.Add(31*time.Minute), loc)
	if !ok || !at.Equal(time.Date(2026, 10, 17, 22, 30, 0, 0, loc)) {
		t.Errorf("due: %v %v", at, ok)
	}
	// A tick that comes a day late still fires once, for the first missed minute.
	at, ok = digestDue("30 22 * * *", since, since.Add(26*time.Hour), loc)
	if !ok || at.Day() != 17 {
		t.Errorf("late tick: %v %v", at, ok)
	}
	if _, ok := digestDue("bad", since, since.Add(time.Hour), loc); ok {
		t.Error("invalid expression fired")
	}
}

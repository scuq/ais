package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/scuq/ais/internal/claude"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/pseudo"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/secret"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

// Reasons attached to terminal run states.
const (
	ReasonOverlap   = "overlap"
	ReasonAuth      = "auth"
	ReasonConfig    = "config"
	ReasonEngine    = "engine"
	ReasonExit      = "exit"
	ReasonBudget    = "budget"
	ReasonTurns     = "turns"
	ReasonSchema    = "schema"
	ReasonTimeout   = "timeout"
	ReasonLeak      = "leak"
	ReasonModel     = "model"
	ReasonRedaction = "redaction"
)

// TokenMinter issues the per-run bearer token the backend accepts. Nil
// means no backend: the MCP server is configured but unreachable, which
// only matters once the backend milestone exists.
type TokenMinter interface {
	MintRunToken(ctx context.Context, taskName, runID string, ttl time.Duration) (string, error)
}

// Runner executes runs.
type Runner struct {
	Cfg     *config.Config
	RT      runtime.Runtime
	Store   *store.Store
	Secrets secret.Store
	Tokens  TokenMinter
	Opts    Options
	Log     *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Outcome is what a finished run produced.
type Outcome struct {
	Run    store.Run
	Clear  any             // depseudonymized, enriched result; nil unless succeeded
	Pseudo json.RawMessage // the model's structured_output as returned
	Leaks  []pseudo.Finding
	Dir    string
}

// Succeeded reports whether the run ended in success.
func (o *Outcome) Succeeded() bool { return o.Run.State == store.StateSucceeded }

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

// maxCapture bounds what is kept of a container's stdout/stderr.
const maxCapture = 32 << 20

// Run executes one task now. trigger is "manual" or "schedule".
func (r *Runner) Run(ctx context.Context, t *task.Task, trigger string) (*Outcome, error) {
	now := r.now()
	log := r.log().With("task", t.Name)

	// Per-task lock: serialises scheduled and manual runs of the same task.
	lockDir := filepath.Join(r.Cfg.RunsDir(), t.Name)
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(lockDir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		run := store.Run{ID: NewRunID(now), Task: t.Name, TaskHash: t.Hash, State: store.StateSkipped, Trigger: trigger, Engine: r.Opts.Engine, StartedAt: now, Model: t.Model, Reason: ReasonOverlap}
		if err := r.Store.InsertRun(ctx, run); err != nil {
			return nil, err
		}
		log.Info("skipped: previous run still active", "run", run.ID)
		return &Outcome{Run: run}, nil
	}
	if active, ok, err := r.Store.ActiveRun(ctx, t.Name); err != nil {
		return nil, err
	} else if ok && r.now().Sub(active.StartedAt) < 2*t.Timeout {
		run := store.Run{ID: NewRunID(now), Task: t.Name, TaskHash: t.Hash, State: store.StateSkipped, Trigger: trigger, Engine: r.Opts.Engine, StartedAt: now, Model: t.Model, Reason: ReasonOverlap, Error: "run " + active.ID + " is still " + active.State}
		if err := r.Store.InsertRun(ctx, run); err != nil {
			return nil, err
		}
		return &Outcome{Run: run}, nil
	}

	token, err := r.Secrets.Get(r.Cfg.Claude.OAuthTokenSecret)
	if err != nil {
		return nil, err
	}
	if err := secret.CheckToken(token); err != nil {
		run := store.Run{ID: NewRunID(now), Task: t.Name, TaskHash: t.Hash, State: store.StateSkipped, Trigger: trigger, Engine: r.Opts.Engine, StartedAt: now, Model: t.Model, Reason: ReasonConfig, Error: "secret " + r.Cfg.Claude.OAuthTokenSecret + ": " + err.Error()}
		if err := r.Store.InsertRun(ctx, run); err != nil {
			return nil, err
		}
		log.Error("run refused: unusable token", "error", err)
		return &Outcome{Run: run}, nil
	}

	prep, err := Prepare(ctx, r.Cfg, t, r.Store, r.Opts)
	if err != nil {
		return nil, err
	}
	run := store.Run{ID: prep.RunID, Task: t.Name, TaskHash: t.Hash, State: store.StateRunning, Trigger: trigger, Engine: r.Opts.Engine, Dir: prep.RunDir, StartedAt: prep.StartedAt, Model: t.Model}
	if err := r.Store.InsertRun(ctx, run); err != nil {
		return nil, err
	}
	// The map must exist before the run so the backend can serve the same
	// tokens, and so a crash mid-run never loses the mapping.
	if err := r.Store.SavePseudonyms(ctx, prep.Map); err != nil {
		return nil, err
	}
	// Every prompt that leaves the host is logged before it leaves.
	pl := prep.PromptLog()
	if err := r.Store.SavePrompt(ctx, pl); err != nil {
		return nil, err
	}
	if err := AppendPromptLog(r.Cfg.RunsDir(), pl); err != nil {
		return nil, err
	}
	log.Info("prompt logged", "run", prep.RunID, "sha256", pl.SHA256, "bytes", pl.Bytes)

	runToken := ""
	if r.Tokens != nil {
		runToken, err = r.Tokens.MintRunToken(ctx, t.Name, prep.RunID, t.Timeout+5*time.Minute)
		if err != nil {
			return nil, err
		}
		defer func() { _ = r.Store.RevokeRunTokens(context.Background(), prep.RunID) }()
	}
	env := []string{"CLAUDE_CODE_OAUTH_TOKEN=" + token, "AIS_RUN_TOKEN=" + runToken}

	log.Info("starting", "run", prep.RunID, "engine", r.Opts.Engine, "model", t.Model)
	outcome := r.execute(ctx, prep, env, run)
	// Bookkeeping must complete even when ctx was cancelled mid-run; that is
	// exactly the case where the row must not be left open.
	ctx = context.WithoutCancel(ctx)
	if err := r.Store.FinishRun(ctx, outcome.Run); err != nil {
		return outcome, err
	}
	switch outcome.Run.State {
	case store.StateSucceeded:
		for _, sink := range t.Sinks {
			if err := r.Store.EnqueueDelivery(ctx, prep.RunID, sink, "result", r.now()); err != nil {
				return outcome, err
			}
		}
	case store.StateLeaked, store.StateFailed, store.StateTimeout:
		// Alerts go to the configured alert sinks; a leak is the loudest.
		for _, sink := range r.Cfg.Alerts {
			if err := r.Store.EnqueueDelivery(ctx, prep.RunID, sink, "alert", r.now()); err != nil {
				return outcome, err
			}
		}
	}
	log.Info("finished", "run", prep.RunID, "state", outcome.Run.State, "reason", outcome.Run.Reason, "cost_usd", outcome.Run.CostUSD, "turns", outcome.Run.NumTurns)
	return outcome, nil
}

// liveWriter splits the container's stdout into lines and renders each
// stream-json event for a human watching the run.
type liveWriter struct {
	out io.Writer
	buf []byte
}

func (l *liveWriter) Write(p []byte) (int, error) {
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		line := l.buf[:i]
		l.buf = l.buf[i+1:]
		if text, ok := claude.RenderStreamLine(line); ok {
			fmt.Fprintln(l.out, text)
		}
	}
	return len(p), nil
}

func (l *liveWriter) flush() {
	if len(bytes.TrimSpace(l.buf)) > 0 {
		if text, ok := claude.RenderStreamLine(l.buf); ok {
			fmt.Fprintln(l.out, text)
		}
	}
	l.buf = nil
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.buf.Len() < l.max {
		room := l.max - l.buf.Len()
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

// execute runs the container and classifies the outcome. It never returns
// an error: every failure becomes a terminal run state with a reason.
func (r *Runner) execute(parent context.Context, prep *Prepared, env []string, run store.Run) *Outcome {
	out := &Outcome{Run: run, Dir: prep.RunDir}
	t := prep.Task
	ctx, cancel := context.WithTimeout(parent, t.Timeout)
	defer cancel()

	stdoutFile, _ := os.OpenFile(filepath.Join(prep.RunDir, "stdout.json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	stderrFile, _ := os.OpenFile(filepath.Join(prep.RunDir, "stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	stdout := &limitedBuffer{max: maxCapture}
	stderr := &limitedBuffer{max: maxCapture}
	var so io.Writer = stdout
	var se io.Writer = stderr
	if stdoutFile != nil {
		defer stdoutFile.Close()
		so = io.MultiWriter(stdout, stdoutFile)
	}
	if r.Opts.Live != nil {
		lw := &liveWriter{out: r.Opts.Live}
		defer lw.flush()
		so = io.MultiWriter(so, lw)
		fmt.Fprintf(r.Opts.Live, "▶ run %s · prompt sha256 %s · %d bytes (aisctl prompts show %s)\n", prep.RunID, prep.PromptLog().SHA256[:16], prep.PromptLog().Bytes, prep.RunID)
	}
	if stderrFile != nil {
		defer stderrFile.Close()
		se = io.MultiWriter(stderr, stderrFile)
	}

	start := r.now()
	code, runErr := r.RT.RunCapture(ctx, prep.Argv, env, so, se)
	finish := func(state, reason, msg string) *Outcome {
		out.Run.State = state
		out.Run.Reason = reason
		out.Run.Error = msg
		out.Run.FinishedAt = r.now()
		out.Run.ExitCode = code
		if out.Run.DurationMS == 0 {
			out.Run.DurationMS = out.Run.FinishedAt.Sub(start).Milliseconds()
		}
		return out
	}

	if ctx.Err() != nil {
		// The engine client was killed; the container may still be running.
		r.stopContainer(prep.Spec.Name)
		if errors.Is(parent.Err(), context.Canceled) {
			return finish(store.StateCancelled, ReasonTimeout, "cancelled")
		}
		return finish(store.StateTimeout, ReasonTimeout, fmt.Sprintf("exceeded %s", t.Timeout))
	}
	if runErr != nil {
		return finish(store.StateFailed, ReasonEngine, runErr.Error())
	}

	env2, perr := claude.ParseEnvelope(stdout.buf.Bytes())
	if perr != nil {
		if code == 78 {
			return finish(store.StateFailed, ReasonConfig, firstLine(stderr.buf.Bytes()))
		}
		if claude.IsAuthFailure(nil, stderr.buf.Bytes()) {
			return finish(store.StateFailed, ReasonAuth, firstLine(stderr.buf.Bytes()))
		}
		return finish(store.StateFailed, ReasonExit, fmt.Sprintf("exit %d without a result envelope: %s", code, firstLine(stderr.buf.Bytes())))
	}
	out.Run.Subtype = env2.Subtype
	out.Run.CostUSD = env2.TotalCostUSD
	out.Run.NumTurns = env2.NumTurns
	if env2.DurationMS > 0 {
		out.Run.DurationMS = env2.DurationMS
	}
	u := env2.Tokens()
	out.Run.InputTokens, out.Run.OutputTokens = u.InputTokens, u.OutputTokens
	out.Run.CacheReadTokens, out.Run.CacheCreationTokens = u.CacheReadInputTokens, u.CacheCreationInputTokens
	if ms := env2.Models(); len(ms) > 0 {
		// The model that did most of the work replaces the configured
		// name, which can be an alias.
		out.Run.Model = ms[0]
		out.Run.Models = strings.Join(ms, ",")
	}
	out.Pseudo = env2.StructuredOutput

	if claude.IsAuthFailure(env2, stderr.buf.Bytes()) {
		return finish(store.StateFailed, ReasonAuth, truncate(env2.Result, 300))
	}
	switch env2.Subtype {
	case claude.SubtypeSuccess:
	case claude.SubtypeErrorMaxBudget:
		return finish(store.StateFailed, ReasonBudget, truncate(env2.Result, 300))
	case claude.SubtypeErrorMaxTurns:
		return finish(store.StateFailed, ReasonTurns, truncate(env2.Result, 300))
	case claude.SubtypeErrorStructuredOutput:
		return finish(store.StateFailed, ReasonSchema, "claude could not produce output matching the schema")
	default:
		if env2.IsError {
			return finish(store.StateFailed, ReasonModel, env2.Subtype+": "+truncate(env2.Result, 300))
		}
	}
	if env2.IsError {
		// Observed on 2.1.301: subtype "success" with is_error true and a
		// terminal_reason such as "api_error".
		return finish(store.StateFailed, ReasonModel, env2.TerminalReason+": "+truncate(env2.Result, 300))
	}

	schema, err := task.CompileSchema(t.SchemaJSON())
	if err != nil {
		return finish(store.StateFailed, ReasonSchema, err.Error())
	}
	doc, err := claude.ValidateOutput(schema, env2.StructuredOutput)
	if err != nil {
		return finish(store.StateFailed, ReasonSchema, err.Error())
	}

	// Leak check on everything the model emitted, not only the structured
	// part: prose in "result" counts too.
	out.Leaks = pseudo.LeakCheck(stdout.buf.Bytes(), prep.Map, prep.Rules)
	if len(out.Leaks) > 0 {
		_ = r.Store.SaveLeaks(context.Background(), prep.RunID, out.Leaks)
		_ = r.Store.SaveResult(context.Background(), prep.RunID, t.Name, r.now(), env2.StructuredOutput, nil)
		_ = os.WriteFile(filepath.Join(prep.RunDir, "result.json"), env2.StructuredOutput, 0o600)
		return finish(store.StateLeaked, ReasonLeak, fmt.Sprintf("%d real value(s) appeared in model output", len(out.Leaks)))
	}

	clear := pseudo.Depseudonymize(doc, prep.Map)
	clear, err = Enrich(clear, t.Enrich, prep.Records)
	if err != nil {
		return finish(store.StateFailed, ReasonSchema, "enrich: "+err.Error())
	}
	out.Clear = clear
	clearJSON, _ := json.Marshal(clear)
	pseudoJSON, _ := json.Marshal(doc)
	finishedAt := r.now()
	_ = r.Store.SaveResult(context.Background(), prep.RunID, t.Name, finishedAt, pseudoJSON, clearJSON)
	_ = os.WriteFile(filepath.Join(prep.RunDir, "result.json"), pseudoJSON, 0o600)
	_ = os.WriteFile(filepath.Join(prep.RunDir, "result.clear.json"), clearJSON, 0o600)
	r.appendNDJSON(t.Name, map[string]any{
		"run_id": prep.RunID, "task": t.Name, "finished_at": finishedAt.UTC().Format(time.RFC3339),
		"state": store.StateSucceeded, "cost_usd": env2.TotalCostUSD, "num_turns": env2.NumTurns,
		"models": out.Run.Models, "tokens_in": u.In(), "tokens_out": u.Out(), "result": doc,
	})
	return finish(store.StateSucceeded, "", "")
}

func (r *Runner) stopContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if running, _ := r.RT.ContainerRunning(ctx, name); running {
		_ = r.RT.Stop(ctx, name, runtime.StopOptions{TimeoutSeconds: 10})
	}
	if exists, _ := r.RT.ContainerExists(ctx, name); exists {
		_ = r.RT.Remove(ctx, name, runtime.RemoveOptions{Force: true})
	}
}

func (r *Runner) appendNDJSON(taskName string, row map[string]any) {
	f, err := os.OpenFile(filepath.Join(r.Cfg.RunsDir(), taskName, "runs.ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(row)
}

func firstLine(b []byte) string {
	b = bytes.TrimSpace(b)
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return truncate(string(b), 300)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

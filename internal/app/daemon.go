package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/scuq/ais/internal/backend"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/doctor"
	"github.com/scuq/ais/internal/egress"
	"github.com/scuq/ais/internal/image"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/pseudo"
	"github.com/scuq/ais/internal/runner"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/scheduler"
	"github.com/scuq/ais/internal/secret"
	"github.com/scuq/ais/internal/sink"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

func newLogger() *slog.Logger {
	if os.Getenv("AIS_LOG_FORMAT") == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// runFunc is the runner call the guard wraps; a var so tests can fake it.
type runFunc func(ctx context.Context, t *task.Task, trigger string) (*runner.Outcome, error)

// guardedRunner is what the scheduler calls: it applies the redaction gate,
// the daily budget cap and the consecutive-auth-failure pause around
// runner.Runner.
type guardedRunner struct {
	r     *runner.Runner
	run   runFunc
	cfg   *config.Config
	sched *scheduler.Scheduler
	log   *slog.Logger
	loc   *time.Location

	// pii is the current redaction policy; SIGHUP replaces it. The runner's
	// cfg.PII is updated at the same time, under the same lock.
	mu  sync.RWMutex
	pii config.PIIConfig
}

// policy returns the current policy and its approved hash.
func (g *guardedRunner) policy() config.PIIConfig {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.pii
}

// setPolicy replaces the policy for the next runs.
func (g *guardedRunner) setPolicy(p config.PIIConfig) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pii = p
	if g.r != nil && g.r.Cfg != nil {
		g.r.Cfg.PII = p
	}
}

func (g *guardedRunner) skip(ctx context.Context, t *task.Task, trigger, reason, msg string) error {
	engine := ""
	if g.r != nil {
		engine = g.r.Opts.Engine
	}
	return g.r.Store.InsertRun(ctx, store.Run{ID: runner.NewRunID(time.Now()), Task: t.Name, TaskHash: t.Hash, State: store.StateSkipped, Trigger: trigger, Engine: engine, StartedAt: time.Now(), Model: t.Model, Reason: reason, Error: msg})
}

func (g *guardedRunner) Run(ctx context.Context, t *task.Task, trigger string) error {
	cur := g.policy()
	pol := pseudo.Redaction{Domains: cur.Domains, CIDRs: cur.CIDRs, Literals: cur.Literals, HostnameMode: cur.HostnameMode, IPMode: cur.IPMode}
	if err := pseudo.CheckApproval(pol, cur.ApprovedHash); err != nil {
		g.log.Error("run refused: redaction policy not approved", "task", t.Name, "error", err)
		return g.skip(ctx, t, trigger, runner.ReasonRedaction, err.Error())
	}
	if g.cfg.Scheduler.DailyBudgetUSD > 0 {
		now := time.Now().In(g.loc)
		dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, g.loc)
		spent, err := g.r.Store.CostSince(ctx, "", dayStart)
		if err == nil && spent >= g.cfg.Scheduler.DailyBudgetUSD {
			g.log.Warn("daily budget reached, run skipped", "task", t.Name, "spent_usd", spent, "budget_usd", g.cfg.Scheduler.DailyBudgetUSD)
			return g.skip(ctx, t, trigger, runner.ReasonBudget, fmt.Sprintf("daily budget $%.2f reached", g.cfg.Scheduler.DailyBudgetUSD))
		}
	}
	run := g.run
	if run == nil {
		run = g.r.Run
	}
	out, err := run(ctx, t, trigger)
	if err != nil {
		return err
	}
	if out.Run.State == store.StateFailed && out.Run.Reason == runner.ReasonAuth && g.cfg.Scheduler.PauseAfterAuthFailures > 0 {
		n, _ := g.r.Store.ConsecutiveFailures(ctx, t.Name, runner.ReasonAuth)
		if n >= g.cfg.Scheduler.PauseAfterAuthFailures {
			g.log.Error("pausing task after consecutive authentication failures; rotate the token with 'claude setup-token' and 'ais secret set', then SIGHUP or restart", "task", t.Name, "failures", n)
			g.sched.Pause(t.Name, "auth")
		}
	}
	return nil
}

func cmdDaemon(ctx context.Context, p *output.Printer, args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := newLogger()
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.RedactionApproved(); err != nil {
		return err
	}
	loc, err := time.LoadLocation(cfg.Scheduler.Timezone)
	if err != nil {
		return fmt.Errorf("scheduler.timezone: %w", err)
	}
	tasks, err := loadTasks(cfg)
	if err != nil {
		return err
	}
	rt, err := runtime.Detect(cfg.Runtime.Engine)
	if err != nil {
		return err
	}
	if err := rt.Available(ctx); err != nil {
		return err
	}
	opts, err := runOptions(cfg)
	if err != nil {
		return err
	}
	secrets := secret.NewFileStore(cfg.SecretsDir())
	if _, err := secrets.Get(cfg.Claude.OAuthTokenSecret); err != nil {
		return err
	}
	if err := ensureImage(ctx, p, rt, cfg, true); err != nil {
		return err
	}
	warnPrefilterImages(ctx, rt, cfg, tasks, log)
	st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	sweepOrphans(ctx, rt, st, log)

	// Shared, reloadable task set.
	var tmu sync.RWMutex
	currentTasks := func() []*task.Task {
		tmu.RLock()
		defer tmu.RUnlock()
		return tasks
	}

	em := &egress.Manager{Cfg: cfg, RT: rt, SELinux: opts.SELinux, Info: func(f string, a ...any) { log.Info(fmt.Sprintf(f, a...)) }}
	if cfg.Egress.Mode == "proxy" {
		if err := em.Ensure(ctx, tasks); err != nil {
			return err
		}
	}

	be := &backend.Backend{Cfg: cfg, Store: st, Tasks: currentTasks, Log: log, Version: Version}
	opL, err := backend.ListenUnix(cfg.BackendSocket(), 0o600)
	if err != nil {
		return err
	}
	mcpL, err := backend.ListenUnix(backend.MCPSocket(cfg), 0o600)
	if err != nil {
		return err
	}
	var tcpL net.Listener
	if cfg.Backend.TCPListen != "" {
		tcpL, err = net.Listen("tcp", cfg.Backend.TCPListen)
		if err != nil {
			return err
		}
	}
	if cfg.Egress.Mode == "proxy" {
		if err := ensureBackendSidecar(ctx, p, cfg, em, opts); err != nil {
			return err
		}
	}

	sinks, err := sink.BuildAll(cfg.Sinks, secrets)
	if err != nil {
		return err
	}
	disp := &sink.Dispatcher{Store: st, Sinks: sinks, Cfg: cfg.Delivery, Version: Version, Log: log}

	r := &runner.Runner{Cfg: cfg, RT: rt, Store: st, Secrets: secrets, Tokens: backend.Minter{Store: st}, Opts: opts, Log: log}
	gr := &guardedRunner{r: r, cfg: cfg, log: log, loc: loc, pii: cfg.PII}
	sched := scheduler.New(tasks, gr, scheduler.Options{Location: loc, DefaultJitter: cfg.Scheduler.DefaultJitter, MaxParallel: cfg.Scheduler.MaxParallel, Log: log})
	gr.sched = sched
	be.Next = sched.Next

	runCtx, cancelRuns := context.WithCancel(ctx)
	defer cancelRuns()
	var wg sync.WaitGroup
	serve := func(l net.Listener, h http.Handler, name string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := backend.Serve(runCtx, l, h); err != nil {
				log.Error("backend listener", "name", name, "error", err)
			}
		}()
	}
	serve(opL, be.OperatorHandler(), "operator")
	serve(mcpL, be.RunHandler(), "mcp")
	if tcpL != nil {
		serve(tcpL, be.OperatorHandler(), "tcp")
	}
	wg.Add(1)
	go func() { defer wg.Done(); disp.Start(runCtx) }()
	wg.Add(1)
	go func() { defer wg.Done(); retentionLoop(runCtx, cfg, st, log) }()
	wg.Add(1)
	go func() { defer wg.Done(); tokenAgeLoop(runCtx, cfg, secrets, log) }()
	wg.Add(1)
	go func() { defer wg.Done(); digestLoop(runCtx, st, currentTasks, sched.Next, loc, log) }()
	sched.Start(runCtx)
	log.Info("ais daemon up", "version", Version, "engine", rt.Engine(), "tasks", len(tasks), "socket", cfg.BackendSocket(), "mcp_socket", backend.MCPSocket(cfg))
	for _, u := range sched.Next() {
		log.Info("scheduled", "task", u.Task, "next", u.At.Format(time.RFC3339))
	}

	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	for {
		select {
		case <-ctx.Done():
			return nil
		case s := <-sigs:
			switch s {
			case syscall.SIGHUP:
				nt, err := loadTasks(cfg)
				if err != nil {
					log.Error("reload: tasks not replaced", "error", err)
					continue
				}
				tmu.Lock()
				tasks = nt
				tmu.Unlock()
				sched.Reload(nt)
				reloadPolicy(cfg, gr, log)
				if cfg.Egress.Mode == "proxy" {
					if err := em.Ensure(ctx, nt); err != nil {
						log.Error("reload: egress", "error", err)
					}
				}
				log.Info("reloaded", "tasks", len(nt))
			default:
				log.Info("shutting down: stopping runs", "signal", s.String())
				cancelRuns()
				done := make(chan struct{})
				go func() { sched.Wait(); wg.Wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(80 * time.Second):
					log.Warn("shutdown timed out")
				}
				return nil
			}
		}
	}
}

// digestLoop queues the digest of each task whose digest schedule came due
// since the last tick. It reads the current tasks on every tick, so a
// reload needs no extra plumbing. A daemon that was down at the scheduled
// minute does not send that digest.
func digestLoop(ctx context.Context, st *store.Store, tasks func() []*task.Task, next func() []scheduler.Upcoming, loc *time.Location, log *slog.Logger) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	start := time.Now()
	last := map[string]time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		for _, tk := range tasks() {
			if tk.Digest == nil || (tk.Enabled != nil && !*tk.Enabled) {
				continue
			}
			since := last[tk.Name]
			if since.IsZero() {
				since = start
			}
			due, ok := digestDue(tk.Digest.Schedule, since, now, loc)
			if !ok {
				continue
			}
			last[tk.Name] = now
			var nextRun *time.Time
			for _, u := range next() {
				if u.Task == tk.Name {
					at := u.At
					nextRun = &at
				}
			}
			reason, err := sink.QueueDigest(ctx, st, tk, due, nextRun, now)
			switch {
			case err != nil:
				log.Error("digest not queued", "task", tk.Name, "error", err)
			case reason != "":
				log.Info("digest not sent", "task", tk.Name, "reason", reason)
			default:
				log.Info("digest queued", "task", tk.Name, "window_end", due.Format(time.RFC3339), "sinks", len(tk.Sinks))
			}
		}
	}
}

// digestDue returns the first tick of expr after since, if it has passed.
func digestDue(expr string, since, now time.Time, loc *time.Location) (time.Time, bool) {
	at, err := scheduler.NextRun(expr, since, loc)
	if err != nil || at.After(now) {
		return time.Time{}, false
	}
	return at, true
}

// reloadPolicy re-reads config.yaml on SIGHUP and applies its pii: section.
// Other sections cannot change live (listeners, engine, sinks), so a
// difference there is logged with the advice to restart.
func reloadPolicy(running *config.Config, gr *guardedRunner, log *slog.Logger) {
	fresh, err := config.Load()
	if err == nil {
		err = fresh.Validate()
	}
	if err != nil {
		log.Error("reload: config.yaml not applied", "error", err)
		return
	}
	gr.setPolicy(fresh.PII)
	if err := fresh.RedactionApproved(); err != nil {
		log.Error("reload: redaction policy not approved; scheduled runs are skipped until 'aisctl redact approve'", "hash", fresh.Redaction().ApprovalHash())
	} else {
		log.Info("reload: redaction policy applied", "hash", fresh.PII.ApprovedHash)
	}
	if configOutsidePIIChanged(running, &fresh) {
		log.Warn("reload: config.yaml changed outside pii:; restart the daemon to apply those changes")
	}
}

// configOutsidePIIChanged compares two configs ignoring the pii section.
func configOutsidePIIChanged(a, b *config.Config) bool {
	ca, cb := *a, *b
	ca.PII, cb.PII = config.PIIConfig{}, config.PIIConfig{}
	ra, _ := config.Render(ca)
	rb, _ := config.Render(cb)
	return ra != rb
}

// warnPrefilterImages logs a warning for every prefilter image a task
// needs that is missing or stale. The daemon never builds it: the export
// downloads torch and the model, which is an operator's decision.
func warnPrefilterImages(ctx context.Context, rt runtime.Runtime, cfg *config.Config, tasks []*task.Task, log *slog.Logger) {
	seen := map[string]bool{}
	for _, t := range tasks {
		if t.Feeds == nil || !t.Feeds.Prefilter.Enabled() || seen[t.Feeds.Prefilter.Image] {
			continue
		}
		ref := t.Feeds.Prefilter.Image
		seen[ref] = true
		exists, current, err := image.PrefilterIsCurrent(ctx, rt, cfg, ref)
		switch {
		case err != nil:
			log.Warn("prefilter image check failed", "image", ref, "error", err)
		case !exists:
			log.Warn("prefilter image missing; feed items are kept unscored until it is built", "image", ref, "task", t.Name, "hint", "ais prefilter build")
		case !current:
			log.Warn("prefilter image was built from another recipe or model", "image", ref, "hint", "ais prefilter build")
		}
	}
}

// sweepOrphans closes run rows left in running/queued by a process that
// died (a crash, a kill) when their container no longer runs.
func sweepOrphans(ctx context.Context, rt runtime.Runtime, st *store.Store, log *slog.Logger) {
	for _, state := range []string{store.StateRunning, store.StateQueued} {
		runs, err := st.ListRuns(ctx, "", state, 200)
		if err != nil {
			continue
		}
		for _, r := range runs {
			name := runner.ContainerName(r.Task, r.ID)
			if running, _ := rt.ContainerRunning(ctx, name); running {
				continue
			}
			if exists, _ := rt.ContainerExists(ctx, name); exists {
				_ = rt.Remove(ctx, name, runtime.RemoveOptions{Force: true})
			}
			r.State, r.Reason, r.Error, r.FinishedAt = store.StateCancelled, "orphan", "no process owned this run at daemon start", time.Now()
			if err := st.FinishRun(ctx, r); err == nil {
				log.Warn("closed orphaned run", "task", r.Task, "run", r.ID)
			}
		}
	}
}

// tokenAgeLoop warns once a day while the OAuth token is near or past its
// expected lifetime, so rotation happens before runs start failing.
func tokenAgeLoop(ctx context.Context, cfg *config.Config, secrets secret.Store, log *slog.Logger) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		switch status, detail := doctor.TokenCheck(cfg, secrets, time.Now()); status {
		case "fail":
			log.Error("oauth token has probably expired", "secret", cfg.Claude.OAuthTokenSecret, "detail", detail)
		case "warn":
			log.Warn("oauth token expires soon", "secret", cfg.Claude.OAuthTokenSecret, "detail", detail)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// retentionLoop prunes old runs and their directories once an hour.
func retentionLoop(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		prune(ctx, cfg, st, log)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func prune(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) {
	entries, err := os.ReadDir(cfg.RunsDir())
	if err != nil {
		return
	}
	before := time.Time{}
	if cfg.Retention.KeepDays > 0 {
		before = time.Now().AddDate(0, 0, -cfg.Retention.KeepDays)
	}
	keep := cfg.Retention.KeepRuns
	if keep <= 0 {
		keep = 1 << 30
	}
	if !before.IsZero() {
		if n, err := st.PruneFeedItems(ctx, before); err != nil {
			log.Error("retention: feed items", "error", err)
		} else if n > 0 {
			log.Info("pruned feed items", "count", n)
		}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ids, err := st.PruneRuns(ctx, e.Name(), keep, before)
		if err != nil {
			log.Error("retention", "task", e.Name(), "error", err)
			continue
		}
		for _, id := range ids {
			_ = os.RemoveAll(filepath.Join(cfg.RunsDir(), e.Name(), id))
		}
		if len(ids) > 0 {
			log.Info("pruned runs", "task", e.Name(), "count", len(ids))
		}
	}
}

// cmdBackendProxy runs inside the backend sidecar: it forwards the
// internal network's requests to the daemon's MCP unix socket.
func cmdBackendProxy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backend-proxy", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "address to listen on")
	upstream := fs.String("upstream", "/run/ais/mcp.sock", "unix socket of the daemon's MCP listener")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	err = backend.Serve(ctx, l, backend.ProxyHandler(*upstream))
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

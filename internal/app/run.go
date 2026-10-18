package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/scuq/ais/internal/backend"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/container"
	"github.com/scuq/ais/internal/doctor"
	"github.com/scuq/ais/internal/egress"
	"github.com/scuq/ais/internal/image"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/runner"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/scheduler"
	"github.com/scuq/ais/internal/secret"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

func cmdRun(ctx context.Context, p *output.Printer, args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "print the container argv and generated files, start nothing")
	engine := fs.String("engine", "", "docker or podman (default: config)")
	asJSON := fs.Bool("json", false, "print the outcome as JSON")
	noBuild := fs.Bool("no-autobuild", false, "fail instead of building a missing or stale image")
	live := fs.Bool("live", false, "stream the model's progress (text, tool calls, results) while the run executes")
	fs.BoolVar(live, "follow", false, "alias for --live")
	full := fs.Bool("full", false, "for a task with feeds: the full check with web search instead of the feed check")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		p.Error("usage: ais run [--dry-run] [--live] [--full] [--engine docker|podman] [--json] <task>")
		return 2
	}
	taskName := pos[0]
	cfg, err := loadConfig()
	if err != nil {
		p.Error("%s", err)
		return 1
	}
	if *engine != "" {
		cfg.Runtime.Engine = *engine
	}
	tasks, err := loadTasks(cfg)
	if err != nil {
		p.Error("%s", err)
		return 1
	}
	t, ok := task.Find(tasks, taskName)
	if !ok {
		p.Error("no task named %q in %s", taskName, cfg.TasksDir())
		return 1
	}
	opts, err := runOptions(cfg)
	if err != nil {
		p.Error("%s", err)
		return 1
	}
	if *live {
		opts.Live = os.Stderr
	}
	trigger := scheduler.TriggerManual
	if *full {
		trigger = scheduler.TriggerManualFull
	}
	opts.Trigger = trigger
	if *dryRun {
		return dryRunTask(ctx, p, cfg, t, opts)
	}
	if err := cfg.RedactionApproved(); err != nil {
		p.Error("%s", err)
		return 1
	}

	rt, err := runtime.Detect(cfg.Runtime.Engine)
	if err != nil {
		p.Error("%s", err)
		return 1
	}
	if err := ensureImage(ctx, p, rt, cfg, !*noBuild); err != nil {
		p.Error("%s", err)
		return 1
	}
	st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
	if err != nil {
		p.Error("%s", err)
		return 1
	}
	defer st.Close()
	// A signal cancels the context: the runner stops the container and
	// records the run as cancelled instead of leaving a running row behind.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	r := &runner.Runner{Cfg: cfg, RT: rt, Store: st, Secrets: secret.NewFileStore(cfg.SecretsDir()), Tokens: backend.Minter{Store: st}, Opts: opts, Log: newLogger()}
	if cfg.Egress.Mode == "proxy" {
		if running, _ := rt.ContainerRunning(ctx, egress.BackendContainer); !running {
			p.Warn("backend sidecar is not running: the inventory MCP server will be unreachable from the container (start 'ais daemon' or 'ais net up')")
		}
	}
	out, err := r.Run(ctx, t, trigger)
	if err != nil {
		p.Error("%s", err)
		return 1
	}
	if *asJSON {
		_ = output.JSON(map[string]any{"run": out.Run, "result": out.Clear, "leaks": out.Leaks})
	} else {
		switch out.Run.State {
		case store.StateSucceeded:
			p.Good("succeeded", "run %s: %d turns on the subscription (est. $%.2f at API prices), result in %s", out.Run.ID, out.Run.NumTurns, out.Run.CostUSD, filepath.Join(out.Dir, "result.clear.json"))
			_ = output.JSON(out.Clear)
		case store.StateSkipped:
			p.Warn("skipped run %s: %s %s", out.Run.ID, out.Run.Reason, out.Run.Error)
		case store.StateLeaked:
			p.Error("run %s LEAKED: %s (see 'ais runs show %s')", out.Run.ID, out.Run.Error, out.Run.ID)
		default:
			p.Error("run %s %s (%s): %s", out.Run.ID, out.Run.State, out.Run.Reason, out.Run.Error)
		}
	}
	if out.Succeeded() {
		return 0
	}
	return 1
}

func dryRunTask(ctx context.Context, p *output.Printer, cfg *config.Config, t *task.Task, opts runner.Options) int {
	// A dry run of a feed check reads the feeds and shows what a run would
	// get, but claims nothing: the next real run still gets the items.
	opts.Peek = true
	if t.Feeds != nil {
		if st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db")); err == nil {
			defer st.Close()
			opts.Feeds = st
		}
		if t.Feeds.Prefilter.Enabled() {
			if rt, err := runtime.Detect(cfg.Runtime.Engine); err == nil {
				opts.Prefilter = rt
			}
		}
	}
	prep, err := runner.Prepare(ctx, cfg, t, runner.EphemeralSalt{}, opts)
	for _, f := range prep.Feeds {
		if f.Err != "" {
			p.Warn("feed %s: %s", f.URL, f.Err)
		} else {
			p.Info("feed %s: %d item(s)", f.URL, f.Items)
		}
	}
	if prep != nil {
		printPrefilter(p, t, prep)
	}
	if errors.Is(err, runner.ErrQuiet) {
		p.Info("feed check: no new item; the daemon would record a quiet run and start no container")
		return 0
	}
	if errors.Is(err, runner.ErrRateLimited) {
		p.Warn("feed check: %v; the daemon would record a skipped run (ratelimit) and start no container", err)
		return 0
	}
	if err != nil {
		p.Error("%s", err)
		return 1
	}
	if prep.Mode == "feed" {
		p.Info("feed check: %d new item(s) go to the model", len(prep.Feed))
		for _, it := range prep.Feed {
			fmt.Fprintf(os.Stdout, "#   %s%s: %s — %s\n", decisionTag(it.Keep, it.Score, it.Match), it.Source, it.Title, it.Link)
		}
	}
	pl := prep.PromptLog()
	pl.RunID += "-dry"
	if err := runner.AppendPromptLog(cfg.RunsDir(), pl); err != nil {
		p.Error("%s", err)
		return 1
	}
	p.Info("run %s prepared in %s (engine %s); prompt logged (sha256 %s, %d bytes)", prep.RunID, prep.RunDir, opts.Engine, pl.SHA256[:16], pl.Bytes)
	fmt.Fprintf(os.Stdout, "%s %s\n", opts.Engine, container.ShellQuote(prep.Argv))
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "# generated input files:")
	names := make([]string, 0, len(prep.Files))
	for n := range prep.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stdout, "#   %s (%d bytes)\n", filepath.Join(prep.RunDir, "in", n), len(prep.Files[n]))
	}
	fmt.Fprintf(os.Stdout, "# pseudonyms minted: %d (map stays on the host)\n", len(prep.Map.Tokens))
	return 0
}

// printPrefilter reports what the prefilter did in a dry run.
func printPrefilter(p *output.Printer, t *task.Task, prep *runner.Prepared) {
	if t.Feeds == nil || !t.Feeds.Prefilter.Enabled() || prep.Mode != "feed" {
		return
	}
	pf := prep.Prefilter
	if pf.Kept+pf.Dropped > 0 {
		p.Info("prefilter (%s, threshold %.2f): %d keyword hit(s), %d scored by %s in %s; %d kept, %d dropped", t.Feeds.Prefilter.Mode, t.Feeds.Prefilter.Threshold, pf.Keyword, pf.Scored, pf.Model, pf.Duration.Round(time.Millisecond), pf.Kept, pf.Dropped)
	}
	if pf.Err != "" {
		p.Warn("prefilter: %s; every undecided item was kept", pf.Err)
	}
	if len(prep.Filtered) > 0 {
		p.Info("prefilter withheld %d item(s) from the model:", len(prep.Filtered))
		for _, it := range prep.Filtered {
			fmt.Fprintf(os.Stdout, "#   [drop %.2f] %s: %s — %s\n", it.Score, it.Source, it.Title, it.Link)
		}
	}
}

// decisionTag renders "[keep 0.71 Palo Alto Networks PAN-OS 11.2] ".
func decisionTag(keep string, score float64, match string) string {
	if keep == "" {
		return ""
	}
	s := "[" + keep
	if score > 0 {
		s += fmt.Sprintf(" %.2f", score)
	}
	if match != "" {
		s += " " + match
	}
	return s + "] "
}

// ensureImage builds the run image when missing or stale (and allowed).
func ensureImage(ctx context.Context, p *output.Printer, rt runtime.Runtime, cfg *config.Config, autobuild bool) error {
	exists, current, err := image.IsCurrent(ctx, rt, cfg)
	if err != nil {
		return err
	}
	if exists && current {
		return nil
	}
	if !autobuild || !cfg.Image.Autobuild {
		if !exists {
			return fmt.Errorf("image %s is missing; run 'ais image build'", cfg.Runtime.Image)
		}
		return fmt.Errorf("image %s is stale; run 'ais image build'", cfg.Runtime.Image)
	}
	if exists {
		p.Info("image %s is stale (recipe changed); rebuilding", cfg.Runtime.Image)
	} else {
		p.Info("image %s is missing; building", cfg.Runtime.Image)
	}
	if err := image.Build(ctx, rt, cfg, false, Version); err != nil {
		return err
	}
	p.Good("built", "%s", cfg.Runtime.Image)
	return nil
}

// runOptions resolves engine, uid/gid and the hook binary from config.
func runOptions(cfg *config.Config) (runner.Options, error) {
	engine, err := runtime.DetectEngine(cfg.Runtime.Engine)
	if err != nil {
		return runner.Options{}, err
	}
	uid, gid := 1000, 1000
	if engine == "docker" {
		if cfg.Runtime.User == "auto" {
			uid, gid = os.Getuid(), os.Getgid()
		} else {
			uid, gid, err = config.ParseUser(cfg.Runtime.User)
			if err != nil {
				return runner.Options{}, err
			}
		}
	}
	bin := config.ExpandPath(cfg.Runtime.Binary)
	if bin == "" {
		if exe, err := os.Executable(); err == nil {
			if real, err := filepath.EvalSymlinks(exe); err == nil {
				bin = real
			}
		}
	}
	return runner.Options{Engine: engine, UID: uid, GID: gid, HostBinary: bin, SELinux: doctor.SELinuxEnforcing()}, nil
}

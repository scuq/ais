package app

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/scheduler"
	"github.com/scuq/ais/internal/secret"
	"github.com/scuq/ais/internal/sink"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

// cmdDigest builds the digest of a task for the window that ends now and
// sends it to the task's sinks, or prints it. The daemon sends digests on
// the task's digest.schedule; this command is for a check or a manual
// summary.
func cmdDigest(ctx context.Context, p *output.Printer, args []string) error {
	fs := flag.NewFlagSet("digest", flag.ContinueOnError)
	printOnly := fs.Bool("print", false, "print the Webex markdown instead of sending")
	window := fs.Duration("window", 0, "window length (default: the task's digest.window, or 24h)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: ais digest <task> [--print] [--window D]")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	tasks, err := loadTasks(cfg)
	if err != nil {
		return err
	}
	var t *task.Task
	for _, tk := range tasks {
		if tk.Name == pos[0] {
			t = tk
		}
	}
	if t == nil {
		return fmt.Errorf("no task named %q", pos[0])
	}
	w := *window
	if w <= 0 {
		w = task.DefaultDigestWindow
		if t.Digest != nil {
			w = t.Digest.Window
		}
	}
	loc, err := time.LoadLocation(cfg.Scheduler.Timezone)
	if err != nil {
		return fmt.Errorf("scheduler.timezone: %w", err)
	}
	st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	end := time.Now()
	var nextRun *time.Time
	if at, err := scheduler.NextRun(t.Schedule, end, loc); err == nil {
		nextRun = &at
	}
	d := &sink.Dispatcher{Store: st, Version: Version}
	ev, err := d.LoadDigest(ctx, t.Name, sink.DigestPayload{WindowStart: end.Add(-w), WindowEnd: end, NextRun: nextRun})
	if err != nil {
		return err
	}
	if *printOnly {
		var scfg configSink
		for _, name := range t.Sinks {
			if c, ok := cfg.Sinks[name]; ok && c.Type == "webex" {
				scfg = configSink{title: c.Title, maxItems: c.MaxItems}
				break
			}
		}
		title, err := sink.RenderTitle(scfg.title, ev)
		if err != nil {
			return err
		}
		fmt.Println(sink.WebexMarkdown(title, ev, scfg.maxItems))
		return nil
	}
	if len(t.Sinks) == 0 {
		return fmt.Errorf("task %s has no sinks (use --print)", t.Name)
	}
	secrets := secret.NewFileStore(cfg.SecretsDir())
	for _, name := range t.Sinks {
		s, err := sink.Build(name, cfg.Sinks[name], secrets)
		if err != nil {
			return err
		}
		if err := s.Deliver(ctx, ev); err != nil {
			return fmt.Errorf("sink %s: %w", name, err)
		}
		p.Good("delivered", "digest of %s (%s, %d run(s)) to sink %s (%s)", t.Name, ev.Digest.WindowLabel(), ev.Digest.Runs, name, s.Type())
	}
	return nil
}

// configSink is the part of a Webex sink that the preview needs.
type configSink struct {
	title    string
	maxItems int
}

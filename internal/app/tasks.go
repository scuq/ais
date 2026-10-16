package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/task"
)

func taskDefaults(cfg *config.Config) task.Defaults {
	return task.Defaults{
		Model:        cfg.Claude.DefaultModel,
		Effort:       cfg.Claude.DefaultEffort,
		MaxTurns:     cfg.Claude.DefaultMaxTurns,
		MaxBudgetUSD: cfg.Claude.DefaultMaxBudgetUSD,
		Timeout:      cfg.Claude.DefaultTimeout,
	}
}

func knownSinks(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	for name := range cfg.Sinks {
		out[name] = true
	}
	return out
}

func loadTasks(cfg *config.Config) ([]*task.Task, error) {
	return task.LoadDir(cfg.TasksDir(), taskDefaults(cfg), knownSinks(cfg))
}

func cmdTasks(p *output.Printer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ais tasks list | validate | show <task> | set <task> key=value [key=value]")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("tasks list", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "print JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		tasks, err := loadTasks(cfg)
		if err != nil {
			return err
		}
		if *asJSON {
			return output.JSON(tasks)
		}
		if len(tasks) == 0 {
			p.Info("no tasks in %s", cfg.TasksDir())
			return nil
		}
		live := daemonTasks(context.Background(), cfg)
		loc, err := time.LoadLocation(cfg.Scheduler.Timezone)
		if err != nil {
			loc = time.Local
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSCHEDULE\tNEXT\tMODEL\tEFFORT\tSINKS\tHASH")
		for _, t := range tasks {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.Name, t.Schedule, nextColumn(live, t.Name, t.Schedule, t.IsEnabled(), loc), t.Model, t.Effort, strings.Join(t.Sinks, ","), t.Hash)
		}
		return tw.Flush()
	case "validate":
		tasks, err := loadTasks(cfg)
		if err != nil {
			return err
		}
		for _, t := range tasks {
			p.Good("ok", "%s (%s)", t.Name, t.Path)
		}
		if len(tasks) == 0 {
			p.Warn("no tasks found in %s", cfg.TasksDir())
		}
		return nil
	case "set":
		return cmdTasksSet(p, cfg, args[1:])
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: ais tasks show <task>")
		}
		tasks, err := loadTasks(cfg)
		if err != nil {
			return err
		}
		t, ok := task.Find(tasks, args[1])
		if !ok {
			return fmt.Errorf("no task named %q", args[1])
		}
		return output.JSON(t)
	}
	return fmt.Errorf("unknown tasks subcommand %q", args[0])
}

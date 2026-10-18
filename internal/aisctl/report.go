package aisctl

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/report"
	"github.com/scuq/ais/internal/store"
)

// ReportOptions tunes `aisctl report`.
type ReportOptions struct {
	Task    string
	Windows string // "24h,7d,30d"
	Runs    bool   // list the runs of the first window
	JSON    bool
}

// daemonUsage is what systemd counts for the ais unit since its start:
// the daemon's own process (feed fetching, the prefilter driver, the
// backend), not the containers, which run under the engine.
type daemonUsage struct {
	Since   time.Time     `json:"since"`
	CPU     time.Duration `json:"cpu"`
	Memory  int64         `json:"memory"`
	MemPeak int64         `json:"memPeak"`
}

// Report implements `aisctl report`: what ran in each window and what it
// cost in runs, feeds, prefilter work, tokens, money, CPU time and memory.
func Report(ctx context.Context, e *Env, o ReportOptions) error {
	p := UserPaths(e.Home)
	cfg, err := loadConfig(p.ConfigFile)
	if err != nil {
		return err
	}
	if o.Windows == "" {
		o.Windows = "24h,7d,30d"
	}
	windows, err := report.ParseWindows(o.Windows)
	if err != nil {
		return err
	}
	longest := windows[0].Span
	for _, w := range windows {
		longest = max(longest, w.Span)
	}
	st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	since := now.Add(-longest)
	runs, err := st.RunsSince(ctx, o.Task, since)
	if err != nil {
		return err
	}
	results, err := st.ResultsSince(ctx, o.Task, since)
	if err != nil {
		return err
	}
	rep := report.Build(o.Task, now, config.Billing, windows, runs, results)
	if o.Runs {
		from := now.Add(-windows[0].Span)
		for _, r := range runs {
			if !r.StartedAt.Before(from) {
				rep.Runs = append(rep.Runs, r)
			}
		}
	}
	du, duErr := readDaemonUsage(ctx, e)
	if o.JSON {
		doc := map[string]any{"report": rep}
		if duErr == nil {
			doc["daemon"] = du
		}
		enc := json.NewEncoder(e.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	}
	if err := report.Render(e.Out, rep); err != nil {
		return err
	}
	if duErr == nil {
		fmt.Fprintf(e.Out, "ais daemon since %s: CPU %s, memory %d MiB (peak %d MiB); the containers are not part of it\n",
			du.Since.Local().Format("2006-01-02 15:04"), du.CPU.Round(time.Millisecond), du.Memory>>20, du.MemPeak>>20)
	}
	return nil
}

// readDaemonUsage asks systemd for the unit's accounting.
func readDaemonUsage(ctx context.Context, e *Env) (daemonUsage, error) {
	var du daemonUsage
	if e.Exec == nil {
		return du, fmt.Errorf("no systemctl")
	}
	out, err := e.Exec(ctx, "systemctl", "--user", "show", UnitName, "-p", "CPUUsageNSec", "-p", "MemoryCurrent", "-p", "MemoryPeak", "-p", "ActiveEnterTimestamp")
	if err != nil {
		return du, err
	}
	got := 0
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		num, numErr := strconv.ParseInt(v, 10, 64)
		switch k {
		case "CPUUsageNSec":
			if numErr == nil {
				du.CPU, got = time.Duration(num), got+1
			}
		case "MemoryCurrent":
			if numErr == nil {
				du.Memory = num
			}
		case "MemoryPeak":
			if numErr == nil {
				du.MemPeak = num
			}
		case "ActiveEnterTimestamp":
			if t, err := time.ParseInLocation("Mon 2006-01-02 15:04:05 MST", v, time.Local); err == nil {
				du.Since = t
			}
		}
	}
	if got == 0 || du.Since.IsZero() {
		return du, fmt.Errorf("systemd reports no accounting for %s", UnitName)
	}
	return du, nil
}

func runReport(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	var o ReportOptions
	fs.StringVar(&o.Task, "task", "", "only this task (default: all)")
	fs.StringVar(&o.Windows, "windows", "24h,7d,30d", "comma-separated windows, for example 24h,7d,30d or 1h")
	fs.BoolVar(&o.Runs, "runs", false, "also list every run of the first window")
	fs.BoolVar(&o.JSON, "json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: aisctl report [--task T] [--windows 24h,7d,30d] [--runs] [--json]")
	}
	return Report(ctx, e, o)
}

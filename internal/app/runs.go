package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/store"
)

func openStore() (*store.Store, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
}

func cmdRuns(ctx context.Context, p *output.Printer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ais runs list | show <run-id> [--prompt] | prompts | redeliver <run-id>")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("runs list", flag.ContinueOnError)
		taskName := fs.String("task", "", "filter by task")
		state := fs.String("state", "", "filter by state")
		limit := fs.Int("n", 30, "max rows")
		asJSON := fs.Bool("json", false, "print JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		runs, err := st.ListRuns(ctx, *taskName, *state, *limit)
		if err != nil {
			return err
		}
		if *asJSON {
			return output.JSON(runs)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "RUN\tTASK\tSTATE\tREASON\tSTARTED\tDURATION\tTURNS\tBILLING")
		for _, r := range runs {
			dur := ""
			if r.DurationMS > 0 {
				dur = (time.Duration(r.DurationMS) * time.Millisecond).Round(time.Second).String()
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\tsub (est. $%.2f)\n", r.ID, r.Task, r.State, r.Reason, r.StartedAt.Local().Format("2006-01-02 15:04"), dur, r.NumTurns, r.CostUSD)
		}
		return tw.Flush()
	case "show":
		fs := flag.NewFlagSet("runs show", flag.ContinueOnError)
		clear := fs.Bool("clear", false, "print the depseudonymized result (host view)")
		showPrompt := fs.Bool("prompt", false, "print the system prompt and prompt that were sent")
		asJSON := fs.Bool("json", false, "print everything as JSON")
		pos, err := parseInterspersed(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: ais runs show [--clear] [--json] <run-id>")
		}
		r, err := st.GetRun(ctx, pos[0])
		if err != nil {
			return err
		}
		res, _ := st.GetResult(ctx, r.ID)
		leaks, _ := st.Leaks(ctx, r.ID)
		dels, _ := st.DeliveriesOf(ctx, r.ID)
		if *showPrompt {
			pl, err := st.GetPrompt(ctx, r.ID)
			if err != nil {
				return err
			}
			if *asJSON {
				return output.JSON(pl)
			}
			fmt.Printf("# run %s, prompt sha256 %s, %d bytes\n\n## system prompt\n\n%s\n## prompt\n\n%s", pl.RunID, pl.SHA256, pl.Bytes, pl.System, pl.Prompt)
			return nil
		}
		if *asJSON {
			var pseudo, clearDoc any
			_ = json.Unmarshal(res.PseudoJSON, &pseudo)
			if *clear {
				_ = json.Unmarshal(res.ClearJSON, &clearDoc)
			}
			return output.JSON(map[string]any{"run": r, "result": pseudo, "clear": clearDoc, "leaks": leaks, "deliveries": dels})
		}
		fmt.Printf("run:      %s\ntask:     %s (%s)\nstate:    %s %s\nengine:   %s\nmodel:    %s\n",
			r.ID, r.Task, r.TaskHash, r.State, r.Reason, r.Engine, r.Model)
		if r.Models != "" && r.Models != r.Model {
			fmt.Printf("models:   %s\n", strings.ReplaceAll(r.Models, ",", ", "))
		}
		fmt.Printf("started:  %s\nfinished: %s\nturns:    %d\n",
			r.StartedAt.Local().Format(time.RFC3339), r.FinishedAt.Local().Format(time.RFC3339), r.NumTurns)
		if in := r.InputTokens + r.CacheReadTokens + r.CacheCreationTokens; in+r.OutputTokens > 0 {
			fmt.Printf("tokens:   %d in (%d input, %d cache read, %d cache write) / %d out\n", in, r.InputTokens, r.CacheReadTokens, r.CacheCreationTokens, r.OutputTokens)
		}
		fmt.Printf("billing:  %s (est. $%.4f at API list prices)\ndir:      %s\n", config.Billing, r.CostUSD, r.Dir)
		if r.Error != "" {
			fmt.Printf("error:    %s\n", r.Error)
		}
		for _, l := range leaks {
			fmt.Printf("LEAK:     %s (%s) …%s…\n", l.Value, l.Field, l.Snippet)
		}
		for _, d := range dels {
			fmt.Printf("delivery: %s %s attempt=%d %s\n", d.Sink, d.State, d.Attempt, d.LastError)
		}
		body := res.PseudoJSON
		if *clear {
			if res.ClearJSON == nil {
				p.Warn("no clear result for this run")
			} else {
				body = res.ClearJSON
			}
		}
		if len(body) > 0 {
			var doc any
			_ = json.Unmarshal(body, &doc)
			return output.JSON(doc)
		}
		return nil
	case "prompts":
		fs := flag.NewFlagSet("runs prompts", flag.ContinueOnError)
		taskName := fs.String("task", "", "filter by task")
		limit := fs.Int("n", 30, "max rows")
		asJSON := fs.Bool("json", false, "print JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		prompts, err := st.ListPrompts(ctx, *taskName, *limit)
		if err != nil {
			return err
		}
		if *asJSON {
			return output.JSON(prompts)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "RUN\tTASK\tSENT\tBYTES\tSHA256")
		for _, pr := range prompts {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", pr.RunID, pr.Task, pr.CreatedAt.Local().Format("2006-01-02 15:04"), pr.Bytes, pr.SHA256[:16])
		}
		return tw.Flush()
	case "redeliver":
		fs := flag.NewFlagSet("runs redeliver", flag.ContinueOnError)
		sink := fs.String("sink", "", "only this sink")
		pos, err := parseInterspersed(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: ais runs redeliver [--sink S] <run-id>")
		}
		n, err := st.ResetDeliveries(ctx, pos[0], *sink, time.Now())
		if err != nil {
			return err
		}
		p.Good("queued", "%d delivery(ies); the daemon sends them", n)
		return nil
	}
	return fmt.Errorf("unknown runs subcommand %q", args[0])
}

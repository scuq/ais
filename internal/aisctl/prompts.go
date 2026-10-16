package aisctl

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/scuq/ais/internal/store"
)

// promptEntry is one line of prompts.ndjson (also covers dry runs, which
// have no database row).
type promptEntry struct {
	RunID  string `json:"run_id"`
	Task   string `json:"task"`
	Time   string `json:"time"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	System string `json:"system"`
	Prompt string `json:"prompt"`
}

func (p promptEntry) when() time.Time {
	t, _ := time.Parse(time.RFC3339, p.Time)
	return t
}

// readPromptLog loads every prompts.ndjson under runsDir (one per task),
// newest first, optionally filtered by task.
func readPromptLog(runsDir, task string) ([]promptEntry, error) {
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []promptEntry
	for _, e := range entries {
		if !e.IsDir() || (task != "" && e.Name() != task) {
			continue
		}
		f, err := os.Open(filepath.Join(runsDir, e.Name(), "prompts.ndjson"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var p promptEntry
			if json.Unmarshal(sc.Bytes(), &p) == nil {
				out = append(out, p)
			}
		}
		f.Close()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].when().After(out[j].when()) })
	return out, nil
}

func printPrompt(e *Env, runID, sha string, bytes int, system, prompt string) {
	fmt.Fprintf(e.Out, "# run %s · sha256 %s · %d bytes\n\n## system prompt\n\n%s\n## prompt\n\n%s", runID, sha, bytes, strings.TrimRight(system, "\n")+"\n", prompt)
	if !strings.HasSuffix(prompt, "\n") {
		fmt.Fprintln(e.Out)
	}
}

// Prompts implements `aisctl prompts list|show|last`.
func Prompts(ctx context.Context, e *Env, args []string) error {
	p := UserPaths(e.Home)
	cfg, err := loadConfig(p.ConfigFile)
	if err != nil {
		return err
	}
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "list":
		fs := flag.NewFlagSet("prompts list", flag.ContinueOnError)
		task := fs.String("task", "", "filter by task")
		n := fs.Int("n", 20, "max rows")
		if err := fs.Parse(args); err != nil {
			return err
		}
		all, err := readPromptLog(cfg.RunsDir(), *task)
		if err != nil {
			return err
		}
		if len(all) == 0 {
			e.headline("no prompts logged yet (under %s/<task>/prompts.ndjson)", cfg.RunsDir())
			return nil
		}
		tw := tabwriter.NewWriter(e.Out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "RUN\tTASK\tSENT\tBYTES\tSHA256")
		for i, pe := range all {
			if i >= *n {
				break
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", pe.RunID, pe.Task, pe.when().Local().Format("2006-01-02 15:04"), pe.Bytes, pe.SHA256[:16])
		}
		return tw.Flush()
	case "last":
		fs := flag.NewFlagSet("prompts last", flag.ContinueOnError)
		task := fs.String("task", "", "filter by task")
		if err := fs.Parse(args); err != nil {
			return err
		}
		all, err := readPromptLog(cfg.RunsDir(), *task)
		if err != nil {
			return err
		}
		if len(all) == 0 {
			return fmt.Errorf("no prompts logged yet")
		}
		pe := all[0]
		printPrompt(e, pe.RunID, pe.SHA256, pe.Bytes, pe.System, pe.Prompt)
		return nil
	case "show":
		if len(args) != 1 {
			return fmt.Errorf("usage: aisctl prompts show <run-id>")
		}
		st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
		if err == nil {
			defer st.Close()
			if pr, err := st.GetPrompt(ctx, args[0]); err == nil {
				printPrompt(e, pr.RunID, pr.SHA256, pr.Bytes, pr.System, pr.Prompt)
				return nil
			}
		}
		all, err := readPromptLog(cfg.RunsDir(), "")
		if err != nil {
			return err
		}
		for _, pe := range all {
			if pe.RunID == args[0] {
				printPrompt(e, pe.RunID, pe.SHA256, pe.Bytes, pe.System, pe.Prompt)
				return nil
			}
		}
		return fmt.Errorf("no prompt logged for run %q", args[0])
	}
	return fmt.Errorf("unknown prompts subcommand %q (list | show <run-id> | last)", sub)
}

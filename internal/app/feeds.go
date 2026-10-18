package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/scuq/ais/internal/feed"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

// cmdFeeds reads the feeds of a task. 'test' shows what each feed returned
// and what a run would get as new, and claims nothing; 'seen' marks every
// current item as seen, so that the feed checks start from now instead of
// handing the whole backlog to the first run.
func cmdFeeds(ctx context.Context, p *output.Printer, args []string) error {
	const usage = "usage: ais feeds test [--items] <task> | ais feeds seen <task>"
	if len(args) == 0 || (args[0] != "test" && args[0] != "seen") {
		return fmt.Errorf("%s", usage)
	}
	mode := args[0]
	fs := flag.NewFlagSet("feeds "+mode, flag.ContinueOnError)
	items := fs.Bool("items", false, "list the new items")
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("%s", usage)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	tasks, err := loadTasks(cfg)
	if err != nil {
		return err
	}
	t, ok := task.Find(tasks, pos[0])
	if !ok {
		return fmt.Errorf("no task named %q", pos[0])
	}
	if t.Feeds == nil {
		return fmt.Errorf("task %s has no feeds key", t.Name)
	}
	results := feed.FetchAll(ctx, t.Feeds.URLs, t.Feeds.Timeout)
	var all []store.FeedItem
	byKey := map[string]feed.Item{}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "FEED\tITEMS\tNEWEST\tSTATUS")
	defer tw.Flush()
	for _, r := range results {
		newest := "-"
		for _, it := range r.Items {
			if !it.Published.IsZero() {
				newest = it.Published.Local().Format("2006-01-02 15:04")
				break
			}
		}
		status := "ok"
		if r.Err != nil {
			status = "FAILED: " + r.Err.Error()
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", r.URL, len(r.Items), newest, status)
		for _, it := range r.Items {
			if _, dup := byKey[it.Key]; dup {
				continue
			}
			byKey[it.Key] = it
			all = append(all, store.FeedItem{Key: it.Key, Title: it.Title, Link: it.Link, Source: it.Source, Published: it.Published})
		}
	}
	tw.Flush()
	st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	cutoff := time.Now().Add(-t.Feeds.MaxAge)
	recent := all[:0]
	old := 0
	for _, it := range all {
		if !it.Published.IsZero() && it.Published.Before(cutoff) {
			old++
			continue
		}
		recent = append(recent, it)
	}
	all = recent
	if old > 0 {
		p.Info("%d item(s) are older than feeds.maxAge (%s) and never count as new", old, t.Feeds.MaxAge)
	}
	if mode == "seen" {
		runID := "seen-" + time.Now().UTC().Format("20060102T150405Z")
		fresh, err := st.ClaimFeedItems(ctx, t.Name, runID, all, 0, time.Now())
		if err != nil {
			return err
		}
		if err := st.SettleFeedItems(ctx, runID, true); err != nil {
			return err
		}
		p.Good("marked", "%d item(s) as seen for %s; the next feed check reports only what appears after now", len(fresh), t.Name)
		return nil
	}
	fresh, err := st.ClaimFeedItems(ctx, t.Name, "", all, 0, time.Now())
	if err != nil {
		return err
	}
	p.Info("%d distinct item(s) in %d feed(s); %d new for the next feed check (cap %d per run)", len(all), len(results), len(fresh), t.Feeds.MaxItems)
	if *items {
		for _, f := range fresh {
			fmt.Fprintf(os.Stdout, "  %s | %s: %s — %s\n", f.Published.Local().Format("01-02 15:04"), f.Source, f.Title, f.Link)
		}
	}
	return nil
}

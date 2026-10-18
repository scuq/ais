package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/scuq/ais/internal/store"
)

// Render writes the report as text: one column per window, one row per
// figure, then the run list when the report has one.
func Render(w io.Writer, rep Report) error {
	task := rep.Task
	if task == "" {
		task = "all tasks"
	}
	fmt.Fprintf(w, "ais report · %s · %s\n", task, rep.At.Local().Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(w, "money: %s; the dollar figures are estimates at API list prices\n\n", rep.Billing)
	// Numbers align right; labels are padded to one width first, so that
	// they read left-aligned in the right-aligned table.
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', tabwriter.AlignRight)
	const labelWidth = 26
	pad := func(s string) string { return fmt.Sprintf("%-*s", labelWidth, s) }
	head := []string{pad("")}
	for _, win := range rep.Windows {
		head = append(head, "last "+win.Name)
	}
	row := func(label string, f func(Stats) string) {
		cells := []string{pad(label)}
		for _, win := range rep.Windows {
			cells = append(cells, f(win.Stats))
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t")+"\t")
	}
	section := func(name string) {
		cells := make([]string, len(rep.Windows)+1)
		cells[0] = pad(name)
		fmt.Fprintln(tw, strings.Join(cells, "\t")+"\t")
	}
	fmt.Fprintln(tw, strings.Join(head, "\t")+"\t")

	section("TICKS")
	row("runs recorded", func(s Stats) string { return n(s.Ticks.Total) })
	row("  feed checks", func(s Stats) string { return n(s.Ticks.FeedChecks) })
	row("  full checks", func(s Stats) string { return n(s.Ticks.FullChecks) })
	row("  older (no mode)", func(s Stats) string { return n(s.Ticks.NoMode) })
	row("  succeeded", func(s Stats) string { return n(s.Ticks.Succeeded) })
	row("  failed", func(s Stats) string { return n(s.Ticks.Failed) })
	row("  quiet (no model)", func(s Stats) string { return n(s.Ticks.Quiet) })
	row("  held back (cap)", func(s Stats) string { return n(s.Ticks.RateLimit) })
	row("  other skips", func(s Stats) string { return n(s.Ticks.Skipped) })

	section("FEEDS (host)")
	row("fetches", func(s Stats) string { return n(s.Feeds.Fetches) })
	row("  with figures", func(s Stats) string { return n(s.Feeds.Measured) })
	row("feeds read", func(s Stats) string { return n(s.Feeds.Feeds) })
	row("feeds failed", func(s Stats) string { return n(s.Feeds.Failed) })
	row("items fetched", func(s Stats) string { return n(s.Feeds.Items) })
	row("new items to model", func(s Stats) string { return n(s.Feeds.New) })
	row("withheld (prefilter)", func(s Stats) string { return n(s.Feeds.Filtered) })
	row("fetch time", func(s Stats) string { return dur(s.Feeds.Wall) })
	row("  per fetch", func(s Stats) string { return avg(s.Feeds.Wall, s.Feeds.Measured) })
	row("  longest", func(s Stats) string { return dur(s.Feeds.WallMax) })

	section("PREFILTER (local model)")
	row("runs", func(s Stats) string { return n(s.Prefilter.Runs) })
	row("  errors (items kept)", func(s Stats) string { return n(s.Prefilter.Errors) })
	row("keyword hits", func(s Stats) string { return n(s.Prefilter.Keyword) })
	row("scored by model", func(s Stats) string { return n(s.Prefilter.Scored) })
	row("kept", func(s Stats) string { return n(s.Prefilter.Kept) })
	row("dropped", func(s Stats) string { return n(s.Prefilter.Dropped) })
	row("  drop rate", func(s Stats) string { return pct(s.Prefilter.Dropped, s.Prefilter.Kept+s.Prefilter.Dropped) })
	row("wall time", func(s Stats) string { return dur(s.Prefilter.Wall) })
	row("  per run", func(s Stats) string { return avg(s.Prefilter.Wall, s.Prefilter.Runs) })
	row("  longest", func(s Stats) string { return dur(s.Prefilter.WallMax) })
	row("CPU time", func(s Stats) string { return measured(dur(s.Prefilter.CPU), s.Prefilter.Measured, s.Prefilter.Runs) })
	row("peak memory", func(s Stats) string { return size(s.Prefilter.MemPeak) })

	section("MODEL (online)")
	row("runs", func(s Stats) string { return n(s.Model.Runs) })
	row("turns", func(s Stats) string { return n(s.Model.Turns) })
	row("tokens in", func(s Stats) string { return tok(s.Model.In()) })
	row("  uncached", func(s Stats) string { return tok(s.Model.Input) })
	row("  cache read", func(s Stats) string { return tok(s.Model.CacheRead) })
	row("  cache write", func(s Stats) string { return tok(s.Model.CacheCreation) })
	row("tokens out", func(s Stats) string { return tok(s.Model.Output) })
	row("est. cost", func(s Stats) string { return usd(s.Model.CostUSD) })
	row("  per run", func(s Stats) string {
		if s.Model.Runs == 0 {
			return "-"
		}
		return usd(s.Model.CostUSD / float64(s.Model.Runs))
	})
	row("wall time", func(s Stats) string { return dur(s.Model.Wall) })
	row("  per run", func(s Stats) string { return avg(s.Model.Wall, s.Model.Runs) })
	row("  longest", func(s Stats) string { return dur(s.Model.WallMax) })
	row("container CPU", func(s Stats) string { return measured(dur(s.Model.CPU), s.Model.Measured, s.Model.Runs) })
	row("peak memory", func(s Stats) string { return size(s.Model.MemPeak) })

	if split := splitModels(rep); len(split) > 0 {
		section("BY MODEL")
		tokenRows := func(get func(Stats) (store.ModelTokens, bool)) {
			cell := func(f func(store.ModelTokens) string) func(Stats) string {
				return func(s Stats) string {
					t, ok := get(s)
					if !ok {
						return "-"
					}
					return f(t)
				}
			}
			row("  uncached", cell(func(t store.ModelTokens) string { return tok(t.Input) }))
			row("  cache read", cell(func(t store.ModelTokens) string { return tok(t.CacheRead) }))
			row("  cache write", cell(func(t store.ModelTokens) string { return tok(t.CacheCreation) }))
			row("  tokens out", cell(func(t store.ModelTokens) string { return tok(t.Output) }))
			row("  est. cost", cell(func(t store.ModelTokens) string { return usd(t.CostUSD) }))
		}
		for _, name := range split {
			section(name)
			tokenRows(func(s Stats) (store.ModelTokens, bool) {
				t, ok := s.Model.ByModel[name]
				return t, ok
			})
		}
		if hasUnsplit(rep) {
			section("not split (older runs)")
			tokenRows(func(s Stats) (store.ModelTokens, bool) {
				return s.Model.Unsplit, s.Model.Unsplit != (store.ModelTokens{})
			})
		}
	}

	section("RESULTS")
	row("results", func(s Stats) string { return n(s.Results.Runs) })
	row("new findings", func(s Stats) string { return n(s.Results.Findings) })
	row("updates", func(s Stats) string { return n(s.Results.Updates) })
	row("items checked", func(s Stats) string { return n(s.Results.Checked) })

	section("TOTAL")
	row("container CPU", func(s Stats) string {
		if s.Prefilter.Measured+s.Model.Measured == 0 {
			return "-"
		}
		return dur(s.CPU)
	})
	row("wall time", func(s Stats) string { return dur(s.Wall) })
	row("est. cost", func(s Stats) string { return usd(s.Model.CostUSD) })
	if err := tw.Flush(); err != nil {
		return err
	}
	var models []string
	for _, win := range rep.Windows {
		for _, m := range win.Stats.Model.Models {
			if !contains(models, m) {
				models = append(models, m)
			}
		}
	}
	if len(models) > 0 {
		fmt.Fprintf(w, "\nmodels: %s\n", strings.Join(models, ", "))
	}
	if len(splitModels(rep)) > 0 {
		fmt.Fprintln(w, "MODEL tokens add up every model of a run; BY MODEL splits them (a helper model, such as the one behind WebFetch, can add many cheap uncached tokens).")
	}
	fmt.Fprintln(w, "CPU and memory come from the containers' cgroups; \"x of y\" means only x runs reported them (older runs and images did not).")
	if len(rep.Runs) > 0 {
		fmt.Fprintf(w, "\nRUNS (last %s)\n", rep.Windows[0].Name)
		return RenderRuns(w, rep)
	}
	return nil
}

// RenderRuns writes one line per run.
func RenderRuns(w io.Writer, rep Report) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STARTED\tTASK\tMODE\tOUTCOME\tFEEDS\tNEW\tPREFILTER\tMODEL\tTURNS\tTOKENS IN/OUT\tCOST\tCPU\tMEM")
	for _, r := range rep.Runs {
		outcome := r.State
		if r.Reason != "" {
			outcome += " (" + r.Reason + ")"
		}
		feeds, newItems, pf := "-", "-", "-"
		if r.Feeds > 0 {
			feeds = fmt.Sprintf("%d/%d", r.FeedItems, r.Feeds)
			if r.FeedsFailed > 0 {
				feeds += fmt.Sprintf(" (%d failed)", r.FeedsFailed)
			}
			newItems = n(r.FeedNew)
			if r.FeedFiltered > 0 {
				newItems += fmt.Sprintf(" (-%d)", r.FeedFiltered)
			}
		}
		if r.PrefilterKept+r.PrefilterDropped > 0 || r.PrefilterError != "" {
			pf = fmt.Sprintf("%s %d/%d", dur(ms(r.PrefilterMS)), r.PrefilterKept, r.PrefilterKept+r.PrefilterDropped)
			if r.PrefilterError != "" {
				pf += " err"
			}
		}
		model, turns, tokens, cost := "-", "-", "-", "-"
		if startedModel(r) {
			model, turns = dur(ms(r.DurationMS)), n(r.NumTurns)
			tokens = tok(r.InputTokens+r.CacheReadTokens+r.CacheCreationTokens) + "/" + tok(r.OutputTokens)
			cost = usd(r.CostUSD)
		}
		cpu := "-"
		if c := r.CPUMS + r.PrefilterCPUMS; c > 0 {
			cpu = dur(ms(c))
		}
		mem := max(r.MemPeak, r.PrefilterMemPeak)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.StartedAt.Local().Format("01-02 15:04"), r.Task, dash(r.Mode), outcome, feeds, newItems, pf, model, turns, tokens, cost, cpu, size(mem))
	}
	return tw.Flush()
}

// splitModels returns the models of the BY MODEL section, the most
// expensive in the longest window first.
func splitModels(rep Report) []string {
	cost := map[string]float64{}
	for _, win := range rep.Windows {
		for name, t := range win.Stats.Model.ByModel {
			cost[name] = max(cost[name], t.CostUSD)
		}
	}
	names := make([]string, 0, len(cost))
	for name := range cost {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if cost[names[i]] != cost[names[j]] {
			return cost[names[i]] > cost[names[j]]
		}
		return names[i] < names[j]
	})
	return names
}

func hasUnsplit(rep Report) bool {
	for _, win := range rep.Windows {
		if win.Stats.Model.Unsplit != (store.ModelTokens{}) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func n(v int) string { return fmt.Sprint(v) }

func pct(part, whole int) string {
	if whole == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(part)/float64(whole))
}

func usd(v float64) string {
	if v == 0 {
		return "$0"
	}
	if v < 0.01 {
		return fmt.Sprintf("$%.4f", v)
	}
	return fmt.Sprintf("$%.2f", v)
}

func tok(v int64) string {
	switch {
	case v == 0:
		return "0"
	case v < 1000:
		return fmt.Sprint(v)
	case v < 1_000_000:
		return fmt.Sprintf("%.1fk", float64(v)/1e3)
	default:
		return fmt.Sprintf("%.2fM", float64(v)/1e6)
	}
}

func size(v int64) string {
	switch {
	case v == 0:
		return "-"
	case v < 1<<20:
		return fmt.Sprintf("%d KiB", v>>10)
	case v < 1<<30:
		return fmt.Sprintf("%d MiB", v>>20)
	default:
		return fmt.Sprintf("%.1f GiB", float64(v)/(1<<30))
	}
}

func dur(d time.Duration) string {
	switch {
	case d == 0:
		return "0"
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func avg(total time.Duration, count int) string {
	if count == 0 {
		return "-"
	}
	return dur(total / time.Duration(count))
}

func measured(v string, got, of int) string {
	if of == 0 {
		return "-"
	}
	if got == 0 {
		return "-"
	}
	if got == of {
		return v
	}
	return fmt.Sprintf("%s (%d of %d)", v, got, of)
}

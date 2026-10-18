package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/scuq/ais/internal/image"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/prefilter"
	"github.com/scuq/ais/internal/runner"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

const prefilterUsage = "usage: ais prefilter build [--no-cache] [--tag REF] [--model-dir DIR] | test [--rescore] [--keep] <task> | stats [--since D] <task> | set <task> key=value..."

// cmdPrefilter manages the feed prefilter: build its image, score the
// current new items of a task to see the decisions, compare recorded
// scores with what the model later reported, and change its settings.
func cmdPrefilter(ctx context.Context, p *output.Printer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", prefilterUsage)
	}
	switch args[0] {
	case "build":
		return cmdPrefilterBuild(ctx, p, args[1:])
	case "test":
		return cmdPrefilterTest(ctx, p, args[1:])
	case "stats":
		return cmdPrefilterStats(ctx, p, args[1:])
	case "set":
		return cmdPrefilterSet(p, args[1:])
	}
	return fmt.Errorf("%s", prefilterUsage)
}

func cmdPrefilterBuild(ctx context.Context, p *output.Printer, args []string) error {
	fs := flag.NewFlagSet("prefilter build", flag.ContinueOnError)
	noCache := fs.Bool("no-cache", false, "build without the layer cache")
	tag := fs.String("tag", task.DefaultPrefilterImage, "image reference to build")
	modelDir := fs.String("model-dir", "", "directory with a model exported elsewhere (model.json, the .onnx file, tokenizer.json) instead of exporting in the build")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	rt, err := runtime.Detect(cfg.Runtime.Engine)
	if err != nil {
		return err
	}
	pc := cfg.Image.Prefilter
	if *modelDir != "" {
		p.Info("building %s from the model in %s (%s)", *tag, *modelDir, rt.Engine())
	} else {
		p.Info("building %s: export of %s@%s to ONNX (%s); the first build downloads torch and the model and takes several minutes", *tag, pc.Model, pc.Revision, pc.Quantize)
	}
	b := image.PrefilterBuild{Ref: *tag, ModelDir: *modelDir, NoCache: *noCache, Version: Version}
	if err := image.BuildPrefilter(ctx, rt, cfg, b); err != nil {
		return err
	}
	p.Good("built", "%s (recipe %s); the build's self-test passed", *tag, image.PrefilterRecipeHash(cfg))
	return nil
}

// cmdPrefilterTest scores the new items of a task the way the next feed
// check would, prints every decision, and claims nothing.
func cmdPrefilterTest(ctx context.Context, p *output.Printer, args []string) error {
	fs := flag.NewFlagSet("prefilter test", flag.ContinueOnError)
	rescore := fs.Bool("rescore", false, "score every new item again, also the ones with a recorded decision")
	keep := fs.Bool("keep", false, "keep the run directory with the model's input and output")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("%s", prefilterUsage)
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
	if !t.Feeds.Prefilter.Enabled() {
		return fmt.Errorf("task %s has no prefilter (set feeds.prefilter.mode to shadow or enforce)", t.Name)
	}
	rt, err := runtime.Detect(cfg.Runtime.Engine)
	if err != nil {
		return err
	}
	if exists, current, err := image.PrefilterIsCurrent(ctx, rt, cfg, t.Feeds.Prefilter.Image); err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("image %s is missing; run 'ais prefilter build'", t.Feeds.Prefilter.Image)
	} else if !current {
		p.Warn("image %s was built from another recipe or model; run 'ais prefilter build'", t.Feeds.Prefilter.Image)
	}
	opts, err := runOptions(cfg)
	if err != nil {
		return err
	}
	opts.Peek, opts.Rescore, opts.Prefilter = true, *rescore, rt
	st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	opts.Feeds = st
	opts.RunID = "prefilter-test-" + time.Now().UTC().Format("20060102T150405Z")
	prep, err := runner.Prepare(ctx, cfg, t, runner.EphemeralSalt{}, opts)
	if prep != nil && prep.RunDir != "" && !*keep {
		defer os.RemoveAll(prep.RunDir)
	}
	if err != nil && prep == nil {
		return err
	}
	for _, f := range prep.Feeds {
		if f.Err != "" {
			p.Warn("feed %s: %s", f.URL, f.Err)
		}
	}
	var rows []feedRow
	for _, it := range prep.Feed {
		rows = append(rows, feedRow{Score: it.Score, Keep: it.Keep, Reason: it.Reason, Match: it.Match, Source: it.Source, Title: it.Title, Link: it.Link})
	}
	for _, it := range prep.Filtered {
		rows = append(rows, feedRow{Score: it.Score, Keep: it.Keep, Reason: it.Reason, Match: it.Match, Source: it.Source, Title: it.Title, Link: it.Link})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Keep != rows[j].Keep {
			return rows[i].Keep == store.DecisionKeep
		}
		return rows[i].Score > rows[j].Score
	})
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SCORE\tDECISION\tWHY\tMATCH\tSOURCE\tTITLE")
	for _, r := range rows {
		score := "-"
		if r.Score > 0 {
			score = fmt.Sprintf("%.2f", r.Score)
		}
		decision := r.Keep
		if decision == "" {
			decision = "(not scored)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", score, decision, reasonLabel(r.Reason), cut(r.Match, 36), cut(r.Source, 24), cut(r.Title, 70))
	}
	tw.Flush()
	pf := prep.Prefilter
	mode := t.Feeds.Prefilter.Mode
	if pf.Kept+pf.Dropped > 0 {
		p.Info("prefilter (%s, threshold %.2f): %d scored by %s in %s, %d keyword hit(s); %d kept, %d dropped", mode, t.Feeds.Prefilter.Threshold, pf.Scored, pf.Model, pf.Duration.Round(time.Millisecond), pf.Keyword, pf.Kept, pf.Dropped)
	} else {
		p.Info("prefilter (%s): nothing new to score; the decisions above were recorded by earlier ticks (use --rescore to score them again)", mode)
	}
	if pf.Err != "" {
		p.Warn("prefilter: %s; every undecided item was kept", pf.Err)
	}
	if mode == task.PrefilterShadow {
		p.Info("shadow mode: every item still goes to the model; 'ais prefilter stats %s' compares the scores with what the model reported", t.Name)
	}
	p.Info("%d item(s) would go to the model, %d withheld", len(prep.Feed), len(prep.Filtered))
	if *keep && prep.RunDir != "" {
		p.Info("model input and output kept in %s", filepath.Join(prep.RunDir, "prefilter"))
	}
	return nil
}

type feedRow struct {
	Score                              float64
	Keep, Reason, Match, Source, Title string
	Link                               string
}

// reasonLabel renders a stored reason for a table: keyword 'pan os', model, error.
func reasonLabel(reason string) string {
	if kw, ok := strings.CutPrefix(reason, prefilter.ReasonKeyword+":"); ok {
		return "keyword '" + kw + "'"
	}
	return reason
}

func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// cmdPrefilterStats compares the recorded scores of a task with the
// model's results: which items it reported or checked, and what they
// scored. The lowest score of a reported item is the evidence for the
// threshold.
func cmdPrefilterStats(ctx context.Context, p *output.Printer, args []string) error {
	fs := flag.NewFlagSet("prefilter stats", flag.ContinueOnError)
	since := fs.Duration("since", 7*24*time.Hour, "window (for example 72h)")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("%s", prefilterUsage)
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
	threshold := task.DefaultPrefilterThreshold
	if t.Feeds != nil && t.Feeds.Prefilter != nil {
		threshold = t.Feeds.Prefilter.Threshold
	}
	st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	from := time.Now().Add(-*since)
	items, err := st.FeedItemScores(ctx, t.Name, from)
	if err != nil {
		return err
	}
	results, err := st.ResultsSince(ctx, t.Name, from)
	if err != nil {
		return err
	}
	verdicts := modelVerdicts(results)
	s := prefilterStats(items, verdicts, threshold)
	if *asJSON {
		return output.JSON(s)
	}
	fmt.Printf("task %s, last %s, threshold %.2f\n", t.Name, since, threshold)
	fmt.Printf("decided: %d item(s): %d keyword hit(s), %d scored by the model, %d not scored (error)\n", s.Decided, s.Keyword, s.Scored, s.Unscored)
	fmt.Printf("at this threshold: %d kept, %d dropped (recorded decisions: %d kept, %d dropped)\n", s.WouldKeep, s.WouldDrop, s.Kept, s.Dropped)
	if s.Scored > 0 {
		fmt.Printf("score histogram (model-scored items):\n")
		for i, n := range s.Histogram {
			lo := float64(i) / 10
			bar := strings.Repeat("#", min(n, 60))
			mark := " "
			if lo < threshold && lo+0.1 > threshold {
				mark = "<"
			}
			fmt.Printf("  %.1f-%.1f %s %4d %s\n", lo, lo+0.1, mark, n, bar)
		}
	}
	fmt.Printf("items the model evaluated (checked or reported) that have a score: %d\n", len(s.Evaluated))
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SCORE\tDECISION\tVERDICT\tTITLE")
	for _, e := range s.Evaluated {
		score := "kw"
		if e.Scored {
			score = fmt.Sprintf("%.2f", e.Score)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", score, e.Decision+" ("+reasonLabel(e.Reason)+")", cut(e.Verdict, 40), cut(e.Title, 60))
	}
	tw.Flush()
	switch {
	case s.Reported == 0:
		p.Info("no reported finding matched a scored feed item in the window; collect more days before enforcing")
	case s.LowestReported >= threshold:
		p.Good("ok", "every reported item scored at least %.2f (threshold %.2f); %d reported, %d dropped wrongly", s.LowestReported, threshold, s.Reported, s.ReportedDropped)
	default:
		p.Warn("a reported item scored %.2f, below the threshold %.2f: %d of %d reported item(s) would be dropped; lower the threshold or keep shadow mode", s.LowestReported, threshold, s.ReportedDropped, s.Reported)
	}
	return nil
}

// verdict is what the model said about a URL: "reported" when it is a
// finding's source, else the checked verdict.
type verdict struct {
	Verdict  string
	Reported bool
}

// modelVerdicts reads findings[].source_urls and checked[].url from the
// results of a task.
func modelVerdicts(results []store.Result) map[string]verdict {
	out := map[string]verdict{}
	for _, r := range results {
		var doc struct {
			Findings []struct {
				SourceURLs []string `json:"source_urls"`
			} `json:"findings"`
			Checked []struct {
				URL     string `json:"url"`
				Verdict string `json:"verdict"`
			} `json:"checked"`
		}
		if err := json.Unmarshal(r.PseudoJSON, &doc); err != nil {
			continue
		}
		for _, c := range doc.Checked {
			k := normURL(c.URL)
			if v, ok := out[k]; !ok || !v.Reported {
				out[k] = verdict{Verdict: c.Verdict}
			}
		}
		for _, f := range doc.Findings {
			for _, u := range f.SourceURLs {
				out[normURL(u)] = verdict{Verdict: "reported", Reported: true}
			}
		}
	}
	return out
}

func normURL(u string) string {
	u = strings.TrimSpace(strings.ToLower(u))
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "www.")
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	return strings.TrimRight(u, "/")
}

// Stats is the output of ais prefilter stats.
type Stats struct {
	Decided, Keyword, Scored, Unscored int
	Kept, Dropped                      int
	WouldKeep, WouldDrop               int
	Histogram                          [10]int
	Evaluated                          []EvaluatedItem
	Reported, ReportedDropped          int
	LowestReported                     float64
}

// EvaluatedItem is a scored feed item the model checked or reported.
type EvaluatedItem struct {
	Key, Title, Link, Decision, Reason, Verdict string
	Score                                       float64
	Scored, Reported                            bool
}

func prefilterStats(items []store.FeedItem, verdicts map[string]verdict, threshold float64) Stats {
	var s Stats
	s.LowestReported = 1
	for _, it := range items {
		s.Decided++
		switch {
		case prefilter.IsKeyword(it.Reason):
			s.Keyword++
		case it.Reason == prefilter.ReasonModel:
			s.Scored++
		default:
			s.Unscored++
		}
		if it.Decision == store.DecisionKeep {
			s.Kept++
		} else {
			s.Dropped++
		}
		wouldKeep := it.Reason != "model" || it.Score >= threshold
		if wouldKeep {
			s.WouldKeep++
		} else {
			s.WouldDrop++
		}
		if it.Scored && it.Reason == "model" {
			b := int(it.Score * 10)
			if b < 0 {
				b = 0
			}
			if b > 9 {
				b = 9
			}
			s.Histogram[b]++
		}
		v, ok := verdicts[normURL(it.Link)]
		if !ok {
			continue
		}
		s.Evaluated = append(s.Evaluated, EvaluatedItem{Key: it.Key, Title: it.Title, Link: it.Link, Decision: it.Decision, Reason: it.Reason, Verdict: v.Verdict, Score: it.Score, Scored: it.Scored, Reported: v.Reported})
		if v.Reported {
			s.Reported++
			if !wouldKeep {
				s.ReportedDropped++
			}
			if it.Scored && it.Reason == "model" && it.Score < s.LowestReported {
				s.LowestReported = it.Score
			}
		}
	}
	sort.SliceStable(s.Evaluated, func(i, j int) bool {
		if s.Evaluated[i].Reported != s.Evaluated[j].Reported {
			return s.Evaluated[i].Reported
		}
		return s.Evaluated[i].Score < s.Evaluated[j].Score
	})
	return s
}

// prefilterKeys are the keys ais prefilter set accepts, with the YAML tag
// their value gets.
var prefilterKeys = map[string]string{
	"mode": "!!str", "threshold": "!!float", "image": "!!str", "timeout": "!!str", "keywords": "!!bool", "maxTokens": "!!int",
}

// cmdPrefilterSet changes feeds.prefilter.<key> in the task file, keeping
// the rest of the document and its comments, and validates the result
// before it replaces the file.
func cmdPrefilterSet(p *output.Printer, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: ais prefilter set <task> key=value... (keys: mode threshold image timeout keywords maxTokens)")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	tasks, err := loadTasks(cfg)
	if err != nil {
		return err
	}
	t, ok := task.Find(tasks, args[0])
	if !ok {
		return fmt.Errorf("no task named %q", args[0])
	}
	if t.Feeds == nil {
		return fmt.Errorf("task %s has no feeds key; the prefilter needs feeds", t.Name)
	}
	data, err := os.ReadFile(t.Path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	for _, kv := range args[1:] {
		key, val, ok := strings.Cut(kv, "=")
		tag, known := prefilterKeys[key]
		if !ok || !known {
			return fmt.Errorf("%q: want key=value with a key from: mode threshold image timeout keywords maxTokens", kv)
		}
		if tag == "!!float" {
			if _, err := strconv.ParseFloat(val, 64); err != nil {
				return fmt.Errorf("%s: %q is not a number", key, val)
			}
		}
		if err := setYAMLPath(&doc, []string{"feeds", "prefilter", key}, val, tag); err != nil {
			return err
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	enc.Close()
	tmp := t.Path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	if _, err := task.LoadFile(tmp, taskDefaults(cfg)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("change rejected: %w", err)
	}
	_ = os.Rename(t.Path, t.Path+".bak-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Rename(tmp, t.Path); err != nil {
		return err
	}
	p.Good("updated", "%s (feeds.prefilter: %s); apply with: systemctl --user kill -s HUP ais", t.Path, strings.Join(args[1:], " "))
	return nil
}

// setYAMLPath sets a scalar at a mapping path, creating mappings on the
// way. The document node wraps one mapping.
func setYAMLPath(doc *yaml.Node, path []string, value, tag string) error {
	node := doc
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			node.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
		}
		node = node.Content[0]
	}
	for i, key := range path {
		if node.Kind != yaml.MappingNode {
			return fmt.Errorf("%s is not a mapping", strings.Join(path[:i], "."))
		}
		var found *yaml.Node
		for j := 0; j+1 < len(node.Content); j += 2 {
			if node.Content[j].Value == key {
				found = node.Content[j+1]
				break
			}
		}
		last := i == len(path)-1
		if found == nil {
			k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
			var v *yaml.Node
			if last {
				v = &yaml.Node{Kind: yaml.ScalarNode}
			} else {
				v = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			}
			node.Content = append(node.Content, k, v)
			found = v
		}
		if last {
			found.Kind, found.Tag, found.Value, found.Content, found.Style = yaml.ScalarNode, tag, value, nil, 0
			if tag == "!!str" {
				found.Tag = ""
			}
			return nil
		}
		if found.Kind != yaml.MappingNode {
			// A scalar or null placeholder: replace it with a mapping.
			found.Kind, found.Tag, found.Value, found.Content, found.Style = yaml.MappingNode, "!!map", "", nil, 0
		}
		node = found
	}
	return nil
}

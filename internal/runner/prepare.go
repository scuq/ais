package runner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/scuq/ais/internal/claude"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/container"
	"github.com/scuq/ais/internal/egress"
	"github.com/scuq/ais/internal/feed"
	"github.com/scuq/ais/internal/inventory"
	"github.com/scuq/ais/internal/prefilter"
	"github.com/scuq/ais/internal/prompt"
	"github.com/scuq/ais/internal/pseudo"
	"github.com/scuq/ais/internal/scheduler"
	"github.com/scuq/ais/internal/store"
	"github.com/scuq/ais/internal/task"
)

// NewRunID returns a sortable, filesystem-safe run id: UTC timestamp plus
// two random bytes.
func NewRunID(now time.Time) string {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

// SaltSource supplies the per-task pseudonymization salt. The store
// implements it; tests and dry runs use an ephemeral one.
type SaltSource interface {
	TaskSalt(ctx context.Context, task string) (id string, salt []byte, err error)
}

// EphemeralSalt mints a fresh salt per call. Tokens from such a run cannot
// be correlated with any other run, which is what a dry run wants.
type EphemeralSalt struct{}

func (EphemeralSalt) TaskSalt(context.Context, string) (string, []byte, error) {
	s, err := pseudo.NewSalt()
	if err != nil {
		return "", nil, err
	}
	return "ephemeral", s, nil
}

// Options tune one run.
type Options struct {
	// Engine is the resolved engine name ("docker" | "podman").
	Engine string
	// UID/GID the container runs as (docker) or maps to (podman).
	UID, GID int
	// HostBinary is the ais executable to mount for the hook.
	HostBinary string
	// Now overrides the clock (tests).
	Now time.Time
	// RunID overrides the generated id (tests).
	RunID string
	// Trigger says why the run starts (scheduler.Trigger*). A "-full"
	// trigger makes a task with feeds do the full check.
	Trigger string
	// Feeds remembers which feed items earlier runs evaluated; nil means
	// every item is new and nothing is recorded (dry runs).
	Feeds FeedStore
	// Peek makes a feed check report the new items without claiming them
	// (dry runs).
	Peek bool
	// Prefilter runs the scoring container of a feed check; nil keeps every
	// item (the prefilter then reports an error, never a drop).
	Prefilter prefilter.Runner
	// Rescore scores new items again even when a tick already decided
	// them (ais prefilter test --rescore).
	Rescore bool
	// SELinux adds the relabel option to bind mounts.
	SELinux bool
	// Live receives a rendered event stream while the container runs; nil
	// keeps the compact json output.
	Live io.Writer
}

// Prepared is a run that is ready to execute: its directory exists, in/ is
// written, the spec is built. The token map stays here, on the host.
type Prepared struct {
	Task      *task.Task
	RunID     string
	RunDir    string
	StartedAt time.Time
	Spec      *container.Spec
	Argv      []string
	Files     prompt.Files
	Map       *pseudo.Map
	Records   []inventory.Record // original, clear records for enrichment
	Rules     pseudo.Rules
	// BackendURL is the inventory MCP endpoint, empty when none.
	BackendURL string
	// Mode is "full" or "feed"; Feed holds the new items of a feed run
	// and Feeds what each feed returned.
	Mode  string
	Feed  []feed.Item
	Feeds []FeedStatus
	// Prefilter is what the host-side filter did with this tick's items;
	// Filtered lists the items it withheld (enforce mode only).
	Prefilter prefilter.Info
	Filtered  []feed.Item
	// FetchTime is the wall time of reading the feeds.
	FetchTime time.Duration
}

// UsageColumns copies what the feed tick fetched and what the prefilter
// did into the columns of a run row.
func (p *Prepared) UsageColumns(r *store.Run) {
	if p == nil || p.Mode != "feed" {
		return
	}
	distinct := 0
	for _, f := range p.Feeds {
		r.Feeds++
		if f.Err != "" {
			r.FeedsFailed++
		}
		distinct += f.Items
	}
	r.FeedItems = distinct
	r.FeedNew, r.FeedFiltered, r.FetchMS = len(p.Feed), len(p.Filtered), p.FetchTime.Milliseconds()
	pf := p.Prefilter
	r.PrefilterMS, r.PrefilterScored, r.PrefilterKeyword = pf.Duration.Milliseconds(), pf.Scored, pf.Keyword
	r.PrefilterKept, r.PrefilterDropped = pf.Kept, pf.Dropped
	r.PrefilterCPUMS, r.PrefilterMemPeak, r.PrefilterError = pf.CPU.Milliseconds(), pf.MemPeak, pf.Err
}

// FeedStore is the part of the store that remembers feed items.
type FeedStore interface {
	ClaimFeedItems(ctx context.Context, task, runID string, items []store.FeedItem, limit int, now time.Time) ([]store.FeedItem, error)
	RecordFeedItemsSeen(ctx context.Context, task string, items []store.FeedItem, now time.Time) error
	ModelRunsSince(ctx context.Context, task, trigger, mode string, since time.Time) (int, error)
	// FeedItemStates returns the rows the task already has for keys.
	FeedItemStates(ctx context.Context, task string, keys []string) (map[string]store.FeedItem, error)
}

// FeedStatus is what one feed returned for a run, for logs and dry runs.
type FeedStatus struct {
	URL   string `json:"url"`
	Items int    `json:"items"`
	New   int    `json:"new"`
	Err   string `json:"error,omitempty"`
	// Unstable is set when every item of a feed with several items is new
	// again: its ids or links change from fetch to fetch, and it would
	// make every tick a model run. The cap on runs per day holds that.
	Unstable bool `json:"unstable,omitempty"`
}

// ErrQuiet means a feed check found no new item; no container starts.
var ErrQuiet = errors.New("no new feed items")

// ErrRateLimited means the task reached feeds.maxRunsPerDay; the new
// items wait for a later tick, and no container starts.
var ErrRateLimited = errors.New("feeds.maxRunsPerDay reached")

// Prepare builds everything a run needs without starting a container. For
// a task with feeds, a run that is not a full run reads the feeds first
// and returns ErrQuiet when nothing is new and the task skips quiet runs.
func Prepare(ctx context.Context, cfg *config.Config, t *task.Task, salts SaltSource, opts Options) (*Prepared, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	runID := opts.RunID
	if runID == "" {
		runID = NewRunID(now)
	}
	runDir := filepath.Join(cfg.RunsDir(), t.Name, runID)
	inDir := filepath.Join(runDir, "in")
	outDir := filepath.Join(runDir, "out")
	for _, d := range []string{inDir, outDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}

	// Inventory: each task key that is set overrides the global one.
	var recs []inventory.Record
	src, textFile := inventorySources(cfg, t)
	if src.File != "" {
		s, err := inventory.Open(src)
		if err != nil {
			return nil, err
		}
		recs, err = s.Load(ctx)
		if err != nil {
			return nil, err
		}
	}
	var text []string
	if textFile != "" {
		var err error
		if text, err = inventory.LoadText(textFile); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%w (create the file or remove inventory.textFile)", err)
			}
			return nil, err
		}
	}

	saltID, salt, err := salts.TaskSalt(ctx, t.Name)
	if err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	m := pseudo.NewMap(t.Name, saltID)
	tok := pseudo.NewTokenizer(salt, nil)
	tok.HostnameMode, tok.IPMode = cfg.PII.HostnameMode, cfg.PII.IPMode
	// Scrub fields (comments) go through the same policy keyed with the task
	// salt, so an address in a comment matches the ip field's token and is
	// reversible on the host.
	scrubRules := cfg.Redaction().Rules()
	scrubRules.Literals = append(append([]string(nil), scrubRules.Literals...), t.PII.Redact.Literals...)
	scrubRules.Domains = append(scrubRules.Domains, t.PII.Redact.Domains...)
	scrubRules.CIDRs = append(scrubRules.CIDRs, t.PII.Redact.CIDRs...)
	scrubRules.Key = hex.EncodeToString(salt)
	scrub, err := pseudo.NewRedactor(scrubRules)
	if err != nil {
		return nil, err
	}
	scrub.OnMap = func(token, real string) { m.Add(token, "scrub", real) }
	pseudoRecs := pseudo.Apply(t.Policy(), tok, m, scrub, recs)
	// Free-text lines are operator prose like a scrub field: the same
	// redactor, so an address in a line matches the inventory tokens.
	pseudoText := make([]string, len(text))
	for i, line := range text {
		pseudoText[i] = scrub.Redact(line)
	}
	var groups []inventory.Group
	if len(t.Expose.Prompt.GroupBy) > 0 {
		groups = inventory.Minimize(pseudoRecs, t.Expose.Prompt.GroupBy, t.Expose.Prompt.Collect)
	}

	mode := "full"
	var feedItems, filtered []feed.Item
	var feedStatus []FeedStatus
	var pfInfo prefilter.Info
	var fetchTime time.Duration
	if t.Feeds != nil && !scheduler.FullRun(opts.Trigger) {
		mode = "feed"
		fr, err := readFeeds(ctx, t, runID, now, opts, runDir, prefilter.BuildTargets(groups, pseudoText))
		if err != nil {
			return nil, err
		}
		feedItems, feedStatus, pfInfo, filtered, fetchTime = fr.Items, fr.Status, fr.Prefilter, fr.Filtered, fr.FetchTime
		if len(feedItems) == 0 && t.Feeds.Quiet() {
			_ = os.RemoveAll(runDir)
			return &Prepared{Task: t, RunID: runID, StartedAt: now, Mode: mode, Feeds: feedStatus, Prefilter: pfInfo, Filtered: filtered, FetchTime: fetchTime}, ErrQuiet
		}
		if cap := t.Feeds.RunCap(); cap > 0 && opts.Feeds != nil && !opts.Peek && opts.Trigger == scheduler.TriggerSchedule {
			n, err := opts.Feeds.ModelRunsSince(ctx, t.Name, scheduler.TriggerSchedule, mode, now.Add(-24*time.Hour))
			if err != nil {
				return nil, err
			}
			if n >= cap {
				_ = os.RemoveAll(runDir)
				if rel, ok := opts.Feeds.(interface {
					SettleFeedItems(context.Context, string, bool) error
				}); ok {
					_ = rel.SettleFeedItems(ctx, runID, false) // the items wait for a later tick
				}
				return &Prepared{Task: t, RunID: runID, StartedAt: now, Mode: mode, Feed: feedItems, Feeds: feedStatus, Prefilter: pfInfo, Filtered: filtered, FetchTime: fetchTime}, fmt.Errorf("%w: %d scheduled feed run(s) started the model in the last 24 h; %d new item(s) wait", ErrRateLimited, n, len(feedItems))
			}
		}
	}

	// The hook's cgnat key is random per run: addresses it rewrites in web
	// content never correlate with inventory tokens or across runs.
	hookKey := make([]byte, 32)
	if _, err := rand.Read(hookKey); err != nil {
		return nil, err
	}
	rules := pseudo.Rules{
		Domains:      append(append([]string(nil), cfg.PII.Domains...), t.PII.Redact.Domains...),
		CIDRs:        append(append([]string(nil), cfg.PII.CIDRs...), t.PII.Redact.CIDRs...),
		Literals:     append(append([]string(nil), cfg.PII.Literals...), t.PII.Redact.Literals...),
		HostnameMode: cfg.PII.HostnameMode,
		IPMode:       cfg.PII.IPMode,
		Key:          hex.EncodeToString(hookKey),
	}

	backendURL := ""
	var noProxy []string
	proxyURL, networkName := "", ""
	if cfg.Egress.Mode == "proxy" {
		ip, err := egress.BackendIP(cfg.Egress.Subnet)
		if err != nil {
			return nil, err
		}
		backendURL = fmt.Sprintf("http://%s:%d/mcp", ip, cfg.Backend.MCPPort)
		noProxy = []string{ip}
		proxyURL, err = egress.ProxyURL(cfg.Egress.Subnet, cfg.Egress.ProxyPort)
		if err != nil {
			return nil, err
		}
		networkName = egress.InternalNetwork
	}

	data := prompt.Data{
		Task:    t,
		Run:     prompt.RunMeta{ID: runID, Task: t.Name, StartedAt: now},
		Now:     now,
		Groups:  groups,
		Records: pseudoRecs,
		Text:    pseudoText,
		Mode:    mode,
		Feed:    feedItems,
	}
	files, err := prompt.Generate(t, data, prompt.Env{
		BackendURL:  backendURL,
		RedactRules: rules,
		HookEnabled: opts.HostBinary != "",
		Stream:      opts.Live != nil,

		EgressRestricted: cfg.Egress.Mode == "proxy",
		EgressAllow:      egress.Reachable(cfg, t),
	})
	if err != nil {
		return nil, err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(inDir, name), content, 0o600); err != nil {
			return nil, err
		}
	}

	spec := composeSpec(SpecInput{
		Image:       cfg.Runtime.Image,
		TaskName:    t.Name,
		RunID:       runID,
		RunDir:      runDir,
		HostBinary:  opts.HostBinary,
		UID:         opts.UID,
		GID:         opts.GID,
		MaxTurns:    t.MaxTurns,
		Memory:      cfg.Runtime.Memory,
		CPUs:        cfg.Runtime.CPUs,
		PidsLimit:   cfg.Runtime.PidsLimit,
		TmpfsSize:   cfg.Runtime.TmpfsSize,
		NetworkName: networkName,
		ProxyURL:    proxyURL,
		NoProxy:     noProxy,
	})
	d, err := container.DialectFor(opts.Engine)
	if err != nil {
		return nil, err
	}
	return &Prepared{
		Task:       t,
		RunID:      runID,
		RunDir:     runDir,
		StartedAt:  now,
		Spec:       spec,
		Argv:       spec.Argv(d, opts.SELinux),
		Files:      files,
		Map:        m,
		Records:    recs,
		Rules:      rules,
		BackendURL: backendURL,
		Mode:       mode,
		Feed:       feedItems,
		Feeds:      feedStatus,
		Prefilter:  pfInfo,
		Filtered:   filtered,
		FetchTime:  fetchTime,
	}, nil
}

// feedRead is what readFeeds returns.
type feedRead struct {
	Items     []feed.Item
	Status    []FeedStatus
	Prefilter prefilter.Info
	Filtered  []feed.Item
	FetchTime time.Duration
}

// readFeeds fetches the task's feeds and returns the items that no earlier
// run evaluated, newest first and capped at feeds.maxItems. A feed that
// fails is reported in the status and skipped; the others still count.
// With a prefilter, every item that no tick has scored is scored against
// targets first; in enforce mode a dropped item is recorded as filtered
// and not returned.
func readFeeds(ctx context.Context, t *task.Task, runID string, now time.Time, opts Options, runDir string, targets []prefilter.Target) (feedRead, error) {
	var fr feedRead
	fetchStart := time.Now()
	results := feed.FetchAll(ctx, t.Feeds.URLs, t.Feeds.Timeout)
	fr.FetchTime = time.Since(fetchStart)
	var status []FeedStatus
	var all []store.FeedItem
	byKey := map[string]feed.Item{}
	failed := 0
	for _, r := range results {
		st := FeedStatus{URL: r.URL, Items: len(r.Items)}
		if r.Err != nil {
			st.Err = r.Err.Error()
			failed++
		}
		status = append(status, st)
		for _, it := range r.Items {
			if _, dup := byKey[it.Key]; dup {
				continue
			}
			byKey[it.Key] = it
			all = append(all, store.FeedItem{Key: it.Key, Title: it.Title, Link: it.Link, Source: it.Source, Summary: it.Summary, Published: it.Published})
		}
	}
	fr.Status = status
	if failed == len(results) {
		return fr, fmt.Errorf("feeds: every feed failed (%s)", status[0].Err)
	}
	// Old items are news to nobody: a feed that rotates its entries must
	// not present them as new.
	cutoff := now.Add(-t.Feeds.MaxAge)
	var recent, old []store.FeedItem
	for _, it := range all {
		if !it.Published.IsZero() && it.Published.Before(cutoff) {
			old = append(old, it)
		} else {
			recent = append(recent, it)
		}
	}
	if opts.Feeds != nil && len(old) > 0 && !opts.Peek {
		if err := opts.Feeds.RecordFeedItemsSeen(ctx, t.Name, old, now); err != nil {
			return fr, fmt.Errorf("feeds: %w", err)
		}
	}
	all = recent
	if t.Feeds.Prefilter.Enabled() {
		info, err := scoreFeedItems(ctx, t, runID, opts, runDir, targets, all)
		if err != nil {
			return fr, err
		}
		fr.Prefilter = info
	}
	var fresh []store.FeedItem
	if opts.Feeds == nil {
		for _, it := range all {
			if it.State != store.FeedFiltered {
				fresh = append(fresh, it)
			}
		}
		if len(fresh) > t.Feeds.MaxItems {
			fresh = fresh[:t.Feeds.MaxItems]
		}
	} else {
		claimAs := runID
		if opts.Peek {
			claimAs = ""
		}
		var err error
		if fresh, err = opts.Feeds.ClaimFeedItems(ctx, t.Name, claimAs, all, t.Feeds.MaxItems, now); err != nil {
			return fr, fmt.Errorf("feeds: %w", err)
		}
	}
	freshKeys := map[string]bool{}
	for _, f := range fresh {
		freshKeys[f.Key] = true
	}
	for i, r := range results {
		for _, it := range r.Items {
			if freshKeys[it.Key] {
				status[i].New++
			}
		}
		if status[i].Items >= 5 && status[i].New == status[i].Items {
			status[i].Unstable = true
		}
	}
	toItem := func(f store.FeedItem) feed.Item {
		it, ok := byKey[f.Key]
		if !ok {
			// An item from an earlier failed run that the feed no longer lists.
			it = feed.Item{Key: f.Key, Title: f.Title, Link: f.Link, Source: f.Source, Summary: f.Summary, Published: f.Published}
		}
		it.Score, it.Keep, it.Reason = f.Score, f.Decision, f.Reason
		if f.Decision == store.DecisionKeep {
			// A dropped item (shadow mode) still goes to the model, but
			// must not be presented as a match.
			it.Match = f.Match
		}
		return it
	}
	fr.Items = make([]feed.Item, 0, len(fresh))
	for _, f := range fresh {
		fr.Items = append(fr.Items, toItem(f))
	}
	for _, f := range all {
		if f.State == store.FeedFiltered {
			fr.Filtered = append(fr.Filtered, toItem(f))
		}
	}
	return fr, nil
}

// scoreFeedItems runs the prefilter over the items of all that no run has
// evaluated and no tick has scored, and writes the decisions into all. In
// enforce mode a dropped item gets the state filtered.
func scoreFeedItems(ctx context.Context, t *task.Task, runID string, opts Options, runDir string, targets []prefilter.Target, all []store.FeedItem) (prefilter.Info, error) {
	pf := t.Feeds.Prefilter
	known := map[string]store.FeedItem{}
	if opts.Feeds != nil {
		keys := make([]string, len(all))
		for i, it := range all {
			keys[i] = it.Key
		}
		var err error
		if known, err = opts.Feeds.FeedItemStates(ctx, t.Name, keys); err != nil {
			return prefilter.Info{}, fmt.Errorf("feeds: %w", err)
		}
	}
	idx := map[string]int{}
	var toScore []prefilter.Item
	for i, it := range all {
		idx[it.Key] = i
		if k, ok := known[it.Key]; ok && (k.State != store.FeedNew || (k.Decision != "" && !opts.Rescore)) {
			continue
		}
		toScore = append(toScore, prefilter.Item{Key: it.Key, Text: prefilter.ItemText(it.Title, it.Summary)})
	}
	if len(toScore) == 0 {
		return prefilter.Info{}, nil
	}
	dialect, err := container.DialectFor(opts.Engine)
	if err != nil {
		dialect = container.DockerDialect{}
	}
	cfg := prefilter.Config{Filter: pf, TaskName: t.Name, RunID: runID, Dialect: dialect, UID: opts.UID, GID: opts.GID, SELinux: opts.SELinux}
	decisions, info := prefilter.Score(ctx, opts.Prefilter, cfg, filepath.Join(runDir, "prefilter"), targets, toScore)
	for _, d := range decisions {
		it := &all[idx[d.Key]]
		it.Decision, it.Reason, it.Match, it.Score, it.Scored, it.Model = store.DecisionKeep, d.Reason, d.Match, d.Score, d.Scored, info.Model
		if !d.Keep {
			it.Decision = store.DecisionDrop
			if pf.Enforces() {
				it.State = store.FeedFiltered
			}
		}
	}
	return info, nil
}

// inventorySources resolves the record source and the free-text file: a
// task key that is set wins, an empty one keeps the configured default.
func inventorySources(cfg *config.Config, t *task.Task) (inventory.SourceConfig, string) {
	src := inventory.SourceConfig{File: config.ExpandPath(cfg.Inventory.File), Format: cfg.Inventory.Format}
	textFile := config.ExpandPath(cfg.Inventory.TextFile)
	if t.Inventory != nil {
		if t.Inventory.File != "" {
			src = inventory.SourceConfig{File: config.ExpandPath(t.Inventory.File), Format: t.Inventory.Format}
		}
		if t.Inventory.TextFile != "" {
			textFile = config.ExpandPath(t.Inventory.TextFile)
		}
	}
	return src, textFile
}

// PromptLog builds the log record of what this run sends to the model.
func (p *Prepared) PromptLog() store.Prompt {
	body := p.Files[prompt.PromptFile]
	system := p.Files[prompt.SystemFile]
	sum := sha256.Sum256(append(append([]byte{}, system...), body...))
	return store.Prompt{
		RunID: p.RunID, Task: p.Task.Name, CreatedAt: p.StartedAt,
		SHA256: hex.EncodeToString(sum[:]), Bytes: len(body) + len(system),
		System: string(system), Prompt: string(body), ArgvJSON: string(p.Files[prompt.ArgvFile]),
	}
}

// AppendPromptLog appends one NDJSON line to <runsDir>/<task>/prompts.ndjson,
// the append-only audit trail of every prompt sent (retention never prunes it).
func AppendPromptLog(runsDir string, p store.Prompt) error {
	dir := filepath.Join(runsDir, p.Task)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "prompts.ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(map[string]any{
		"run_id": p.RunID, "task": p.Task, "time": p.CreatedAt.UTC().Format(time.RFC3339),
		"sha256": p.SHA256, "bytes": p.Bytes, "system": p.System, "prompt": p.Prompt,
	})
}

// ClaudeArgvPath is the host path of the generated argv file.
func (p *Prepared) ClaudeArgvPath() string {
	return filepath.Join(p.RunDir, "in", prompt.ArgvFile)
}

// InContainerArgvPath is where the entrypoint reads the argv.
const InContainerArgvPath = claude.ArgvFile

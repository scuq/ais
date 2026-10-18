// Package prefilter scores new feed items against the inventory on the
// host, before a run, so that an item that cannot concern an inventoried
// product never costs a model turn. Two passes: a lexical pass on vendor
// and product names, which always keeps a hit, and an embedding pass in a
// one-shot container with no network, which scores the rest by cosine
// similarity to the closest inventory entry. Any failure keeps every
// undecided item: a missed vulnerability costs more than a model turn.
package prefilter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scuq/ais/internal/container"
	"github.com/scuq/ais/internal/task"
)

// Runner is the part of the container runtime the prefilter needs.
type Runner interface {
	RunCapture(ctx context.Context, argv []string, env []string, stdout, stderr io.Writer) (int, error)
}

// Config is one scoring call.
type Config struct {
	// Filter holds the prefilter settings of the task.
	Filter *task.Prefilter
	// Container identity and posture.
	TaskName string
	RunID    string
	Dialect  container.Dialect
	UID, GID int
	SELinux  bool
	// Memory caps the container; empty means 2g (an fp32 export of a
	// 0.1B model is 600 MB on disk and more in memory).
	Memory string
}

// Target is one thing the inventory cares about: the text the model
// embeds, the label a match reports, and the keywords of the lexical pass
// (phrases as space-joined lower-case tokens).
type Target struct {
	ID       string   `json:"id"`
	Label    string   `json:"-"`
	Text     string   `json:"text"`
	Keywords []string `json:"-"`
}

// Item is one feed item to score.
type Item struct {
	Key  string `json:"key"`
	Text string `json:"text"`
}

// Reasons of a decision. A keyword reason carries the keyword:
// "keyword:pan os".
const (
	ReasonKeyword = "keyword" // a vendor or product name is in the text
	ReasonModel   = "model"   // the embedding score decided
	ReasonError   = "error"   // the model did not run; kept
)

// IsKeyword reports whether a reason is a keyword hit.
func IsKeyword(reason string) bool {
	return reason == ReasonKeyword || strings.HasPrefix(reason, ReasonKeyword+":")
}

// Decision is the outcome for one item. Keep is true when the item goes on.
// Scored is true when Score holds a model score. Match is the label of the
// matching target. Reason is one of the Reason constants.
type Decision struct {
	Key    string
	Keep   bool
	Score  float64
	Scored bool
	Match  string
	Reason string
}

// Info summarizes one scoring call, for logs and dry runs.
type Info struct {
	Model    string        `json:"model,omitempty"`
	Dim      int           `json:"dim,omitempty"`
	Duration time.Duration `json:"duration"`
	// Err is why the model pass did not decide; the items were kept.
	Err     string `json:"error,omitempty"`
	Keyword int    `json:"keyword"`
	Scored  int    `json:"scored"`
	Kept    int    `json:"kept"`
	Dropped int    `json:"dropped"`
	// CPU and MemPeak are what the container used, as it reported them:
	// CPU time, and peak memory in bytes. Zero when the container did not
	// run or an older image did not report them.
	CPU     time.Duration `json:"cpu,omitempty"`
	MemPeak int64         `json:"memPeak,omitempty"`
}

// protocol is the version of in.json and out.json.
const protocol = 1

type input struct {
	V         int      `json:"v"`
	MaxTokens int      `json:"max_tokens"`
	Targets   []Target `json:"targets"`
	Items     []Item   `json:"items"`
}

type output struct {
	V      int     `json:"v"`
	Model  string  `json:"model"`
	Dim    int     `json:"dim"`
	MS     int64   `json:"ms"`
	Scores []score `json:"scores"`
	Usage  struct {
		CPUUsec int64 `json:"cpu_usec"`
		MemPeak int64 `json:"mem_peak"`
	} `json:"usage"`
}

type score struct {
	Key   string  `json:"key"`
	Score float64 `json:"score"`
	Best  string  `json:"best"`
}

// Score decides every item. workDir receives in.json, out.json and
// err.log of the container; it must exist. The returned decisions are in
// item order. Score never fails: an error of the model pass is in
// Info.Err and the affected items are kept.
func Score(ctx context.Context, rt Runner, cfg Config, workDir string, targets []Target, items []Item) (decisions []Decision, info Info) {
	start := time.Now()
	out := make([]Decision, len(items))
	pending := make([]int, 0, len(items))
	byID := map[string]Target{}
	for _, t := range targets {
		byID[t.ID] = t
	}
	for i, it := range items {
		out[i] = Decision{Key: it.Key}
		if cfg.Filter.UseKeywords() {
			if t, kw, ok := Lexical(targets, it.Text); ok {
				out[i].Keep, out[i].Match, out[i].Reason = true, t.Label, ReasonKeyword+":"+kw
				info.Keyword++
				continue
			}
		}
		pending = append(pending, i)
	}
	keepAll := func(why string) {
		info.Err = why
		for _, i := range pending {
			out[i].Keep, out[i].Reason = true, ReasonError
		}
	}
	defer func() {
		for _, d := range out {
			if d.Keep {
				info.Kept++
			} else {
				info.Dropped++
			}
		}
		info.Duration = time.Since(start)
	}()
	if len(pending) == 0 {
		return out, info
	}
	if len(targets) == 0 {
		keepAll("no inventory targets to score against")
		return out, info
	}
	if rt == nil {
		keepAll("no container runtime")
		return out, info
	}
	res, err := run(ctx, rt, cfg, workDir, targets, pick(items, pending))
	if err != nil {
		keepAll(err.Error())
		return out, info
	}
	info.Model, info.Dim = res.Model, res.Dim
	info.CPU, info.MemPeak = time.Duration(res.Usage.CPUUsec)*time.Microsecond, res.Usage.MemPeak
	scores := map[string]score{}
	for _, s := range res.Scores {
		scores[s.Key] = s
	}
	missing := 0
	for _, i := range pending {
		s, ok := scores[items[i].Key]
		if !ok {
			out[i].Keep, out[i].Reason = true, ReasonError
			missing++
			continue
		}
		out[i].Score, out[i].Scored, out[i].Reason = s.Score, true, ReasonModel
		out[i].Match = byID[s.Best].Label
		out[i].Keep = s.Score >= cfg.Filter.Threshold
		info.Scored++
	}
	if missing > 0 {
		info.Err = fmt.Sprintf("the model returned no score for %d item(s); kept", missing)
	}
	return out, info
}

func pick(items []Item, idx []int) []Item {
	out := make([]Item, 0, len(idx))
	for _, i := range idx {
		out = append(out, items[i])
	}
	return out
}

// run writes in.json, runs the container and parses its stdout.
func run(ctx context.Context, rt Runner, cfg Config, workDir string, targets []Target, items []Item) (*output, error) {
	in := input{V: protocol, MaxTokens: cfg.Filter.MaxTokens, Targets: targets, Items: items}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(workDir, "in.json"), raw, 0o644); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(workDir, "in.json")); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(workDir)
	if err != nil {
		return nil, err
	}
	spec := Spec(cfg, abs)
	argv := spec.Argv(cfg.Dialect, cfg.SELinux)
	timeout := cfg.Filter.Timeout
	if timeout <= 0 {
		timeout = task.DefaultPrefilterTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code, err := rt.RunCapture(ctx, argv, nil, &stdout, &stderr)
	_ = os.WriteFile(filepath.Join(workDir, "out.json"), stdout.Bytes(), 0o600)
	_ = os.WriteFile(filepath.Join(workDir, "err.log"), stderr.Bytes(), 0o600)
	if ctx.Err() != nil {
		return nil, fmt.Errorf("prefilter container exceeded %s", timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("prefilter container: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("prefilter container exited %d: %s", code, firstLine(stderr.String()))
	}
	var res output
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return nil, fmt.Errorf("prefilter output is not JSON: %w", err)
	}
	if res.V != protocol {
		return nil, fmt.Errorf("prefilter output protocol %d, want %d (rebuild the image with 'ais prefilter build')", res.V, protocol)
	}
	return &res, nil
}

// Spec is the container the scoring runs in: the image only, read-only,
// no capabilities, no network, one read-only mount of the work directory,
// a tmpfs for /tmp and a memory cap. It prints its result on stdout.
func Spec(cfg Config, workDir string) *container.Spec {
	memory := cfg.Memory
	if memory == "" {
		memory = "2g"
	}
	s := &container.Spec{
		Image:           cfg.Filter.Image,
		Name:            ContainerName(cfg.TaskName, cfg.RunID),
		Hostname:        "ais-prefilter",
		Remove:          true,
		UID:             cfg.UID,
		GID:             cfg.GID,
		ReadOnlyRootfs:  true,
		CapDropAll:      true,
		NoNewPrivileges: true,
		PidsLimit:       64,
		Memory:          memory,
		NoNetwork:       true,
		Labels:          container.BaseLabels(container.RolePrefilter),
		Tmpfs:           []container.TmpfsMount{container.Tmpfs("/tmp", "64m")},
		Mounts:          []container.Mount{{Type: container.MountBind, Source: workDir, Dest: "/work", Options: []string{"ro"}}},
		Env:             []container.EnvVar{{Name: "HOME", Value: "/tmp"}},
	}
	s.Labels[container.LabelTask] = cfg.TaskName
	s.Labels[container.LabelRun] = cfg.RunID
	return s
}

// ContainerName returns the prefilter container's name.
func ContainerName(taskName, runID string) string {
	return fmt.Sprintf("ais-prefilter-%s-%s", taskName, runID)
}

// ItemText is the text the model sees for a feed item: title and summary.
func ItemText(title, summary string) string {
	title, summary = strings.TrimSpace(title), strings.TrimSpace(summary)
	if summary == "" {
		return title
	}
	return title + ". " + summary
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

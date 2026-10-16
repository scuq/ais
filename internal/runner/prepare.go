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
	"github.com/scuq/ais/internal/inventory"
	"github.com/scuq/ais/internal/prompt"
	"github.com/scuq/ais/internal/pseudo"
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
}

// Prepare builds everything a run needs without starting a container.
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
	}, nil
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

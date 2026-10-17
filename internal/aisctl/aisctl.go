// Package aisctl is the operator's installer and lifecycle tool, modelled
// on chalkctl: one `init` performs the complete setup, and status, up,
// down, update, logs and uninstall cover the rest. Everything runs in the
// user's own systemd scope; nothing needs root.
package aisctl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"golang.org/x/term"

	"github.com/scuq/ais/assets"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/doctor"
	"github.com/scuq/ais/internal/egress"
	"github.com/scuq/ais/internal/image"
	"github.com/scuq/ais/internal/pseudo"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/secret"
	"github.com/scuq/ais/internal/task"
	"github.com/scuq/ais/internal/templates"
)

// Version is stamped at link time.
var Version = "0.1.0-dev"

// Env is everything aisctl touches on the host, injectable for tests.
type Env struct {
	Out  io.Writer
	Home string
	// Exec runs a host command (systemctl, loginctl) and returns its output.
	Exec func(ctx context.Context, name string, args ...string) (string, error)
	// Confirm asks a yes/no question; nil means not interactive (false).
	Confirm func(prompt string) bool
	// ReadSecret reads a hidden line; nil means no terminal.
	ReadSecret func(prompt string) (string, error)
	// Runtime overrides engine detection (tests).
	Runtime runtime.Runtime
	// Now is the clock.
	Now func() time.Time
}

// DefaultEnv is the real host.
func DefaultEnv() *Env {
	home, _ := os.UserHomeDir()
	return &Env{
		Out:  os.Stdout,
		Home: home,
		Exec: func(ctx context.Context, name string, args ...string) (string, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			err := cmd.Run()
			if err != nil {
				msg := strings.TrimSpace(out.String())
				if msg == "" {
					msg = err.Error()
				}
				return out.String(), fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
			}
			return out.String(), nil
		},
		Confirm: func(prompt string) bool {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return false
			}
			fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			l := strings.ToLower(strings.TrimSpace(line))
			return l == "y" || l == "yes"
		},
		ReadSecret: func(prompt string) (string, error) {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return "", errors.New("no terminal to prompt on; pass --token-file or set CLAUDE_CODE_OAUTH_TOKEN")
			}
			fmt.Fprint(os.Stderr, prompt)
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return strings.TrimSpace(string(raw)), err
		},
		Now: time.Now,
	}
}

func (e *Env) logf(format string, args ...any) {
	fmt.Fprintf(e.Out, "  "+format+"\n", args...)
}

func (e *Env) headline(format string, args ...any) {
	fmt.Fprintf(e.Out, format+"\n", args...)
}

// Paths are the install locations for the user scope.
type Paths struct {
	Bin        string // ~/.local/bin/ais
	ConfigDir  string // ~/.config/ais
	ConfigFile string // ~/.config/ais/config.yaml
	TasksDir   string
	UnitFile   string // ~/.config/systemd/user/ais.service
	Inventory  string // ~/.config/ais/inventory.mdj
}

// UserPaths returns the standard locations under home.
func UserPaths(home string) Paths {
	cfg := filepath.Join(home, ".config", "ais")
	return Paths{
		Bin:        filepath.Join(home, ".local", "bin", "ais"),
		ConfigDir:  cfg,
		ConfigFile: filepath.Join(cfg, "config.yaml"),
		TasksDir:   filepath.Join(cfg, "tasks"),
		UnitFile:   filepath.Join(home, ".config", "systemd", "user", "ais.service"),
		Inventory:  filepath.Join(cfg, "inventory.mdj"),
	}
}

// UnitName is the systemd unit.
const UnitName = "ais.service"

// InitOptions configure the one-shot setup.
type InitOptions struct {
	Engine        string // auto | docker | podman
	Egress        string // proxy | open
	Timezone      string
	ClaudeVersion string
	// Image is a prebuilt run image to pull instead of building locally.
	Image string
	// AISBinary is the ais binary to install; empty searches next to aisctl
	// and then PATH.
	AISBinary string
	TokenFile string
	// PassphraseFile seeds the secret store passphrase; empty generates one.
	PassphraseFile string
	Inventory      string
	// Templates lists shipped task templates to install (ais templates use).
	Templates []string
	Force     bool
	NoStart   bool
	NoLinger  bool
	// WaitHealth bounds the wait for the daemon's health endpoint.
	WaitHealth time.Duration
}

func (o *InitOptions) defaults() {
	if o.Engine == "" {
		o.Engine = "auto"
	}
	if o.Egress == "" {
		o.Egress = "proxy"
	}
	if o.WaitHealth == 0 {
		o.WaitHealth = 60 * time.Second
	}
}

// Init performs the complete setup.
func Init(ctx context.Context, e *Env, o InitOptions) error {
	o.defaults()
	p := UserPaths(e.Home)
	e.headline("aisctl %s: setting up ais for %s", Version, e.Home)

	// 1. Preflight.
	if os.Geteuid() == 0 {
		return errors.New("run aisctl as the user who will own the daemon, not as root (ais uses a systemd user unit)")
	}
	rt := e.Runtime
	if rt == nil {
		var err error
		rt, err = runtime.Detect(o.Engine)
		if err != nil {
			return err
		}
	}
	if err := rt.Available(ctx); err != nil {
		return fmt.Errorf("container engine: %w (is this user allowed to use %s?)", err, rt.Engine())
	}
	info, _ := rt.Info(ctx)
	e.logf("engine %s %s (rootless=%v)", info.Engine, info.Version, info.Rootless)
	if _, err := e.Exec(ctx, "systemctl", "--user", "--version"); err != nil {
		return fmt.Errorf("systemd user session not reachable: %w (log in as this user, or set XDG_RUNTIME_DIR)", err)
	}
	installed := fileExists(p.ConfigFile) || fileExists(p.UnitFile)
	if installed && !o.Force {
		return fmt.Errorf("ais is already set up (%s exists); pass --force to re-apply, or use 'aisctl update'", p.ConfigFile)
	}

	// 2. Binary.
	src, err := findAISBinary(o.AISBinary)
	if err != nil {
		return err
	}
	if err := installFile(src, p.Bin, 0o755); err != nil {
		return err
	}
	e.logf("installed %s (from %s)", p.Bin, src)

	// 3. Config, tasks, inventory.
	if err := os.MkdirAll(p.TasksDir, 0o700); err != nil {
		return err
	}
	if !fileExists(p.ConfigFile) || o.Force {
		backup(p.ConfigFile)
		if err := os.WriteFile(p.ConfigFile, RenderConfig(o, p), 0o600); err != nil {
			return err
		}
		e.logf("wrote %s", p.ConfigFile)
	}
	if o.Inventory != "" {
		if err := installFile(o.Inventory, p.Inventory, 0o600); err != nil {
			return err
		}
		e.logf("installed inventory %s", p.Inventory)
	} else if !fileExists(p.Inventory) {
		if err := os.WriteFile(p.Inventory, assets.Read("examples/inventory.mdj"), 0o600); err != nil {
			return err
		}
		e.logf("wrote example inventory %s (replace it with yours)", p.Inventory)
	}
	cfg, err := loadConfig(p.ConfigFile)
	if err != nil {
		return err
	}
	for _, name := range o.Templates {
		dst, err := templates.Install(name, "", p.TasksDir, p.Inventory, taskDefaults(cfg), o.Force)
		if errors.Is(err, templates.ErrExists) {
			e.logf("task %s already exists (kept)", dst)
			continue
		}
		if err != nil {
			return err
		}
		e.logf("installed task template %s -> %s", name, dst)
	}
	tasks, err := task.LoadDir(cfg.TasksDir(), taskDefaults(cfg), nil)
	if err != nil {
		return err
	}
	e.logf("%d task(s) in %s", len(tasks), cfg.TasksDir())

	// 4. Token.
	secrets := secret.NewFileStore(cfg.SecretsDir())
	if o.PassphraseFile != "" {
		data, err := os.ReadFile(o.PassphraseFile)
		if err != nil {
			return err
		}
		if _, err := secrets.SetPassphrase(strings.TrimSpace(string(data))); err != nil {
			return err
		}
		e.logf("set the secret store passphrase from %s", o.PassphraseFile)
	} else if created, err := secrets.EnsurePassphrase(); err != nil {
		return err
	} else if created {
		e.logf("generated a random passphrase in %s (secrets are encrypted at rest; 'ais secret passphrase set' changes it)", cfg.SecretsDir())
	}
	if _, err := secrets.Get(cfg.Claude.OAuthTokenSecret); err != nil || o.TokenFile != "" {
		tok, err := readToken(e, o.TokenFile)
		if err != nil {
			return err
		}
		if err := secrets.Set(cfg.Claude.OAuthTokenSecret, tok); err != nil {
			return err
		}
		e.logf("stored OAuth token as secret %q", cfg.Claude.OAuthTokenSecret)
	} else {
		e.logf("secret %q already present (pass --token-file to replace it)", cfg.Claude.OAuthTokenSecret)
	}

	// 5. Images.
	if o.Image != "" {
		e.logf("pulling run image %s", o.Image)
		if _, err := e.Exec(ctx, rt.Engine(), "pull", o.Image); err != nil {
			return err
		}
		if err := image.CheckFlags(ctx, rt, o.Image); err != nil {
			return err
		}
	} else {
		exists, current, err := image.IsCurrent(ctx, rt, cfg)
		if err != nil {
			return err
		}
		if !exists || !current || o.Force {
			e.logf("building run image %s with claude-code %s (takes a few minutes the first time)", cfg.Runtime.Image, cfg.Image.ClaudeVersion)
			if err := image.Build(ctx, rt, cfg, false, Version); err != nil {
				return err
			}
		}
		v, err := image.Version(ctx, rt, cfg.Runtime.Image)
		if err != nil {
			return err
		}
		e.logf("run image %s ready (claude %s)", cfg.Runtime.Image, v)
	}
	for _, ref := range []string{cfg.Egress.ProxyImage, cfg.Backend.SidecarImage} {
		if exists, _ := rt.ImageExists(ctx, ref); !exists {
			e.logf("pulling %s", ref)
			if _, err := e.Exec(ctx, rt.Engine(), "pull", ref); err != nil {
				return err
			}
		}
	}

	// 6. Network topology (the daemon also ensures it; doing it here surfaces
	// engine problems before the unit starts).
	if cfg.Egress.Mode == "proxy" {
		em := &egress.Manager{Cfg: cfg, RT: rt, SELinux: doctor.SELinuxEnforcing(), Info: e.logf}
		if err := em.Ensure(ctx, tasks); err != nil {
			return err
		}
	}

	// 7. systemd user unit.
	unit, err := RenderUnit(p.Bin, nil)
	if err != nil {
		return err
	}
	backup(p.UnitFile)
	if err := os.MkdirAll(filepath.Dir(p.UnitFile), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p.UnitFile, unit, 0o644); err != nil {
		return err
	}
	e.logf("wrote %s", p.UnitFile)
	if _, err := e.Exec(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if !o.NoLinger {
		if _, err := e.Exec(ctx, "loginctl", "enable-linger", currentUser()); err != nil {
			e.logf("warning: could not enable linger: %v (the daemon stops at logout)", err)
		} else {
			e.logf("linger enabled: the daemon keeps running without a login session")
		}
	}
	if err := cfg.RedactionApproved(); err != nil {
		if _, err := e.Exec(ctx, "systemctl", "--user", "enable", UnitName); err != nil {
			return err
		}
		rep, terr := RunRedactTest(ctx, cfg, RedactTestOptions{})
		if terr == nil {
			rep.print(e)
		}
		e.headline("installed, not started: the redaction policy is not approved yet.")
		e.logf("review %s (pii:), run 'aisctl redact test', then 'aisctl redact approve' to start the daemon")
		return nil
	}
	if o.NoStart {
		e.headline("done (not started). Start with: systemctl --user enable --now %s", UnitName)
		return nil
	}
	if _, err := e.Exec(ctx, "systemctl", "--user", "enable", "--now", UnitName); err != nil {
		return err
	}
	e.logf("enabled and started %s", UnitName)

	// 8. Health.
	if err := waitHealth(ctx, cfg.BackendSocket(), o.WaitHealth); err != nil {
		return fmt.Errorf("%w (check: journalctl --user -u %s)", err, UnitName)
	}
	e.logf("daemon healthy on %s", cfg.BackendSocket())
	e.headline("ais is up. Next: edit %s and the tasks in %s; 'aisctl status' shows the state; 'ais run <task> --dry-run' previews a run.", p.ConfigFile, cfg.TasksDir())
	return nil
}

// RenderConfig writes the initial config.yaml: a commented skeleton with
// the values init chose and the sink examples left commented out.
func RenderConfig(o InitOptions, p Paths) []byte {
	tz := o.Timezone
	if tz == "" {
		tz = "Local"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# ais configuration, written by aisctl init on %s.\n", time.Now().Format("2006-01-02"))
	b.WriteString("# Every key is optional; 'ais config show' prints the resolved result.\n")
	b.WriteString("version: 1\n")
	// Explicit paths: the defaults use "~", which the daemon resolves against
	// its own HOME; pinning them here keeps every file under the install home.
	fmt.Fprintf(&b, "paths:\n  stateDir: %s\n  tasksDir: %s\n", filepath.Join(filepath.Dir(filepath.Dir(p.ConfigDir)), ".local", "state", "ais"), p.TasksDir)
	fmt.Fprintf(&b, "secrets:\n  dir: %s\n", filepath.Join(p.ConfigDir, "secrets"))
	fmt.Fprintf(&b, "runtime:\n  engine: %s\n", o.Engine)
	if o.Image != "" {
		fmt.Fprintf(&b, "  image: %s\n", o.Image)
	}
	if o.ClaudeVersion != "" {
		fmt.Fprintf(&b, "image:\n  claudeVersion: %q\n", o.ClaudeVersion)
	}
	fmt.Fprintf(&b, "egress:\n  mode: %s\n", o.Egress)
	fmt.Fprintf(&b, "scheduler:\n  timezone: %s\n", tz)
	fmt.Fprintf(&b, "inventory:\n  file: %s\n", p.Inventory)
	pol := pseudo.DefaultRedaction()
	b.WriteString("# Redaction policy. Nothing runs until 'aisctl redact approve' records its\n# hash in approvedHash; any later change here reopens the gate.\n")
	fmt.Fprintf(&b, "pii:\n  domains: [%s]\n  cidrs: [%s]\n  literals: []\n  hostnameMode: %s      # rot13 | token\n  ipMode: %s            # cgnat (100.64.0.0/10) | token\n  approvedHash: \"\"\n",
		quoteList(pol.Domains), quoteList(pol.CIDRs), pol.HostnameMode, pol.IPMode)
	b.WriteString("# Sinks receive results; alerts receive failures and leaks. Uncomment and adjust.\n")
	for _, line := range strings.Split(strings.TrimSpace(sinkExample), "\n") {
		b.WriteString("#" + line + "\n")
	}
	return []byte(b.String())
}

const sinkExample = `
sinks:
  splunk:
    type: splunk_hec
    url: https://splunk.example:8088/services/collector
    tokenSecret: splunk-hec-token          # ais secret set splunk-hec-token
    sourcetype: ais:vulnerability:notification
    host: ais-host-1
    insecureSkipVerify: false
    split: findings
  nats:
    type: nats
    url: nats://nats.example:4222
    subject: "ais.results.{{ .Task }}"
    stream: { name: AIS, subjects: ["ais.results.>"] }
  webex:
    type: webex
    url: https://webexapis.com/v1/webhooks/incoming/XXXXXXXX   # or bot: url https://webexapis.com/v1/messages + tokenSecret + roomId
    maxItems: 10
    card: false
    skipEmpty: false   # true: do not post a result without findings
  ops-webhook:
    type: webhook
    url: https://hooks.example/ais
    headers: { X-Token: "${secret:ops-webhook-token}" }
alerts: [webex]
`

func quoteList(in []string) string {
	q := make([]string, len(in))
	for i, s := range in {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, ", ")
}

// RenderUnit renders the systemd user unit for the installed binary.
func RenderUnit(execStart string, environment []string) ([]byte, error) {
	tmpl, err := template.New("unit").Parse(string(assets.Read("systemd/ais.service")))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, map[string]any{"ExecStart": execStart, "Environment": environment}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func taskDefaults(cfg *config.Config) task.Defaults {
	return task.Defaults{Model: cfg.Claude.DefaultModel, Effort: cfg.Claude.DefaultEffort, MaxTurns: cfg.Claude.DefaultMaxTurns, MaxBudgetUSD: cfg.Claude.DefaultMaxBudgetUSD, Timeout: cfg.Claude.DefaultTimeout}
}

func loadConfig(path string) (*config.Config, error) {
	cfg := config.Defaults()
	if err := config.MergeFile(&cfg, path); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

func readToken(e *Env, file string) (string, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return secret.NormalizeToken(string(data)), nil
	}
	if v := os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"); v != "" {
		return secret.NormalizeToken(v), nil
	}
	if e.ReadSecret == nil {
		return "", errors.New("no token: pass --token-file, or set CLAUDE_CODE_OAUTH_TOKEN")
	}
	tok, err := e.ReadSecret("OAuth token from 'claude setup-token' (input hidden): ")
	if err != nil {
		return "", err
	}
	tok = secret.NormalizeToken(tok)
	if tok == "" {
		return "", errors.New("empty token")
	}
	return tok, nil
}

// findAISBinary locates the ais binary to install: explicit path, then a
// sibling of this executable, then PATH, then this executable itself (ais
// and aisctl are the same program, dispatching on their name).
func findAISBinary(explicit string) (string, error) {
	if explicit != "" {
		if fileExists(explicit) {
			return explicit, nil
		}
		return "", fmt.Errorf("--ais-binary %s does not exist", explicit)
	}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			if sib := filepath.Join(filepath.Dir(real), "ais"); fileExists(sib) {
				return sib, nil
			}
		}
	}
	if p, err := exec.LookPath("ais"); err == nil {
		return p, nil
	}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil && fileExists(real) {
			return real, nil
		}
	}
	return "", errors.New("cannot find the ais binary: pass --ais-binary")
}

func installFile(src, dst string, mode os.FileMode) error {
	if sa, err := os.Stat(src); err == nil {
		if da, err := os.Stat(dst); err == nil && os.SameFile(sa, da) {
			return nil
		}
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// backup moves the file aside under a timestamped name. A second backup in
// the same second gets a numeric suffix, so none is lost.
func backup(path string) {
	if !fileExists(path) {
		return
	}
	base := path + ".bak-" + time.Now().UTC().Format("20060102T150405Z")
	dst := base
	for i := 1; fileExists(dst); i++ {
		dst = fmt.Sprintf("%s-%d", base, i)
	}
	_ = os.Rename(path, dst)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return fmt.Sprint(os.Getuid())
}

// waitHealth polls the daemon's operator socket.
func waitHealth(ctx context.Context, socket string, timeout time.Duration) error {
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}, Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)
	for {
		resp, err := client.Get("http://ais/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("daemon not healthy after %s", timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// --- lifecycle ---------------------------------------------------------------

// Status prints unit, network and doctor state.
func Status(ctx context.Context, e *Env) error {
	p := UserPaths(e.Home)
	e.headline("ais on %s", e.Home)
	active, _ := e.Exec(ctx, "systemctl", "--user", "is-active", UnitName)
	enabled, _ := e.Exec(ctx, "systemctl", "--user", "is-enabled", UnitName)
	e.logf("unit %s: %s, %s", UnitName, strings.TrimSpace(active), strings.TrimSpace(enabled))
	if !fileExists(p.ConfigFile) {
		e.logf("not set up: run 'aisctl init'")
		return nil
	}
	cfg, err := loadConfig(p.ConfigFile)
	if err != nil {
		return err
	}
	rt := e.Runtime
	if rt == nil {
		rt, err = runtime.Detect(cfg.Runtime.Engine)
		if err != nil {
			return err
		}
	}
	if cfg.Egress.Mode == "proxy" {
		st := (&egress.Manager{Cfg: cfg, RT: rt}).GetStatus(ctx)
		e.logf("proxy %s (%s), backend %s (%s), allowlist %d entries", st.Proxy.State, st.Proxy.IP, st.Backend.State, st.Backend.IP, st.Entries)
	}
	in := doctor.Inputs{Cfg: cfg, RT: rt, Secrets: secret.NewFileStore(cfg.SecretsDir())}
	in.Tasks, in.TasksErr = task.LoadDir(cfg.TasksDir(), task.Defaults{Model: cfg.Claude.DefaultModel, MaxTurns: cfg.Claude.DefaultMaxTurns, MaxBudgetUSD: cfg.Claude.DefaultMaxBudgetUSD, Timeout: cfg.Claude.DefaultTimeout}, nil)
	for _, c := range doctor.Run(ctx, in).Checks {
		e.logf("%-4s %-12s %s", c.Status, c.Name, c.Detail)
	}
	if strings.TrimSpace(active) == "active" {
		if err := waitHealth(ctx, cfg.BackendSocket(), 3*time.Second); err == nil {
			e.logf("daemon healthy on %s", cfg.BackendSocket())
			for _, u := range upcoming(ctx, cfg.BackendSocket()) {
				if u.Paused != "" {
					e.logf("next run %-14s paused (%s)", u.Name, u.Paused)
				} else if !u.Next.IsZero() {
					e.logf("next run %-14s %s", u.Name, u.Next.Local().Format("2006-01-02 15:04"))
				}
			}
		} else {
			e.logf("daemon not answering on %s", cfg.BackendSocket())
		}
	}
	return nil
}

type upcomingRow struct {
	Name   string    `json:"name"`
	Next   time.Time `json:"next"`
	Paused string    `json:"paused"`
}

// upcoming asks the daemon for its scheduled fire times.
func upcoming(ctx context.Context, socket string) []upcomingRow {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ais/api/v1/tasks", nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var rows []upcomingRow
	_ = json.NewDecoder(resp.Body).Decode(&rows)
	return rows
}

// Up starts the unit (and the topology, which the daemon ensures).
func Up(ctx context.Context, e *Env) error {
	if _, err := e.Exec(ctx, "systemctl", "--user", "start", UnitName); err != nil {
		return err
	}
	e.headline("started %s", UnitName)
	return nil
}

// DownOptions control Down.
type DownOptions struct {
	// Network also removes the sidecars and networks.
	Network bool
}

// Down stops the unit, optionally tearing the network down.
func Down(ctx context.Context, e *Env, o DownOptions) error {
	if _, err := e.Exec(ctx, "systemctl", "--user", "stop", UnitName); err != nil {
		e.logf("stop: %v", err)
	}
	e.headline("stopped %s", UnitName)
	if !o.Network {
		return nil
	}
	p := UserPaths(e.Home)
	cfg, err := loadConfig(p.ConfigFile)
	if err != nil {
		return err
	}
	rt := e.Runtime
	if rt == nil {
		rt, err = runtime.Detect(cfg.Runtime.Engine)
		if err != nil {
			return err
		}
	}
	return (&egress.Manager{Cfg: cfg, RT: rt, Info: e.logf}).Remove(ctx)
}

// UpdateOptions control Update.
type UpdateOptions struct {
	ClaudeVersion string // rebuild the run image with this version
	Image         string // or pull this prebuilt image
	AISBinary     string // reinstall the ais binary from here (or sibling/PATH)
	SkipHealth    bool
	WaitHealth    time.Duration
}

// Update reinstalls the binary and/or rebuilds the image, then restarts
// the unit and waits for health.
func Update(ctx context.Context, e *Env, o UpdateOptions) error {
	if o.WaitHealth == 0 {
		o.WaitHealth = 60 * time.Second
	}
	p := UserPaths(e.Home)
	if !fileExists(p.ConfigFile) {
		return errors.New("ais is not set up: run 'aisctl init' first")
	}
	cfg, err := loadConfig(p.ConfigFile)
	if err != nil {
		return err
	}
	rt := e.Runtime
	if rt == nil {
		rt, err = runtime.Detect(cfg.Runtime.Engine)
		if err != nil {
			return err
		}
	}
	e.headline("aisctl %s: updating ais", Version)
	changed := false
	if src, err := findAISBinary(o.AISBinary); err == nil {
		before, _ := os.ReadFile(p.Bin)
		after, _ := os.ReadFile(src)
		if !bytes.Equal(before, after) {
			if err := installFile(src, p.Bin, 0o755); err != nil {
				return err
			}
			e.logf("installed new binary %s (from %s)", p.Bin, src)
			changed = true
			// aisctl is the same program: refresh the running copy too, so the
			// operator tool never lags behind the daemon it manages.
			if exe, err := os.Executable(); err == nil {
				if real, err := filepath.EvalSymlinks(exe); err == nil && filepath.Base(real) == "aisctl" && real != src {
					if err := installFile(src, real, 0o755); err == nil {
						e.logf("refreshed %s", real)
					}
				}
			}
		} else {
			e.logf("binary unchanged")
		}
	} else if o.AISBinary != "" {
		return err
	}
	if o.ClaudeVersion != "" && o.ClaudeVersion != cfg.Image.ClaudeVersion {
		if err := setConfigKey(p.ConfigFile, "image", "claudeVersion", fmt.Sprintf("%q", o.ClaudeVersion)); err != nil {
			return err
		}
		cfg.Image.ClaudeVersion = o.ClaudeVersion
		e.logf("pinned image.claudeVersion %s in %s", o.ClaudeVersion, p.ConfigFile)
	}
	if o.Image != "" {
		e.logf("pulling run image %s", o.Image)
		if _, err := e.Exec(ctx, rt.Engine(), "pull", o.Image); err != nil {
			return err
		}
		if err := image.CheckFlags(ctx, rt, o.Image); err != nil {
			return err
		}
		if err := setConfigKey(p.ConfigFile, "runtime", "image", o.Image); err != nil {
			return err
		}
		changed = true
	} else if exists, current, _ := image.IsCurrent(ctx, rt, cfg); !exists || !current {
		e.logf("rebuilding run image %s with claude-code %s", cfg.Runtime.Image, cfg.Image.ClaudeVersion)
		if err := image.Build(ctx, rt, cfg, false, Version); err != nil {
			return err
		}
		changed = true
	} else {
		e.logf("run image current")
	}
	if !changed {
		e.headline("nothing to do")
		return nil
	}
	if err := cfg.RedactionApproved(); err != nil {
		e.headline("updated, not restarted: %v", err)
		return nil
	}
	if _, err := e.Exec(ctx, "systemctl", "--user", "restart", UnitName); err != nil {
		return err
	}
	e.logf("restarted %s", UnitName)
	if o.SkipHealth {
		return nil
	}
	if err := waitHealth(ctx, cfg.BackendSocket(), o.WaitHealth); err != nil {
		return fmt.Errorf("%w (check: journalctl --user -u %s)", err, UnitName)
	}
	e.headline("ais updated and healthy")
	return nil
}

// setConfigKey sets section.key in a YAML config written by RenderConfig
// (two-space indented, one level deep). It appends the section when
// missing. Other layouts are left to the operator's editor.
func setConfigKey(path, section, key, value string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	inSection, done := false, false
	var out []string
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "#") && trimmed != "" {
			if inSection && !done {
				out = append(out, "  "+key+": "+value)
				done = true
			}
			inSection = strings.HasPrefix(trimmed, section+":")
		}
		if inSection && strings.HasPrefix(strings.TrimSpace(l), key+":") && !done {
			out = append(out, "  "+key+": "+value)
			done = true
			continue
		}
		out = append(out, l)
		if i == len(lines)-1 && inSection && !done {
			out = append(out, "  "+key+": "+value)
			done = true
		}
	}
	if !done {
		out = append(out, section+":", "  "+key+": "+value, "")
	}
	backup(path)
	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600)
}

// Logs follows the unit's journal.
func Logs(ctx context.Context, e *Env, follow bool, lines int) error {
	args := []string{"--user", "-u", UnitName, "-n", fmt.Sprint(lines), "--no-pager"}
	if follow {
		args = append(args, "-f")
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	cmd.Stdout = e.Out
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// UninstallOptions control Uninstall.
type UninstallOptions struct {
	// PurgeState removes the state directory (runs, database, token maps).
	PurgeState bool
	// PurgeAll also removes config, tasks and secrets.
	PurgeAll bool
	Yes      bool
}

// Uninstall stops and disables the unit, tears the network down and removes
// the unit file and binary. Data is kept unless purged.
func Uninstall(ctx context.Context, e *Env, o UninstallOptions) error {
	p := UserPaths(e.Home)
	if o.PurgeAll && !o.Yes {
		if e.Confirm == nil || !e.Confirm(fmt.Sprintf("Remove ALL ais data under %s including secrets?", p.ConfigDir)) {
			return errors.New("aborted")
		}
	}
	e.headline("uninstalling ais")
	_, _ = e.Exec(ctx, "systemctl", "--user", "disable", "--now", UnitName)
	e.logf("unit stopped and disabled")
	if fileExists(p.ConfigFile) {
		if cfg, err := loadConfig(p.ConfigFile); err == nil {
			rt := e.Runtime
			if rt == nil {
				rt, _ = runtime.Detect(cfg.Runtime.Engine)
			}
			if rt != nil {
				_ = (&egress.Manager{Cfg: cfg, RT: rt, Info: e.logf}).Remove(ctx)
			}
			if o.PurgeState || o.PurgeAll {
				_ = os.RemoveAll(cfg.StateDir())
				e.logf("removed %s", cfg.StateDir())
			}
		}
	}
	for _, f := range []string{p.UnitFile, p.Bin} {
		if fileExists(f) {
			_ = os.Remove(f)
			e.logf("removed %s", f)
		}
	}
	_, _ = e.Exec(ctx, "systemctl", "--user", "daemon-reload")
	if o.PurgeAll {
		_ = os.RemoveAll(p.ConfigDir)
		e.logf("removed %s", p.ConfigDir)
	} else {
		e.logf("kept %s (config, tasks, secrets); pass --purge-all to remove", p.ConfigDir)
	}
	e.headline("done. The run image stays; remove it with: <engine> rmi <image>")
	return nil
}

// Package config owns configuration: compiled defaults, the user YAML file
// and environment variables, merged in exactly that order. Flags are applied
// by the commands. `ais config show` prints the resolved result.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scuq/ais/internal/pseudo"
)

// Version is the current config schema version.
const Version = 1

// Config is the resolved configuration for one invocation.
type Config struct {
	Version int `yaml:"version"`

	Runtime   RuntimeConfig         `yaml:"runtime"`
	Paths     PathsConfig           `yaml:"paths"`
	Image     ImageConfig           `yaml:"image"`
	Claude    ClaudeConfig          `yaml:"claude"`
	Egress    EgressConfig          `yaml:"egress"`
	Backend   BackendConfig         `yaml:"backend"`
	Secrets   SecretsConfig         `yaml:"secrets"`
	PII       PIIConfig             `yaml:"pii"`
	Scheduler SchedulerConfig       `yaml:"scheduler"`
	Retention RetentionConfig       `yaml:"retention"`
	Inventory InventoryConfig       `yaml:"inventory"`
	Sinks     map[string]SinkConfig `yaml:"sinks"`
	// Alerts names the sinks that receive leak and failure alerts.
	Alerts   []string       `yaml:"alerts"`
	Delivery DeliveryConfig `yaml:"delivery"`
}

type RuntimeConfig struct {
	// Engine is "auto" (podman if it is on PATH, else docker), "docker"
	// or "podman".
	Engine string `yaml:"engine"`
	Image  string `yaml:"image"`
	// User is the uid:gid the container process runs as on docker. "auto"
	// uses the ais process's own uid:gid, which is what owns the one rw
	// mount. Podman always maps the caller onto the image uid with keep-id.
	User      string `yaml:"user"`
	Memory    string `yaml:"memory"`
	CPUs      string `yaml:"cpus"`
	PidsLimit int    `yaml:"pidsLimit"`
	TmpfsSize string `yaml:"tmpfsSize"`
	// Binary is the host path of the ais binary that is bind-mounted
	// read-only into run containers for the redaction hook. Empty means the
	// running executable.
	Binary string `yaml:"binary"`
}

type PathsConfig struct {
	StateDir string `yaml:"stateDir"`
	TasksDir string `yaml:"tasksDir"`
}

type ImageConfig struct {
	ClaudeVersion string `yaml:"claudeVersion"`
	Autobuild     bool   `yaml:"autobuild"`
	// CACertificates is a host path (file or directory) of additional CA
	// certificates baked into the image's trust store at build time.
	CACertificates string `yaml:"caCertificates"`
}

type ClaudeConfig struct {
	// OAuthTokenSecret is the secret-store name holding the long-lived token
	// from `claude setup-token`. It is forwarded into the container by env
	// name only.
	OAuthTokenSecret string `yaml:"oauthTokenSecret"`
	DefaultModel     string `yaml:"defaultModel"`
	// DefaultEffort is Claude Code's --effort level: low, medium, high,
	// xhigh or max.
	DefaultEffort       string        `yaml:"defaultEffort"`
	DefaultMaxTurns     int           `yaml:"defaultMaxTurns"`
	DefaultMaxBudgetUSD float64       `yaml:"defaultMaxBudgetUsd"`
	DefaultTimeout      time.Duration `yaml:"defaultTimeout"`
	// TokenLifetime is how long a `claude setup-token` token is valid (about
	// one year per the Claude Code docs); TokenWarnBefore is how long before
	// the end doctor and the daemon start warning. The token is opaque, so
	// its age since `ais secret set` is the only signal.
	TokenLifetime   time.Duration `yaml:"tokenLifetime"`
	TokenWarnBefore time.Duration `yaml:"tokenWarnBefore"`
}

type EgressConfig struct {
	// Mode "proxy" puts run containers on an internal network whose only way
	// out is the squid sidecar; "open" uses the engine's default network and
	// exists for the first bring-up and for debugging.
	Mode       string   `yaml:"mode"`
	Subnet     string   `yaml:"subnet"`
	ProxyImage string   `yaml:"proxyImage"`
	ProxyPort  int      `yaml:"proxyPort"`
	BaseAllow  []string `yaml:"baseAllowlist"`
}

type BackendConfig struct {
	Socket       string `yaml:"socket"`
	TCPListen    string `yaml:"tcpListen"`
	SidecarImage string `yaml:"sidecarImage"`
	MCPPort      int    `yaml:"mcpPort"`
}

type SecretsConfig struct {
	Dir string `yaml:"dir"`
}

// PIIConfig is the redaction policy. It must be approved with `aisctl
// redact approve` before any run starts; ApprovedHash records the policy
// that was approved, so a later change reopens the gate.
type PIIConfig struct {
	Domains      []string `yaml:"domains"`
	CIDRs        []string `yaml:"cidrs"`
	Literals     []string `yaml:"literals"`
	HostnameMode string   `yaml:"hostnameMode"` // rot13 | token
	IPMode       string   `yaml:"ipMode"`       // cgnat | token
	ApprovedHash string   `yaml:"approvedHash"`
}

type SchedulerConfig struct {
	Timezone       string        `yaml:"timezone"`
	DefaultJitter  time.Duration `yaml:"defaultJitter"`
	MaxParallel    int           `yaml:"maxParallel"`
	DailyBudgetUSD float64       `yaml:"dailyBudgetUsd"`
	// PauseAfterAuthFailures pauses a task after this many consecutive
	// authentication failures so an expired token does not alert hourly.
	PauseAfterAuthFailures int `yaml:"pauseAfterAuthFailures"`
}

type RetentionConfig struct {
	KeepRuns int `yaml:"keepRuns"`
	KeepDays int `yaml:"keepDays"`
}

// InventoryConfig is the default inventory source; tasks may override it.
type InventoryConfig struct {
	File   string `yaml:"file"`
	Format string `yaml:"format"` // yaml | json | csv | mdj | auto
	// TextFile is the free-text inventory: one product per line, no
	// device records. Empty means none.
	TextFile string `yaml:"textFile"`
}

// SinkConfig is one named delivery target. Fields not used by a type are
// ignored by that type but still validated as known keys.
type SinkConfig struct {
	Type string `yaml:"type"` // webhook | nats | splunk_hec | webex

	URL                string            `yaml:"url"`
	Headers            map[string]string `yaml:"headers"`
	Body               string            `yaml:"body"`
	Timeout            time.Duration     `yaml:"timeout"`
	InsecureSkipVerify bool              `yaml:"insecureSkipVerify"`
	// SkipEmpty drops a result event whose findings array is empty. The
	// delivery is recorded as skipped. Alerts are never skipped.
	SkipEmpty bool `yaml:"skipEmpty"`

	// nats
	CredsSecret string         `yaml:"credsSecret"`
	TokenSecret string         `yaml:"tokenSecret"`
	Subject     string         `yaml:"subject"`
	Stream      NatsStreamSpec `yaml:"stream"`

	// splunk_hec
	Sourcetype string `yaml:"sourcetype"`
	Source     string `yaml:"source"`
	Index      string `yaml:"index"`
	Host       string `yaml:"host"`
	// Split names a top-level array field of the result; one event is sent
	// per element. Empty sends the whole result as one event.
	Split string `yaml:"split"`

	// webex: RoomID for bot mode (url https://webexapis.com/v1/messages with
	// tokenSecret), MaxItems findings per message (default 10), Card adds an
	// Adaptive Card, Title is a template for the headline.
	RoomID   string `yaml:"roomId"`
	MaxItems int    `yaml:"maxItems"`
	Card     bool   `yaml:"card"`
	Title    string `yaml:"title"`
}

type NatsStreamSpec struct {
	Name     string   `yaml:"name"`
	Subjects []string `yaml:"subjects"`
}

type DeliveryConfig struct {
	MaxAttempts int           `yaml:"maxAttempts"`
	Backoff     BackoffConfig `yaml:"backoff"`
}

type BackoffConfig struct {
	Initial time.Duration `yaml:"initial"`
	Max     time.Duration `yaml:"max"`
}

// Defaults returns the compiled-in configuration.
func Defaults() Config {
	return Config{
		Version: Version,
		Runtime: RuntimeConfig{
			Engine:    "auto",
			Image:     "localhost/ais:latest",
			User:      "auto",
			Memory:    "2g",
			CPUs:      "1",
			PidsLimit: 256,
			TmpfsSize: "256m",
		},
		Paths: PathsConfig{
			StateDir: "~/.local/state/ais",
			TasksDir: "~/.config/ais/tasks",
		},
		Image: ImageConfig{
			ClaudeVersion: "2.1.301",
			Autobuild:     true,
		},
		Claude: ClaudeConfig{
			OAuthTokenSecret:    "claude-oauth-token",
			DefaultModel:        "claude-opus-5-5",
			DefaultEffort:       "high",
			DefaultMaxTurns:     30,
			DefaultMaxBudgetUSD: 2.0,
			DefaultTimeout:      20 * time.Minute,
			TokenLifetime:       365 * 24 * time.Hour,
			TokenWarnBefore:     30 * 24 * time.Hour,
		},
		Egress: EgressConfig{
			Mode:       "proxy",
			Subnet:     "10.199.0.0/24",
			ProxyImage: "docker.io/ubuntu/squid:latest",
			ProxyPort:  3128,
		},
		Backend: BackendConfig{
			Socket:       "~/.local/state/ais/backend.sock",
			SidecarImage: "gcr.io/distroless/static-debian12:nonroot",
			MCPPort:      8080,
		},
		Secrets: SecretsConfig{Dir: "~/.config/ais/secrets"},
		PII:     piiDefaults(),
		Scheduler: SchedulerConfig{
			Timezone:               "Local",
			DefaultJitter:          2 * time.Minute,
			MaxParallel:            2,
			PauseAfterAuthFailures: 3,
		},
		Retention: RetentionConfig{KeepRuns: 500, KeepDays: 90},
		Inventory: InventoryConfig{Format: "auto"},
		Delivery: DeliveryConfig{
			MaxAttempts: 10,
			Backoff:     BackoffConfig{Initial: 30 * time.Second, Max: time.Hour},
		},
	}
}

// Validate rejects a resolved configuration that asks for something ais does
// not do. Loud beats silent.
func (c *Config) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("unsupported config version %d (this ais understands version %d)", c.Version, Version)
	}
	switch c.Runtime.Engine {
	case "auto", "docker", "podman":
	default:
		return fmt.Errorf("unknown runtime.engine %q (use: auto, docker, podman)", c.Runtime.Engine)
	}
	if c.Runtime.User != "auto" {
		if _, _, err := ParseUser(c.Runtime.User); err != nil {
			return fmt.Errorf("runtime.user: %w", err)
		}
	}
	switch c.Egress.Mode {
	case "open", "proxy":
	default:
		return fmt.Errorf("unknown egress.mode %q (use: open, proxy)", c.Egress.Mode)
	}
	if _, _, err := net.ParseCIDR(c.Egress.Subnet); err != nil {
		return fmt.Errorf("egress.subnet %q: %w", c.Egress.Subnet, err)
	}
	switch c.Inventory.Format {
	case "", "auto", "yaml", "json", "csv", "mdj":
	default:
		return fmt.Errorf("unknown inventory.format %q (use: auto, yaml, json, csv, mdj)", c.Inventory.Format)
	}
	for name, s := range c.Sinks {
		switch s.Type {
		case "webhook", "nats", "splunk_hec", "webex":
		default:
			return fmt.Errorf("sink %q: unknown type %q (use: webhook, nats, splunk_hec, webex)", name, s.Type)
		}
		if s.URL == "" {
			return fmt.Errorf("sink %q has no url", name)
		}
	}
	for _, a := range c.Alerts {
		if _, ok := c.Sinks[a]; !ok {
			return fmt.Errorf("alerts: unknown sink %q", a)
		}
	}
	if c.Backend.TCPListen != "" {
		host, _, err := net.SplitHostPort(c.Backend.TCPListen)
		if err != nil {
			return fmt.Errorf("backend.tcpListen %q: %w", c.Backend.TCPListen, err)
		}
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			// The operator API has no authentication of its own; the unix
			// socket's file mode is the guard. A TCP listener is for local
			// tooling only.
			return fmt.Errorf("backend.tcpListen %q must bind a loopback address (the operator API is unauthenticated)", c.Backend.TCPListen)
		}
	}
	if err := c.Redaction().Validate(); err != nil {
		return fmt.Errorf("pii: %w", err)
	}
	if !ValidEffort(c.Claude.DefaultEffort) {
		return fmt.Errorf("claude.defaultEffort %q (use: low, medium, high, xhigh, max)", c.Claude.DefaultEffort)
	}
	if c.Claude.TokenLifetime <= 0 || c.Claude.TokenWarnBefore < 0 || c.Claude.TokenWarnBefore >= c.Claude.TokenLifetime {
		return fmt.Errorf("claude.tokenWarnBefore must be shorter than claude.tokenLifetime, and both positive")
	}
	if c.Scheduler.MaxParallel < 1 {
		return fmt.Errorf("scheduler.maxParallel must be >= 1")
	}
	if c.Delivery.MaxAttempts < 1 {
		return fmt.Errorf("delivery.maxAttempts must be >= 1")
	}
	return nil
}

func piiDefaults() PIIConfig {
	d := pseudo.DefaultRedaction()
	return PIIConfig{Domains: d.Domains, CIDRs: d.CIDRs, HostnameMode: d.HostnameMode, IPMode: d.IPMode}
}

// Redaction returns the policy as the pseudo package sees it.
func (c *Config) Redaction() pseudo.Redaction {
	return pseudo.Redaction{Domains: c.PII.Domains, CIDRs: c.PII.CIDRs, Literals: c.PII.Literals, HostnameMode: c.PII.HostnameMode, IPMode: c.PII.IPMode}
}

// RedactionApproved reports whether the current policy is the approved one.
func (c *Config) RedactionApproved() error {
	return pseudo.CheckApproval(c.Redaction(), c.PII.ApprovedHash)
}

// Efforts are the accepted --effort levels.
var Efforts = []string{"low", "medium", "high", "xhigh", "max"}

// ValidEffort reports whether e is an accepted effort level.
func ValidEffort(e string) bool {
	for _, x := range Efforts {
		if x == e {
			return true
		}
	}
	return false
}

// Billing is how ais runs are paid for. ais authenticates with a
// subscription OAuth token only, so API cost figures are estimates that
// Claude Code computes at list prices; they still drive the budget caps.
const Billing = "subscription"

// ParseUser parses "uid:gid".
func ParseUser(s string) (int, int, error) {
	var uid, gid int
	if _, err := fmt.Sscanf(s, "%d:%d", &uid, &gid); err != nil || uid < 0 || gid < 0 {
		return 0, 0, fmt.Errorf("want uid:gid, got %q", s)
	}
	return uid, gid, nil
}

// ExpandPath resolves a leading "~" and environment variables in a path.
func ExpandPath(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return os.ExpandEnv(p)
}

// StateDir returns the expanded state directory.
func (c *Config) StateDir() string { return ExpandPath(c.Paths.StateDir) }

// TasksDir returns the expanded tasks directory.
func (c *Config) TasksDir() string { return ExpandPath(c.Paths.TasksDir) }

// RunsDir returns where run directories live.
func (c *Config) RunsDir() string { return filepath.Join(c.StateDir(), "runs") }

// SecretsDir returns the expanded secret store directory.
func (c *Config) SecretsDir() string { return ExpandPath(c.Secrets.Dir) }

// BackendSocket returns the expanded backend socket path.
func (c *Config) BackendSocket() string { return ExpandPath(c.Backend.Socket) }

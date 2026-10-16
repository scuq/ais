// Package doctor checks that the host can actually run ais: engine, image,
// credentials, tasks and the hardening preconditions.
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/image"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/secret"
	"github.com/scuq/ais/internal/task"
)

// Check is one diagnostic result.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail"`
}

// Report is the set of checks plus the overall verdict.
type Report struct {
	Checks []Check `json:"checks"`
	OK     bool    `json:"ok"`
}

func (r *Report) add(status, name, format string, args ...any) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: fmt.Sprintf(format, args...)})
	if status == "fail" {
		r.OK = false
	}
}

// SELinuxEnforcing reports whether bind mounts need the :z relabel option.
func SELinuxEnforcing() bool {
	out, err := exec.Command("getenforce").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "Enforcing"
}

// CgroupsV2 reports a unified cgroup hierarchy.
func CgroupsV2() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// PlaintextSecrets lists secrets in the store that are not encrypted.
func PlaintextSecrets(fs *secret.FileStore) []string {
	names, err := fs.List()
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range names {
		if !fs.Encrypted(n) {
			out = append(out, n)
		}
	}
	return out
}

// TokenCheck returns the doctor status (ok | warn | fail) and detail for the
// OAuth token's age, or "" when the store cannot date it.
func TokenCheck(cfg *config.Config, secrets secret.Store, now time.Time) (string, string) {
	d, ok := secrets.(secret.Dated)
	if !ok {
		return "", ""
	}
	at, err := d.StoredAt(cfg.Claude.OAuthTokenSecret)
	if err != nil {
		return "", ""
	}
	status, _, detail := secret.TokenStatus(at, now, cfg.Claude.TokenLifetime, cfg.Claude.TokenWarnBefore)
	switch status {
	case secret.StatusExpired:
		return "fail", detail
	case secret.StatusExpiring:
		return "warn", detail
	}
	return "ok", detail
}

// Inputs are the pieces doctor inspects. Nil runtime means detection failed
// and Err says why.
type Inputs struct {
	Cfg       *config.Config
	RT        runtime.Runtime
	EngineErr error
	Secrets   secret.Store
	Tasks     []*task.Task
	TasksErr  error
}

// Run performs the checks.
func Run(ctx context.Context, in Inputs) Report {
	r := Report{OK: true}
	cfg := in.Cfg

	if in.RT == nil {
		r.add("fail", "engine", "%v", in.EngineErr)
	} else if err := in.RT.Available(ctx); err != nil {
		r.add("fail", "engine", "%s: %v", in.RT.Engine(), err)
	} else {
		info, err := in.RT.Info(ctx)
		if err != nil {
			r.add("fail", "engine", "%s: %v", in.RT.Engine(), err)
		} else {
			r.add("ok", "engine", "%s %s", info.Engine, info.Version)
			if info.Rootless {
				r.add("ok", "rootless", "%s runs rootless", info.Engine)
			} else {
				r.add("warn", "rootless", "%s is rootful: a container escape lands as root; mitigations are the read-only rootfs, cap-drop=ALL, no-new-privileges and the single rw mount", info.Engine)
			}
			if info.CgroupsVersion == "2" || CgroupsV2() {
				r.add("ok", "cgroups", "v2")
			} else {
				r.add("warn", "cgroups", "not v2; memory/cpu caps may be ignored")
			}
		}
		if SELinuxEnforcing() {
			r.add("ok", "selinux", "enforcing; bind mounts get :z")
		}
		exists, current, err := image.IsCurrent(ctx, in.RT, cfg)
		switch {
		case err != nil:
			r.add("fail", "image", "%v", err)
		case !exists:
			r.add("fail", "image", "%s is missing; run 'ais image build'", cfg.Runtime.Image)
		case !current:
			r.add("warn", "image", "%s is stale (recipe changed); run 'ais image build'", cfg.Runtime.Image)
		default:
			if v, err := image.Version(ctx, in.RT, cfg.Runtime.Image); err == nil {
				r.add("ok", "image", "%s, claude %s", cfg.Runtime.Image, v)
			} else {
				r.add("warn", "image", "%s present but 'claude --version' failed: %v", cfg.Runtime.Image, err)
			}
		}
	}

	if in.Secrets != nil {
		if tok, err := in.Secrets.Get(cfg.Claude.OAuthTokenSecret); err != nil {
			r.add("fail", "credentials", "secret %q: %v (create it with 'claude setup-token' and 'ais secret set %s')", cfg.Claude.OAuthTokenSecret, err, cfg.Claude.OAuthTokenSecret)
		} else if err := secret.CheckToken(tok); err != nil {
			r.add("fail", "credentials", "secret %q: %v", cfg.Claude.OAuthTokenSecret, err)
		} else if status, detail := TokenCheck(cfg, in.Secrets, time.Now()); status != "" {
			r.add(status, "credentials", "secret %q %s", cfg.Claude.OAuthTokenSecret, detail)
		} else {
			r.add("ok", "credentials", "secret %q present (age unknown)", cfg.Claude.OAuthTokenSecret)
		}
	}
	if fs, ok := in.Secrets.(*secret.FileStore); ok {
		if plain := PlaintextSecrets(fs); len(plain) > 0 {
			r.add("warn", "secrets", "stored in plaintext: %s; re-run 'ais secret set <name>' to encrypt", strings.Join(plain, ", "))
		}
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		r.add("warn", "environment", "ANTHROPIC_API_KEY is set in this environment; it is never forwarded, but unset it to be safe")
	}

	if in.TasksErr != nil {
		r.add("fail", "tasks", "%v", in.TasksErr)
	} else {
		enabled := 0
		for _, t := range in.Tasks {
			if t.IsEnabled() {
				enabled++
			}
		}
		if len(in.Tasks) == 0 {
			r.add("warn", "tasks", "no tasks in %s (install one with: ais templates use vuln-watch)", cfg.TasksDir())
		} else {
			r.add("ok", "tasks", "%d task(s), %d enabled", len(in.Tasks), enabled)
		}
	}

	if err := os.MkdirAll(cfg.RunsDir(), 0o700); err != nil {
		r.add("fail", "state", "%v", err)
	} else {
		r.add("ok", "state", "%s", cfg.StateDir())
	}
	if err := cfg.RedactionApproved(); err != nil {
		r.add("fail", "redaction", "%v", err)
	} else {
		pol := cfg.Redaction()
		r.add("ok", "redaction", "approved (%s): %d domain(s), %d range(s), hostnames %s, ips %s", cfg.PII.ApprovedHash, len(pol.Domains), len(pol.CIDRs), pol.HostnameMode, pol.IPMode)
	}
	if cfg.Egress.Mode == "open" {
		r.add("warn", "egress", "mode open: run containers can reach any host; set egress.mode: proxy")
	}
	return r
}

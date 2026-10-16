// Package runner executes one task run end to end: prepare the run
// directory, build the container spec, run it, parse and validate the
// result, check for leaks, re-attach identity and hand the result to the
// store and the sinks.
package runner

import (
	"fmt"
	"path/filepath"

	"github.com/scuq/ais/internal/claude"
	"github.com/scuq/ais/internal/container"
)

// SpecInput is everything composeSpec depends on. It is plain data so the
// function stays pure and golden-testable.
type SpecInput struct {
	Image    string
	TaskName string
	RunID    string
	// RunDir is the host run directory holding in/ and out/.
	RunDir string
	// HostBinary is the ais executable bind-mounted for the hook; empty
	// omits the mount.
	HostBinary string

	UID, GID  int
	MaxTurns  int
	Memory    string
	CPUs      string
	PidsLimit int
	TmpfsSize string

	// Proxy mode: the internal network and the squid URL. Empty NetworkName
	// means the engine's default network (egress open).
	NetworkName string
	ProxyURL    string
	// NoProxy lists addresses reachable directly (the backend sidecar).
	NoProxy []string
}

// ContainerName returns the run container's name.
func ContainerName(task, runID string) string {
	return fmt.Sprintf("ais-run-%s-%s", task, runID)
}

// composeSpec builds the run container. Every non-obvious flag carries its
// reason here or in container.Spec. The posture: read-only image, no
// capabilities, no privilege escalation, hard resource caps, tmpfs for every
// writable location except the one rw bind mount (out/), secrets by env
// name only.
func composeSpec(in SpecInput) *container.Spec {
	s := &container.Spec{
		Image:    in.Image,
		Name:     ContainerName(in.TaskName, in.RunID),
		Hostname: "ais",
		Remove:   true,
		UID:      in.UID,
		GID:      in.GID,

		ReadOnlyRootfs:  true,
		CapDropAll:      true,
		NoNewPrivileges: true,
		PidsLimit:       in.PidsLimit,
		Memory:          in.Memory,
		CPUs:            in.CPUs,
		Workdir:         claude.WorkDir,
		Labels:          container.BaseLabels(container.RoleRun),
	}
	s.Labels[container.LabelTask] = in.TaskName
	s.Labels[container.LabelRun] = in.RunID

	size := in.TmpfsSize
	if size == "" {
		size = "256m"
	}
	s.Tmpfs = []container.TmpfsMount{
		container.Tmpfs("/tmp", size),
		// CLAUDE_CONFIG_DIR: settings and credentials live here for the
		// lifetime of the run and vanish with it.
		container.Tmpfs(claude.ConfigTmpfs, "64m"),
		container.Tmpfs(claude.HomeTmpfs, "64m"),
		// An empty cwd: nothing to discover (no CLAUDE.md, no .mcp.json).
		container.Tmpfs(claude.WorkDir, "16m"),
	}

	s.Mounts = []container.Mount{
		{Type: container.MountBind, Source: filepath.Join(in.RunDir, "in"), Dest: claude.InDir, Options: []string{"ro"}},
		// The one writable host path.
		{Type: container.MountBind, Source: filepath.Join(in.RunDir, "out"), Dest: claude.OutDir},
	}
	if in.HostBinary != "" {
		s.Mounts = append(s.Mounts, container.Mount{Type: container.MountBind, Source: in.HostBinary, Dest: claude.BinPath, Options: []string{"ro"}})
	}

	s.Env = []container.EnvVar{
		{Name: "HOME", Value: claude.HomeDir},
		{Name: "CLAUDE_CONFIG_DIR", Value: claude.ConfigDir},
		// Secrets: by name only.
		{Name: "CLAUDE_CODE_OAUTH_TOKEN", FromHost: true},
		{Name: "AIS_RUN_TOKEN", FromHost: true},
		// A pinned image never updates itself, phones home or reports.
		{Name: "DISABLE_UPDATES", Value: "1"},
		{Name: "DISABLE_AUTOUPDATER", Value: "1"},
		{Name: "DISABLE_TELEMETRY", Value: "1"},
		{Name: "DISABLE_ERROR_REPORTING", Value: "1"},
		{Name: "DISABLE_BUG_COMMAND", Value: "1"},
		{Name: "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", Value: "1"},
		{Name: "AIS_TASK", Value: in.TaskName},
		{Name: "AIS_RUN_ID", Value: in.RunID},
	}
	if in.MaxTurns > 0 {
		// Belt and braces for the hidden --max-turns flag.
		s.Env = append(s.Env, container.EnvVar{Name: claude.MaxTurnsEnv, Value: fmt.Sprint(in.MaxTurns)})
	}
	if in.ProxyURL != "" {
		noProxy := "localhost,127.0.0.1,::1"
		for _, n := range in.NoProxy {
			noProxy += "," + n
		}
		for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			s.Env = append(s.Env, container.EnvVar{Name: name, Value: in.ProxyURL})
		}
		s.Env = append(s.Env, container.EnvVar{Name: "NO_PROXY", Value: noProxy}, container.EnvVar{Name: "no_proxy", Value: noProxy})
	}
	if in.NetworkName != "" {
		s.Networks = []container.NetworkAttach{{Name: in.NetworkName}}
	}
	return s
}

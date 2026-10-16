// Package runtime abstracts the container engine. ais drives the docker or
// podman CLI, not a REST API: rootless support is straightforward, there is
// no socket discovery, and --dry-run can print exactly what will run.
package runtime

import (
	"context"
	"io"

	"github.com/scuq/ais/internal/container"
)

// Container is one engine container as ais sees it: identity plus labels.
// Labels are the authoritative ownership mechanism.
type Container struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Image  string            `json:"image"`
	State  string            `json:"state"` // running | exited | created | ...
	Labels map[string]string `json:"labels"`
}

// Filter selects containers by label equality. Name is for the few places
// (sidecars) where a fixed name is the contract; lifecycle cleanup must
// filter on labels, never on names.
type Filter struct {
	Labels map[string]string
	Name   string
}

// StopOptions controls Stop.
type StopOptions struct {
	TimeoutSeconds int
}

// RemoveOptions controls Remove.
type RemoveOptions struct {
	Force bool
}

// ExecResult is the outcome of an Exec.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// Info describes the engine host.
type Info struct {
	Engine   string `json:"engine"`
	Version  string `json:"version"`
	Rootless bool   `json:"rootless"`
	// CgroupsVersion is "1", "2" or "" when unknown.
	CgroupsVersion string `json:"cgroupsVersion"`
}

// Runtime is the engine surface ais needs. Implementations: Docker, Podman
// (the real ones) and Fake (a recorder for tests that asserts call
// sequences and feeds canned container output).
type Runtime interface {
	Engine() string
	Dialect() container.Dialect
	// Available reports whether the engine CLI responds.
	Available(ctx context.Context) error
	Info(ctx context.Context) (Info, error)

	// RunCapture runs a container in the foreground with no terminal, copying
	// its stdout and stderr to the writers. env entries ("K=V") are added to
	// the engine process environment for this call only, which is how a
	// FromHost EnvVar gets a per-run value without touching the daemon's own
	// environment. The container's exit code is returned; err is set only
	// when the engine itself failed.
	//
	// Legacy comment:
	// its stdout and stderr to the writers. The container's exit code is
	// returned; err is set only when the engine itself failed.
	RunCapture(ctx context.Context, argv []string, env []string, stdout, stderr io.Writer) (int, error)
	// RunDetached starts a container in the background (sidecars).
	RunDetached(ctx context.Context, argv []string) error

	ContainerExists(ctx context.Context, name string) (bool, error)
	ContainerRunning(ctx context.Context, name string) (bool, error)
	Stop(ctx context.Context, name string, opts StopOptions) error
	Remove(ctx context.Context, name string, opts RemoveOptions) error
	List(ctx context.Context, f Filter) ([]Container, error)
	Exec(ctx context.Context, name string, cmd []string) (ExecResult, error)
	Logs(ctx context.Context, name string, tail int) (string, error)
	Kill(ctx context.Context, name string, signal string) error

	ImageExists(ctx context.Context, ref string) (bool, error)
	ImageLabel(ctx context.Context, ref string, label string) (string, error)
	ImageBuild(ctx context.Context, argv []string) error

	NetworkExists(ctx context.Context, name string) (bool, error)
	NetworkCreate(ctx context.Context, name string, internal bool, subnet string, labels map[string]string) error
	NetworkRemove(ctx context.Context, name string) error
}

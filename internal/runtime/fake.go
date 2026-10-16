package runtime

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/scuq/ais/internal/container"
)

// Fake is a recording Runtime for tests. It answers from in-memory state and
// records every call as one line, so tests can assert call sequences. Stdout
// is what RunCapture feeds back, so the whole run pipeline can be exercised
// with a canned Claude envelope.
type Fake struct {
	Calls []string

	EngineName string
	Dial       container.Dialect

	Containers map[string]*Container
	Networks   map[string]bool
	Images     map[string]map[string]string // ref -> labels

	// Stdout and Stderr are written by RunCapture; ExitCode is its result.
	Stdout   string
	Stderr   string
	ExitCode int
	// RunError, when set, is returned by RunCapture and RunDetached.
	RunError error
	// BlockUntilCancel makes RunCapture wait for ctx to end, like an engine
	// client attached to a long-running container.
	BlockUntilCancel bool
	// LastEnv is the env passed to the last RunCapture.
	LastEnv []string
	// Rootless is reported by Info.
	Rootless bool
}

// NewFake returns an empty fake runtime speaking the podman dialect.
func NewFake() *Fake {
	return &Fake{
		EngineName: "podman",
		Dial:       container.PodmanDialect{},
		Containers: map[string]*Container{},
		Networks:   map[string]bool{},
		Images:     map[string]map[string]string{},
		Rootless:   true,
	}
}

// NewFakeDocker returns an empty fake runtime speaking the docker dialect.
func NewFakeDocker() *Fake {
	f := NewFake()
	f.EngineName = "docker"
	f.Dial = container.DockerDialect{}
	f.Rootless = false
	return f
}

func (f *Fake) record(format string, args ...any) {
	f.Calls = append(f.Calls, fmt.Sprintf(format, args...))
}

// CallsMatching returns the recorded calls whose first word is verb.
func (f *Fake) CallsMatching(verb string) []string {
	var out []string
	for _, c := range f.Calls {
		if strings.HasPrefix(c, verb+" ") || c == verb {
			out = append(out, c)
		}
	}
	return out
}

func (f *Fake) Engine() string                  { return f.EngineName }
func (f *Fake) Dialect() container.Dialect      { return f.Dial }
func (f *Fake) Available(context.Context) error { return nil }

func (f *Fake) Info(context.Context) (Info, error) {
	f.record("info")
	return Info{Engine: f.EngineName, Version: "fake", Rootless: f.Rootless, CgroupsVersion: "2"}, nil
}

func (f *Fake) RunCapture(ctx context.Context, argv []string, env []string, stdout, stderr io.Writer) (int, error) {
	f.LastEnv = env
	f.record("run %s", strings.Join(argv, " "))
	if f.RunError != nil {
		return -1, f.RunError
	}
	if f.BlockUntilCancel {
		for i, a := range argv {
			if a == "--name" && i+1 < len(argv) {
				f.Containers[argv[i+1]] = &Container{Name: argv[i+1], State: "running", Labels: labelsOf(argv)}
			}
		}
		<-ctx.Done()
		return 137, nil
	}
	_, _ = io.WriteString(stdout, f.Stdout)
	_, _ = io.WriteString(stderr, f.Stderr)
	return f.ExitCode, nil
}

func (f *Fake) RunDetached(ctx context.Context, argv []string) error {
	f.record("run-detached %s", strings.Join(argv, " "))
	if f.RunError != nil {
		return f.RunError
	}
	for i, a := range argv {
		if a == "--name" && i+1 < len(argv) {
			f.Containers[argv[i+1]] = &Container{Name: argv[i+1], State: "running", Labels: labelsOf(argv)}
		}
	}
	return nil
}

func labelsOf(argv []string) map[string]string {
	out := map[string]string{}
	for i, a := range argv {
		if a == "--label" && i+1 < len(argv) {
			if k, v, ok := strings.Cut(argv[i+1], "="); ok {
				out[k] = v
			}
		}
	}
	return out
}

func (f *Fake) ContainerExists(ctx context.Context, name string) (bool, error) {
	f.record("container-exists %s", name)
	_, ok := f.Containers[name]
	return ok, nil
}

func (f *Fake) ContainerRunning(ctx context.Context, name string) (bool, error) {
	f.record("container-running %s", name)
	c, ok := f.Containers[name]
	return ok && c.State == "running", nil
}

func (f *Fake) Stop(ctx context.Context, name string, opts StopOptions) error {
	f.record("stop %s", name)
	if c, ok := f.Containers[name]; ok {
		c.State = "exited"
		return nil
	}
	return fmt.Errorf("no such container %s", name)
}

func (f *Fake) Remove(ctx context.Context, name string, opts RemoveOptions) error {
	f.record("remove %s force=%v", name, opts.Force)
	if _, ok := f.Containers[name]; !ok {
		return fmt.Errorf("no such container %s", name)
	}
	delete(f.Containers, name)
	return nil
}

func matches(labels map[string]string, name string, f Filter) bool {
	for k, v := range f.Labels {
		if labels[k] != v {
			return false
		}
	}
	if f.Name != "" && !strings.Contains(name, f.Name) {
		return false
	}
	return true
}

func (f *Fake) List(ctx context.Context, flt Filter) ([]Container, error) {
	f.record("list labels=%v name=%s", flt.Labels, flt.Name)
	var out []Container
	for name, c := range f.Containers {
		if matches(c.Labels, name, flt) {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (f *Fake) Exec(ctx context.Context, name string, cmd []string) (ExecResult, error) {
	f.record("exec %s %s", name, strings.Join(cmd, " "))
	return ExecResult{}, nil
}

func (f *Fake) Logs(ctx context.Context, name string, tail int) (string, error) {
	f.record("logs %s", name)
	return "", nil
}

func (f *Fake) Kill(ctx context.Context, name string, signal string) error {
	f.record("kill %s %s", name, signal)
	return nil
}

func (f *Fake) ImageExists(ctx context.Context, ref string) (bool, error) {
	f.record("image-exists %s", ref)
	_, ok := f.Images[ref]
	return ok, nil
}

func (f *Fake) ImageLabel(ctx context.Context, ref string, label string) (string, error) {
	f.record("image-label %s %s", ref, label)
	labels, ok := f.Images[ref]
	if !ok {
		return "", fmt.Errorf("no such image %s", ref)
	}
	return labels[label], nil
}

func (f *Fake) ImageBuild(ctx context.Context, argv []string) error {
	f.record("image-build %s", strings.Join(argv, " "))
	return nil
}

func (f *Fake) NetworkExists(ctx context.Context, name string) (bool, error) {
	f.record("network-exists %s", name)
	return f.Networks[name], nil
}

func (f *Fake) NetworkCreate(ctx context.Context, name string, internal bool, subnet string, labels map[string]string) error {
	f.record("network-create %s internal=%v subnet=%s", name, internal, subnet)
	f.Networks[name] = true
	return nil
}

func (f *Fake) NetworkRemove(ctx context.Context, name string) error {
	f.record("network-remove %s", name)
	delete(f.Networks, name)
	return nil
}

var _ Runtime = (*Fake)(nil)

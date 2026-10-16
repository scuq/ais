package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/scuq/ais/internal/container"
)

// CLI drives the docker or podman command line. The two differ only in
// existence checks, the ps/info output shapes and the user mapping, which
// is handled by the dialect.
type CLI struct {
	Executable string
	engine     string
	dialect    container.Dialect
}

// NewDocker returns a docker-backed runtime.
func NewDocker() *CLI {
	return &CLI{Executable: "docker", engine: "docker", dialect: container.DockerDialect{}}
}

// NewPodman returns a podman-backed runtime.
func NewPodman() *CLI {
	return &CLI{Executable: "podman", engine: "podman", dialect: container.PodmanDialect{}}
}

// Detect resolves the configured engine preference to a runtime.
func Detect(pref string) (Runtime, error) {
	engine, err := DetectEngine(pref)
	if err != nil {
		return nil, err
	}
	if engine == "podman" {
		return NewPodman(), nil
	}
	return NewDocker(), nil
}

func (c *CLI) Engine() string             { return c.engine }
func (c *CLI) Dialect() container.Dialect { return c.dialect }

func (c *CLI) Available(ctx context.Context) error {
	if _, err := exec.LookPath(c.Executable); err != nil {
		return fmt.Errorf("%s is not on PATH", c.Executable)
	}
	_, err := c.command(ctx, "version", "--format", "{{.Client.Version}}")
	return err
}

// command captures stdout/stderr and returns stdout on success.
func (c *CLI) command(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, c.Executable, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s %s: %s", c.Executable, strings.Join(args, " "), msg)
	}
	return out.String(), nil
}

// silent runs a command purely for its exit code.
func (c *CLI) silent(ctx context.Context, args ...string) bool {
	cmd := exec.CommandContext(ctx, c.Executable, args...)
	return cmd.Run() == nil
}

// Capture runs an arbitrary invocation and returns its stdout.
func (c *CLI) Capture(ctx context.Context, args ...string) (string, error) {
	return c.command(ctx, args...)
}

func (c *CLI) RunCapture(ctx context.Context, argv []string, env []string, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, c.Executable, argv...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return -1, err
}

func (c *CLI) RunDetached(ctx context.Context, argv []string) error {
	_, err := c.command(ctx, argv...)
	return err
}

func (c *CLI) ContainerExists(ctx context.Context, name string) (bool, error) {
	if c.engine == "podman" {
		return c.silent(ctx, "container", "exists", name), nil
	}
	return c.silent(ctx, "container", "inspect", "--format", "{{.Id}}", name), nil
}

func (c *CLI) ContainerRunning(ctx context.Context, name string) (bool, error) {
	out, err := c.command(ctx, "container", "inspect", name, "--format", "{{.State.Running}}")
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(out) == "true", nil
}

func (c *CLI) Stop(ctx context.Context, name string, opts StopOptions) error {
	args := []string{"stop"}
	if opts.TimeoutSeconds > 0 {
		args = append(args, "--time", strconv.Itoa(opts.TimeoutSeconds))
	}
	args = append(args, name)
	_, err := c.command(ctx, args...)
	return err
}

func (c *CLI) Remove(ctx context.Context, name string, opts RemoveOptions) error {
	args := []string{"rm"}
	if opts.Force {
		args = append(args, "--force")
	}
	args = append(args, name)
	_, err := c.command(ctx, args...)
	return err
}

func filterArgs(f Filter) []string {
	var args []string
	for k, v := range f.Labels {
		args = append(args, "--filter", fmt.Sprintf("label=%s=%s", k, v))
	}
	if f.Name != "" {
		args = append(args, "--filter", "name="+f.Name)
	}
	return args
}

// psRow is the union of docker's and podman's ps JSON. Docker prints one
// object per line with Names and Labels as strings; podman prints an array
// with Names as a list and Labels as a map.
type psRow struct {
	ID     string          `json:"Id"`
	IDAlt  string          `json:"ID"`
	Names  json.RawMessage `json:"Names"`
	Image  string          `json:"Image"`
	State  string          `json:"State"`
	Labels json.RawMessage `json:"Labels"`
}

func (r psRow) toContainer() Container {
	ct := Container{ID: r.ID, Image: r.Image, State: r.State, Labels: map[string]string{}}
	if ct.ID == "" {
		ct.ID = r.IDAlt
	}
	var names []string
	if err := json.Unmarshal(r.Names, &names); err == nil && len(names) > 0 {
		ct.Name = names[0]
	} else {
		var s string
		if json.Unmarshal(r.Names, &s) == nil {
			ct.Name = strings.Split(s, ",")[0]
		}
	}
	if err := json.Unmarshal(r.Labels, &ct.Labels); err != nil {
		var s string
		if json.Unmarshal(r.Labels, &s) == nil {
			ct.Labels = map[string]string{}
			for _, kv := range strings.Split(s, ",") {
				if k, v, ok := strings.Cut(kv, "="); ok {
					ct.Labels[k] = v
				}
			}
		}
	}
	return ct
}

func (c *CLI) List(ctx context.Context, f Filter) ([]Container, error) {
	args := append([]string{"ps", "--all", "--format", "json"}, filterArgs(f)...)
	out, err := c.command(ctx, args...)
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	var rows []psRow
	if strings.HasPrefix(out, "[") {
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			return nil, fmt.Errorf("cannot parse %s ps output: %w", c.Executable, err)
		}
	} else {
		sc := bufio.NewScanner(strings.NewReader(out))
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var r psRow
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return nil, fmt.Errorf("cannot parse %s ps output: %w", c.Executable, err)
			}
			rows = append(rows, r)
		}
	}
	containers := make([]Container, 0, len(rows))
	for _, r := range rows {
		containers = append(containers, r.toContainer())
	}
	return containers, nil
}

func (c *CLI) Exec(ctx context.Context, name string, cmdv []string) (ExecResult, error) {
	args := append([]string{"exec", name}, cmdv...)
	cmd := exec.CommandContext(ctx, c.Executable, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := ExecResult{Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}

func (c *CLI) Logs(ctx context.Context, name string, tail int) (string, error) {
	args := []string{"logs"}
	if tail > 0 {
		args = append(args, "--tail", strconv.Itoa(tail))
	}
	args = append(args, name)
	cmd := exec.CommandContext(ctx, c.Executable, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s logs %s: %w", c.Executable, name, err)
	}
	return buf.String(), nil
}

// FollowLogs streams `logs -f`, calling onLine per line until ctx ends.
func (c *CLI) FollowLogs(ctx context.Context, name string, tail int, onLine func(string)) error {
	args := []string{"logs", "-f", "--tail", strconv.Itoa(tail), name}
	cmd := exec.CommandContext(ctx, c.Executable, args...)
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s logs -f %s: %w", c.Executable, name, err)
	}
	go func() { _ = cmd.Wait(); _ = pw.Close() }()
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		onLine(sc.Text())
	}
	return nil
}

func (c *CLI) Kill(ctx context.Context, name string, signal string) error {
	_, err := c.command(ctx, "kill", "--signal", signal, name)
	return err
}

func (c *CLI) ImageExists(ctx context.Context, ref string) (bool, error) {
	if c.engine == "podman" {
		return c.silent(ctx, "image", "exists", ref), nil
	}
	return c.silent(ctx, "image", "inspect", "--format", "{{.Id}}", ref), nil
}

func (c *CLI) ImageLabel(ctx context.Context, ref string, label string) (string, error) {
	format := fmt.Sprintf("{{index .Config.Labels %q}}", label)
	if c.engine == "podman" {
		format = fmt.Sprintf("{{index .Labels %q}}", label)
	}
	out, err := c.command(ctx, "image", "inspect", ref, "--format", format)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// ImageBuild streams build output to stderr so stdout stays clean.
func (c *CLI) ImageBuild(ctx context.Context, argv []string) error {
	cmd := exec.CommandContext(ctx, c.Executable, argv...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c *CLI) NetworkExists(ctx context.Context, name string) (bool, error) {
	if c.engine == "podman" {
		return c.silent(ctx, "network", "exists", name), nil
	}
	return c.silent(ctx, "network", "inspect", "--format", "{{.Id}}", name), nil
}

func (c *CLI) NetworkCreate(ctx context.Context, name string, internal bool, subnet string, labels map[string]string) error {
	args := []string{"network", "create"}
	if internal {
		args = append(args, "--internal")
	}
	if subnet != "" {
		args = append(args, "--subnet", subnet)
	}
	for k, v := range labels {
		args = append(args, "--label", fmt.Sprintf("%s=%s", k, v))
	}
	args = append(args, name)
	_, err := c.command(ctx, args...)
	return err
}

func (c *CLI) NetworkRemove(ctx context.Context, name string) error {
	_, err := c.command(ctx, "network", "rm", name)
	return err
}

// NetworkInternal reports whether a network has no route out.
func (c *CLI) NetworkInternal(ctx context.Context, name string) (bool, error) {
	out, err := c.command(ctx, "network", "inspect", name, "--format", "{{.Internal}}")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "true", nil
}

func (c *CLI) Info(ctx context.Context) (Info, error) {
	info := Info{Engine: c.engine}
	if c.engine == "podman" {
		out, err := c.command(ctx, "info", "--format", "{{.Host.Security.Rootless}} {{.Host.CgroupsVersion}} {{.Version.Version}}")
		if err != nil {
			return info, err
		}
		f := strings.Fields(out)
		if len(f) > 0 {
			info.Rootless = f[0] == "true"
		}
		if len(f) > 1 {
			info.CgroupsVersion = f[1]
		}
		if len(f) > 2 {
			info.Version = f[2]
		}
		return info, nil
	}
	out, err := c.command(ctx, "info", "--format", "{{.CgroupVersion}} {{.ServerVersion}} {{.SecurityOptions}}")
	if err != nil {
		return info, err
	}
	f := strings.Fields(out)
	if len(f) > 0 {
		info.CgroupsVersion = f[0]
	}
	if len(f) > 1 {
		info.Version = f[1]
	}
	info.Rootless = strings.Contains(out, "name=rootless")
	return info, nil
}

var _ Runtime = (*CLI)(nil)

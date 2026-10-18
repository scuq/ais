package container

import (
	"fmt"
	"sort"
	"strings"
)

// EnvVar is one --env argument. FromHost forwards the variable by name only,
// so the engine imports the value from the ais process environment: the
// value never reaches the engine argv, where `ps` on a shared host would show
// it and where --dry-run output would print it. Secrets are always FromHost.
type EnvVar struct {
	Name     string
	Value    string
	FromHost bool
}

// Spec is everything needed to render a `run` argv. It is pure data: building
// one has no side effects, which is what makes --dry-run exact: the printed
// argv is the same slice the real run executes.
type Spec struct {
	Image    string
	Name     string
	Hostname string
	Remove   bool // --rm
	Detach   bool

	// UID/GID the container process runs as; how that is expressed is the
	// dialect's business (podman keep-id, docker --user).
	UID, GID int

	// ReadOnlyRootfs makes the image layers immutable at run time. Every
	// writable location is then an explicit tmpfs or bind mount, and the
	// Spec can be checked for "exactly one writable host path".
	ReadOnlyRootfs bool

	Workdir string
	Mounts  []Mount
	Tmpfs   []TmpfsMount
	Env     []EnvVar

	// Resource limits cap the blast radius of a runaway process. Memory sets
	// --memory-swap equal to --memory, disabling swap growth. Empty strings
	// disable a cap.
	PidsLimit int
	Memory    string
	CPUs      string

	NoNewPrivileges bool
	CapDropAll      bool

	// Networks the container joins. An internal network with no route out is
	// the egress enforcement; the proxy env vars in Env only tell tools where
	// the one door is.
	Networks []NetworkAttach
	// NoNetwork renders --network none: no interface at all. A container
	// that only reads a mounted file needs no network.
	NoNetwork bool

	Labels map[string]string

	// Command is what the entrypoint receives. Empty for ais run containers:
	// the entrypoint reads its argv from a mounted file.
	Command []string
}

// Argv renders the spec, starting with "run". selinuxRelabel adds the mount
// relabel option on SELinux-enforcing hosts. The order is fixed so --dry-run
// output and golden tests are deterministic.
func (s *Spec) Argv(d Dialect, selinuxRelabel bool) []string {
	args := []string{"run"}
	if s.Remove {
		args = append(args, "--rm")
	}
	if s.Detach {
		args = append(args, "--detach")
	}
	if s.Name != "" {
		args = append(args, "--name", s.Name)
	}
	if s.Hostname != "" {
		args = append(args, "--hostname", s.Hostname)
	}
	if s.UID > 0 || s.GID > 0 {
		args = append(args, d.UserArgs(s.UID, s.GID)...)
	}
	if s.ReadOnlyRootfs {
		args = append(args, "--read-only")
	}
	if s.CapDropAll {
		args = append(args, "--cap-drop=ALL")
	}
	if s.NoNewPrivileges {
		args = append(args, "--security-opt", "no-new-privileges")
	}
	if s.PidsLimit > 0 {
		args = append(args, "--pids-limit", fmt.Sprintf("%d", s.PidsLimit))
	}
	if s.Memory != "" {
		args = append(args, "--memory", s.Memory, "--memory-swap", s.Memory)
	}
	if s.CPUs != "" {
		args = append(args, "--cpus", s.CPUs)
	}
	for _, t := range s.Tmpfs {
		args = append(args, t.Args()...)
	}
	for _, m := range s.Mounts {
		args = append(args, m.Args(selinuxRelabel)...)
	}
	if s.Workdir != "" {
		args = append(args, "--workdir", s.Workdir)
	}
	for _, e := range s.Env {
		if e.FromHost {
			args = append(args, "--env", e.Name)
		} else {
			args = append(args, "--env", fmt.Sprintf("%s=%s", e.Name, e.Value))
		}
	}
	if s.NoNetwork {
		args = append(args, "--network", "none")
	}
	for _, n := range s.Networks {
		args = append(args, d.NetworkArgs(n)...)
	}
	labels := make([]string, 0, len(s.Labels))
	for k, v := range s.Labels {
		labels = append(labels, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(labels)
	for _, l := range labels {
		args = append(args, "--label", l)
	}
	args = append(args, s.Image)
	args = append(args, s.Command...)
	return args
}

// WritableMounts returns the host mounts that the container can write to.
// The run container contract is exactly one; tests assert it.
func (s *Spec) WritableMounts() []Mount {
	var out []Mount
	for _, m := range s.Mounts {
		if !m.ReadOnly() {
			out = append(out, m)
		}
	}
	return out
}

// ShellQuote renders an argv for human eyes (--dry-run output), quoting only
// where needed.
func ShellQuote(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\n\"'\\$&|;<>(){}[]*?~#") {
			quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			quoted[i] = a
		}
	}
	return strings.Join(quoted, " ")
}

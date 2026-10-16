package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/scuq/ais/internal/backend"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/container"
	"github.com/scuq/ais/internal/doctor"
	"github.com/scuq/ais/internal/egress"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/runner"
	"github.com/scuq/ais/internal/runtime"
)

func newEgressManager(p *output.Printer, cfg *config.Config) (*egress.Manager, error) {
	rt, err := runtime.Detect(cfg.Runtime.Engine)
	if err != nil {
		return nil, err
	}
	return &egress.Manager{Cfg: cfg, RT: rt, SELinux: doctor.SELinuxEnforcing(), Info: p.Info}, nil
}

// cmdNet stands up or tears down the persistent topology: the internal
// network (no route out), the egress network (the sidecars' way out), the
// squid proxy on both, and the backend sidecar.
func cmdNet(ctx context.Context, p *output.Printer, args []string) error {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	m, err := newEgressManager(p, cfg)
	if err != nil {
		return err
	}
	switch sub {
	case "up":
		tasks, err := loadTasks(cfg)
		if err != nil {
			return err
		}
		if err := m.Ensure(ctx, tasks); err != nil {
			return err
		}
		opts, err := runOptions(cfg)
		if err != nil {
			return err
		}
		if err := ensureBackendSidecar(ctx, p, cfg, m, opts); err != nil {
			return err
		}
		p.Good("ready", "ais network is up")
		return nil
	case "down":
		return m.Remove(ctx)
	case "status":
		fs := flag.NewFlagSet("net status", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "print JSON")
		if err := fs.Parse(args); err != nil {
			return err
		}
		st := m.GetStatus(ctx)
		if *asJSON {
			return output.JSON(st)
		}
		fmt.Printf("subnet:    %s\n", st.Subnet)
		for n, ok := range st.Networks {
			fmt.Printf("network:   %s %v\n", n, map[bool]string{true: "present", false: "absent"}[ok])
		}
		fmt.Printf("proxy:     %s %s (%s)\nbackend:   %s %s (%s)\nallowlist: %d entries in %s\n",
			st.Proxy.Name, st.Proxy.State, st.Proxy.IP, st.Backend.Name, st.Backend.State, st.Backend.IP, st.Entries, st.Files["allowlist"])
		return nil
	}
	return fmt.Errorf("unknown net subcommand %q (up | down | status)", sub)
}

func cmdEgress(ctx context.Context, p *output.Printer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ais egress status | list | denied [-n N] | reload | allow DOMAIN.. | remove DOMAIN.. | logs")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	m, err := newEgressManager(p, cfg)
	if err != nil {
		return err
	}
	reload := func() error {
		tasks, err := loadTasks(cfg)
		if err != nil {
			return err
		}
		return m.Reload(ctx, tasks)
	}
	switch args[0] {
	case "status":
		return cmdNet(ctx, p, append([]string{"status"}, args[1:]...))
	case "list":
		tasks, err := loadTasks(cfg)
		if err != nil {
			return err
		}
		acl, err := egress.Compose(cfg, tasks)
		if err != nil {
			return err
		}
		fmt.Print(acl)
		return nil
	case "reload":
		return reload()
	case "allow":
		if len(args) < 2 {
			return fmt.Errorf("usage: ais egress allow DOMAIN [DOMAIN ...]")
		}
		if err := egress.AddExtra(cfg, args[1:]); err != nil {
			return err
		}
		p.Good("allowed", "%s (in %s)", strings.Join(args[1:], ", "), egress.ExtraPath(cfg))
		return reload()
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: ais egress remove DOMAIN [DOMAIN ...]")
		}
		n, err := egress.RemoveExtra(cfg, args[1:])
		if err != nil {
			return err
		}
		p.Good("removed", "%d entry(ies)", n)
		return reload()
	case "denied":
		fs := flag.NewFlagSet("egress denied", flag.ContinueOnError)
		tail := fs.Int("n", 5000, "log lines to scan")
		asJSON := fs.Bool("json", false, "print JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		denied, err := m.Denied(ctx, *tail)
		if err != nil {
			return err
		}
		if *asJSON {
			return output.JSON(denied)
		}
		if len(denied) == 0 {
			p.Info("no denied requests in the last %d log lines", *tail)
			return nil
		}
		for _, d := range denied {
			fmt.Printf("%6d  %s\n", d.Count, d.Host)
		}
		return nil
	case "logs":
		fs := flag.NewFlagSet("egress logs", flag.ContinueOnError)
		tail := fs.Int("n", 200, "lines")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		logs, err := m.RT.Logs(ctx, egress.ProxyContainer, *tail)
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stdout, logs)
		return nil
	}
	return fmt.Errorf("unknown egress subcommand %q", args[0])
}

// backendSidecarSpec is the container that gives run containers a fixed
// address for the inventory MCP server. It holds no data and no secrets: it
// forwards to the daemon's MCP unix socket, which is bind-mounted in.
func backendSidecarSpec(cfg *config.Config, opts runner.Options) (*container.Spec, error) {
	ip, err := egress.BackendIP(cfg.Egress.Subnet)
	if err != nil {
		return nil, err
	}
	return &container.Spec{
		Image:           cfg.Backend.SidecarImage,
		Name:            egress.BackendContainer,
		Detach:          true,
		UID:             opts.UID,
		GID:             opts.GID,
		ReadOnlyRootfs:  true,
		CapDropAll:      true,
		NoNewPrivileges: true,
		PidsLimit:       64,
		Memory:          "64m",
		Mounts: []container.Mount{
			{Type: container.MountBind, Source: opts.HostBinary, Dest: "/ais", Options: []string{"ro"}},
			{Type: container.MountBind, Source: backend.MCPSocket(cfg), Dest: "/run/ais/mcp.sock"},
		},
		Networks: []container.NetworkAttach{{Name: egress.InternalNetwork, IP: ip}},
		Labels:   container.BaseLabels(container.RoleBackend),
		Command:  []string{"/ais", "backend-proxy", "--listen", fmt.Sprintf(":%d", cfg.Backend.MCPPort), "--upstream", "/run/ais/mcp.sock"},
	}, nil
}

// ensureBackendSidecar (re)creates the backend sidecar. The socket must
// exist, so this runs after the daemon's listeners are up; `ais net up`
// without a daemon skips it with a note.
func ensureBackendSidecar(ctx context.Context, p *output.Printer, cfg *config.Config, m *egress.Manager, opts runner.Options) error {
	if _, err := os.Stat(backend.MCPSocket(cfg)); err != nil {
		p.Info("backend sidecar not started: no daemon socket at %s (start 'ais daemon')", backend.MCPSocket(cfg))
		return nil
	}
	if exists, _ := m.RT.ContainerExists(ctx, egress.BackendContainer); exists {
		_ = m.RT.Remove(ctx, egress.BackendContainer, runtime.RemoveOptions{Force: true})
	}
	spec, err := backendSidecarSpec(cfg, opts)
	if err != nil {
		return err
	}
	if err := m.RT.RunDetached(ctx, spec.Argv(m.RT.Dialect(), opts.SELinux)); err != nil {
		return fmt.Errorf("could not start the backend sidecar: %w", err)
	}
	ip, _ := egress.BackendIP(cfg.Egress.Subnet)
	p.Info("backend sidecar %s up at %s:%d", egress.BackendContainer, ip, cfg.Backend.MCPPort)
	return nil
}

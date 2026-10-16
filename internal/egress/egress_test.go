package egress

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/task"
)

func TestIPs(t *testing.T) {
	if ip, _ := ProxyIP("10.199.0.0/24"); ip != "10.199.0.2" {
		t.Errorf("proxy %s", ip)
	}
	if ip, _ := BackendIP("10.199.0.0/24"); ip != "10.199.0.4" {
		t.Errorf("backend %s", ip)
	}
	if u, _ := ProxyURL("192.168.50.0/24", 3128); u != "http://192.168.50.2:3128" {
		t.Errorf("url %s", u)
	}
	if _, err := HostIP("10.0.0.0/30", 4); err == nil {
		t.Error("offset outside subnet accepted")
	}
}

func TestParseAccess(t *testing.T) {
	cases := map[string]struct {
		host   string
		denied bool
		ok     bool
	}{
		"1791887647.435    168 10.199.0.3 TCP_TUNNEL/200 4931 CONNECT api.anthropic.com:443 - HIER_DIRECT/1.2.3.4 -":  {"api.anthropic.com", false, true},
		"1791887568.778      0 10.199.0.3 TCP_DENIED_ABORTED/403 326 CONNECT example.com:443 - HIER_NONE/- text/html": {"example.com", true, true},
		"1791887568.778      0 10.199.0.3 TCP_DENIED/403 326 GET http://plain.example/path - HIER_NONE/- text/html":   {"plain.example", true, true},
		"2026/10/13 10:31:29| Processing Configuration File: /etc/squid/squid.conf (depth 0)":                         {"", false, false},
		"": {"", false, false},
	}
	for line, want := range cases {
		host, denied, ok := ParseAccess(line)
		if host != want.host || denied != want.denied || ok != want.ok {
			t.Errorf("%q: got %q %v %v", line, host, denied, ok)
		}
	}
	d := ParseDenied(strings.Join([]string{
		"1.0 0 10.199.0.3 TCP_DENIED/403 1 CONNECT a.example:443 - HIER_NONE/- -",
		"2.0 0 10.199.0.3 TCP_DENIED/403 1 CONNECT a.example:443 - HIER_NONE/- -",
		"3.0 0 10.199.0.3 TCP_TUNNEL/200 1 CONNECT b.example:443 - HIER_DIRECT/1.1.1.1 -",
	}, "\n"))
	if d["a.example"] != 2 || d["b.example"] != 0 {
		t.Errorf("denied: %v", d)
	}
}

func testConfig(t *testing.T) *config.Config {
	cfg := config.Defaults()
	dir := t.TempDir()
	cfg.Paths.StateDir = dir
	cfg.Paths.TasksDir = filepath.Join(dir, "tasks")
	cfg.Egress.BaseAllow = []string{"cfg.example"}
	return &cfg
}

func TestCompose(t *testing.T) {
	cfg := testConfig(t)
	tk, _ := task.Parse([]byte("version: 1\nname: t\nschedule: '@hourly'\nprompt: p\noutputSchema: {type: object}\negress: {allow: [a.example, api.anthropic.com]}\n"), task.Defaults{Model: "m", MaxTurns: 1, MaxBudgetUSD: 1, Timeout: time.Minute})
	_ = AddExtra(cfg, []string{"extra.example"})
	acl, err := Compose(cfg, []*task.Task{tk})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"api.anthropic.com", "cfg.example", "a.example", "extra.example", "# --- task t ---"} {
		if !strings.Contains(acl, want) {
			t.Errorf("missing %q in\n%s", want, acl)
		}
	}
	if strings.Count(acl, "api.anthropic.com\n") != 1 {
		t.Error("duplicate not removed")
	}
	if _, err := Compose(cfg, []*task.Task{{Name: "bad", Egress: task.Egress{Allow: []string{"not a domain"}}}}); err == nil {
		t.Error("invalid domain accepted")
	}
	// Reachable: no claude infrastructure, config + task + extra, in order.
	got := strings.Join(Reachable(cfg, tk), " ")
	if got != "cfg.example a.example api.anthropic.com extra.example" {
		t.Errorf("reachable: %q", got)
	}
	n, _ := RemoveExtra(cfg, []string{"extra.example"})
	if n != 1 {
		t.Errorf("remove %d", n)
	}
}

func TestManagerEnsureAndReload(t *testing.T) {
	cfg := testConfig(t)
	fake := runtime.NewFakeDocker()
	m := &Manager{Cfg: cfg, RT: fake}
	ctx := context.Background()
	if err := m.Ensure(ctx, nil); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(fake.Calls, "\n")
	if !strings.Contains(calls, "network-create ais-internal internal=true subnet=10.199.0.0/24") || !strings.Contains(calls, "network-create ais-egress internal=false") {
		t.Errorf("networks: %s", calls)
	}
	run := fake.CallsMatching("run-detached")
	if len(run) != 1 || !strings.Contains(run[0], "--network name=ais-internal,ip=10.199.0.2 --network ais-egress") || !strings.Contains(run[0], "--name ais-proxy") {
		t.Errorf("proxy run: %v", run)
	}
	if strings.Contains(run[0], "--read-only") {
		t.Error("squid needs a writable rootfs for its logs")
	}
	if _, err := os.Stat(GeneratedPath(cfg)); err != nil {
		t.Error("allowlist not written")
	}
	// Second Ensure with the proxy running and nothing changed: no reload.
	fake.Calls = nil
	if err := m.Ensure(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(fake.CallsMatching("exec")) != 0 || len(fake.CallsMatching("run-detached")) != 0 {
		t.Errorf("unexpected calls: %v", fake.Calls)
	}
	// Allowlist change: parse gate then reconfigure.
	_ = AddExtra(cfg, []string{"new.example"})
	fake.Calls = nil
	if err := m.Ensure(ctx, nil); err != nil {
		t.Fatal(err)
	}
	ex := fake.CallsMatching("exec")
	if len(ex) != 2 || !strings.Contains(ex[0], "squid -k parse") || !strings.Contains(ex[1], "squid -k reconfigure") {
		t.Errorf("reload sequence: %v", ex)
	}
	st := m.GetStatus(ctx)
	if st.Proxy.State != "running" || !st.Networks[InternalNetwork] {
		t.Errorf("status %+v", st)
	}
	if err := m.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fake.Containers) != 0 || len(fake.Networks) != 0 {
		t.Error("remove left resources")
	}
}

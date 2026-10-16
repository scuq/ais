package runner

import (
	"strings"
	"testing"

	"github.com/scuq/ais/internal/container"
)

func input() SpecInput {
	return SpecInput{
		Image: "localhost/ais:latest", TaskName: "vuln-watch", RunID: "20260101T000000Z-abcd", RunDir: "/state/runs/vuln-watch/20260101T000000Z-abcd",
		HostBinary: "/usr/local/bin/ais", UID: 1001, GID: 1001, MaxTurns: 40, Memory: "2g", CPUs: "1", PidsLimit: 256, TmpfsSize: "256m",
		NetworkName: "ais-internal", ProxyURL: "http://10.199.0.2:3128", NoProxy: []string{"10.199.0.4"},
	}
}

func TestComposeSpecPosture(t *testing.T) {
	s := composeSpec(input())
	if !s.ReadOnlyRootfs || !s.CapDropAll || !s.NoNewPrivileges || !s.Remove {
		t.Error("hardening flags missing")
	}
	w := s.WritableMounts()
	if len(w) != 1 || w[0].Dest != "/run/ais/out" {
		t.Errorf("exactly one writable mount expected, got %+v", w)
	}
	for _, tm := range s.Tmpfs {
		for _, o := range tm.Options {
			if strings.HasPrefix(o, "uid=") || strings.HasPrefix(o, "gid=") {
				t.Errorf("tmpfs %s carries %s (podman rejects it)", tm.Dest, o)
			}
		}
	}
	for _, e := range s.Env {
		if (e.Name == "CLAUDE_CODE_OAUTH_TOKEN" || e.Name == "AIS_RUN_TOKEN") && !e.FromHost {
			t.Errorf("secret %s rendered by value", e.Name)
		}
		if e.Name == "ANTHROPIC_API_KEY" {
			t.Error("ANTHROPIC_API_KEY must never be forwarded (it overrides the OAuth token)")
		}
	}
	if s.Labels[container.LabelTask] != "vuln-watch" || s.Labels[container.LabelRole] != container.RoleRun {
		t.Errorf("labels: %v", s.Labels)
	}
	if len(s.Command) != 0 {
		t.Error("run containers take their argv from the mounted file, not the command")
	}
}

func TestComposeSpecGoldenDocker(t *testing.T) {
	got := container.ShellQuote(composeSpec(input()).Argv(container.DockerDialect{}, false))
	want := "run --rm --name ais-run-vuln-watch-20260101T000000Z-abcd --hostname ais --user 1001:1001 --read-only --cap-drop=ALL --security-opt no-new-privileges --pids-limit 256 --memory 2g --memory-swap 2g --cpus 1 --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m --tmpfs /run/ais/cfg:rw,nosuid,nodev,noexec,mode=1777,size=64m --tmpfs /run/ais/home:rw,nosuid,nodev,noexec,mode=1777,size=64m --tmpfs /run/ais/work:rw,nosuid,nodev,noexec,mode=1777,size=16m --volume /state/runs/vuln-watch/20260101T000000Z-abcd/in:/run/ais/in:ro --volume /state/runs/vuln-watch/20260101T000000Z-abcd/out:/run/ais/out --volume /usr/local/bin/ais:/run/ais/bin/ais:ro --workdir /run/ais/work --env HOME=/run/ais/home/ais --env CLAUDE_CONFIG_DIR=/run/ais/cfg/claude --env CLAUDE_CODE_OAUTH_TOKEN --env AIS_RUN_TOKEN --env DISABLE_UPDATES=1 --env DISABLE_AUTOUPDATER=1 --env DISABLE_TELEMETRY=1 --env DISABLE_ERROR_REPORTING=1 --env DISABLE_BUG_COMMAND=1 --env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 --env AIS_TASK=vuln-watch --env AIS_RUN_ID=20260101T000000Z-abcd --env CLAUDE_CODE_MAX_TURNS=40 --env HTTPS_PROXY=http://10.199.0.2:3128 --env https_proxy=http://10.199.0.2:3128 --env HTTP_PROXY=http://10.199.0.2:3128 --env http_proxy=http://10.199.0.2:3128 --env NO_PROXY=localhost,127.0.0.1,::1,10.199.0.4 --env no_proxy=localhost,127.0.0.1,::1,10.199.0.4 --network ais-internal --label io.ais.managed=true --label io.ais.role=run --label io.ais.run=20260101T000000Z-abcd --label io.ais.schema=1 --label io.ais.task=vuln-watch localhost/ais:latest"
	if got != want {
		t.Errorf("docker argv drift\n got: %s\nwant: %s", got, want)
	}
}

func TestComposeSpecGoldenPodman(t *testing.T) {
	got := container.ShellQuote(composeSpec(input()).Argv(container.PodmanDialect{}, false))
	if !strings.HasPrefix(got, "run --rm --name ais-run-vuln-watch-20260101T000000Z-abcd --hostname ais --userns=keep-id:uid=1001,gid=1001 --read-only") {
		t.Errorf("podman argv: %s", got)
	}
}

func TestOpenEgressHasNoProxy(t *testing.T) {
	in := input()
	in.NetworkName, in.ProxyURL, in.NoProxy = "", "", nil
	s := composeSpec(in)
	if len(s.Networks) != 0 {
		t.Error("open mode must not attach a network")
	}
	for _, e := range s.Env {
		if strings.Contains(strings.ToLower(e.Name), "proxy") {
			t.Errorf("proxy env in open mode: %s", e.Name)
		}
	}
}

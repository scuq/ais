package container

import (
	"strings"
	"testing"
)

func sampleSpec() *Spec {
	s := &Spec{
		Image: "localhost/ais:latest", Name: "ais-run-t-1", Hostname: "ais", Remove: true,
		UID: 1001, GID: 1001, ReadOnlyRootfs: true, CapDropAll: true, NoNewPrivileges: true,
		PidsLimit: 256, Memory: "2g", CPUs: "1", Workdir: "/run/ais/work",
		Tmpfs:    []TmpfsMount{Tmpfs("/tmp", "256m")},
		Mounts:   []Mount{{Type: MountBind, Source: "/h/in", Dest: "/run/ais/in", Options: []string{"ro"}}, {Type: MountBind, Source: "/h/out", Dest: "/run/ais/out"}},
		Env:      []EnvVar{{Name: "A", Value: "1"}, {Name: "SECRET", FromHost: true}},
		Networks: []NetworkAttach{{Name: "ais-internal"}},
		Labels:   BaseLabels(RoleRun),
	}
	return s
}

func TestArgvDocker(t *testing.T) {
	got := strings.Join(sampleSpec().Argv(DockerDialect{}, false), " ")
	want := "run --rm --name ais-run-t-1 --hostname ais --user 1001:1001 --read-only --cap-drop=ALL --security-opt no-new-privileges --pids-limit 256 --memory 2g --memory-swap 2g --cpus 1 --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m --volume /h/in:/run/ais/in:ro --volume /h/out:/run/ais/out --workdir /run/ais/work --env A=1 --env SECRET --network ais-internal --label io.ais.managed=true --label io.ais.role=run --label io.ais.schema=1 localhost/ais:latest"
	if got != want {
		t.Fatalf("docker argv\n got: %s\nwant: %s", got, want)
	}
}

func TestArgvPodman(t *testing.T) {
	got := strings.Join(sampleSpec().Argv(PodmanDialect{}, true), " ")
	if !strings.Contains(got, "--userns=keep-id:uid=1001,gid=1001") {
		t.Errorf("podman user mapping missing: %s", got)
	}
	if !strings.Contains(got, "--volume /h/in:/run/ais/in:ro,z") || !strings.Contains(got, "--volume /h/out:/run/ais/out:z") {
		t.Errorf("selinux relabel rendering wrong: %s", got)
	}
	if strings.Contains(got, "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m,z") {
		t.Errorf("tmpfs must never be relabelled: %s", got)
	}
}

func TestNetworkWithIP(t *testing.T) {
	n := NetworkAttach{Name: "ais-internal", IP: "10.199.0.2"}
	if got := strings.Join(DockerDialect{}.NetworkArgs(n), " "); got != "--network name=ais-internal,ip=10.199.0.2" {
		t.Errorf("docker: %s", got)
	}
	if got := strings.Join(PodmanDialect{}.NetworkArgs(n), " "); got != "--network ais-internal:ip=10.199.0.2" {
		t.Errorf("podman: %s", got)
	}
}

func TestSecretsNeverByValue(t *testing.T) {
	for _, a := range sampleSpec().Argv(DockerDialect{}, false) {
		if strings.HasPrefix(a, "SECRET=") {
			t.Fatalf("secret rendered by value: %s", a)
		}
	}
}

func TestMountRenderNoOptions(t *testing.T) {
	m := Mount{Source: "/a", Dest: "/b"}
	if got := m.Render(true); got != "/a:/b:z" {
		t.Errorf("got %s", got)
	}
	if got := m.Render(false); got != "/a:/b" {
		t.Errorf("got %s", got)
	}
}

func TestShellQuote(t *testing.T) {
	got := ShellQuote([]string{"run", "--json-schema", `{"a":1}`, "it's"})
	want := `run --json-schema '{"a":1}' 'it'\''s'`
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestNoNetwork(t *testing.T) {
	s := sampleSpec()
	s.Networks, s.NoNetwork = nil, true
	got := strings.Join(s.Argv(DockerDialect{}, false), " ")
	if !strings.Contains(got, "--network none") || strings.Contains(got, "ais-internal") {
		t.Errorf("argv: %s", got)
	}
}

package aisctl

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scuq/ais/assets"
	"github.com/scuq/ais/internal/claude"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/secret"
)

type fakeHost struct {
	calls []string
	fail  map[string]string
}

func (f *fakeHost) exec(ctx context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	for prefix, msg := range f.fail {
		if strings.HasPrefix(line, prefix) {
			return "", errorf(msg)
		}
	}
	if strings.Contains(line, "is-active") {
		return "active\n", nil
	}
	return "", nil
}

type strErr string

func (s strErr) Error() string { return string(s) }
func errorf(s string) error    { return strErr(s) }

func testEnv(t *testing.T) (*Env, *fakeHost, *runtime.Fake) {
	t.Helper()
	home := t.TempDir()
	host := &fakeHost{fail: map[string]string{}}
	fake := runtime.NewFakeDocker()
	fake.Images["localhost/ais:latest"] = map[string]string{}
	// The fake image is "stale" (no recipe label), so init builds it; the
	// post-build flag check and version probe read this canned help text.
	fake.Stdout = strings.Join(claude.VisibleFlags, " ") + "\n2.1.301 (Claude Code)\n"
	var out bytes.Buffer
	e := &Env{Out: &out, Home: home, Exec: host.exec, Runtime: fake, Now: time.Now,
		ReadSecret: func(string) (string, error) { return "prompted-token", nil }}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("output:\n%s", out.String())
		}
	})
	return e, host, fake
}

func assetsInventory() []byte { return assets.Read("examples/inventory.mdj") }

func writeFakeAIS(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ais")
	_ = os.WriteFile(p, []byte("#!/bin/sh\necho fake\n"), 0o755)
	return p
}

func TestRenderUnit(t *testing.T) {
	u, err := RenderUnit("/home/x/.local/bin/ais", []string{"AIS_CONFIG=/etc/ais.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(u)
	for _, want := range []string{"ExecStart=/home/x/.local/bin/ais daemon", "Environment=AIS_LOG_FORMAT=json", "Environment=AIS_CONFIG=/etc/ais.yaml", "WantedBy=default.target"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in unit:\n%s", want, s)
		}
	}
	if strings.Contains(s, "{{") {
		t.Error("unrendered template")
	}
}

func TestRenderConfigParses(t *testing.T) {
	p := UserPaths("/h")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	_ = os.WriteFile(cfgPath, RenderConfig(InitOptions{Engine: "docker", Egress: "open", Timezone: "UTC", ClaudeVersion: "2.1.301"}, p), 0o600)
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Runtime.Image != "localhost/ais:latest" {
		t.Errorf("image default: %s", cfg.Runtime.Image)
	}
	cfg2, _ := loadConfigBytes(t, RenderConfig(InitOptions{Engine: "auto", Egress: "proxy", Image: "ghcr.io/x/ais:1"}, p))
	if cfg2.Runtime.Image != "ghcr.io/x/ais:1" {
		t.Errorf("init --image not persisted: %s", cfg2.Runtime.Image)
	}
	if cfg.Runtime.Engine != "docker" || cfg.Egress.Mode != "open" || cfg.Scheduler.Timezone != "UTC" || cfg.Image.ClaudeVersion != "2.1.301" || cfg.Inventory.File != "/h/.config/ais/inventory.mdj" || cfg.Inventory.TextFile != "" || cfg.Paths.StateDir != "/h/.local/state/ais" || cfg.Secrets.Dir != "/h/.config/ais/secrets" || cfg.Paths.TasksDir != "/h/.config/ais/tasks" {
		t.Errorf("%+v", cfg)
	}
	if len(cfg.Sinks) != 0 {
		t.Error("sink examples must stay commented out")
	}
}

func TestSetConfigKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	_ = os.WriteFile(path, RenderConfig(InitOptions{Engine: "auto", Egress: "proxy"}, UserPaths("/h")), 0o600)
	if err := setConfigKey(path, "image", "claudeVersion", `"2.2.0"`); err != nil {
		t.Fatal(err)
	}
	if err := setConfigKey(path, "runtime", "image", "ghcr.io/x/ais:1"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Image.ClaudeVersion != "2.2.0" || cfg.Runtime.Image != "ghcr.io/x/ais:1" || cfg.Runtime.Engine != "auto" {
		t.Errorf("%+v %+v", cfg.Image, cfg.Runtime)
	}
}

func TestInitNoStart(t *testing.T) {
	e, host, fake := testEnv(t)
	tok := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(tok, []byte("sk-ant-oat01-test\n"), 0o600)
	o := InitOptions{Engine: "docker", Egress: "proxy", AISBinary: writeFakeAIS(t), TokenFile: tok, Templates: []string{"vuln-watch"}, NoStart: true, NoLinger: true}
	if err := Init(context.Background(), e, o); err != nil {
		t.Fatal(err)
	}
	p := UserPaths(e.Home)
	for _, f := range []string{p.Bin, p.ConfigFile, p.UnitFile, p.Inventory, filepath.Join(p.TasksDir, "vuln-watch.yaml"), filepath.Join(p.ConfigDir, "secrets", "claude-oauth-token")} {
		if !fileExists(f) {
			t.Errorf("missing %s", f)
		}
	}
	data, _ := os.ReadFile(filepath.Join(p.ConfigDir, "secrets", "claude-oauth-token"))
	if strings.Contains(string(data), "sk-ant-oat01-test") {
		t.Errorf("token stored in plaintext: %q", data)
	}
	if v, err := (&secret.FileStore{Dir: filepath.Join(p.ConfigDir, "secrets")}).Get("claude-oauth-token"); err != nil || v != "sk-ant-oat01-test" {
		t.Errorf("token round trip: %q %v", v, err)
	}
	calls := strings.Join(host.calls, "\n")
	if !strings.Contains(calls, "systemctl --user daemon-reload") || strings.Contains(calls, "enable --now") || strings.Contains(calls, "loginctl") {
		t.Errorf("host calls: %s", calls)
	}
	if !strings.Contains(calls, "docker pull docker.io/ubuntu/squid:latest") {
		t.Errorf("sidecar images not pulled: %s", calls)
	}
	if len(fake.CallsMatching("image-build")) != 1 {
		t.Errorf("stale image not rebuilt: %v", fake.Calls)
	}
	if len(fake.CallsMatching("network-create")) != 2 {
		t.Errorf("networks not created: %v", fake.Calls)
	}
	// Second init without --force refuses.
	if err := Init(context.Background(), e, o); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("expected refusal, got %v", err)
	}
	// With --force the config is backed up and rewritten.
	o.Force = true
	if err := Init(context.Background(), e, o); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(p.ConfigFile + ".bak-*"); len(m) != 1 {
		t.Errorf("backup missing: %v", m)
	}
}

func TestInitRefusesWithoutEngine(t *testing.T) {
	e, _, fake := testEnv(t)
	fake.RunError = errorf("engine down")
	fake.Images = map[string]map[string]string{}
	o := InitOptions{Engine: "docker", AISBinary: writeFakeAIS(t), TokenFile: "/nonexistent", NoStart: true}
	if err := Init(context.Background(), e, o); err == nil {
		t.Error("expected an error")
	}
}

func TestUninstallKeepsConfigByDefault(t *testing.T) {
	e, host, _ := testEnv(t)
	tok := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(tok, []byte("x"), 0o600)
	o := InitOptions{Engine: "docker", AISBinary: writeFakeAIS(t), TokenFile: tok, NoStart: true, NoLinger: true}
	if err := Init(context.Background(), e, o); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(context.Background(), e, UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	p := UserPaths(e.Home)
	if fileExists(p.UnitFile) || fileExists(p.Bin) {
		t.Error("unit or binary left behind")
	}
	if !fileExists(p.ConfigFile) {
		t.Error("config removed without --purge-all")
	}
	if !strings.Contains(strings.Join(host.calls, "\n"), "systemctl --user disable --now ais.service") {
		t.Errorf("unit not disabled: %v", host.calls)
	}
	if err := Uninstall(context.Background(), e, UninstallOptions{PurgeAll: true}); err == nil {
		t.Error("purge-all without confirmation must abort")
	}
	if err := Uninstall(context.Background(), e, UninstallOptions{PurgeAll: true, Yes: true}); err != nil {
		t.Fatal(err)
	}
	if fileExists(p.ConfigDir) {
		t.Error("config dir left after --purge-all")
	}
}

func loadConfigBytes(t *testing.T, data []byte) (*config.Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	_ = os.WriteFile(path, data, 0o600)
	return loadConfig(path)
}

func TestRedactTestAndApproveGate(t *testing.T) {
	e, host, _ := testEnv(t)
	tok := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(tok, []byte("x"), 0o600)
	o := InitOptions{Engine: "docker", AISBinary: writeFakeAIS(t), TokenFile: tok, Templates: []string{"vuln-watch"}, NoLinger: true}
	if err := Init(context.Background(), e, o); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(host.calls, "\n")
	if strings.Contains(calls, "enable --now") || !strings.Contains(calls, "systemctl --user enable ais.service") {
		t.Errorf("init must enable but not start before approval: %s", calls)
	}
	p := UserPaths(e.Home)
	cfg, _ := loadConfig(p.ConfigFile)
	if cfg.RedactionApproved() == nil {
		t.Fatal("fresh config must not be approved")
	}
	rep, err := RunRedactTest(context.Background(), cfg, RedactTestOptions{Text: "db01.cyberdyne.systems 10.9.9.9 8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	last := rep.Samples[len(rep.Samples)-1][1]
	if strings.Contains(last, "cyberdyne") || strings.Contains(last, "10.9.9.9") || !strings.Contains(last, "8.8.8.8") || !strings.Contains(last, "qo01.ploreqlar.flfgrzf") {
		t.Errorf("sample redaction: %s", last)
	}
	if rep.Records == 0 || rep.Uncovered() != 0 {
		t.Errorf("example inventory must be fully covered: %+v (%d records)", rep.Coverage, rep.Records)
	}
	// An uncovered inventory value blocks approval unless forced.
	_ = os.WriteFile(p.Inventory, []byte("# x\n```json\n{\"hostname\": \"x.other.example\", \"ip\": \"8.8.4.4\", \"product\": \"P\"}\n```\n"), 0o600)
	if err := RedactApprove(context.Background(), e, RedactApproveOptions{}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("expected refusal, got %v", err)
	}
	_ = os.WriteFile(p.Inventory, assetsInventory(), 0o600)
	host.calls = nil
	if err := RedactApprove(context.Background(), e, RedactApproveOptions{Start: true}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadConfig(p.ConfigFile)
	if err := cfg.RedactionApproved(); err != nil {
		t.Errorf("approval not recorded: %v", err)
	}
	// Changing the policy voids the approval.
	_ = setConfigKey(p.ConfigFile, "pii", "domains", `[".cyberdyne.systems", ".more.example"]`)
	cfg, _ = loadConfig(p.ConfigFile)
	if cfg.RedactionApproved() == nil {
		t.Error("changed policy still approved")
	}
}

func TestRedactTestInventoryFormats(t *testing.T) {
	e, _, _ := testEnv(t)
	tok := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(tok, []byte("x"), 0o600)
	if err := Init(context.Background(), e, InitOptions{Engine: "docker", AISBinary: writeFakeAIS(t), TokenFile: tok, NoStart: true, NoLinger: true}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := loadConfig(UserPaths(e.Home).ConfigFile)
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "inv.csv")
	jsonPath := filepath.Join(dir, "inv.json")
	yamlPath := filepath.Join(dir, "inv.yaml")
	mdjPath := filepath.Join(dir, "inv.mdj")
	_ = os.WriteFile(csvPath, []byte("hostname,ip,product,comment\nfw01.cyberdyne.systems,10.1.0.1,PAN-OS,\"exposed via jump01.cyberdyne.systems, auth using saml\"\n"), 0o600)
	_ = os.WriteFile(jsonPath, []byte(`[{"hostname":"fw01.cyberdyne.systems","ip":"10.1.0.1","product":"PAN-OS","comment":"exposed via jump01.cyberdyne.systems, auth using saml"}]`), 0o600)
	_ = os.WriteFile(yamlPath, []byte("- hostname: fw01.cyberdyne.systems\n  ip: 10.1.0.1\n  product: PAN-OS\n  comment: exposed via jump01.cyberdyne.systems, auth using saml\n"), 0o600)
	_ = os.WriteFile(mdjPath, []byte("# fw01\n\n```json\n{\"hostname\": \"fw01.cyberdyne.systems\", \"ip\": \"10.1.0.1\", \"product\": \"PAN-OS\"}\n```\n\n## Comment\n\nexposed via jump01.cyberdyne.systems, auth using saml\n"), 0o600)
	for _, path := range []string{csvPath, jsonPath, yamlPath, mdjPath} {
		rep, err := RunRedactTest(context.Background(), cfg, RedactTestOptions{Inventory: path})
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if rep.Records != 1 || len(rep.Diffs) != 1 {
			t.Fatalf("%s: %+v", path, rep)
		}
		a := rep.Diffs[0].After
		if a["hostname"] != "sj01.ploreqlar.flfgrzf" || !strings.HasPrefix(a["ip"], "100.") || a["product"] != "PAN-OS" {
			t.Errorf("%s: %v", path, a)
		}
		if strings.Contains(a["comment"], "cyberdyne") || !strings.Contains(a["comment"], "auth using saml") {
			t.Errorf("%s: comment not scrubbed: %q", path, a["comment"])
		}
		if rep.Fields["comment"] != "scrub" || rep.Fields["hostname"] != "pseudonym" {
			t.Errorf("generic policy: %v", rep.Fields)
		}
	}
	if _, err := RunRedactTest(context.Background(), cfg, RedactTestOptions{Inventory: filepath.Join(dir, "x.txt")}); err == nil {
		t.Error("unknown format accepted")
	}
}

func TestPromptsListAndShow(t *testing.T) {
	e, _, _ := testEnv(t)
	tok := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(tok, []byte("x"), 0o600)
	if err := Init(context.Background(), e, InitOptions{Engine: "docker", AISBinary: writeFakeAIS(t), TokenFile: tok, NoStart: true, NoLinger: true}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := loadConfig(UserPaths(e.Home).ConfigFile)
	dir := filepath.Join(cfg.RunsDir(), "vuln-watch")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "prompts.ndjson"), []byte(`{"run_id":"r1-dry","task":"vuln-watch","time":"2026-10-16T08:00:00Z","sha256":"abcdef0123456789abcdef","bytes":10,"system":"SYS","prompt":"PROMPT ONE"}
{"run_id":"r2","task":"vuln-watch","time":"2026-10-16T09:00:00Z","sha256":"0123456789abcdef0123","bytes":12,"system":"SYS2","prompt":"PROMPT TWO"}
`), 0o600)
	out := e.Out.(*bytes.Buffer)
	out.Reset()
	if err := Prompts(context.Background(), e, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "r2") || !strings.Contains(s, "r1-dry") || strings.Index(s, "r2") > strings.Index(s, "r1-dry") {
		t.Errorf("list order/content: %s", s)
	}
	out.Reset()
	if err := Prompts(context.Background(), e, []string{"last"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "PROMPT TWO") {
		t.Errorf("last: %s", out.String())
	}
	out.Reset()
	if err := Prompts(context.Background(), e, []string{"show", "r1-dry"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "PROMPT ONE") || !strings.Contains(out.String(), "SYS") {
		t.Errorf("show: %s", out.String())
	}
	if err := Prompts(context.Background(), e, []string{"show", "nope"}); err == nil {
		t.Error("unknown run accepted")
	}
}

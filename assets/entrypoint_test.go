package assets

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The entrypoint runs under the host bash against a fake claude that
// records its argv and stdin.
func runEntrypoint(t *testing.T, env map[string]string, files map[string]string) (string, string, int) {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	cfg := filepath.Join(dir, "cfg")
	_ = os.MkdirAll(in, 0o700)
	for name, body := range files {
		_ = os.WriteFile(filepath.Join(in, name), []byte(body), 0o600)
	}
	fake := filepath.Join(dir, "claude")
	_ = os.WriteFile(fake, []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \""+dir+"/argv.txt\"\ncat > \""+dir+"/stdin.txt\"\necho '{\"type\":\"result\"}'\nif [ -n \"${FAKE_SLEEP:-}\" ]; then trap 'echo term > \""+dir+"/term.txt\"; exit 143' TERM; sleep \"$FAKE_SLEEP\" & wait; fi\nexit \"${FAKE_RC:-0}\"\n"), 0o755)
	ep := filepath.Join(dir, "entrypoint.sh")
	_ = os.WriteFile(ep, Read("entrypoint.sh"), 0o755)
	cmd := exec.Command("bash", ep)
	outDir := filepath.Join(dir, "out")
	cg := filepath.Join(dir, "cgroup")
	_ = os.MkdirAll(outDir, 0o700)
	_ = os.MkdirAll(cg, 0o700)
	_ = os.WriteFile(filepath.Join(cg, "cpu.stat"), []byte("usage_usec 4200000\nuser_usec 4000000\nsystem_usec 200000\nnr_periods 0\n"), 0o600)
	_ = os.WriteFile(filepath.Join(cg, "memory.peak"), []byte("314572800\n"), 0o600)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(dir, "home"), "AIS_IN_DIR=" + in, "AIS_OUT_DIR=" + outDir, "AIS_CGROUP_DIR=" + cg, "AIS_CLAUDE_BIN=" + fake, "CLAUDE_CONFIG_DIR=" + cfg}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	if code == 0 || code == 3 {
		usage, err := os.ReadFile(filepath.Join(outDir, "usage.json"))
		if err != nil || strings.TrimSpace(string(usage)) != `{"cpu_usec":4200000,"user_usec":4000000,"system_usec":200000,"mem_peak":314572800}` {
			t.Errorf("usage.json: %q %v", usage, err)
		}
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv.txt"))
	stdin, _ := os.ReadFile(filepath.Join(dir, "stdin.txt"))
	t.Logf("stderr: %s", errb.String())
	if code == 0 {
		if st, err := os.Stat(filepath.Join(cfg, "settings.json")); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("settings.json not installed 0600: %v", err)
		}
	}
	return string(argv), string(stdin), code
}

var okFiles = map[string]string{
	"argv.json":     `["-p","--output-format","json","--json-schema","{\"type\":\"object\"}"]`,
	"prompt.md":     "hello prompt\n",
	"settings.json": "{}",
}

func TestEntrypointRunsClaude(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	argv, stdin, code := runEntrypoint(t, map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": "x"}, okFiles)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if argv != "-p\n--output-format\njson\n--json-schema\n{\"type\":\"object\"}\n" {
		t.Errorf("argv: %q", argv)
	}
	if stdin != "hello prompt\n" {
		t.Errorf("stdin: %q", stdin)
	}
}

func TestEntrypointRefusals(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	if _, _, code := runEntrypoint(t, nil, okFiles); code != 78 {
		t.Errorf("no token: exit %d", code)
	}
	if _, _, code := runEntrypoint(t, map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": "x", "ANTHROPIC_API_KEY": "k"}, okFiles); code != 78 {
		t.Errorf("api key set: exit %d", code)
	}
	missing := map[string]string{"argv.json": "[]", "prompt.md": "p", "settings.json": "{}"}
	if _, _, code := runEntrypoint(t, map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": "x"}, missing); code != 78 {
		t.Errorf("empty argv: exit %d", code)
	}
}

func TestEntrypointPassesExitCodeAndWritesUsage(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	if _, _, code := runEntrypoint(t, map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": "x", "FAKE_RC": "3"}, okFiles); code != 3 {
		t.Errorf("exit code not passed on: %d", code)
	}
}

// TestEntrypointForwardsTerm stops the entrypoint while claude runs: the
// signal must reach claude, and the entrypoint must wait for it.
func TestEntrypointForwardsTerm(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	_ = os.MkdirAll(in, 0o700)
	for name, body := range okFiles {
		_ = os.WriteFile(filepath.Join(in, name), []byte(body), 0o600)
	}
	fake := filepath.Join(dir, "claude")
	_ = os.WriteFile(fake, []byte("#!/usr/bin/env bash\ntrap 'echo term > \""+dir+"/term.txt\"; exit 143' TERM\nsleep 30 & wait\n"), 0o755)
	ep := filepath.Join(dir, "entrypoint.sh")
	_ = os.WriteFile(ep, Read("entrypoint.sh"), 0o755)
	cmd := exec.Command("bash", ep)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(dir, "home"), "AIS_IN_DIR=" + in, "AIS_OUT_DIR=" + dir, "AIS_CGROUP_DIR=" + filepath.Join(dir, "none"), "AIS_CLAUDE_BIN=" + fake, "CLAUDE_CONFIG_DIR=" + filepath.Join(dir, "cfg"), "CLAUDE_CODE_OAUTH_TOKEN=x"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 143 {
			t.Errorf("exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("entrypoint did not stop")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "term.txt")); strings.TrimSpace(string(b)) != "term" {
		t.Error("claude did not get the signal")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "usage.json")); err != nil || !strings.Contains(string(b), `"cpu_usec":0`) {
		t.Errorf("usage.json without cgroup: %q %v", b, err)
	}
}

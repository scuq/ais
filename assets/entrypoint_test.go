package assets

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	_ = os.WriteFile(fake, []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \""+dir+"/argv.txt\"\ncat > \""+dir+"/stdin.txt\"\necho '{\"type\":\"result\"}'\n"), 0o755)
	ep := filepath.Join(dir, "entrypoint.sh")
	_ = os.WriteFile(ep, Read("entrypoint.sh"), 0o755)
	cmd := exec.Command("bash", ep)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(dir, "home"), "AIS_IN_DIR=" + in, "AIS_CLAUDE_BIN=" + fake, "CLAUDE_CONFIG_DIR=" + cfg}
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

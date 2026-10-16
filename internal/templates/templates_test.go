package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scuq/ais/internal/task"
)

var d = task.Defaults{Model: "m", MaxTurns: 1, MaxBudgetUSD: 1, Timeout: time.Minute}

func TestEveryTemplateIsValid(t *testing.T) {
	infos, err := List(d)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range infos {
		if i.Name == "vuln-watch" {
			found = true
		}
		if i.Description == "" || i.Schedule == "" {
			t.Errorf("template %s lacks description or schedule", i.Name)
		}
		raw, _ := TaskYAML(i.Name)
		tk, err := task.Parse(raw, d)
		if err != nil {
			t.Fatal(err)
		}
		if err := tk.Validate(); err != nil {
			t.Errorf("%s: %v", i.Name, err)
		}
		if Readme(i.Name) == "" {
			t.Errorf("%s has no README", i.Name)
		}
	}
	if !found {
		t.Error("vuln-watch missing")
	}
}

func TestInstall(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inv.mdj")
	_ = os.WriteFile(inv, []byte("# P\n```json\n{\"product\": \"P\", \"version\": \"1\"}\n```\n"), 0o600)
	path, err := Install("vuln-watch", "my-watch", filepath.Join(dir, "tasks"), inv, d, false)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := task.LoadFile(path, d)
	if err != nil {
		t.Fatal(err)
	}
	if tk.Name != "my-watch" || tk.Inventory == nil || tk.Inventory.File != inv || tk.Inventory.TextFile != "" {
		t.Errorf("%+v", tk)
	}
	if _, err := Install("vuln-watch", "my-watch", filepath.Join(dir, "tasks"), inv, d, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("overwrite not refused: %v", err)
	}
	if _, err := Install("vuln-watch", "my-watch", filepath.Join(dir, "tasks"), inv, d, true); err != nil {
		t.Error(err)
	}
	if _, err := Install("nope", "", dir, "", d, false); err == nil {
		t.Error("unknown template accepted")
	}
}

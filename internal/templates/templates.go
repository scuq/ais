// Package templates serves the preconfigured tasks shipped in the binary:
// listing them, showing them and installing a copy into the tasks directory
// under a name of the operator's choice.
package templates

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/scuq/ais/assets"
	"github.com/scuq/ais/internal/task"
)

// Info describes one template.
type Info struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Schedule    string `json:"schedule"`
	Model       string `json:"model"`
}

// Names returns the embedded template names, sorted.
func Names() []string { return assets.Templates() }

// Exists reports whether name is a template.
func Exists(name string) bool {
	for _, n := range Names() {
		if n == name {
			return true
		}
	}
	return false
}

// TaskYAML returns the template's task definition.
func TaskYAML(name string) ([]byte, error) {
	if !Exists(name) {
		return nil, fmt.Errorf("no template named %q (see 'ais templates list')", name)
	}
	return assets.Read("templates/" + name + "/task.yaml"), nil
}

// Readme returns the template's description text, or "" when absent.
func Readme(name string) string {
	data, err := assets.FS.ReadFile("templates/" + name + "/README.md")
	if err != nil {
		return ""
	}
	return string(data)
}

// List parses every template header.
func List(d task.Defaults) ([]Info, error) {
	var out []Info
	for _, n := range Names() {
		raw, err := TaskYAML(n)
		if err != nil {
			return nil, err
		}
		t, err := task.Parse(raw, d)
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", n, err)
		}
		out = append(out, Info{Name: n, Description: t.Description, Schedule: t.Schedule, Model: t.Model})
	}
	return out, nil
}

var nameLine = regexp.MustCompile(`(?m)^name:[^\n]*$`)

// Render returns the template's task.yaml with the task name and the
// inventory paths adjusted. An empty path keeps the template's default.
func Render(name, asName, inventoryFile, textFile string) ([]byte, error) {
	raw, err := TaskYAML(name)
	if err != nil {
		return nil, err
	}
	doc := string(raw)
	if asName != "" && asName != name {
		doc = nameLine.ReplaceAllString(doc, "name: "+asName)
	}
	if inventoryFile != "" {
		doc = strings.ReplaceAll(doc, "~/.config/ais/inventory.csv", inventoryFile)
	}
	if textFile != "" {
		doc = strings.ReplaceAll(doc, "~/.config/ais/inventory.txt", textFile)
	}
	return []byte(doc), nil
}

// ErrExists means the target task file is already there.
var ErrExists = errors.New("task file exists; pass --force to overwrite")

// Install writes the template into tasksDir as <asName>.yaml and validates
// the result. Returns the path written.
func Install(name, asName, tasksDir, inventoryFile, textFile string, d task.Defaults, force bool) (string, error) {
	if asName == "" {
		asName = name
	}
	doc, err := Render(name, asName, inventoryFile, textFile)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(tasksDir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(tasksDir, asName+".yaml")
	if _, err := os.Stat(dst); err == nil && !force {
		return dst, fmt.Errorf("%s: %w", dst, ErrExists)
	}
	if err := os.WriteFile(dst, doc, 0o600); err != nil {
		return "", err
	}
	if _, err := task.LoadFile(dst, d); err != nil {
		_ = os.Remove(dst)
		return "", fmt.Errorf("template %s renders an invalid task: %w", name, err)
	}
	return dst, nil
}

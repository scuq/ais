package app

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/task"
)

// settableKeys are the top-level scalar task keys `ais tasks set` edits.
// Lists (sinks, tools) are written as flow sequences.
var settableKeys = map[string]bool{
	"model": true, "effort": true, "schedule": true, "jitter": true, "timeout": true,
	"maxTurns": true, "maxBudgetUsd": true, "enabled": true, "sinks": true, "overlap": true,
}

// cmdTasksSet rewrites top-level keys of a task file in place, keeping the
// rest of the file (comments included) untouched, then validates it. The
// previous file is kept as .bak-<ts>.
func cmdTasksSet(p *output.Printer, cfg *config.Config, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: ais tasks set <task> key=value... (keys: model effort schedule jitter timeout maxTurns maxBudgetUsd enabled overlap sinks=a,b)")
	}
	tasks, err := loadTasks(cfg)
	if err != nil {
		return err
	}
	t, ok := task.Find(tasks, args[0])
	if !ok {
		return fmt.Errorf("no task named %q", args[0])
	}
	data, err := os.ReadFile(t.Path)
	if err != nil {
		return err
	}
	doc := string(data)
	for _, kv := range args[1:] {
		key, val, ok := strings.Cut(kv, "=")
		if !ok || !settableKeys[key] {
			return fmt.Errorf("%q: want key=value with a key from: model effort schedule jitter timeout maxTurns maxBudgetUsd enabled overlap sinks", kv)
		}
		rendered := renderTaskValue(key, val)
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:[^\n]*$`)
		if re.MatchString(doc) {
			doc = re.ReplaceAllLiteralString(doc, key+": "+rendered)
		} else {
			doc = strings.TrimRight(doc, "\n") + "\n" + key + ": " + rendered + "\n"
		}
	}
	tmp := t.Path + ".tmp"
	if err := os.WriteFile(tmp, []byte(doc), 0o600); err != nil {
		return err
	}
	if _, err := task.LoadFile(tmp, taskDefaults(cfg)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("change rejected: %w", err)
	}
	_ = os.Rename(t.Path, t.Path+".bak-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Rename(tmp, t.Path); err != nil {
		return err
	}
	p.Good("updated", "%s (%s); apply with: systemctl --user kill -s HUP ais", t.Path, strings.Join(args[1:], " "))
	return nil
}

func renderTaskValue(key, val string) string {
	switch key {
	case "sinks":
		if strings.TrimSpace(val) == "" {
			return "[]"
		}
		parts := strings.Split(val, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case "schedule":
		return fmt.Sprintf("%q", val)
	}
	return val
}

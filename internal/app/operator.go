package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/scheduler"
)

// TaskStatus is a row of the daemon's /api/v1/tasks.
type TaskStatus struct {
	Name   string    `json:"name"`
	Next   time.Time `json:"next"`
	Paused string    `json:"paused"`
}

// daemonTasks asks the running daemon over the operator socket; nil when
// no daemon answers (the caller then computes from the cron expression).
func daemonTasks(ctx context.Context, cfg *config.Config) map[string]TaskStatus {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", cfg.BackendSocket())
	}}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ais/api/v1/tasks", nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var rows []TaskStatus
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil
	}
	out := map[string]TaskStatus{}
	for _, r := range rows {
		out[r.Name] = r
	}
	return out
}

// nextColumn renders the NEXT cell: the daemon's exact (jittered) time, or
// the cron time marked "~" when computed locally.
func nextColumn(live map[string]TaskStatus, name, schedule string, enabled bool, loc *time.Location) string {
	if !enabled {
		return "disabled"
	}
	if live != nil {
		if s, ok := live[name]; ok && !s.Next.IsZero() {
			if s.Paused != "" {
				return fmt.Sprintf("paused (%s)", s.Paused)
			}
			return s.Next.Local().Format("2006-01-02 15:04")
		}
		return "daemon: not scheduled"
	}
	next, err := scheduler.NextRun(schedule, time.Now(), loc)
	if err != nil {
		return "?"
	}
	return "~" + next.Local().Format("2006-01-02 15:04") + " (daemon not running)"
}

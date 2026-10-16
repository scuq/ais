package claude

import (
	"encoding/json"
	"fmt"
	"strings"
)

// streamEvent is the subset of a --output-format stream-json line that the
// live view renders.
type streamEvent struct {
	Type    string `json:"type"`
	Subtype string `json:"subtype"`
	Model   string `json:"model"`
	Message struct {
		Role    string `json:"role"`
		Content []struct {
			Type    string          `json:"type"`
			Text    string          `json:"text"`
			Name    string          `json:"name"`
			Input   json.RawMessage `json:"input"`
			Content json.RawMessage `json:"content"`
			IsError bool            `json:"is_error"`
		} `json:"content"`
	} `json:"message"`
	NumTurns     int      `json:"num_turns"`
	TotalCostUSD float64  `json:"total_cost_usd"`
	IsError      bool     `json:"is_error"`
	Result       string   `json:"result"`
	Tools        []string `json:"tools"`
	MCPServers   []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"mcp_servers"`
}

// RenderStreamLine turns one stream-json line into human-readable lines
// for a live view; ok is false for lines that carry nothing to show.
func RenderStreamLine(line []byte) (string, bool) {
	var ev streamEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return "", false
	}
	var b strings.Builder
	switch ev.Type {
	case "system":
		if ev.Subtype == "init" {
			servers := make([]string, 0, len(ev.MCPServers))
			for _, s := range ev.MCPServers {
				servers = append(servers, s.Name+":"+s.Status)
			}
			fmt.Fprintf(&b, "▶ session started · model %s · tools %s · mcp %s", ev.Model, strings.Join(ev.Tools, ","), strings.Join(servers, ","))
			return b.String(), true
		}
	case "assistant":
		for _, c := range ev.Message.Content {
			switch c.Type {
			case "text":
				if t := strings.TrimSpace(c.Text); t != "" {
					fmt.Fprintf(&b, "💬 %s\n", t)
				}
			case "tool_use":
				fmt.Fprintf(&b, "🔧 %s %s\n", c.Name, compactJSON(c.Input, 300))
			}
		}
	case "user":
		for _, c := range ev.Message.Content {
			if c.Type == "tool_result" {
				mark := "↩"
				if c.IsError {
					mark = "✖"
				}
				fmt.Fprintf(&b, "%s %s\n", mark, compactJSON(c.Content, 300))
			}
		}
	case "result":
		fmt.Fprintf(&b, "■ result %s · %d turns · est. $%.2f", ev.Subtype, ev.NumTurns, ev.TotalCostUSD)
		if ev.IsError {
			fmt.Fprintf(&b, " · error: %s", truncate(ev.Result, 200))
		}
		return b.String(), true
	}
	out := strings.TrimRight(b.String(), "\n")
	return out, out != ""
}

func compactJSON(raw json.RawMessage, n int) string {
	s := strings.TrimSpace(string(raw))
	var str string
	if json.Unmarshal(raw, &str) == nil {
		s = str
	}
	s = strings.Join(strings.Fields(s), " ")
	return truncate(s, n)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

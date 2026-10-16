package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/scuq/ais/internal/pseudo"
)

// cmdHook implements the Claude Code hooks that run inside the container.
// They must never block a run: on any error the hook exits 0 with nothing
// on stdout, which leaves the tool output as it was. The host-side leak
// check is the real control; this is defence in depth.
func cmdHook(args []string) int {
	if len(args) == 0 || args[0] != "redact" {
		fmt.Fprintln(os.Stderr, "usage: ais hook redact --rules FILE")
		return 2
	}
	fs := flag.NewFlagSet("hook redact", flag.ContinueOnError)
	rulesPath := fs.String("rules", "", "redaction rules JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 0
	}
	if err := hookRedact(*rulesPath, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "ais hook redact: %v\n", err)
	}
	return 0
}

// hookInput is the subset of the PostToolUse payload the hook needs.
type hookInput struct {
	ToolName     string          `json:"tool_name"`
	ToolResponse json.RawMessage `json:"tool_response"`
}

func hookRedact(rulesPath string, in io.Reader, out io.Writer) error {
	var rules pseudo.Rules
	if rulesPath != "" {
		raw, err := os.ReadFile(rulesPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &rules); err != nil {
			return fmt.Errorf("rules: %w", err)
		}
	}
	rd, err := pseudo.NewRedactor(rules)
	if err != nil {
		return err
	}
	payload, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	var hi hookInput
	if err := json.Unmarshal(payload, &hi); err != nil {
		return fmt.Errorf("hook payload: %w", err)
	}
	if len(hi.ToolResponse) == 0 {
		return nil
	}
	var resp any
	if err := json.Unmarshal(hi.ToolResponse, &resp); err != nil {
		return fmt.Errorf("tool_response: %w", err)
	}
	redacted := rd.RedactDoc(resp)
	// Shape-preserving by construction (string leaves only), so the engine
	// accepts it for built-in tools as well as MCP tools.
	result := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PostToolUse",
			"updatedToolOutput": redacted,
		},
	}
	return json.NewEncoder(out).Encode(result)
}

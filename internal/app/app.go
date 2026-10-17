// Package app wires the command surface. Parsing stays thin here; behaviour
// lives in the internal packages so it can be tested without a CLI.
package app

import (
	"context"
	"fmt"
	"os"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/output"
)

// Version is the ais version, overridable at link time.
var Version = "0.1.0-dev"

const usage = `ais — AI scheduler: Claude Code on a timer, in a box.

USAGE
    ais <command> [options] [args...]

COMMANDS
    daemon            Run the scheduler, backend and sink dispatcher (foreground)
    run <task>        Run one task now. --dry-run prints the container argv and
                      the generated input files without starting anything;
                      --live streams the model's text, tool calls and results
    tasks <sub>       list [--json] | validate | show <task>
                      | set <task> key=value...  (model, effort, schedule,
                      maxBudgetUsd, maxTurns, sinks=a,b, enabled, ...)
    templates <sub>   list [--json] | show <name> | use <name> [--as NAME] [--force]
                      Preconfigured tasks shipped in the binary; 'use' copies
                      one into the tasks directory
    runs <sub>        list [--task T] [--state S] [-n N] [--json]
                      | show <run-id> [--clear] [--json]
                      | redeliver <run-id> [--sink S]
    image <sub>       build [--no-cache] | status
    net <sub>         up | down | status [--json]: the internal network and
                      the proxy and backend sidecars
    egress <sub>      status | list | denied [-n N] | reload
                      | allow DOMAIN.. | remove DOMAIN.. | logs [-n N]
    sinks <sub>       list | test <sink> [--run RUN-ID] [--print]: send a sample
                      (or a run's result) to a sink to check the formatting
    secret <sub>      set NAME [--stdin] | list | delete NAME
                      | passphrase set [--stdin] | passphrase generate
                      (secrets are encrypted at rest with the passphrase file)
    digest <task>     Send the summary of the last window (runs, turns, tokens,
                      cost) to the task's sinks now; --print shows it, --window D
                      sets the window (default: the task's digest.window, 24h)
    hook redact       PostToolUse hook (runs inside the container)
    config show       Print the resolved configuration (--json for JSON)
    doctor            Check the engine and host
    version           Print the ais version
    help              This text

REDACTION
    Nothing runs until the redaction policy in config.yaml (pii:) is approved
    with 'aisctl redact approve'. 'ais doctor' shows the state.

CONFIGURATION
    ~/.config/ais/config.yaml ($AIS_CONFIG overrides), then AIS_* environment
    variables, then flags. Tasks live in ~/.config/ais/tasks/*.yaml.
    'ais config show' prints the resolved result.
`

// Main runs the CLI and returns the process exit code.
func Main(args []string) int {
	p := output.NewStderr()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 0
	}
	ctx := context.Background()

	var err error
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, usage)
	case "version", "--version":
		fmt.Printf("ais %s\n", Version)
	case "config":
		err = cmdConfig(args[1:])
	case "tasks":
		err = cmdTasks(p, args[1:])
	case "templates":
		err = cmdTemplates(p, args[1:])
	case "sinks":
		err = cmdSinks(ctx, p, args[1:])
	case "digest":
		err = cmdDigest(ctx, p, args[1:])
	case "run":
		return cmdRun(ctx, p, args[1:])
	case "hook":
		return cmdHook(args[1:])
	case "runs":
		err = cmdRuns(ctx, p, args[1:])
	case "image":
		err = cmdImage(ctx, p, args[1:])
	case "secret":
		err = cmdSecret(p, args[1:])
	case "doctor":
		return cmdDoctor(ctx, p, args[1:])
	case "net":
		err = cmdNet(ctx, p, args[1:])
	case "egress":
		err = cmdEgress(ctx, p, args[1:])
	case "daemon":
		err = cmdDaemon(ctx, p, args[1:])
	case "backend-proxy":
		err = cmdBackendProxy(ctx, args[1:])
	default:
		p.Error("unknown command %q — see 'ais help'", args[0])
		return 1
	}
	if err != nil {
		p.Error("%s", err)
		return 1
	}
	return 0
}

// loadConfig resolves and validates the configuration.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &cfg, nil
}

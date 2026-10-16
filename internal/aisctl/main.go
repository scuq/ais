package aisctl

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/scuq/ais/internal/app"
)

const usage = `aisctl — install and operate ais on this host (systemd user scope).

USAGE
    aisctl <command> [options]

COMMANDS
    init        Complete setup: install the ais binary, write config and an
                example task, store the OAuth token, build or pull the run
                image, pull the sidecar images, bring the network up, install
                and start the systemd user unit, wait for health
    redact test [--text T] [--stdin] [--inventory FILE [--format mdj|csv|json|yaml]]
                Show the redaction policy, run samples (and your text) through
                it, show every inventory record before and after, and list
                inventory values the policy would miss
    templates list | show NAME | use NAME [--as NAME] [--force]
                Shipped task templates (same as 'ais templates')
    prompts [list [--task T] [-n N]] | show RUN-ID | last [--task T]
                The prompts that were sent to the model, including dry runs
    run TASK [--live] [--dry-run]
                Start a manual run now; --live streams the model's progress
    redact approve [--force] [--no-start]
                Record the policy hash in config.yaml; nothing runs before this.
                Starts the installed unit when it is not running
    status      Unit state, network state and the doctor checks
    up | down   Start or stop the unit (down --network also removes sidecars)
    update      Reinstall the binary and/or rebuild the run image, restart
    logs        journalctl for the unit (-f follows)
    uninstall   Stop and disable the unit, remove sidecars and networks, the
                unit file and the binary; data kept unless purged
    version | help

INIT OPTIONS
    --engine auto|docker|podman   (default auto)
    --egress proxy|open           (default proxy)
    --timezone ZONE               scheduler timezone (default Local)
    --claude-version V            pin the Claude Code version baked into the image
    --image REF                   pull a prebuilt run image instead of building
    --ais-binary PATH             ais binary to install (default: next to aisctl,
                                  then PATH, then aisctl itself: same program)
    --token-file PATH             OAuth token from 'claude setup-token' (else
                                  $CLAUDE_CODE_OAUTH_TOKEN, else a hidden prompt)
    --passphrase-file PATH        passphrase that encrypts the secret store
                                  (default: generated into ~/.config/ais/secrets/.passphrase)
    --inventory PATH              inventory file (mdj) to install as ~/.config/ais/inventory.mdj
    --template NAME               install a shipped task template (repeatable;
                                  'ais templates list' shows them)
    --force                       re-apply over an existing setup (files are backed up)
    --no-start                    write everything, start nothing
    --no-linger                   do not run 'loginctl enable-linger'
    --wait DURATION               health wait (default 60s)

UPDATE OPTIONS
    --claude-version V | --image REF | --ais-binary PATH | --skip-health
    --wait DURATION               health wait after the restart (default 60s)

UNINSTALL OPTIONS
    --purge-state                 also remove the state directory (runs, database)
    --purge-all                   also remove config, tasks and secrets (asks; --yes skips)
`

// Main runs the CLI and returns the exit code.
func Main(args []string) int {
	e := DefaultEnv()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "version", "--version", "-v":
		fmt.Printf("aisctl %s\n", Version)
	case "init":
		err = runInit(ctx, e, args[1:])
	case "redact":
		err = runRedact(ctx, e, args[1:])
	case "templates":
		return app.Main(append([]string{"templates"}, args[1:]...))
	case "prompts":
		err = Prompts(ctx, e, args[1:])
	case "run":
		return app.Main(append([]string{"run"}, args[1:]...))
	case "status":
		err = Status(ctx, e)
	case "up":
		err = Up(ctx, e)
	case "down":
		fs := flag.NewFlagSet("down", flag.ContinueOnError)
		network := fs.Bool("network", false, "also remove sidecars and networks")
		if err = fs.Parse(args[1:]); err == nil {
			err = Down(ctx, e, DownOptions{Network: *network})
		}
	case "update":
		fs := flag.NewFlagSet("update", flag.ContinueOnError)
		var o UpdateOptions
		fs.StringVar(&o.ClaudeVersion, "claude-version", "", "")
		fs.StringVar(&o.Image, "image", "", "")
		fs.StringVar(&o.AISBinary, "ais-binary", "", "")
		fs.BoolVar(&o.SkipHealth, "skip-health", false, "")
		fs.DurationVar(&o.WaitHealth, "wait", 60*time.Second, "")
		if err = fs.Parse(args[1:]); err == nil {
			err = Update(ctx, e, o)
		}
	case "logs":
		fs := flag.NewFlagSet("logs", flag.ContinueOnError)
		follow := fs.Bool("f", false, "follow")
		n := fs.Int("n", 200, "lines")
		if err = fs.Parse(args[1:]); err == nil {
			err = Logs(ctx, e, *follow, *n)
		}
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
		var o UninstallOptions
		fs.BoolVar(&o.PurgeState, "purge-state", false, "")
		fs.BoolVar(&o.PurgeAll, "purge-all", false, "")
		fs.BoolVar(&o.Yes, "yes", false, "")
		if err = fs.Parse(args[1:]); err == nil {
			err = Uninstall(ctx, e, o)
		}
	default:
		fmt.Fprintf(os.Stderr, "aisctl: unknown command %q (see 'aisctl help')\n", args[0])
		return 2
	}
	if err != nil {
		if strings.Contains(err.Error(), "flag") && strings.Contains(err.Error(), "defined") {
			return 2
		}
		fmt.Fprintf(os.Stderr, "aisctl: %v\n", err)
		return 1
	}
	return 0
}

// listFlag collects a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func runRedact(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: aisctl redact test [--text T] | approve [--force] [--no-start]")
	}
	switch args[0] {
	case "test":
		fs := flag.NewFlagSet("redact test", flag.ContinueOnError)
		text := fs.String("text", "", "extra text to redact")
		fromStdin := fs.Bool("stdin", false, "also redact text read from standard input")
		inv := fs.String("inventory", "", "inventory file to show before/after (default: configured)")
		format := fs.String("format", "", "csv | json | yaml (default: by extension)")
		taskName := fs.String("task", "", "task whose field policy to apply (default: a generic policy)")
		asJSON := fs.Bool("json", false, "print the report as JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var stdin io.Reader
		if *fromStdin {
			stdin = os.Stdin
		}
		return RedactTest(ctx, e, RedactTestOptions{Text: *text, Stdin: stdin, Inventory: *inv, Format: *format, Task: *taskName, JSON: *asJSON})
	case "approve":
		fs := flag.NewFlagSet("redact approve", flag.ContinueOnError)
		force := fs.Bool("force", false, "approve although inventory values are uncovered")
		noStart := fs.Bool("no-start", false, "do not start the unit afterwards")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return RedactApprove(ctx, e, RedactApproveOptions{Force: *force, Start: !*noStart})
	}
	return fmt.Errorf("unknown redact subcommand %q", args[0])
}

func runInit(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	var o InitOptions
	fs.StringVar(&o.Engine, "engine", "auto", "")
	fs.StringVar(&o.Egress, "egress", "proxy", "")
	fs.StringVar(&o.Timezone, "timezone", "", "")
	fs.StringVar(&o.ClaudeVersion, "claude-version", "", "")
	fs.StringVar(&o.Image, "image", "", "")
	fs.StringVar(&o.AISBinary, "ais-binary", "", "")
	fs.StringVar(&o.TokenFile, "token-file", "", "")
	fs.StringVar(&o.PassphraseFile, "passphrase-file", "", "")
	fs.StringVar(&o.Inventory, "inventory", "", "")
	fs.Var((*listFlag)(&o.Templates), "template", "")
	fs.BoolVar(&o.Force, "force", false, "")
	fs.BoolVar(&o.NoStart, "no-start", false, "")
	fs.BoolVar(&o.NoLinger, "no-linger", false, "")
	fs.DurationVar(&o.WaitHealth, "wait", 60*time.Second, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("init takes no positional arguments")
	}
	return Init(ctx, e, o)
}

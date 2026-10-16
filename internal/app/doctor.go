package app

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/scuq/ais/internal/doctor"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/secret"
)

func cmdDoctor(ctx context.Context, p *output.Printer, args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig()
	if err != nil {
		p.Error("%s", err)
		return 1
	}
	in := doctor.Inputs{Cfg: cfg, Secrets: secret.NewFileStore(cfg.SecretsDir())}
	in.RT, in.EngineErr = runtime.Detect(cfg.Runtime.Engine)
	in.Tasks, in.TasksErr = loadTasks(cfg)
	rep := doctor.Run(ctx, in)
	if *asJSON {
		_ = output.JSON(rep)
	} else {
		for _, c := range rep.Checks {
			mark := map[string]string{"ok": "ok  ", "warn": "warn", "fail": "FAIL"}[c.Status]
			fmt.Fprintf(os.Stdout, "%s  %-12s %s\n", mark, c.Name, c.Detail)
		}
	}
	if rep.OK {
		return 0
	}
	return 1
}

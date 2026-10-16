package app

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/templates"
)

func cmdTemplates(p *output.Printer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ais templates list [--json] | show <name> | use <name> [--as NAME] [--force]")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("templates list", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "print JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		infos, err := templates.List(taskDefaults(cfg))
		if err != nil {
			return err
		}
		if *asJSON {
			return output.JSON(infos)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "TEMPLATE\tSCHEDULE\tDESCRIPTION")
		for _, i := range infos {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", i.Name, i.Schedule, i.Description)
		}
		return tw.Flush()
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: ais templates show <name>")
		}
		raw, err := templates.TaskYAML(args[1])
		if err != nil {
			return err
		}
		if r := templates.Readme(args[1]); r != "" {
			fmt.Fprint(os.Stderr, r, "\n")
		}
		fmt.Print(string(raw))
		return nil
	case "use":
		fs := flag.NewFlagSet("templates use", flag.ContinueOnError)
		as := fs.String("as", "", "task name (default: the template name)")
		force := fs.Bool("force", false, "overwrite an existing task file")
		pos, err := parseInterspersed(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: ais templates use <name> [--as NAME] [--force]")
		}
		path, err := templates.Install(pos[0], *as, cfg.TasksDir(), config.ExpandPath(cfg.Inventory.File), taskDefaults(cfg), *force)
		if err != nil {
			return err
		}
		p.Good("installed", "%s (edit sinks and schedule, then SIGHUP the daemon or restart it)", path)
		return nil
	}
	return fmt.Errorf("unknown templates subcommand %q", args[0])
}

package app

import (
	"flag"
	"fmt"
	"os"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/output"
)

func cmdConfig(args []string) error {
	if len(args) == 0 || args[0] != "show" {
		return fmt.Errorf("usage: ais config show [--json]")
	}
	fs := flag.NewFlagSet("config show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if *asJSON {
		return output.JSON(cfg)
	}
	out, err := config.Render(*cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "# resolved from %s\n%s", config.UserConfigPath(), out)
	return nil
}

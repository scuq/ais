package app

import (
	"context"
	"flag"
	"fmt"

	"github.com/scuq/ais/internal/image"
	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/runtime"
)

func cmdImage(ctx context.Context, p *output.Printer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ais image build [--no-cache] | status")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	rt, err := runtime.Detect(cfg.Runtime.Engine)
	if err != nil {
		return err
	}
	switch args[0] {
	case "build":
		fs := flag.NewFlagSet("image build", flag.ContinueOnError)
		noCache := fs.Bool("no-cache", false, "build without the layer cache")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		p.Info("building %s with claude-code %s (%s)", cfg.Runtime.Image, cfg.Image.ClaudeVersion, rt.Engine())
		if err := image.Build(ctx, rt, cfg, *noCache, Version); err != nil {
			return err
		}
		v, err := image.Version(ctx, rt, cfg.Runtime.Image)
		if err != nil {
			return err
		}
		p.Good("built", "%s (claude %s, recipe %s)", cfg.Runtime.Image, v, image.RecipeHash(cfg))
		return nil
	case "status":
		exists, current, err := image.IsCurrent(ctx, rt, cfg)
		if err != nil {
			return err
		}
		return output.JSON(map[string]any{"image": cfg.Runtime.Image, "exists": exists, "current": current, "recipe": image.RecipeHash(cfg), "claudeVersion": cfg.Image.ClaudeVersion})
	}
	return fmt.Errorf("unknown image subcommand %q", args[0])
}

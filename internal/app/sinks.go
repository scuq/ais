package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/secret"
	"github.com/scuq/ais/internal/sink"
	"github.com/scuq/ais/internal/store"
)

// cmdSinks lists configured sinks and sends a sample (or a real run's
// result) to one, so the formatting can be checked in the target before
// the first scheduled delivery.
func cmdSinks(ctx context.Context, p *output.Printer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ais sinks list | test <sink> [--run RUN-ID] [--print]")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SINK\tTYPE\tURL")
		for name, s := range cfg.Sinks {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", name, s.Type, s.URL)
		}
		return tw.Flush()
	case "test":
		fs := flag.NewFlagSet("sinks test", flag.ContinueOnError)
		runID := fs.String("run", "", "send this run's clear result instead of the sample")
		printOnly := fs.Bool("print", false, "print the Webex markdown instead of sending")
		pos, err := parseInterspersed(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: ais sinks test <sink> [--run RUN-ID] [--print]")
		}
		scfg, ok := cfg.Sinks[pos[0]]
		if !ok && !*printOnly {
			return fmt.Errorf("no sink named %q (--print previews the Webex formatting without one)", pos[0])
		}
		ev := sink.SampleEvent("vuln-watch")
		if *runID != "" {
			st, err := store.Open(filepath.Join(cfg.StateDir(), "ais.db"))
			if err != nil {
				return err
			}
			defer st.Close()
			d := &sink.Dispatcher{Store: st, Version: Version}
			if ev, err = d.LoadEvent(ctx, *runID, "result"); err != nil {
				return err
			}
		}
		if *printOnly {
			title, err := sink.RenderTitle(scfg.Title, ev)
			if err != nil {
				return err
			}
			fmt.Println(sink.WebexMarkdown(title, ev, scfg.MaxItems))
			if scfg.SkipEmpty && sink.EmptyFindings(ev.Result) {
				p.Warn("sink %s has skipEmpty: true; the daemon would not send this event", pos[0])
			}
			return nil
		}
		s, err := sink.Build(pos[0], scfg, secret.NewFileStore(cfg.SecretsDir()))
		if err != nil {
			return err
		}
		if sk, ok := s.(sink.Skipper); ok {
			if reason := sk.Skip(ev); reason != "" {
				p.Info("skipped %s event %s for sink %s: %s", ev.Kind, ev.RunID, pos[0], reason)
				return nil
			}
		}
		if err := s.Deliver(ctx, ev); err != nil {
			return err
		}
		p.Good("delivered", "%s event %s to sink %s (%s)", ev.Kind, ev.RunID, pos[0], s.Type())
		return nil
	}
	return fmt.Errorf("unknown sinks subcommand %q", args[0])
}

package app

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/scuq/ais/internal/output"
	"github.com/scuq/ais/internal/secret"
)

// readValue reads a secret from stdin (piped or --stdin) or a hidden prompt.
func readValue(what string, fromStdin bool) (string, error) {
	var value string
	if fromStdin || !term.IsTerminal(int(os.Stdin.Fd())) {
		data, err := io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			return "", err
		}
		value = strings.TrimRight(string(data), "\r\n")
	} else {
		fmt.Fprintf(os.Stderr, "%s (input hidden): ", what)
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(raw))
	}
	if value == "" {
		return "", fmt.Errorf("empty %s", what)
	}
	return value, nil
}

func cmdSecret(p *output.Printer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ais secret set NAME [--stdin] | list | delete NAME | passphrase set [--stdin] | passphrase generate")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	st := secret.NewFileStore(cfg.SecretsDir())
	switch args[0] {
	case "set":
		fs := flag.NewFlagSet("secret set", flag.ContinueOnError)
		fromStdin := fs.Bool("stdin", false, "read the value from stdin (one line)")
		pos, err := parseInterspersed(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: ais secret set NAME [--stdin]")
		}
		name := pos[0]
		value, err := readValue("value for "+name, *fromStdin)
		if err != nil {
			return err
		}
		if name == cfg.Claude.OAuthTokenSecret {
			if n := secret.NormalizeToken(value); n != value {
				p.Info("removed whitespace/line breaks from the token")
				value = n
			}
		}
		created, err := st.EnsurePassphrase()
		if err != nil {
			return err
		}
		if created {
			p.Info("generated a random passphrase in %s (change it with 'ais secret passphrase set')", cfg.SecretsDir())
		}
		if err := st.Set(name, value); err != nil {
			return err
		}
		p.Good("stored", "%s (%d bytes, encrypted) in %s", name, len(value), cfg.SecretsDir())
		return nil
	case "list":
		names, err := st.List()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSTORED\tAGE\tENCRYPTED\tSTATUS")
		now := time.Now()
		for _, n := range names {
			at, err := st.StoredAt(n)
			if err != nil {
				fmt.Fprintf(tw, "%s\t?\t?\t?\t\n", n)
				continue
			}
			status := ""
			if n == cfg.Claude.OAuthTokenSecret {
				status, _, _ = secret.TokenStatus(at, now, cfg.Claude.TokenLifetime, cfg.Claude.TokenWarnBefore)
			}
			enc := "yes"
			if !st.Encrypted(n) {
				enc = "no (plaintext; re-run 'ais secret set')"
			}
			fmt.Fprintf(tw, "%s\t%s\t%dd\t%s\t%s\n", n, at.Format("2006-01-02"), int(now.Sub(at).Hours()/24), enc, status)
		}
		if !st.HasPassphrase() {
			p.Warn("no passphrase file yet; the next 'ais secret set' generates one")
		}
		return tw.Flush()
	case "passphrase":
		if len(args) < 2 {
			return fmt.Errorf("usage: ais secret passphrase set [--stdin] | generate")
		}
		switch args[1] {
		case "generate":
			phrase, err := secret.NewPassphrase()
			if err != nil {
				return err
			}
			n, err := st.SetPassphrase(phrase)
			if err != nil {
				return err
			}
			p.Good("generated", "random passphrase in %s; %d secret(s) re-encrypted", cfg.SecretsDir(), n)
			return nil
		case "set":
			fs := flag.NewFlagSet("secret passphrase set", flag.ContinueOnError)
			fromStdin := fs.Bool("stdin", false, "read the passphrase from stdin (one line)")
			if err := fs.Parse(args[2:]); err != nil {
				return err
			}
			phrase, err := readValue("passphrase", *fromStdin)
			if err != nil {
				return err
			}
			n, err := st.SetPassphrase(phrase)
			if err != nil {
				return err
			}
			p.Good("set", "passphrase in %s; %d secret(s) re-encrypted", cfg.SecretsDir(), n)
			return nil
		}
		return fmt.Errorf("unknown passphrase subcommand %q", args[1])
	case "delete":
		if len(args) != 2 {
			return fmt.Errorf("usage: ais secret delete NAME")
		}
		if err := st.Delete(args[1]); err != nil {
			return err
		}
		p.Good("deleted", "%s", args[1])
		return nil
	}
	return fmt.Errorf("unknown secret subcommand %q", args[0])
}

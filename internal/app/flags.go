package app

import (
	"flag"
	"strings"
)

// parseInterspersed parses flags that may appear before or after positional
// arguments ("ais runs show ID --clear" and "ais runs show --clear ID" both
// work). Returns the positional arguments in order.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if strings.HasPrefix(rest[0], "-") && rest[0] != "-" {
			// fs.Parse stopped at "--": everything after is positional.
			return append(positional, rest[1:]...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

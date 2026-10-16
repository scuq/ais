// Command ais is the AI scheduler: it runs Claude Code headless on a
// schedule inside disposable, hardened containers and dispatches the
// structured results. The same program serves as the installer when it is
// named aisctl, so a release needs one download: `aisctl init` installs a
// copy of itself as ais.
package main

import (
	"os"
	"path/filepath"

	"github.com/scuq/ais/internal/aisctl"
	"github.com/scuq/ais/internal/app"
)

func main() {
	if filepath.Base(os.Args[0]) == "aisctl" {
		os.Exit(aisctl.Main(os.Args[1:]))
	}
	os.Exit(app.Main(os.Args[1:]))
}

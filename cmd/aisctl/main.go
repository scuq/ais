// Command aisctl installs and operates ais on a host. It is the same
// program as ais; this entry point only defaults to the installer when the
// binary is not named aisctl.
package main

import (
	"os"
	"path/filepath"

	"github.com/scuq/ais/internal/aisctl"
	"github.com/scuq/ais/internal/app"
)

func main() {
	if filepath.Base(os.Args[0]) == "ais" {
		os.Exit(app.Main(os.Args[1:]))
	}
	os.Exit(aisctl.Main(os.Args[1:]))
}

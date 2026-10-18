// Package assets embeds the container recipe and its supporting files into
// the ais binary, so `ais image build` needs nothing but the binary.
package assets

import "embed"

// FS holds every embedded asset.
//
//go:embed Containerfile entrypoint.sh squid.conf.tmpl allowlists examples systemd templates prefilter
var FS embed.FS

// Templates lists the embedded task templates by name.
func Templates() []string {
	entries, err := FS.ReadDir("templates")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// Read returns one embedded file's contents; unknown names are a programmer
// error, so it panics rather than returning an error nobody checks.
func Read(name string) []byte {
	data, err := FS.ReadFile(name)
	if err != nil {
		panic("ais: missing embedded asset " + name + ": " + err.Error())
	}
	return data
}

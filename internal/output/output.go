// Package output is the one place user-facing text is written. Status and
// diagnostics go to stderr so stdout stays clean for the actual product of a
// command: machine-readable output, printed files, dry-run argv lines.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// Printer writes human-readable status. Colours only when stderr is a
// terminal.
type Printer struct {
	W     io.Writer
	Color bool
}

// NewStderr returns the standard printer.
func NewStderr() *Printer {
	return &Printer{W: os.Stderr, Color: term.IsTerminal(int(os.Stderr.Fd()))}
}

const (
	cRed = "\033[31m"
	cYel = "\033[33m"
	cGrn = "\033[32m"
	cDim = "\033[2m"
	cOff = "\033[0m"
)

func (p *Printer) c(code string) string {
	if p.Color {
		return code
	}
	return ""
}

// Info prints a dim-prefixed status line.
func (p *Printer) Info(format string, args ...any) {
	fmt.Fprintf(p.W, "%sais:%s %s\n", p.c(cDim), p.c(cOff), fmt.Sprintf(format, args...))
}

// Warn prints a warning.
func (p *Printer) Warn(format string, args ...any) {
	fmt.Fprintf(p.W, "%sais: warning:%s %s\n", p.c(cYel), p.c(cOff), fmt.Sprintf(format, args...))
}

// Error prints an error message (without exiting; exit policy belongs to main).
func (p *Printer) Error(format string, args ...any) {
	fmt.Fprintf(p.W, "%sais: error:%s %s\n", p.c(cRed), p.c(cOff), fmt.Sprintf(format, args...))
}

// Good prints a success line with a green verb, e.g. Good("built", "%s", img).
func (p *Printer) Good(verb, format string, args ...any) {
	fmt.Fprintf(p.W, "%sais:%s %s%s%s %s\n", p.c(cDim), p.c(cOff),
		p.c(cGrn), verb, p.c(cOff), fmt.Sprintf(format, args...))
}

// JSON writes v as indented JSON to stdout. Every inspection command supports
// --json, and this is how.
func JSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

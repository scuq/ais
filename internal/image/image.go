// Package image owns the run image: the embedded recipe, the build
// invocation, the recipe-hash staleness check and the flag-drift check that
// keeps a new Claude Code version from silently changing the contract.
package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scuq/ais/assets"
	"github.com/scuq/ais/internal/claude"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/container"
	"github.com/scuq/ais/internal/runtime"
)

// RecipeHash is sha256 over everything that determines the image contents,
// cut to 16 hex chars. Stamped as io.ais.recipe at build time and checked
// at run time: "the binary changed, your local image did not" is answered
// here.
func RecipeHash(cfg *config.Config) string {
	h := sha256.New()
	for _, name := range []string{"Containerfile", "entrypoint.sh"} {
		h.Write(assets.Read(name))
	}
	fmt.Fprintf(h, "claude=%s\n", cfg.Image.ClaudeVersion)
	for _, f := range caCertFiles(config.ExpandPath(cfg.Image.CACertificates)) {
		if data, err := os.ReadFile(f); err == nil {
			fmt.Fprintf(h, "ca=%s\n", filepath.Base(f))
			h.Write(data)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func caCertFiles(path string) []string {
	if path == "" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !st.IsDir() {
		return []string{path}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".crt", ".pem":
			out = append(out, filepath.Join(path, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// WriteContext writes the embedded recipe into dir, ready for a build.
func WriteContext(dir string, caCertsPath string) error {
	files := map[string]os.FileMode{"Containerfile": 0o644, "entrypoint.sh": 0o755}
	for name, mode := range files {
		if err := os.WriteFile(filepath.Join(dir, name), assets.Read(name), mode); err != nil {
			return fmt.Errorf("cannot write build context: %w", err)
		}
	}
	certDir := filepath.Join(dir, "ca-certificates")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return fmt.Errorf("cannot write build context: %w", err)
	}
	if caCertsPath == "" {
		return nil
	}
	if _, err := os.Stat(caCertsPath); err != nil {
		return fmt.Errorf("image.caCertificates: %w", err)
	}
	certs := caCertFiles(caCertsPath)
	if len(certs) == 0 {
		return fmt.Errorf("image.caCertificates: no *.crt or *.pem files at %s", caCertsPath)
	}
	for _, src := range certs {
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("image.caCertificates: %w", err)
		}
		name := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src)) + ".crt"
		if err := os.WriteFile(filepath.Join(certDir, name), data, 0o644); err != nil {
			return fmt.Errorf("cannot write build context: %w", err)
		}
	}
	return nil
}

// BuildArgs returns the engine argv (starting at "build").
func BuildArgs(cfg *config.Config, ctxDir string, noCache bool, version string) []string {
	args := []string{
		"build",
		"--tag", cfg.Runtime.Image,
		"--build-arg", "CLAUDE_VERSION=" + cfg.Image.ClaudeVersion,
		"--label", container.LabelManaged + "=true",
		"--label", container.LabelSchema + "=" + container.SchemaVersion,
		"--label", container.LabelRecipe + "=" + RecipeHash(cfg),
		"--label", "io.ais.version=" + version,
		"--file", filepath.Join(ctxDir, "Containerfile"),
	}
	if noCache {
		args = append(args, "--no-cache")
	}
	return append(args, ctxDir)
}

// IsCurrent reports whether the image exists and its recipe label matches
// this binary's recipe.
func IsCurrent(ctx context.Context, rt runtime.Runtime, cfg *config.Config) (exists, current bool, err error) {
	ref := cfg.Runtime.Image
	exists, err = rt.ImageExists(ctx, ref)
	if err != nil || !exists {
		return exists, false, err
	}
	label, err := rt.ImageLabel(ctx, ref, container.LabelRecipe)
	if err != nil {
		return true, false, nil
	}
	return true, label == RecipeHash(cfg), nil
}

// Build writes the context, runs the build and checks the result.
func Build(ctx context.Context, rt runtime.Runtime, cfg *config.Config, noCache bool, version string) error {
	dir, err := os.MkdirTemp("", "ais-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := WriteContext(dir, config.ExpandPath(cfg.Image.CACertificates)); err != nil {
		return err
	}
	if err := rt.ImageBuild(ctx, BuildArgs(cfg, dir, noCache, version)); err != nil {
		return fmt.Errorf("image build failed: %w", err)
	}
	return CheckFlags(ctx, rt, cfg.Runtime.Image)
}

// CheckFlags runs `claude --help` in the freshly built image and fails if
// any flag ais relies on is missing. Flag drift is the main maintenance
// risk of a pinned CLI; this makes it a build error, not a 3 a.m. failure.
func CheckFlags(ctx context.Context, rt runtime.Runtime, ref string) error {
	var out, errb bytes.Buffer
	argv := []string{"run", "--rm", "--entrypoint", "claude", "--env", "DISABLE_UPDATES=1", ref, "--help"}
	code, err := rt.RunCapture(ctx, argv, nil, &out, &errb)
	if err != nil {
		return fmt.Errorf("claude --help: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("claude --help exited %d: %s", code, strings.TrimSpace(errb.String()))
	}
	return MissingFlags(out.String())
}

// MissingFlags compares help text against claude.VisibleFlags.
func MissingFlags(help string) error {
	var missing []string
	for _, f := range claude.VisibleFlags {
		if !strings.Contains(help, f) {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the image's claude does not advertise: %s (pin a different image.claudeVersion)", strings.Join(missing, ", "))
	}
	return nil
}

// Version runs `claude --version` in the image.
func Version(ctx context.Context, rt runtime.Runtime, ref string) (string, error) {
	var out, errb bytes.Buffer
	code, err := rt.RunCapture(ctx, []string{"run", "--rm", "--entrypoint", "claude", "--env", "DISABLE_UPDATES=1", ref, "--version"}, nil, &out, &errb)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("claude --version exited %d: %s", code, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

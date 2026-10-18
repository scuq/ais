package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/scuq/ais/assets"
	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/container"
	"github.com/scuq/ais/internal/runtime"
)

// prefilterFiles are the embedded files of the prefilter recipe.
var prefilterFiles = []string{"Containerfile", "prefilter.py", "export.py", "selftest.json"}

// PrefilterBuild says what to build.
type PrefilterBuild struct {
	// Ref is the image tag.
	Ref string
	// ModelDir is a directory with a model exported elsewhere (model.json,
	// the .onnx file and the tokenizer); empty exports in the build.
	ModelDir string
	// NoCache builds without the layer cache.
	NoCache bool
	// Version is the ais version, stamped as the label io.ais.version.
	Version string
}

// PrefilterRecipeHash covers everything that determines the prefilter
// image: the recipe files and the model settings. The image carries it in
// the label io.ais.recipe.
func PrefilterRecipeHash(cfg *config.Config) string {
	h := sha256.New()
	for _, name := range prefilterFiles {
		h.Write(assets.Read("prefilter/" + name))
	}
	p := cfg.Image.Prefilter
	fmt.Fprintf(h, "model=%s\nrevision=%s\nquantize=%s\n", p.Model, p.Revision, p.Quantize)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// WritePrefilterContext writes the recipe into dir. modelDir, when set, is
// copied to dir/model so the build can take it instead of exporting.
func WritePrefilterContext(dir, modelDir string) error {
	for _, name := range prefilterFiles {
		if err := os.WriteFile(filepath.Join(dir, name), assets.Read("prefilter/"+name), 0o644); err != nil {
			return fmt.Errorf("cannot write build context: %w", err)
		}
	}
	dst := filepath.Join(dir, "model")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("cannot write build context: %w", err)
	}
	if modelDir == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(modelDir, "model.json")); err != nil {
		return fmt.Errorf("--model-dir: %s has no model.json (export it with assets/prefilter/export.py first): %w", modelDir, err)
	}
	entries, err := os.ReadDir(modelDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(modelDir, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			return fmt.Errorf("cannot write build context: %w", err)
		}
	}
	return nil
}

// PrefilterBuildArgs returns the engine argv (starting at "build").
func PrefilterBuildArgs(cfg *config.Config, b PrefilterBuild, ctxDir string) []string {
	p := cfg.Image.Prefilter
	source := "hf"
	if b.ModelDir != "" {
		source = "dir"
	}
	args := []string{
		"build",
		"--tag", b.Ref,
		"--build-arg", "SOURCE=" + source,
		"--build-arg", "MODEL=" + p.Model,
		"--build-arg", "MODEL_REVISION=" + p.Revision,
		"--build-arg", "QUANTIZE=" + p.Quantize,
		"--label", container.LabelManaged + "=true",
		"--label", container.LabelSchema + "=" + container.SchemaVersion,
		"--label", container.LabelRecipe + "=" + PrefilterRecipeHash(cfg),
		"--label", "io.ais.version=" + b.Version,
		"--label", "io.ais.model=" + p.Model,
		"--file", filepath.Join(ctxDir, "Containerfile"),
	}
	if b.NoCache {
		args = append(args, "--no-cache")
	}
	return append(args, ctxDir)
}

// PrefilterIsCurrent reports whether the image exists and carries this
// binary's recipe hash.
func PrefilterIsCurrent(ctx context.Context, rt runtime.Runtime, cfg *config.Config, ref string) (exists, current bool, err error) {
	exists, err = rt.ImageExists(ctx, ref)
	if err != nil || !exists {
		return exists, false, err
	}
	label, err := rt.ImageLabel(ctx, ref, container.LabelRecipe)
	if err != nil {
		return true, false, nil
	}
	return true, label == PrefilterRecipeHash(cfg), nil
}

// BuildPrefilter writes the context and runs the build. The recipe's own
// self-test runs inside the build, so a finished build is a working image.
func BuildPrefilter(ctx context.Context, rt runtime.Runtime, cfg *config.Config, b PrefilterBuild) error {
	dir, err := os.MkdirTemp("", "ais-prefilter-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := WritePrefilterContext(dir, b.ModelDir); err != nil {
		return err
	}
	if err := rt.ImageBuild(ctx, PrefilterBuildArgs(cfg, b, dir)); err != nil {
		return fmt.Errorf("prefilter image build failed: %w", err)
	}
	return nil
}

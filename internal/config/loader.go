package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// UserConfigPath is the per-user config file.
func UserConfigPath() string {
	if p := os.Getenv("AIS_CONFIG"); p != "" {
		return p
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "ais", "config.yaml")
}

// Load resolves the configuration:
//
//	compiled defaults → ~/.config/ais/config.yaml (or $AIS_CONFIG) → AIS_* env
//
// Missing files are fine; unparsable or unknown-key files are not. A typo'd
// key silently ignored is a policy the user believes is active and is not.
func Load() (Config, error) {
	cfg := Defaults()
	if p := UserConfigPath(); p != "" {
		if err := MergeFile(&cfg, p); err != nil {
			return cfg, err
		}
	}
	applyEnv(&cfg)
	if cfg.Version == 0 {
		cfg.Version = Version
	}
	return cfg, nil
}

// MergeFile decodes one YAML file over cfg. Decoding over the existing struct
// gives merge semantics: only keys present in the document are set.
func MergeFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	return MergeYAML(cfg, data, path)
}

// MergeYAML decodes YAML bytes over cfg; name is used in error messages.
func MergeYAML(cfg *Config, data []byte, name string) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && err != io.EOF {
		return fmt.Errorf("cannot parse %s: %w", name, err)
	}
	return nil
}

// applyEnv reads only AIS_-prefixed variables; plain names like IMAGE are
// ordinary words other tools export for their own purposes.
func applyEnv(cfg *Config) {
	str := func(name string, dst *string) {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			*dst = v
		}
	}
	boolish := func(name string, dst *bool) {
		if v, ok := os.LookupEnv(name); ok {
			*dst = v == "1" || v == "true"
		}
	}
	str("AIS_ENGINE", &cfg.Runtime.Engine)
	str("AIS_IMAGE", &cfg.Runtime.Image)
	str("AIS_STATE_DIR", &cfg.Paths.StateDir)
	str("AIS_TASKS_DIR", &cfg.Paths.TasksDir)
	str("AIS_EGRESS", &cfg.Egress.Mode)
	str("AIS_EGRESS_SUBNET", &cfg.Egress.Subnet)
	str("AIS_SECRETS_DIR", &cfg.Secrets.Dir)
	str("AIS_CA_CERTS", &cfg.Image.CACertificates)
	boolish("AIS_AUTOBUILD", &cfg.Image.Autobuild)
}

// Render returns the resolved configuration as YAML, for `ais config show`.
func Render(cfg Config) (string, error) {
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

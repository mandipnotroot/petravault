// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package config loads the human-edited global CLI configuration
// (DESIGN.md §7). YAML is used only here; everything Petravault writes
// is JSON. Loading fails closed on unknown keys, and secrets never belong
// in the config file: passwords, private keys, and cloud credentials come
// from the keystore, PETRAVAULT_PASSWORD_* helpers, and standard credential
// providers.
package config

import (
	"cmp"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Supported log levels.
var logLevels = []string{"debug", "info", "warn", "error"}

// Supported ECC settings: off, a named profile, or a custom percentage.
var eccProfiles = []string{"off", "low", "medium", "high"}

// Defaults applied when neither flags, environment, nor file sets a value.
const (
	DefaultLogLevel    = "info"
	DefaultConcurrency = 4
	DefaultECC         = "medium"
)

// S3 holds non-secret S3 client settings. Credentials are never stored here;
// they come from standard AWS credential providers (DESIGN.md §7, §8).
type S3 struct {
	Profile string `yaml:"profile"`
	Region  string `yaml:"region"`
}

// Config is the global CLI configuration (DESIGN.md §7).
type Config struct {
	DefaultRepository string `yaml:"default_repository"`
	LogLevel          string `yaml:"log_level"`
	Concurrency       int    `yaml:"concurrency"`
	DefaultIdentity   string `yaml:"default_identity"`
	ECC               string `yaml:"ecc"`
	S3                S3     `yaml:"s3"`
	// VerifyAfterBackup is a pointer so an explicit false is not
	// mistaken for "unset" when applying precedence.
	VerifyAfterBackup *bool `yaml:"verify_after_backup"`
}

// fileConfig mirrors Config for strict decoding. It is a separate type so
// future file-only or runtime-only fields cannot drift silently.
type fileConfig Config

// Options supplies flag values, environment lookup, file location, and the
// logger used for non-fatal warnings (for example loose file permissions).
type Options struct {
	// ConfigPath overrides the file location (PETRAVAULT_CONFIG / --config).
	// Empty means the default XDG location.
	ConfigPath string
	// Flag overrides from the CLI. Zero values mean "unset".
	FlagRepository  string
	FlagLogLevel    string
	FlagIdentity    string
	FlagConcurrency int
	// LookupEnv defaults to os.LookupEnv when nil.
	LookupEnv func(string) (string, bool)
	Logger    *slog.Logger
}

// Load reads the config file (if present), then applies the precedence
// flags > PETRAVAULT_* environment > file > built-in defaults.
func Load(o Options) (Config, error) {
	lookup := o.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	logger := o.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	path := cmp.Or(o.ConfigPath, envOr(lookup, "PETRAVAULT_CONFIG", ""), DefaultPath())

	var file fileConfig
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			if !os.IsNotExist(err) || o.ConfigPath != "" {
				return Config{}, fmt.Errorf("open config %s: %w", path, err)
			}
			// Default location with no file yet: fall through to defaults.
		} else {
			defer f.Close()
			if err := decodeStrict(f, &file); err != nil {
				return Config{}, err
			}
			checkPermissions(logger, path)
		}
	}

	cfg := Config{
		DefaultRepository: cmp.Or(o.FlagRepository, envOr(lookup, "PETRAVAULT_REPOSITORY", ""), file.DefaultRepository),
		LogLevel:          cmp.Or(o.FlagLogLevel, envOr(lookup, "PETRAVAULT_LOG_LEVEL", ""), file.LogLevel, DefaultLogLevel),
		DefaultIdentity:   cmp.Or(o.FlagIdentity, envOr(lookup, "PETRAVAULT_IDENTITY", ""), file.DefaultIdentity),
		ECC:               cmp.Or(envOr(lookup, "PETRAVAULT_ECC", ""), file.ECC, DefaultECC),
		S3: S3{
			Profile: cmp.Or(envOr(lookup, "PETRAVAULT_S3_PROFILE", ""), file.S3.Profile),
			Region:  cmp.Or(envOr(lookup, "PETRAVAULT_S3_REGION", ""), file.S3.Region),
		},
	}
	envConcurrency, err := envInt(lookup, "PETRAVAULT_CONCURRENCY")
	if err != nil {
		return Config{}, err
	}
	cfg.Concurrency = cmp.Or(o.FlagConcurrency, envConcurrency, file.Concurrency, DefaultConcurrency)
	envVerify, err := envBool(lookup, "PETRAVAULT_VERIFY_AFTER_BACKUP")
	if err != nil {
		return Config{}, err
	}
	cfg.VerifyAfterBackup = orBool(envVerify, file.VerifyAfterBackup, new(true))

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate rejects values that fail closed: unknown log levels, unknown ECC
// settings, and non-positive concurrency (DESIGN.md §7).
func (c Config) Validate() error {
	if !slices.Contains(logLevels, strings.ToLower(c.LogLevel)) {
		return fmt.Errorf("invalid log_level %q: want one of %s", c.LogLevel, strings.Join(logLevels, ", "))
	}
	if c.Concurrency <= 0 {
		return fmt.Errorf("invalid concurrency %d: want a positive number", c.Concurrency)
	}
	if !validECC(c.ECC) {
		return fmt.Errorf("invalid ecc %q: want off, low, medium, high, or <N>%%", c.ECC)
	}
	return nil
}

// ResolveRepository picks the repository for every command except init:
// --repository, then PETRAVAULT_REPOSITORY, then default_repository.
func (c Config) ResolveRepository(flag string) string {
	return cmp.Or(flag, c.DefaultRepository)
}

// DefaultPath returns the default config.yaml location.
func DefaultPath() string {
	return filepath.Join(Dir(), "petravault", "config.yaml")
}

// Dir returns the OS config directory (XDG with platform equivalents
// via os.UserConfigDir).
func Dir() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return dir
	}
	return filepath.Join(homeDir(), ".config")
}

// DataDir follows XDG with platform equivalents.
func DataDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return xdg
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		if dir, err := os.UserConfigDir(); err == nil && dir != "" {
			return dir
		}
	}
	return filepath.Join(homeDir(), ".local", "share")
}

// StateDir follows XDG with platform equivalents.
func StateDir() string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return xdg
	}
	return filepath.Join(homeDir(), ".local", "state")
}

// CacheDir follows XDG with platform equivalents.
func CacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return dir
	}
	return filepath.Join(homeDir(), ".cache")
}

func decodeStrict(r io.Reader, v *fileConfig) error {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	return nil
}

// checkPermissions warns on group/world-readable config files. Secrets do
// not belong here, but a warning is cheap defense in depth (DESIGN.md §7).
func checkPermissions(logger *slog.Logger, path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	if fi.Mode().Perm()&0o077 != 0 {
		logger.Warn("config file is readable by group or others", slog.String("path", path))
	}
}

func validECC(s string) bool {
	if slices.Contains(eccProfiles, strings.ToLower(s)) {
		return true
	}
	v, ok := strings.CutSuffix(s, "%")
	if !ok || v == "" {
		return false
	}
	dots := 0
	for i := range len(v) {
		switch {
		case v[i] >= '0' && v[i] <= '9':
		case v[i] == '.' && dots == 0:
			dots++
		default:
			return false
		}
	}
	return true
}

func envOr(lookup func(string) (string, bool), key, fallback string) string {
	return cmp.Or(lookupValue(lookup, key), fallback)
}

func lookupValue(lookup func(string) (string, bool), key string) string {
	if v, ok := lookup(key); ok {
		return v
	}
	return ""
}

func envInt(lookup func(string) (string, bool), key string) (int, error) {
	v, ok := lookup(key)
	if !ok || v == "" {
		return 0, nil
	}
	n := 0
	for i := range len(v) {
		if v[i] < '0' || v[i] > '9' {
			return 0, fmt.Errorf("invalid %s %q: want a positive number", key, v)
		}
		n = n*10 + int(v[i]-'0')
	}
	return n, nil
}

func envBool(lookup func(string) (string, bool), key string) (*bool, error) {
	v, ok := lookup(key)
	if !ok || v == "" {
		return nil, nil
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes":
		return new(true), nil
	case "0", "false", "no":
		return new(false), nil
	default:
		return nil, fmt.Errorf("invalid %s %q: want one of 1, true, yes, 0, false, no", key, v)
	}
}

func orBool(vals ...*bool) *bool {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return "."
}

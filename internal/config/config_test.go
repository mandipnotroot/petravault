// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"petravault/internal/config"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func envOf(vars map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := vars[key]
		return v, ok
	}
}

func TestLoadDefaultsWhenNoFile(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(config.Options{
		ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"),
		LookupEnv:  envOf(nil),
	})
	// An explicit path that does not exist is an error (fail closed).
	if err == nil {
		t.Fatalf("Load = %+v, want error for missing explicit file", cfg)
	}
}

func TestLoadMissingDefaultLocationFallsBackToDefaults(t *testing.T) {
	// Serial: t.Setenv cannot be used in parallel tests.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg, err := config.Load(config.Options{LookupEnv: envOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != config.DefaultLogLevel {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, config.DefaultLogLevel)
	}
	if cfg.Concurrency != config.DefaultConcurrency {
		t.Fatalf("Concurrency = %d, want %d", cfg.Concurrency, config.DefaultConcurrency)
	}
	if cfg.ECC != config.DefaultECC {
		t.Fatalf("ECC = %q, want %q", cfg.ECC, config.DefaultECC)
	}
	if cfg.VerifyAfterBackup == nil || !*cfg.VerifyAfterBackup {
		t.Fatalf("VerifyAfterBackup = %v, want non-nil true", cfg.VerifyAfterBackup)
	}
}

func TestPrecedenceFlagOverEnvOverFile(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "default_repository: file-repo\nlog_level: warn\nconcurrency: 2\n")
	cfg, err := config.Load(config.Options{
		ConfigPath:     path,
		FlagRepository: "flag-repo",
		LookupEnv: envOf(map[string]string{
			"PETRAVAULT_LOG_LEVEL": "error",
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultRepository != "flag-repo" {
		t.Fatalf("DefaultRepository = %q, want flag-repo", cfg.DefaultRepository)
	}
	if cfg.LogLevel != "error" {
		t.Fatalf("LogLevel = %q, want error (env beats file)", cfg.LogLevel)
	}
	if cfg.Concurrency != 2 {
		t.Fatalf("Concurrency = %d, want 2 (file beats default)", cfg.Concurrency)
	}
}

func TestRejectUnknownKeys(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "log_level: info\npassword: hunter2\n")
	if _, err := config.Load(config.Options{ConfigPath: path, LookupEnv: envOf(nil)}); err == nil {
		t.Fatal("Load accepted unknown key, want error")
	}
}

func TestRejectBadValues(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		"log_level: verbose\n",
		"concurrency: -2\n",
		"ecc: ultra\n",
		"ecc: \"%\"\n",
	} {
		path := writeConfig(t, body)
		if _, err := config.Load(config.Options{ConfigPath: path, LookupEnv: envOf(nil)}); err == nil {
			t.Fatalf("Load accepted %q, want error", body)
		}
	}
}

func TestZeroConcurrencyFallsBackToDefault(t *testing.T) {
	t.Parallel()

	// Zero is not a usable concurrency, so it means "unset" and the
	// default applies (cmp.Or precedence); negatives fail validation.
	path := writeConfig(t, "concurrency: 0\n")
	cfg, err := config.Load(config.Options{ConfigPath: path, LookupEnv: envOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Concurrency != config.DefaultConcurrency {
		t.Fatalf("Concurrency = %d, want default %d", cfg.Concurrency, config.DefaultConcurrency)
	}
}

func TestCustomECCPercentAccepted(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "ecc: 8%\n")
	cfg, err := config.Load(config.Options{ConfigPath: path, LookupEnv: envOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ECC != "8%" {
		t.Fatalf("ECC = %q, want 8%%", cfg.ECC)
	}
}

func TestResolveRepository(t *testing.T) {
	// Serial: t.Setenv cannot be used in parallel tests.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg, err := config.Load(config.Options{LookupEnv: envOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResolveRepository("flag"); got != "flag" {
		t.Fatalf("ResolveRepository = %q, want flag", got)
	}
}

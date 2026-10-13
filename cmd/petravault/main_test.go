// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolatedEnv(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("PETRAVAULT_CONFIG", "")
	t.Setenv("PETRAVAULT_REPOSITORY", "")
}

func TestVersion(t *testing.T) {
	// Serial: isolatedEnv uses t.Setenv, which parallel tests forbid.
	isolatedEnv(t)

	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "petravault ") {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestInitAndInfo(t *testing.T) {
	// Serial: isolatedEnv uses t.Setenv, which parallel tests forbid.
	isolatedEnv(t)

	root := filepath.Join(t.TempDir(), "repo")
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"init", root}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(root, "packs")); err != nil || !fi.IsDir() {
		t.Fatalf("init did not create layout: %v", err)
	}

	stdout.Reset()
	if err := run(context.Background(), []string{"--repository", root, "info"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), root) {
		t.Fatalf("info output = %q, want repository path", stdout.String())
	}
}

func TestInfoWithoutRepositoryIsUsageError(t *testing.T) {
	// Serial: isolatedEnv uses t.Setenv, which parallel tests forbid.
	isolatedEnv(t)

	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"info"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("info without repository succeeded, want usage error")
	}
}

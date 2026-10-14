// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package nofollow_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"petravault/internal/nofollow"
)

func TestOpenRegularFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := nofollow.Open(path)
	if err != nil {
		t.Fatalf("Open refused a regular file: %v", err)
	}
	defer f.Close()
	if _, err := f.Stat(); err != nil {
		t.Fatalf("fstat failed: %v", err)
	}
}

func TestOpenRefusesTrailingSymlink(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW has no Windows equivalent by documentation")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := nofollow.Open(link); err == nil {
		t.Fatal("Open followed a trailing symlink, want refusal")
	}
}

func TestOpenMissingFails(t *testing.T) {
	t.Parallel()

	if _, err := nofollow.Open(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("Open accepted a missing file, want failure")
	}
}

func TestReadFileCapsSize(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "big")
	big := make([]byte, 64)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := nofollow.ReadFile(path, 8)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(raw) != 9 {
		t.Fatalf("ReadFile returned %d bytes, want 9 (cap+1)", len(raw))
	}
	if _, err := nofollow.ReadFile(path, 0); err == nil {
		t.Fatal("ReadFile accepted a non-positive cap, want failure")
	}
}

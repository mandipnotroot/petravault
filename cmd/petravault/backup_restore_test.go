// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSrcFile(t *testing.T, dir, name, data string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func snapshotFromBackup(t *testing.T, output string) string {
	t.Helper()
	for line := range strings.Lines(output) {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "snapshot "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no snapshot in output %q", output)
	return ""
}

func TestBackupVerifyRestoreRoundTrip(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)

	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")

	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "hello.txt", "hello backup")
	writeSrcFile(t, src, "sub/nested.txt", "nested")
	writeSrcFile(t, src, "empty.txt", "")
	if err := os.MkdirAll(filepath.Join(src, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("hello.txt", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	out, _ = runCmd(t, "--repository", repo, "backup", src, "--source-id", "laptop", "--ecc", "off")
	snap := snapshotFromBackup(t, out)
	if len(snap) != 64 {
		t.Fatalf("snapshot id = %q, want 64 hex chars", snap)
	}

	out, _ = runCmd(t, "--repository", repo, "snapshots", "list")
	if !strings.Contains(out, snap) || !strings.Contains(out, "laptop") {
		t.Fatalf("snapshots list = %q, want snapshot and source", out)
	}
	out, _ = runCmd(t, "--repository", repo, "snapshots", "show", snap)
	if !strings.Contains(out, "hello.txt") {
		t.Fatalf("snapshots show = %q, want files", out)
	}

	out, _ = runCmd(t, "--repository", repo, "verify")
	if !strings.Contains(out, "verify: ok") {
		t.Fatalf("verify output = %q, want ok", out)
	}
	out, _ = runCmd(t, "--repository", repo, "verify", "--deep")
	if !strings.Contains(out, "deep verify: ok") {
		t.Fatalf("deep verify output = %q, want ok", out)
	}
	out, _ = runCmd(t, "--repository", repo, "verify", snap)
	if !strings.Contains(out, "verify: ok") {
		t.Fatalf("single verify output = %q, want ok", out)
	}

	dest := filepath.Join(t.TempDir(), "restore")
	runCmd(t, "--repository", repo, "restore", snap, dest)
	got, err := os.ReadFile(filepath.Join(dest, "hello.txt"))
	if err != nil || string(got) != "hello backup" {
		t.Fatalf("restored hello.txt = %q, err %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(dest, "sub", "nested.txt"))
	if err != nil || string(got) != "nested" {
		t.Fatalf("restored nested.txt = %q, err %v", got, err)
	}
	if target, err := os.Readlink(filepath.Join(dest, "link")); err != nil || target != "hello.txt" {
		t.Fatalf("restored link = %q, err %v", target, err)
	}

	// Incremental second backup reuses unchanged files.
	writeSrcFile(t, src, "new.txt", "brand new")
	out, _ = runCmd(t, "--repository", repo, "backup", src, "--source-id", "laptop", "--ecc", "off")
	if !strings.Contains(out, "reused:") {
		t.Fatalf("second backup output = %q, want reuse summary", out)
	}
	out, _ = runCmd(t, "--repository", repo, "verify")
	if !strings.Contains(out, "verify: ok") {
		t.Fatalf("verify after second backup = %q", out)
	}
}

func TestBackupVerifyAfterBackupFlags(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "data")

	out, _ = runCmd(t, "--repository", repo, "backup", src, "--source-id", "s1", "--ecc", "off", "--verify")
	if !strings.Contains(out, "verify: ok") {
		t.Fatalf("backup --verify output = %q, want verify ok", out)
	}
	out, _ = runCmd(t, "--repository", repo, "backup", src, "--source-id", "s1", "--ecc", "off", "--no-verify")
	if strings.Contains(out, "verify: ok") {
		t.Fatalf("backup --no-verify output = %q, want no verification", out)
	}
	if err := runCmdErr(t, "--repository", repo, "backup", src, "--verify", "--no-verify"); err == nil {
		t.Fatal("backup with both --verify and --no-verify succeeded")
	}
}

func TestRestoreIncludeAndOverwrite(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "keep.txt", "keep")
	writeSrcFile(t, src, "skip.txt", "skip")
	out, _ = runCmd(t, "--repository", repo, "backup", src, "--source-id", "s", "--ecc", "off", "--no-verify")
	snap := snapshotFromBackup(t, out)

	dest := filepath.Join(t.TempDir(), "partial")
	runCmd(t, "--repository", repo, "restore", snap, dest, "--include", "keep.txt")
	if _, err := os.Stat(filepath.Join(dest, "keep.txt")); err != nil {
		t.Fatalf("included file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "skip.txt")); err == nil {
		t.Fatal("excluded file was restored")
	}

	// Existing files are kept without --overwrite.
	writeSrcFile(t, dest, "keep.txt", "existing")
	if err := runCmdErr(t, "--repository", repo, "restore", snap, dest, "--include", "keep.txt"); err == nil {
		t.Fatal("restore overwrote without --overwrite")
	}
	runCmd(t, "--repository", repo, "restore", snap, dest, "--include", "keep.txt", "--overwrite")
	got, err := os.ReadFile(filepath.Join(dest, "keep.txt"))
	if err != nil || string(got) != "keep" {
		t.Fatalf("overwrite restore = %q, err %v", got, err)
	}
}

func TestVerifyDetectsTamperCLI(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", strings.Repeat("x", 5000))
	runCmd(t, "--repository", repo, "backup", src, "--source-id", "s", "--ecc", "off", "--no-verify")

	entries, err := os.ReadDir(filepath.Join(repo, "packs"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no packs to tamper: %v", err)
	}
	packPath := filepath.Join(repo, "packs", entries[0].Name())
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := os.WriteFile(packPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCmdErr(t, "--repository", repo, "verify", "--deep"); err == nil {
		t.Fatal("deep verify accepted a tampered pack")
	}
}

func TestVerifyDetectsRollbackCLI(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "v1")
	runCmd(t, "--repository", repo, "backup", src, "--source-id", "s", "--ecc", "off", "--no-verify")
	writeSrcFile(t, src, "b.txt", "v2")
	out, _ = runCmd(t, "--repository", repo, "backup", src, "--source-id", "s", "--ecc", "off", "--no-verify")
	second := snapshotFromBackup(t, out)
	runCmd(t, "--repository", repo, "verify")
	// Delete the newest snapshot: the head record must catch it.
	if err := os.Remove(filepath.Join(repo, "snapshots", second)); err != nil {
		t.Fatal(err)
	}
	if err := runCmdErr(t, "--repository", repo, "verify"); err == nil {
		t.Fatal("verify accepted deletion of the newest snapshot")
	}
}

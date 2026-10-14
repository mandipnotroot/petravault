// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"petravault/internal/repository"
)

func TestPruneKeepsTipAndRefusesWithoutRule(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)

	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")

	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "v1")
	runCmd(t, "--repository", repo, "backup", src, "--source-id", "laptop", "--ecc", "off", "--no-verify")
	writeSrcFile(t, src, "a.txt", "v2")
	out, _ = runCmd(t, "--repository", repo, "backup", src, "--source-id", "laptop", "--ecc", "off", "--no-verify")
	tip := snapshotFromBackup(t, out)

	if err := runCmdErr(t, "--repository", repo, "prune"); err == nil {
		t.Fatal("prune without keep rule succeeded, want usage error")
	}

	out, _ = runCmd(t, "--repository", repo, "prune", "--keep-daily", "1", "--dry-run")
	if !strings.Contains(out, "dry run") {
		t.Fatalf("prune dry run output = %q, want dry run marker", out)
	}
	// Dry run deletes nothing: the tip still verifies.
	runCmd(t, "--repository", repo, "verify", tip)

	out, _ = runCmd(t, "--repository", repo, "prune", "--keep-daily", "30")
	if !strings.Contains(out, "prune: ok") {
		t.Fatalf("prune output = %q, want ok", out)
	}
	// The tip survives retention and still restores.
	dest := filepath.Join(t.TempDir(), "restore")
	runCmd(t, "--repository", repo, "restore", tip, dest)
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil || string(got) != "v2" {
		t.Fatalf("restored after prune = %q, err %v; want v2", got, err)
	}
	runCmd(t, "--repository", repo, "verify")
}

func TestPruneRefusesWhileGCLocked(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)

	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "x")
	runCmd(t, "--repository", repo, "backup", src, "--source-id", "s", "--ecc", "off", "--no-verify")

	// Hold the maintenance lock out of band: prune must refuse while it
	// is live and must not delete anything.
	local := repository.NewLocal(repo)
	acquired, err := repository.TryAcquireGCLock(context.Background(), local, repository.OperationECCRebuild, "other", repository.DefaultHost(), repository.DefaultLockTTL, time.Now)
	if err != nil || !acquired {
		t.Fatalf("hold gc lock = %v, %v", acquired, err)
	}
	if err := runCmdErr(t, "--repository", repo, "prune", "--keep-daily", "7"); err == nil {
		t.Fatal("prune succeeded while gc.lock held, want refusal")
	}
	if err := repository.ReleaseGCLock(context.Background(), local); err != nil {
		t.Fatal(err)
	}
	// Released: prune proceeds.
	runCmd(t, "--repository", repo, "prune", "--keep-daily", "7")
}

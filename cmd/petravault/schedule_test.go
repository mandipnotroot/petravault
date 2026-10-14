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

	"petravault/internal/config"
	"petravault/internal/prune"
	"petravault/internal/repository"
	"petravault/internal/scheduler"
)

func scheduleDirsForTest() (string, string) {
	return scheduler.ScheduleDir(config.Dir()), scheduler.StateDir(config.StateDir())
}

func forceJobDue(t *testing.T, name string) {
	t.Helper()
	_, stateDir := scheduleDirsForTest()
	path, err := scheduler.StatePath(stateDir, name)
	if err != nil {
		t.Fatal(err)
	}
	state, err := scheduler.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	state.NextRun = time.Now().Add(-time.Minute).UTC()
	if err := scheduler.SaveState(path, state); err != nil {
		t.Fatal(err)
	}
}

func TestScheduleAddListStatusRemove(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "data")

	out, _ = runCmd(t, "schedule", "add", "--name", "daily-docs",
		"--source", src, "--repository", repo,
		"--daily", "02:00", "--keep-daily", "7")
	if !strings.Contains(out, "daily-docs") || !strings.Contains(out, "next run") {
		t.Fatalf("schedule add output = %q", out)
	}

	out, _ = runCmd(t, "schedule", "list")
	if !strings.Contains(out, "daily-docs") || !strings.Contains(out, "daily 02:00") {
		t.Fatalf("schedule list = %q", out)
	}

	out, _ = runCmd(t, "schedule", "status")
	if !strings.Contains(out, "daily-docs") || !strings.Contains(out, "next_run:") {
		t.Fatalf("schedule status = %q", out)
	}

	runCmd(t, "schedule", "remove", "daily-docs")
	out, _ = runCmd(t, "schedule", "list")
	if strings.Contains(out, "daily-docs") {
		t.Fatalf("schedule list after remove = %q", out)
	}
}

func TestScheduleAddValidation(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "data")

	cases := [][]string{
		{"schedule", "add", "--source", src, "--repository", repo, "--daily", "02:00"},
		{"schedule", "add", "--name", "job", "--repository", repo, "--daily", "02:00"},
		{"schedule", "add", "--name", "job", "--source", src, "--repository", repo},
		{"schedule", "add", "--name", "job", "--source", src, "--repository", repo, "--daily", "02:00", "--hourly"},
		{"schedule", "add", "--name", "job", "--source", src, "--repository", repo, "--daily", "noon"},
		{"schedule", "add", "--name", "job", "--source", src, "--repository", repo, "--weekly", "02:00"},
		{"schedule", "add", "--name", "job", "--source", src, "--repository", repo, "--daily", "02:00", "--verify", "--no-verify"},
		{"schedule", "add", "--name", "job", "--source", src, "--repository", repo, "--daily", "02:00", "--keep-daily", "-1"},
		{"schedule", "add", "--name", "bad/name", "--source", src, "--repository", repo, "--daily", "02:00"},
		{"schedule", "add", "--name", "job", "--source", src, "--repository", repo, "--daily", "02:00", "--retry", "99"},
		{"schedule", "add", "--name", "job", "--source", src, "--repository", repo, "--daily", "02:00", "--ecc", "ultra"},
	}
	for _, args := range cases {
		if err := runCmdErr(t, args...); err == nil {
			t.Fatalf("schedule add %v succeeded, want error", args)
		}
	}
}

func TestScheduleEnableDisable(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "data")

	runCmd(t, "schedule", "add", "--name", "job", "--source", src, "--repository", repo, "--hourly")
	runCmd(t, "schedule", "disable", "job")
	out, _ = runCmd(t, "schedule", "list")
	if !strings.Contains(out, "disabled") {
		t.Fatalf("list after disable = %q", out)
	}
	// Disabled jobs never run on schedule run, even when due.
	forceJobDue(t, "job")
	out, _ = runCmd(t, "schedule", "run")
	if strings.Contains(out, "snapshot") {
		t.Fatalf("disabled job ran: %q", out)
	}
	runCmd(t, "schedule", "enable", "job")
	out, _ = runCmd(t, "schedule", "list")
	if !strings.Contains(out, "enabled") {
		t.Fatalf("list after enable = %q", out)
	}
}

func TestScheduleRunBacksUp(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "hello.txt", "hello schedule")

	runCmd(t, "schedule", "add", "--name", "hourly-docs",
		"--source", src, "--repository", repo, "--hourly", "--no-verify")
	forceJobDue(t, "hourly-docs")

	out, _ = runCmd(t, "schedule", "run")
	if !strings.Contains(out, "hourly-docs") || !strings.Contains(out, "snapshot") {
		t.Fatalf("schedule run output = %q", out)
	}
	snap := snapshotFromScheduleRun(t, out)

	out, _ = runCmd(t, "--repository", repo, "snapshots", "list")
	if !strings.Contains(out, snap) {
		t.Fatalf("snapshots list = %q, want %s", out, snap)
	}
	dest := filepath.Join(t.TempDir(), "restore")
	runCmd(t, "--repository", repo, "restore", snap, dest)
	got, err := os.ReadFile(filepath.Join(dest, "hello.txt"))
	if err != nil || string(got) != "hello schedule" {
		t.Fatalf("restored = %q, err %v", got, err)
	}

	// Nothing due anymore: second run reports no jobs due.
	out, _ = runCmd(t, "schedule", "run")
	if !strings.Contains(out, "no jobs due") {
		t.Fatalf("second run = %q, want no jobs due", out)
	}
}

func TestScheduleRunOneImmediately(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "data")

	// Daily jobs are rarely due at add time; run <name> overrides that.
	runCmd(t, "schedule", "add", "--name", "daily-docs",
		"--source", src, "--repository", repo, "--daily", "02:00", "--no-verify")
	out, _ = runCmd(t, "schedule", "run", "daily-docs")
	if !strings.Contains(out, "snapshot") {
		t.Fatalf("run one output = %q, want snapshot", out)
	}
}

func TestScheduleRunWithRetention(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "v1")

	runCmd(t, "schedule", "add", "--name", "job",
		"--source", src, "--repository", repo, "--hourly",
		"--keep-daily", "30", "--no-verify")
	forceJobDue(t, "job")
	runCmd(t, "schedule", "run")
	writeSrcFile(t, src, "a.txt", "v2")
	forceJobDue(t, "job")
	out, _ = runCmd(t, "schedule", "run")
	snap := snapshotFromScheduleRun(t, out)

	// The tip survives retention and still verifies.
	runCmd(t, "--repository", repo, "verify")
	dest := filepath.Join(t.TempDir(), "restore")
	runCmd(t, "--repository", repo, "restore", snap, dest)
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil || string(got) != "v2" {
		t.Fatalf("restored after scheduled retention = %q, err %v", got, err)
	}
}

func TestScheduleRunAbortsWhileLocked(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "data")

	runCmd(t, "schedule", "add", "--name", "job",
		"--source", src, "--repository", repo, "--hourly",
		"--keep-daily", "7", "--no-verify")
	forceJobDue(t, "job")

	// A gc.lock held through the backup forces the backup itself to back
	// off and abort (DESIGN.md §10.2); the job fails rather than backing
	// up under maintenance.
	local := repository.NewLocal(repo)
	acquired, err := repository.TryAcquireGCLock(context.Background(), local, repository.OperationECCRebuild, "other", repository.DefaultHost(), repository.DefaultLockTTL, time.Now)
	if err != nil || !acquired {
		t.Fatalf("hold gc lock = %v, %v", acquired, err)
	}
	defer func() {
		_ = repository.ReleaseGCLock(context.Background(), local)
	}()
	if err := runCmdErr(t, "schedule", "run"); err == nil {
		t.Fatal("scheduled run succeeded while gc.lock held, want abort")
	}
}

func TestPruneAfterJobSkipsWhenLocked(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repoPath := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repoPath, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "data")
	runCmd(t, "--repository", repoPath, "backup", src, "--source-id", "s", "--ecc", "off", "--no-verify")

	// With the backup already committed, a gc.lock held at prune time
	// skips pruning with a log rather than failing the job (DESIGN.md
	// §11.1). Call the helper directly to avoid racing the backup window.
	var f flags
	f.repository = repoPath
	cfg, logger, err := setup(&f, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	repo, repoCfg, trust, trusted, err := openVerifiedRepo(ctx, cfg, repoPath)
	if err != nil {
		t.Fatal(err)
	}
	master, priv, _, err := openMaster(ctx, &f, cfg, repo, trust, repoCfg.RepositoryID)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Zero()
	defer priv.Zero()
	local := repository.NewLocal(repoPath)
	acquired, err := repository.TryAcquireGCLock(ctx, local, repository.OperationECCRebuild, "other", repository.DefaultHost(), repository.DefaultLockTTL, time.Now)
	if err != nil || !acquired {
		t.Fatalf("hold gc lock = %v, %v", acquired, err)
	}
	defer func() {
		_ = repository.ReleaseGCLock(ctx, local)
	}()
	if err := pruneAfterJob(ctx, repo, repoCfg, trust, trusted, master, prune.Retention{Daily: 7}, logger); err != nil {
		t.Fatalf("pruneAfterJob under lock = %v, want skip (nil)", err)
	}
}

func TestScheduleRunFailsWithoutRepository(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	runCmd(t, "identity", "create", "--name", "alice")
	if err := runCmdErr(t, "schedule", "run", "missing-job"); err == nil {
		t.Fatal("run of a missing job succeeded")
	}
}

func TestScheduleJobPermissionsEnforced(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "data")

	runCmd(t, "schedule", "add", "--name", "job", "--source", src, "--repository", repo, "--hourly")
	scheduleDir, _ := scheduleDirsForTest()
	jobPath, err := scheduler.JobPath(scheduleDir, "job")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(jobPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runCmdErr(t, "schedule", "list"); err == nil {
		t.Fatal("listed a group/world-readable job file")
	}
	if err := runCmdErr(t, "schedule", "run", "job"); err == nil {
		t.Fatal("ran a group/world-readable job file")
	}
}

func TestScheduleRejectsSecretFields(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	runCmd(t, "identity", "create", "--name", "alice")

	scheduleDir, _ := scheduleDirsForTest()
	bad := filepath.Join(scheduleDir, "evil.json")
	body := `{"name":"evil","source":"/s","repository":"/r","frequency":"hourly","password":"hunter2"}`
	if err := os.MkdirAll(scheduleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCmdErr(t, "schedule", "list"); err == nil {
		t.Fatal("listed a job with secret fields")
	}
}

func TestScheduleWeeklyAdd(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	src := filepath.Join(t.TempDir(), "src")
	writeSrcFile(t, src, "a.txt", "data")

	runCmd(t, "schedule", "add", "--name", "weekly-docs",
		"--source", src, "--repository", repo, "--weekly", "mon 02:00")
	out, _ = runCmd(t, "schedule", "list")
	if !strings.Contains(out, "weekly mon 02:00") {
		t.Fatalf("schedule list = %q, want weekly schedule", out)
	}
}

func snapshotFromScheduleRun(t *testing.T, output string) string {
	t.Helper()
	for line := range strings.Lines(output) {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "job "); ok {
			// Format: job "name" snapshot <id>
			if _, snap, found := strings.Cut(rest, "snapshot "); found {
				return strings.TrimSpace(snap)
			}
		}
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "snapshot "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no snapshot in output %q", output)
	return ""
}

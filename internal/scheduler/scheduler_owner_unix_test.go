// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build unix

package scheduler_test

import (
	"os"
	"testing"

	"petravault/internal/scheduler"
)

func TestLoadJobRejectsForeignOwner(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	job := testJob("foreign-owner")
	if err := scheduler.SaveJob(dir, job); err != nil {
		t.Fatal(err)
	}
	path, err := scheduler.JobPath(dir, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	foreignUID := os.Geteuid() + 1
	if os.Geteuid() == 0 {
		foreignUID = 1
	}
	if err := os.Chown(path, foreignUID, -1); err != nil {
		t.Skipf("set a foreign owner: %v", err)
	}
	if _, err := scheduler.LoadJob(path); err == nil {
		t.Fatal("loaded a schedule job owned by another user")
	}
}

func TestListJobsRejectsGroupWritableDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("restore schedule directory mode: %v", err)
		}
	})
	if _, err := scheduler.ListJobs(dir); err == nil {
		t.Fatal("listed schedule jobs from a group-writable directory")
	}
}

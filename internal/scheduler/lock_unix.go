// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build !windows

package scheduler

import (
	"fmt"
	"os"
	"syscall"
)

// JobLock is a held per-job overlap lock. The file stays open while the job
// runs; Unlock releases the flock and closes it. The lock file itself is
// kept for reuse across runs.
type JobLock struct {
	file *os.File
}

// TryLock opens the job lock file and takes a non-blocking exclusive
// flock. A job that is still running is not started again (DESIGN.md
// §11.1); the per-source local lock in DESIGN.md §10.2 is this file.
func TryLock(stateDir, name string) (*JobLock, error) {
	path, err := LockPath(stateDir, name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create schedule state dir: %w", err)
	}
	if err := checkScheduleDirectory(stateDir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open job lock: %w", err)
	}
	if err := checkScheduleFileOwner(f, path); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s", ErrLocked, name)
	}
	return &JobLock{file: f}, nil
}

// Unlock releases the flock and closes the lock file.
func (l *JobLock) Unlock() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}

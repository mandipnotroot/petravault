// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package scheduler

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// lockTTL bounds a Windows overlap lock: a lock file older than this is
// treated as abandoned (its holder crashed) and may be replaced. Unix uses
// flock instead (see lock_unix.go); Windows has no stdlib flock, so this
// file-based, best-effort protocol stands in without adding a dependency.
const lockTTL = time.Hour

// JobLock is a held per-job overlap lock on Windows.
type JobLock struct {
	path string
	file *os.File
}

// acquireForRun creates the job lock file exclusively. An existing,
// recently-written lock means the job is still running and the run is
// skipped; a stale lock is reaped and acquisition retried once.
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
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if ownerErr := checkScheduleFileOwner(f, path); ownerErr != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return nil, ownerErr
		}
		return &JobLock{path: path, file: f}, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("open job lock: %w", err)
	}
	fi, statErr := os.Lstat(path)
	if statErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrLocked, name)
	}
	if err := checkScheduleDirectoryOwner(path, fi); err != nil {
		return nil, err
	}
	if time.Since(fi.ModTime()) < lockTTL {
		return nil, fmt.Errorf("%w: %s", ErrLocked, name)
	}
	if removeErr := os.Remove(path); removeErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrLocked, name)
	}
	f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrLocked, name)
	}
	if err := checkScheduleFileOwner(f, path); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &JobLock{path: path, file: f}, nil
}

// Unlock closes and removes the lock file.
func (l *JobLock) Unlock() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = l.file.Close()
	return os.Remove(l.path)
}

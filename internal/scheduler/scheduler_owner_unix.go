// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build unix

package scheduler

import (
	"fmt"
	"os"
	"syscall"
)

func checkScheduleFileOwner(f *os.File, path string) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat schedule file: %w", err)
	}
	return checkScheduleOwner(fi, path)
}

func checkScheduleDirectoryOwner(_ string, fi os.FileInfo) error {
	return checkScheduleOwner(fi, "schedule directory")
}

func checkScheduleDirectoryPermissions(path string, fi os.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("schedule directory %s: group/world writable", path)
	}
	return nil
}

func checkScheduleOwner(fi os.FileInfo, path string) error {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("schedule path %s: cannot determine owner", path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("schedule path %s is not owned by the current user", path)
	}
	return nil
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build darwin

package backup

import (
	"os"
	"syscall"
	"time"
)

// fillMeta records Darwin file ownership and timestamps. Inodes and
// nanosecond times feed the unchanged-file fast path (DESIGN.md §3.4).
func fillMeta(fi os.FileInfo, e *FileEntry) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	e.UID = st.Uid
	e.GID = st.Gid
	e.Inode = st.Ino
	e.Ctime = time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec).UTC()
}

// deviceOf returns the filesystem device holding fi.
func deviceOf(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build !linux && !darwin

package backup

import (
	"os"
)

// fillMeta has no ownership or creation-time source on this platform, so
// UIDs, GIDs, inodes, and ctimes stay zero and the fast path compares size
// and mtime only. Ctime falls back to mtime at the call site.
func fillMeta(_ os.FileInfo, _ *FileEntry) {}

// deviceOf is unavailable on this platform, so --one-file-system cannot
// detect mount crossings here and the check is skipped.
func deviceOf(_ os.FileInfo) (uint64, bool) {
	return 0, false
}

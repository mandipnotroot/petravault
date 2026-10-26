// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package nofollow opens secret-adjacent files without following a trailing
// symlink (DESIGN.md §11.2): password files, schedule job and state files,
// and exclude files are checked (type, permissions, size) and then read, and
// a symlink swapped in between the check and the read must not redirect
// either. Unix opens are nonblocking and reject non-regular files before
// reading. On Windows, which has no equivalent open flags, it is a plain open
// followed by a regular-file check; the limitation is documented (the
// mode-based permission checks do not apply there either).
package nofollow

import (
	"fmt"
	"io"
	"os"
)

// maxReadBytes bounds helper reads so a swapped-in huge file cannot
// exhaust memory; callers pass their own documented cap.
const maxReadBytes = 8 << 20

// Open opens path without following a trailing symlink and accepts only a
// regular file. See the platform files for symlink behavior.
func Open(path string) (*os.File, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("nofollow stat %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("nofollow open %q: not a regular file", path)
	}
	return f, nil
}

// OpenInRoot opens a source path under a retained directory capability.
// Unix opens are nonblocking and refuse a trailing symlink; callers must
// check the opened descriptor's type and identity before reading it.
func OpenInRoot(root *os.Root, path string) (*os.File, error) {
	return openRootNoFollow(root, path)
}

// ReadFile opens path without following symlinks and reads at most
// maxBytes+1 bytes, reporting how many were read so callers can enforce
// their own size cap without a separate stat-then-read race.
func ReadFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > maxReadBytes {
		return nil, fmt.Errorf("nofollow read %q: invalid cap %d", path, maxBytes)
	}
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("nofollow read %q: %w", path, err)
	}
	return raw, nil
}

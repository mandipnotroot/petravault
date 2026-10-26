// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package nofollow

import (
	"fmt"
	"os"
)

// openNoFollow is a plain open on Windows: the platform has no equivalent
// open flag, so trailing-symlink protection and the mode-based permission
// checks built on it are Unix-only by documentation (DESIGN.md §11.2).
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("nofollow open %q: %w", path, err)
	}
	return f, nil
}

func openRootNoFollow(root *os.Root, path string) (*os.File, error) {
	return root.Open(path)
}

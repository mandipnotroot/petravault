// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build unix

package nofollow

import (
	"fmt"
	"os"
	"syscall"
)

// openNoFollow refuses trailing symlinks: O_NOFOLLOW fails the open itself
// instead of racing a separate check.
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("nofollow open %s: %w", path, err)
	}
	return f, nil
}

func openRootNoFollow(root *os.Root, path string) (*os.File, error) {
	return root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

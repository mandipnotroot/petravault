// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build linux || darwin

package backup_test

import (
	"syscall"
)

// makeFifo creates a named pipe, an entry type backup records as a warning
// rather than data.
func makeFifo(path string) error {
	return syscall.Mkfifo(path, 0o644)
}

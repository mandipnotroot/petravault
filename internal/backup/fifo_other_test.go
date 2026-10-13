// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build !linux && !darwin

package backup_test

import (
	"errors"
)

// makeFifo is unavailable on this platform; the warning test skips.
func makeFifo(_ string) error {
	return errors.New("fifos unsupported on this platform")
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"testing"
	"time"
)

// A hanging helper must fail fast instead of blocking unlock forever. The
// timeout is shortened here; production always uses the 60s default. Serial
// by necessity: it mutates process environment and package state, like the
// other password tests.
func TestPasswordCommandTimeout(t *testing.T) {
	old := passwordCommandTimeout
	passwordCommandTimeout = 200 * time.Millisecond
	defer func() { passwordCommandTimeout = old }()

	t.Setenv("PETRAVAULT_PASSWORD_FILE", "")
	t.Setenv("PETRAVAULT_PASSWORD_COMMAND", "sleep 30")
	start := time.Now()
	if _, err := ReadPassword(t.Context(), ""); err == nil {
		t.Fatal("ReadPassword accepted a hanging helper, want timeout failure")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("helper took %v, want failure near the 200ms test timeout", elapsed)
	}
}

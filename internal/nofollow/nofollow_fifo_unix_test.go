// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build unix

package nofollow_test

import (
	"path/filepath"
	"syscall"
	"testing"

	"petravault/internal/nofollow"
)

func TestOpenRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("create FIFO: %v", err)
	}
	f, err := nofollow.Open(path)
	if f != nil {
		_ = f.Close()
	}
	if err == nil {
		t.Fatal("Open accepted a FIFO, want a regular-file error")
	}
}

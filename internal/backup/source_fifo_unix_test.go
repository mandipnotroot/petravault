// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build unix

package backup

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSourceFIFOReplacementBeforeOpen(t *testing.T) {
	source := t.TempDir()
	file := filepath.Join(source, "file")
	if err := os.WriteFile(file, []byte("dummy content"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(file, 0o600); err != nil {
		t.Fatal(err)
	}
	b := runner{sourceRoot: root}
	if chunks, added, err := b.chunkFile(t.Context(), "file", expected); err == nil || len(chunks) != 0 || len(added) != 0 {
		t.Fatalf("FIFO replacement was consumed: chunks=%v added=%v err=%v", chunks, added, err)
	}
}

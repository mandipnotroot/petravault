// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build unix

package repository_test

import (
	"io"
	"path/filepath"
	"syscall"
	"testing"

	"petravault/internal/repository"
)

func TestLocalReadsRejectFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := repo.Close(); err != nil {
			t.Errorf("close repository: %v", err)
		}
	})

	key := "packs/pipe"
	path := filepath.Join(repo.Root(), filepath.FromSlash(key))
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("create FIFO: %v", err)
	}
	for _, read := range []struct {
		name string
		open func() (io.ReadCloser, error)
	}{
		{name: "object", open: func() (io.ReadCloser, error) {
			return repo.GetObject(t.Context(), key)
		}},
		{name: "range", open: func() (io.ReadCloser, error) {
			return repo.GetRange(t.Context(), key, 0, 1)
		}},
	} {
		t.Run(read.name, func(t *testing.T) {
			t.Parallel()

			reader, err := read.open()
			if reader != nil {
				if closeErr := reader.Close(); closeErr != nil {
					t.Errorf("close reader: %v", closeErr)
				}
			}
			if err == nil {
				t.Fatal("read accepted a FIFO, want a regular-file error")
			}
		})
	}
}

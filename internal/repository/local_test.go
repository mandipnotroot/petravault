// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository_test

import (
	"os"
	"path/filepath"
	"testing"

	"petravault/internal/repository"
)

func newLocal(t *testing.T) *repository.Local {
	t.Helper()
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestLocalContract(t *testing.T) {
	t.Parallel()

	runContract(t, func(t *testing.T) repository.Repository {
		t.Helper()
		return newLocal(t)
	})
}

func TestInitCreatesLayout(t *testing.T) {
	t.Parallel()

	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"config", "keys", "identities", "revocations", "snapshots", "packs", "indexes", "locks"} {
		if fi, err := os.Stat(filepath.Join(repo.Root(), dir)); err != nil || !fi.IsDir() {
			t.Fatalf("layout dir %s missing: %v", dir, err)
		}
	}
	// Idempotent.
	if _, err := repository.Init(repo.Root()); err != nil {
		t.Fatal(err)
	}
}

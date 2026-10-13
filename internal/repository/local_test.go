// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
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

func TestPutGetRoundTrip(t *testing.T) {
	t.Parallel()

	repo := newLocal(t)
	ctx := t.Context()
	want := bytes.Repeat([]byte("chunk"), 1000)

	if err := repo.PutObject(ctx, "packs/abc123", bytes.NewReader(want)); err != nil {
		t.Fatal(err)
	}
	rc, err := repo.GetObject(ctx, "packs/abc123")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("round trip mismatch")
	}
}

func TestPutObjectOverwrites(t *testing.T) {
	t.Parallel()

	repo := newLocal(t)
	ctx := t.Context()

	if err := repo.PutObject(ctx, "k", bytes.NewReader([]byte("one"))); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutObject(ctx, "k", bytes.NewReader([]byte("two"))); err != nil {
		t.Fatal(err)
	}
	rc, err := repo.GetObject(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "two" {
		t.Fatalf("got %q, want two", got)
	}
}

func TestPutObjectIfAbsentIsCompareAndSwap(t *testing.T) {
	t.Parallel()

	repo := newLocal(t)
	ctx := t.Context()

	created, err := repo.PutObjectIfAbsent(ctx, "locks/gc.lock", bytes.NewReader([]byte("holder-a")))
	if err != nil || !created {
		t.Fatalf("first create = %v, %v; want true, nil", created, err)
	}
	created, err = repo.PutObjectIfAbsent(ctx, "locks/gc.lock", bytes.NewReader([]byte("holder-b")))
	if err != nil || created {
		t.Fatalf("second create = %v, %v; want false, nil", created, err)
	}
	rc, err := repo.GetObject(ctx, "locks/gc.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "holder-a" {
		t.Fatalf("lock content = %q, want holder-a", got)
	}
}

func TestGetRange(t *testing.T) {
	t.Parallel()

	repo := newLocal(t)
	ctx := t.Context()
	data := []byte("0123456789abcdef")

	if err := repo.PutObject(ctx, "packs/p", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	rc, err := repo.GetRange(ctx, "packs/p", 4, 6)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "456789" {
		t.Fatalf("range = %q, want 456789", got)
	}
}

func TestGetRangeRejectsNegative(t *testing.T) {
	t.Parallel()

	repo := newLocal(t)
	ctx := t.Context()

	if _, err := repo.GetRange(ctx, "packs/p", -1, 4); err == nil {
		t.Fatal("negative offset accepted, want error")
	}
	if _, err := repo.GetRange(ctx, "packs/p", 0, -4); err == nil {
		t.Fatal("negative length accepted, want error")
	}
}

func TestMissingKeyBehavior(t *testing.T) {
	t.Parallel()

	repo := newLocal(t)
	ctx := t.Context()

	if _, err := repo.GetObject(ctx, "packs/nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("GetObject err = %v, want fs.ErrNotExist", err)
	}
	exists, err := repo.Exists(ctx, "packs/nope")
	if err != nil || exists {
		t.Fatalf("Exists = %v, %v; want false, nil", exists, err)
	}
	if err := repo.DeleteObject(ctx, "packs/nope"); err != nil {
		t.Fatalf("DeleteObject missing = %v, want nil", err)
	}
}

func TestUnsafeKeysRejected(t *testing.T) {
	t.Parallel()

	repo := newLocal(t)
	ctx := t.Context()

	for _, key := range []string{"", "../escape", "/absolute", "a/../../b"} {
		if err := repo.PutObject(ctx, key, bytes.NewReader([]byte("x"))); err == nil {
			t.Fatalf("PutObject(%q) accepted, want error", key)
		}
		if _, err := repo.GetObject(ctx, key); err == nil {
			t.Fatalf("GetObject(%q) accepted, want error", key)
		}
	}
}

func TestListSortedWithPrefix(t *testing.T) {
	t.Parallel()

	repo := newLocal(t)
	ctx := t.Context()

	for _, key := range []string{"packs/c", "packs/a", "indexes/b", "packs/b"} {
		if err := repo.PutObject(ctx, key, bytes.NewReader([]byte("x"))); err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.List(ctx, "packs/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"packs/a", "packs/b", "packs/c"}
	if len(got) != len(want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("List = %v, want %v", got, want)
		}
	}
}

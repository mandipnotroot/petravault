// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"

	pverrors "petravault/internal/errors"
	"petravault/internal/repository"
)

type objectOverrideRepo struct {
	repository.Repository
	key string
	raw []byte
}

func (r objectOverrideRepo) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if key == r.key {
		return io.NopCloser(bytes.NewReader(r.raw)), nil
	}
	return r.Repository.GetObject(ctx, key)
}

// runContract exercises the Repository contract shared by LocalRepository
// and S3Repository (DESIGN.md §8, GO_GUIDELINES.md §14). newRepo returns an
// isolated repository per subtest: a fresh temp dir for local, a unique
// prefix for S3. Callers parallelize subtests; S3 is safe for concurrent
// use.
func runContract(t *testing.T, newRepo func(t *testing.T) repository.Repository) {
	t.Helper()

	t.Run("put get round trip", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		repo := newRepo(t)
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
	})

	t.Run("put overwrites", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		repo := newRepo(t)
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
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "two" {
			t.Fatalf("got %q, want two", got)
		}
	})

	t.Run("put if absent is compare and swap", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		repo := newRepo(t)
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
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "holder-a" {
			t.Fatalf("lock content = %q, want holder-a", got)
		}
	})

	t.Run("get range", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		repo := newRepo(t)
		data := []byte("0123456789abcdef")
		if err := repo.PutObject(ctx, "packs/p", bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		got, err := repository.ReadRange(ctx, repo, "packs/p", 4, 6)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "456789" {
			t.Fatalf("range = %q, want 456789", got)
		}
	})

	t.Run("get range rejects negative", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		repo := newRepo(t)
		if _, err := repo.GetRange(ctx, "packs/p", -1, 4); err == nil {
			t.Fatal("negative offset accepted, want error")
		}
		if _, err := repo.GetRange(ctx, "packs/p", 0, -4); err == nil {
			t.Fatal("negative length accepted, want error")
		}
	})

	t.Run("bounded object read", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		repo := newRepo(t)
		key := "locks/read-limit"
		withinLimit := bytes.Repeat([]byte("x"), int(repository.MaxLockObjectBytes))
		if err := repo.PutObject(ctx, key, bytes.NewReader(withinLimit)); err != nil {
			t.Fatal(err)
		}
		got, err := repository.ReadObject(ctx, repo, key)
		if err != nil {
			t.Fatalf("read object at limit: %v", err)
		}
		if len(got) != len(withinLimit) {
			t.Fatalf("read %d bytes, want %d", len(got), len(withinLimit))
		}
		overLimit := append(withinLimit, 'x')
		if err := repo.PutObject(ctx, key, bytes.NewReader(overLimit)); !errors.Is(err, pverrors.ErrUsage) {
			t.Fatalf("oversized write error = %v, want ErrUsage", err)
		}
		oversized := objectOverrideRepo{Repository: repo, key: key, raw: overLimit}
		if _, err := repository.ReadObject(ctx, oversized, key); !errors.Is(err, pverrors.ErrIntegrity) {
			t.Fatalf("oversized read error = %v, want ErrIntegrity", err)
		}
		if _, err := repository.ReadRange(ctx, repo, "packs/missing", 0, repository.MaxChunkRangeBytes+1); !errors.Is(err, pverrors.ErrIntegrity) {
			t.Fatalf("oversized range error = %v, want ErrIntegrity", err)
		}
		unknownOverLimit := bytes.Repeat([]byte("x"), int(repository.MaxUnclassifiedWriteBytes)+1)
		if err := repo.PutObject(ctx, "custom/read-limit", bytes.NewReader(unknownOverLimit)); !errors.Is(err, pverrors.ErrUsage) {
			t.Fatalf("oversized unclassified write error = %v, want ErrUsage", err)
		}
	})

	t.Run("missing key behavior", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		repo := newRepo(t)
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
	})

	t.Run("unsafe keys rejected", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		repo := newRepo(t)
		for _, key := range []string{"", "../escape", "/absolute", "a/../../b"} {
			if err := repo.PutObject(ctx, key, bytes.NewReader([]byte("x"))); err == nil {
				t.Fatalf("PutObject(%q) accepted, want error", key)
			}
			if _, err := repo.GetObject(ctx, key); err == nil {
				t.Fatalf("GetObject(%q) accepted, want error", key)
			}
		}
	})

	t.Run("list sorted with prefix", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		repo := newRepo(t)
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
	})
}

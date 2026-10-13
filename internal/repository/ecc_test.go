// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
	"petravault/internal/repository"
)

func writeObject(t *testing.T, repo *repository.Local, key string, data []byte) {
	t.Helper()
	if err := repo.PutObject(t.Context(), key, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
}

func readObject(t *testing.T, repo *repository.Local, key string) []byte {
	t.Helper()
	r, err := repo.GetObject(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func acceptAll(_ string, _ []byte) error { return nil }

func TestWriteAndRepairSidecar(t *testing.T) {
	t.Parallel()

	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	key := "packs/" + string(bytes.Repeat([]byte("a"), 64)[:64])
	data := bytes.Repeat([]byte("object bytes for sidecars"), 4000)
	writeObject(t, repo, key, data)
	if err := repository.WriteSidecar(ctx, repo, key, data, "medium"); err != nil {
		t.Fatal(err)
	}
	if exists, err := repo.Exists(ctx, key+".ecc"); err != nil || !exists {
		t.Fatalf("sidecar missing: exists=%v err=%v", exists, err)
	}
	// Damage one shard and repair through the repository helper.
	p, err := erasure.Parse("medium")
	if err != nil {
		t.Fatal(err)
	}
	size := erasure.ShardSize(len(data), p.K)
	damaged := bytes.Clone(data)
	damaged[2*size+10] ^= 0x01
	fixed, err := erasure.Repair(damaged, readObject(t, repo, key+".ecc"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixed, data) {
		t.Fatal("repair mismatch")
	}
	// RepairObject with an intact object returns its bytes.
	got, err := repository.RepairObject(ctx, repo, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("RepairObject mismatch on intact input")
	}
}

func TestWriteSidecarOffWritesNothing(t *testing.T) {
	t.Parallel()

	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	key := "indexes/abc"
	data := bytes.Repeat([]byte("x"), 1000)
	writeObject(t, repo, key, data)
	if err := repository.WriteSidecar(ctx, repo, key, data, "off"); err != nil {
		t.Fatal(err)
	}
	if exists, _ := repo.Exists(ctx, key+".ecc"); exists {
		t.Fatal("off wrote a sidecar, want none")
	}
	// Missing sidecars leave repair untouched.
	got, err := repository.RepairObject(ctx, repo, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("RepairObject without a sidecar changed the bytes")
	}
}

func TestRebuildReprotectsAndRemoves(t *testing.T) {
	t.Parallel()

	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	keys := []string{"packs/p1", "indexes/i1", "snapshots/s1"}
	datas := make([][]byte, len(keys))
	for i, key := range keys {
		datas[i] = bytes.Repeat([]byte{byte(i + 1), 0x42}, 30000)
		writeObject(t, repo, key, datas[i])
		if err := repository.WriteSidecar(ctx, repo, key, datas[i], "medium"); err != nil {
			t.Fatal(err)
		}
	}
	// Rebuild under high: every sidecar decodes to k=20 m=3.
	if err := repository.Rebuild(ctx, repo, "high", acceptAll); err != nil {
		t.Fatal(err)
	}
	for i, key := range keys {
		sc, err := erasure.Decode(readObject(t, repo, key+".ecc"))
		if err != nil {
			t.Fatal(err)
		}
		if sc.K != 20 || sc.M != 3 {
			t.Fatalf("%s rebuilt to k=%d m=%d, want k=20 m=3", key, sc.K, sc.M)
		}
		if err := erasure.Verify(datas[i], readObject(t, repo, key+".ecc")); err != nil {
			t.Fatalf("%s fresh sidecar fails verify: %v", key, err)
		}
	}
	// Rebuilding to off removes sidecars and leaves objects alone.
	if err := repository.Rebuild(ctx, repo, "off", acceptAll); err != nil {
		t.Fatal(err)
	}
	for i, key := range keys {
		if exists, _ := repo.Exists(ctx, key+".ecc"); exists {
			t.Fatalf("%s sidecar survives rebuild to off", key)
		}
		if !bytes.Equal(readObject(t, repo, key), datas[i]) {
			t.Fatalf("%s object changed by rebuild", key)
		}
	}
}

func TestRebuildRefusesDamagedData(t *testing.T) {
	t.Parallel()

	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "packs/damaged"
	p, err := erasure.Parse("medium")
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("rebuild refusal target"), 8000)
	writeObject(t, repo, key, data)
	if err := repository.WriteSidecar(ctx, repo, key, data, "medium"); err != nil {
		t.Fatal(err)
	}
	before := readObject(t, repo, key+".ecc")
	// Damage two shards: beyond the single-shard budget.
	size := erasure.ShardSize(len(data), p.K)
	damaged := bytes.Clone(data)
	damaged[10] ^= 0x01
	damaged[5*size+7] ^= 0x01
	if err := repo.PutObject(ctx, key, bytes.NewReader(damaged)); err != nil {
		t.Fatal(err)
	}
	err = repository.Rebuild(ctx, repo, "high", acceptAll)
	if err == nil {
		t.Fatal("Rebuild accepted unrecoverable damage, want failure")
	}
	if !errors.Is(err, pverrors.ErrUnrecoverable) {
		t.Fatalf("rebuild error = %v, want unrecoverable", err)
	}
	// The old sidecar is kept, never overwritten with damaged parity.
	if !bytes.Equal(readObject(t, repo, key+".ecc"), before) {
		t.Fatal("damaged rebuild overwrote the sidecar")
	}
	// A failing verifier also blocks fresh parity.
	deny := func(string, []byte) error {
		return pverrors.ErrAuthFailed
	}
	if err := repository.Rebuild(ctx, repo, "high", deny); err == nil {
		t.Fatal("Rebuild accepted unverified data, want failure")
	}
}

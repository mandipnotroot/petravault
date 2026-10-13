// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package pack_test

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"petravault/internal/compression"
	"petravault/internal/crypto"
	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
	"petravault/internal/pack"
	"petravault/internal/repository"
)

const testRepoID = "test-repository"

type testKeys struct {
	data    crypto.SecretKey
	chunkID crypto.SecretKey
	chunker crypto.SecretKey
}

func mustSubkeys(t *testing.T) testKeys {
	t.Helper()
	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sub := master.DeriveSubkeys()
	master.Zero()
	return testKeys{data: sub.Data, chunkID: sub.ChunkID, chunker: sub.Chunker}
}

func mustRepo(t *testing.T) *repository.Local {
	t.Helper()
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func chunkID(t *testing.T, k crypto.SecretKey, plaintext []byte) [32]byte {
	t.Helper()
	id, err := crypto.KeyedSum(k, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func readKey(t *testing.T, repo *repository.Local, ctxKey string) []byte {
	t.Helper()
	r, err := repo.GetObject(t.Context(), ctxKey)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustRepair(t *testing.T, data, sidecar []byte) []byte {
	t.Helper()
	fixed, err := erasure.Repair(data, sidecar)
	if err != nil {
		t.Fatal(err)
	}
	return fixed
}

func TestPackRoundTrip(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	ctx := t.Context()

	plaintexts := [][]byte{
		[]byte("first chunk"),
		bytes.Repeat([]byte("b"), 5000),
		{},
		bytes.Repeat([]byte("0123456789"), 1000),
	}
	w := pack.NewWriter(testRepoID, keys.data, 4096)
	if got := w.Buffered(); got != 0 {
		t.Fatalf("Buffered = %d, want 0", got)
	}
	for _, p := range plaintexts {
		if err := w.Add(chunkID(t, keys.chunkID, p), p); err != nil {
			t.Fatal(err)
		}
		if w.Buffered() >= 4096 {
			if _, err := w.Flush(ctx, repo, "off"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := w.Flush(ctx, repo, "off"); err != nil {
		t.Fatal(err)
	}
	if len(w.Packs()) == 0 {
		t.Fatal("no packs written")
	}
	entries := w.Entries()
	if len(entries) != len(plaintexts) {
		t.Fatalf("entries = %d, want %d", len(entries), len(plaintexts))
	}

	for _, e := range entries {
		got, err := pack.ReadChunk(ctx, repo, testRepoID, keys.data, keys.chunkID, e, compression.DefaultMaxSize)
		if err != nil {
			t.Fatal(err)
		}
		wantID := e.ID
		found := false
		for _, p := range plaintexts {
			if chunkID(t, keys.chunkID, p) == wantID {
				if !bytes.Equal(got, p) {
					t.Fatalf("chunk %s mismatched", pack.FormatID(wantID))
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("chunk %s not among the inputs", pack.FormatID(wantID))
		}
	}

	for _, packKey := range w.Packs() {
		refs, err := pack.ListPack(ctx, repo, testRepoID, keys.data, packKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) == 0 {
			t.Fatalf("pack %s lists no chunks", packKey)
		}
	}

	indexKey, err := pack.WriteIndex(ctx, repo, testRepoID, keys.data, entries, "off")
	if err != nil {
		t.Fatal(err)
	}
	back, err := pack.ReadIndex(ctx, repo, testRepoID, keys.data, indexKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(entries) {
		t.Fatalf("index holds %d entries, want %d", len(back), len(entries))
	}
	merged, err := pack.LoadEntries(ctx, repo, testRepoID, keys.data)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != len(entries) {
		t.Fatalf("merged %d entries, want %d", len(merged), len(entries))
	}
}

func TestPackNameIsContentHash(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	ctx := t.Context()

	w := pack.NewWriter(testRepoID, keys.data, 0)
	plaintext := []byte("name me by my bytes")
	if err := w.Add(chunkID(t, keys.chunkID, plaintext), plaintext); err != nil {
		t.Fatal(err)
	}
	packKey, err := w.Flush(ctx, repo, "off")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(packKey, pack.PackPrefix) {
		t.Fatalf("pack key %q lacks prefix %q", packKey, pack.PackPrefix)
	}
	content := readKey(t, repo, packKey)
	want := pack.PackPrefix + pack.FormatID(crypto.Sum256(content))
	if packKey != want {
		t.Fatalf("pack key = %q, want hash of content %q", packKey, want)
	}
}

func TestFlushEmptyWritesNothing(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	w := pack.NewWriter(testRepoID, keys.data, 0)
	key, err := w.Flush(t.Context(), repo, "off")
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		t.Fatalf("Flush key = %q, want empty", key)
	}
	if len(w.Packs()) != 0 || len(w.Entries()) != 0 {
		t.Fatal("empty flush recorded packs or entries")
	}
}

func TestReadChunkRejectsTampering(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	ctx := t.Context()

	plaintext := bytes.Repeat([]byte("tamper me"), 500)
	id := chunkID(t, keys.chunkID, plaintext)
	w := pack.NewWriter(testRepoID, keys.data, 0)
	if err := w.Add(id, plaintext); err != nil {
		t.Fatal(err)
	}
	packKey, err := w.Flush(ctx, repo, "off")
	if err != nil {
		t.Fatal(err)
	}
	entry := w.Entries()[0]
	packBytes := readKey(t, repo, packKey)

	// Damage inside the chunk blob breaks ranged reads: the blob is bound
	// to its chunk ID.
	raw := bytes.Clone(packBytes)
	raw[len(raw)-1] ^= 0x01
	if err := repo.PutObject(ctx, packKey, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := pack.ReadChunk(ctx, repo, testRepoID, keys.data, keys.chunkID, entry, compression.DefaultMaxSize); err == nil {
		t.Fatal("ReadChunk accepted a damaged blob, want failure")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("err = %v, want an integrity failure", err)
	}

	// Damage to the framing prefix or the sealed header breaks header
	// verification. Ranged reads trust the authenticated index rather than
	// the pack header, so they still succeed; ListPack reports the damage.
	for _, offset := range []int{0, 20} {
		raw := bytes.Clone(packBytes)
		raw[offset] ^= 0x01
		if err := repo.PutObject(ctx, packKey, bytes.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := pack.ListPack(ctx, repo, testRepoID, keys.data, packKey); err == nil {
			t.Fatalf("ListPack accepted damage at byte %d, want failure", offset)
		}
		if _, err := pack.ReadChunk(ctx, repo, testRepoID, keys.data, keys.chunkID, entry, compression.DefaultMaxSize); err != nil {
			t.Fatalf("ReadChunk trusts the index, yet failed after header damage at byte %d: %v", offset, err)
		}
	}
}

func TestReadChunkRejectsWrongKeyAndSwappedBlob(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	ctx := t.Context()

	first := []byte("first blob contents")
	second := bytes.Repeat([]byte("second blob contents"), 200)
	w := pack.NewWriter(testRepoID, keys.data, 0)
	for _, p := range [][]byte{first, second} {
		if err := w.Add(chunkID(t, keys.chunkID, p), p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Flush(ctx, repo, "off"); err != nil {
		t.Fatal(err)
	}
	entries := w.Entries()

	other, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherSub := other.DeriveSubkeys()
	if _, err := pack.ReadChunk(ctx, repo, testRepoID, otherSub.Data, keys.chunkID, entries[0], compression.DefaultMaxSize); err == nil {
		t.Fatal("ReadChunk with the wrong data key succeeded, want failure")
	}
	if _, err := pack.ReadChunk(ctx, repo, "other-repository", keys.data, keys.chunkID, entries[0], compression.DefaultMaxSize); err == nil {
		t.Fatal("ReadChunk with another repository ID succeeded, want failure")
	}
	// A blob moved to another pack offset fails: the chunk ID is bound in
	// the associated data.
	swapped := entries[0]
	swapped.Offset = entries[1].Offset
	swapped.Length = entries[1].Length
	if _, err := pack.ReadChunk(ctx, repo, testRepoID, keys.data, keys.chunkID, swapped, compression.DefaultMaxSize); err == nil {
		t.Fatal("ReadChunk of a swapped blob succeeded, want failure")
	}
}

func TestIndexRoundTripAndMerge(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	ctx := t.Context()

	writePack := func(chunks ...[]byte) []pack.Entry {
		w := pack.NewWriter(testRepoID, keys.data, 0)
		for _, p := range chunks {
			if err := w.Add(chunkID(t, keys.chunkID, p), p); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := w.Flush(ctx, repo, "off"); err != nil {
			t.Fatal(err)
		}
		return w.Entries()
	}
	first := writePack([]byte("alpha"), []byte("beta"))
	second := writePack([]byte("gamma"))
	all := slices.Concat(first, second)

	indexA, err := pack.WriteIndex(ctx, repo, testRepoID, keys.data, first, "off")
	if err != nil {
		t.Fatal(err)
	}
	indexB, err := pack.WriteIndex(ctx, repo, testRepoID, keys.data, second, "off")
	if err != nil {
		t.Fatal(err)
	}
	if indexA == indexB {
		t.Fatal("two indexes with different entries share a key")
	}
	for _, key := range []string{indexA, indexB} {
		if !strings.HasPrefix(key, pack.IndexPrefix) {
			t.Fatalf("index key %q lacks prefix %q", key, pack.IndexPrefix)
		}
	}
	merged, err := pack.LoadEntries(ctx, repo, testRepoID, keys.data)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != len(all) {
		t.Fatalf("merged %d entries, want %d", len(merged), len(all))
	}
	for _, e := range all {
		got, ok := merged[e.ID]
		if !ok {
			t.Fatalf("chunk %s missing after merge", pack.FormatID(e.ID))
		}
		if got != e {
			t.Fatalf("chunk %s merged to %+v, want %+v", pack.FormatID(e.ID), got, e)
		}
	}
}

func TestWriteIndexRejectsBadEntries(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	ctx := t.Context()

	w := pack.NewWriter(testRepoID, keys.data, 0)
	plaintext := []byte("indexed")
	if err := w.Add(chunkID(t, keys.chunkID, plaintext), plaintext); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Flush(ctx, repo, "off"); err != nil {
		t.Fatal(err)
	}
	good := w.Entries()[0]

	if _, err := pack.WriteIndex(ctx, repo, testRepoID, keys.data, nil, "off"); err == nil {
		t.Fatal("WriteIndex accepted an empty entry list, want rejection")
	}
	dup := good
	if _, err := pack.WriteIndex(ctx, repo, testRepoID, keys.data, []pack.Entry{good, dup}, "off"); err == nil {
		t.Fatal("WriteIndex accepted duplicate entries, want rejection")
	}
	bad := good
	bad.Length = -1
	if _, err := pack.WriteIndex(ctx, repo, testRepoID, keys.data, []pack.Entry{bad}, "off"); err == nil {
		t.Fatal("WriteIndex accepted a negative length, want rejection")
	}
}

func TestReadIndexRejectsTampering(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	ctx := t.Context()

	w := pack.NewWriter(testRepoID, keys.data, 0)
	plaintext := []byte("indexed tamper target")
	if err := w.Add(chunkID(t, keys.chunkID, plaintext), plaintext); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Flush(ctx, repo, "off"); err != nil {
		t.Fatal(err)
	}
	indexKey, err := pack.WriteIndex(ctx, repo, testRepoID, keys.data, w.Entries(), "off")
	if err != nil {
		t.Fatal(err)
	}
	raw := readKey(t, repo, indexKey)
	raw[len(raw)-1] ^= 0x01
	if err := repo.PutObject(ctx, indexKey, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := pack.ReadIndex(ctx, repo, testRepoID, keys.data, indexKey); err == nil {
		t.Fatal("ReadIndex accepted a tampered index, want failure")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("err = %v, want an integrity failure", err)
	}
}

func TestParseID(t *testing.T) {
	t.Parallel()

	var id [32]byte
	for i := range id {
		id[i] = byte(i)
	}
	back, err := pack.ParseID(pack.FormatID(id))
	if err != nil {
		t.Fatal(err)
	}
	if back != id {
		t.Fatal("ParseID does not round-trip FormatID")
	}
	for _, bad := range []string{"", "zz", pack.FormatID(id)[:62], pack.FormatID(id) + "00"} {
		if _, err := pack.ParseID(bad); err == nil {
			t.Fatalf("ParseID accepted %q, want rejection", bad)
		}
	}
}

func TestFlushWritesSidecar(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	ctx := t.Context()

	w := pack.NewWriter(testRepoID, keys.data, 0)
	plaintext := bytes.Repeat([]byte("sidecar pack contents"), 500)
	if err := w.Add(chunkID(t, keys.chunkID, plaintext), plaintext); err != nil {
		t.Fatal(err)
	}
	packKey, err := w.Flush(ctx, repo, "medium")
	if err != nil {
		t.Fatal(err)
	}
	exists, err := repo.Exists(ctx, packKey+".ecc")
	if err != nil || !exists {
		t.Fatalf("pack sidecar missing: exists=%v err=%v", exists, err)
	}
	content := readKey(t, repo, packKey)
	if err := pack.VerifyPack(content, testRepoID, keys.data, packKey); err != nil {
		t.Fatalf("VerifyPack failed: %v", err)
	}
	// Damage the stored pack within budget, repair via the sidecar, and
	// re-verify the repaired bytes.
	sidecar := readKey(t, repo, packKey+".ecc")
	damaged := bytes.Clone(content)
	damaged[len(damaged)-1] ^= 0x01
	if err := pack.VerifyPack(damaged, testRepoID, keys.data, packKey); err == nil {
		t.Fatal("VerifyPack accepted damage, want failure")
	}
	fixed := mustRepair(t, damaged, sidecar)
	if err := pack.VerifyPack(fixed, testRepoID, keys.data, packKey); err != nil {
		t.Fatalf("repaired pack fails verify: %v", err)
	}
}

func TestWriteIndexWritesSidecar(t *testing.T) {
	t.Parallel()

	keys := mustSubkeys(t)
	repo := mustRepo(t)
	ctx := t.Context()

	w := pack.NewWriter(testRepoID, keys.data, 0)
	plaintext := []byte("indexed with sidecar")
	if err := w.Add(chunkID(t, keys.chunkID, plaintext), plaintext); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Flush(ctx, repo, "off"); err != nil {
		t.Fatal(err)
	}
	indexKey, err := pack.WriteIndex(ctx, repo, testRepoID, keys.data, w.Entries(), "medium")
	if err != nil {
		t.Fatal(err)
	}
	exists, err := repo.Exists(ctx, indexKey+".ecc")
	if err != nil || !exists {
		t.Fatalf("index sidecar missing: exists=%v err=%v", exists, err)
	}
	sealed := readKey(t, repo, indexKey)
	if err := pack.VerifyIndex(sealed, testRepoID, keys.data, indexKey); err != nil {
		t.Fatalf("VerifyIndex failed: %v", err)
	}
	bad := bytes.Clone(sealed)
	bad[len(bad)-1] ^= 0x01
	if err := pack.VerifyIndex(bad, testRepoID, keys.data, indexKey); err == nil {
		t.Fatal("VerifyIndex accepted damage, want failure")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("verify error = %v, want integrity failure", err)
	}
}

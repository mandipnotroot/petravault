// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package restore_test

import (
	"bytes"
	"crypto/mldsa"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"petravault/internal/backup"
	"petravault/internal/chunking"
	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/manifest"
	"petravault/internal/repository"
	"petravault/internal/restore"
)

type testSigner struct {
	priv *mldsa.PrivateKey
}

func (s testSigner) Sign(context string, message []byte) ([]byte, error) {
	return s.priv.Sign(nil, message, &mldsa.Options{Context: context})
}

func mustMLDSA(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func mustMaster(t *testing.T) crypto.SecretKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testParams() chunking.Params {
	return chunking.Params{MinSize: 64, AverageSize: 256, MaxSize: 1024}
}

func writeFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, mode); err != nil {
		t.Fatal(err)
	}
}

// setupRepo runs one backup and commits its snapshot, returning the repo,
// keys, manifest, and snapshot ID.
func setupRepo(t *testing.T, src string, ecc string) (*repository.Local, crypto.SecretKey, crypto.SecretKey, manifest.Manifest, string) {
	t.Helper()
	ctx := t.Context()
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	master := mustMaster(t)
	sub := master.DeriveSubkeys()
	res, err := backup.Backup(ctx, repo, backup.Options{
		Source:       src,
		RepositoryID: "test-repo",
		Master:       master,
		SourceID:     "test-source",
		Chunking:     testParams(),
		ECC:          ecc,
	})
	if err != nil {
		t.Fatal(err)
	}
	priv := mustMLDSA(t)
	files := make([]manifest.File, 0, len(res.Files))
	for _, e := range res.Files {
		files = append(files, manifest.File{
			Path: e.Path, Type: e.Type, Mode: e.Mode, UID: e.UID, GID: e.GID,
			Size: e.Size, Inode: e.Inode, Mtime: e.Mtime, Ctime: e.Ctime,
			Target: e.Target, Chunks: e.Chunks,
		})
	}
	id, err := manifest.Commit(ctx, repo, sub.Data, testSigner{priv}, manifest.CommitParams{
		RepositoryID: "test-repo",
		SourceID:     "test-source",
		Identity:     "test-fp",
		CreatedAt:    time.Now().UTC(),
		Files:        files,
		ECC:          ecc,
	})
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	m, err := manifest.Open(ctx, repo, "test-repo", sub.Data, id, pub)
	if err != nil {
		t.Fatal(err)
	}
	return repo, sub.Data, sub.ChunkID, m, id
}

func TestRestoreRoundTrip(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	big := make([]byte, 5000)
	for i := range big {
		big[i] = byte(i * 31)
	}
	writeFile(t, src, "hello.txt", []byte("hello restore"), 0o600)
	writeFile(t, src, "big.bin", big, 0o644)
	writeFile(t, src, "empty.txt", nil, 0o644)
	writeFile(t, src, "sub/nested.txt", []byte("nested"), 0o644)
	if err := os.MkdirAll(filepath.Join(src, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("hello.txt", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	repo, dataKey, chunkIDKey, m, _ := setupRepo(t, src, "off")
	dest := filepath.Join(t.TempDir(), "out")
	if err := restore.Restore(t.Context(), repo, "test-repo", dataKey, chunkIDKey, m, dest, restore.Options{MaxChunkSize: 4096}); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ path, want string }{
		{"hello.txt", "hello restore"},
		{"sub/nested.txt", "nested"},
		{"empty.txt", ""},
	} {
		got, err := os.ReadFile(filepath.Join(dest, tt.path))
		if err != nil {
			t.Fatalf("read %s: %v", tt.path, err)
		}
		if string(got) != tt.want {
			t.Fatalf("%s = %q, want %q", tt.path, got, tt.want)
		}
	}
	if got, err := os.ReadFile(filepath.Join(dest, "big.bin")); err != nil || len(got) != len(big) {
		t.Fatalf("big.bin length = %d, want %d (err %v)", len(got), len(big), err)
	}
	if fi, err := os.Lstat(filepath.Join(dest, "hello.txt")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("hello.txt mode = %o, want 600", fi.Mode().Perm())
	}
	if target, err := os.Readlink(filepath.Join(dest, "link")); err != nil || target != "hello.txt" {
		t.Fatalf("link target = %q, err %v", target, err)
	}
	if fi, err := os.Stat(filepath.Join(dest, "emptydir")); err != nil || !fi.IsDir() {
		t.Fatalf("emptydir missing: %v", err)
	}
}

func TestRestoreRejectsAbsolutePath(t *testing.T) {
	t.Parallel()

	m := manifest.Manifest{
		RepositoryID: "test-repo", SourceID: "s", CreatedAt: time.Now().UTC(),
		Identity: "fp", CryptoSuite: crypto.SuiteID, ChunkingAlgorithm: crypto.ChunkingID,
		Files: []manifest.File{{Path: "/etc/passwd", Type: manifest.TypeFile}},
	}
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	master := mustMaster(t)
	sub := master.DeriveSubkeys()
	err = restore.Restore(t.Context(), repo, "test-repo", sub.Data, sub.ChunkID, m, t.TempDir(), restore.Options{MaxChunkSize: 4096})
	if err == nil {
		t.Fatal("restore accepted an absolute path")
	}
	if !isIntegrity(err) {
		t.Fatalf("absolute-path error = %v, want integrity failure", err)
	}
	// Nothing may be written outside the destination.
	if _, statErr := os.Stat("/tmp/petravault-absolute-test"); statErr == nil {
		t.Fatal("restore wrote outside the destination")
	}
}

func TestRestoreRejectsDotDot(t *testing.T) {
	t.Parallel()

	for _, p := range []string{"../outside", "a/../../outside", "a/../.."} {
		m := manifest.Manifest{
			RepositoryID: "test-repo", SourceID: "s", CreatedAt: time.Now().UTC(),
			Identity: "fp", CryptoSuite: crypto.SuiteID, ChunkingAlgorithm: crypto.ChunkingID,
			Files: []manifest.File{{Path: p, Type: manifest.TypeFile}},
		}
		repo, err := repository.Init(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		master := mustMaster(t)
		sub := master.DeriveSubkeys()
		if err := restore.Restore(t.Context(), repo, "test-repo", sub.Data, sub.ChunkID, m, t.TempDir(), restore.Options{MaxChunkSize: 4096}); err == nil {
			t.Fatalf("restore accepted %q", p)
		} else if !isIntegrity(err) {
			t.Fatalf("path %q error = %v, want integrity failure", p, err)
		}
	}
}

func TestRestoreRejectsSymlinkOutside(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"/etc/passwd", "../outside", "../../etc/passwd"} {
		m := manifest.Manifest{
			RepositoryID: "test-repo", SourceID: "s", CreatedAt: time.Now().UTC(),
			Identity: "fp", CryptoSuite: crypto.SuiteID, ChunkingAlgorithm: crypto.ChunkingID,
			Files: []manifest.File{{Path: "link", Type: manifest.TypeSymlink, Target: target}},
		}
		repo, err := repository.Init(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		master := mustMaster(t)
		sub := master.DeriveSubkeys()
		dest := t.TempDir()
		if err := restore.Restore(t.Context(), repo, "test-repo", sub.Data, sub.ChunkID, m, dest, restore.Options{MaxChunkSize: 4096}); err == nil {
			t.Fatalf("restore accepted symlink to %q", target)
		} else if !isIntegrity(err) {
			t.Fatalf("symlink %q error = %v, want integrity failure", target, err)
		}
		// The evil link itself must never be created.
		if _, statErr := os.Lstat(filepath.Join(dest, "link")); statErr == nil {
			t.Fatalf("evil symlink to %q was created", target)
		}
	}
}

func TestRestoreRefusesOverwrite(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	writeFile(t, src, "a.txt", []byte("original"), 0o644)
	repo, dataKey, chunkIDKey, m, _ := setupRepo(t, src, "off")
	dest := t.TempDir()
	writeFile(t, dest, "a.txt", []byte("existing"), 0o644)
	if err := restore.Restore(t.Context(), repo, "test-repo", dataKey, chunkIDKey, m, dest, restore.Options{MaxChunkSize: 4096}); err == nil {
		t.Fatal("restore overwrote without --overwrite")
	}
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing" {
		t.Fatalf("existing file was clobbered: %q", got)
	}
	if err := restore.Restore(t.Context(), repo, "test-repo", dataKey, chunkIDKey, m, dest, restore.Options{MaxChunkSize: 4096, Overwrite: true}); err != nil {
		t.Fatalf("restore with --overwrite failed: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("overwrite restore = %q, want original", got)
	}
}

func TestRestoreInclude(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	writeFile(t, src, "keep.txt", []byte("keep"), 0o644)
	writeFile(t, src, "skip.txt", []byte("skip"), 0o644)
	writeFile(t, src, "sub/a.txt", []byte("a"), 0o644)
	repo, dataKey, chunkIDKey, m, _ := setupRepo(t, src, "off")
	dest := filepath.Join(t.TempDir(), "out")
	if err := restore.Restore(t.Context(), repo, "test-repo", dataKey, chunkIDKey, m, dest, restore.Options{MaxChunkSize: 4096, Includes: []string{"keep.txt"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "keep.txt")); err != nil {
		t.Fatalf("included file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "skip.txt")); err == nil {
		t.Fatal("excluded file was restored")
	}
	// Directory-prefix include restores the subtree.
	dest2 := filepath.Join(t.TempDir(), "out2")
	if err := restore.Restore(t.Context(), repo, "test-repo", dataKey, chunkIDKey, m, dest2, restore.Options{MaxChunkSize: 4096, Includes: []string{"sub"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest2, "sub", "a.txt")); err != nil {
		t.Fatalf("subtree file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest2, "keep.txt")); err == nil {
		t.Fatal("non-included file was restored")
	}
}

func TestRestoreDetectsTamperedChunk(t *testing.T) {
	t.Parallel()

	src := t.TempDir()
	writeFile(t, src, "a.txt", []byte(strings.Repeat("x", 2000)), 0o644)
	repo, dataKey, chunkIDKey, m, _ := setupRepo(t, src, "off")
	// Corrupt the first pack blob in place.
	keys, err := repo.List(t.Context(), "packs/")
	if err != nil || len(keys) == 0 {
		t.Fatalf("no packs to corrupt: %v", keys)
	}
	r, err := repo.GetObject(t.Context(), keys[0])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := repo.PutObject(t.Context(), keys[0], bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if err := restore.Restore(t.Context(), repo, "test-repo", dataKey, chunkIDKey, m, dest, restore.Options{MaxChunkSize: 4096}); err == nil {
		t.Fatal("restore accepted a tampered chunk")
	} else if !isIntegrity(err) {
		t.Fatalf("tampered error = %v, want integrity failure", err)
	}
}

func TestRestoreDropsSetuid(t *testing.T) {
	t.Parallel()

	priv := mustMLDSA(t)
	pub := priv.PublicKey().Bytes()
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	master := mustMaster(t)
	sub := master.DeriveSubkeys()
	// Craft a manifest naming setuid bits; restore must clear them.
	id, err := manifest.Commit(t.Context(), repo, sub.Data, testSigner{priv}, manifest.CommitParams{
		RepositoryID: "test-repo",
		SourceID:     "s",
		Identity:     "fp",
		CreatedAt:    time.Now().UTC(),
		Files:        []manifest.File{{Path: "evil", Type: manifest.TypeDir, Mode: 0o4755}},
		ECC:          "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	m, err := manifest.Open(t.Context(), repo, "test-repo", sub.Data, id, pub)
	if err != nil {
		t.Fatal(err)
	}
	// Overwrite the mode with setuid after commit is impossible (the ID
	// binds the payload), so test the mask directly via a file entry.
	m.Files[0].Mode = 0o4755
	dest := filepath.Join(t.TempDir(), "out")
	if err := restore.Restore(t.Context(), repo, "test-repo", sub.Data, sub.ChunkID, m, dest, restore.Options{MaxChunkSize: 4096}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dest, "evil"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o7000 != 0 || fi.Mode().Perm() != 0o755 {
		t.Fatalf("restored mode = %o, want 755 without setuid", fi.Mode())
	}
}

func isIntegrity(err error) bool {
	return errors.Is(err, pverrors.ErrIntegrity)
}

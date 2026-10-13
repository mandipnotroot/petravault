// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package verify_test

import (
	"bytes"
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
	"petravault/internal/identity"
	"petravault/internal/manifest"
	"petravault/internal/repository"
	"petravault/internal/verify"
)

func testParams() chunking.Params {
	return chunking.Params{MinSize: 64, AverageSize: 256, MaxSize: 1024}
}

func testTime() time.Time {
	return time.Date(2026, time.October, 13, 10, 0, 0, 0, time.UTC)
}

type fixture struct {
	repo      *repository.Local
	repoCfg   repository.Config
	repoID    string
	master    crypto.SecretKey
	sub       crypto.Subkeys
	alice     *identity.Identity
	alicePriv *identity.PrivateIdentity
	trust     *identity.TrustStore
	trusted   map[string][]byte
	headsPath string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := t.Context()
	keystoreDir := filepath.Join(t.TempDir(), "keystore")
	trustDir := filepath.Join(t.TempDir(), "trust")
	store := identity.NewStore(keystoreDir)
	alice, err := store.Create("alice", []byte("test-password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	trust := identity.NewTrustStore(trustDir)
	if err := trust.Add(alice); err != nil {
		t.Fatal(err)
	}
	alicePriv, err := store.LoadPrivate(alice.Fingerprint, []byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repoID := "test-repo-" + strings.ToLower(alice.Fingerprint.String()[:8])
	repoCfg, err := repository.NewConfig(repoID, testParams(), 1<<20, "medium", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.WriteConfig(ctx, repo, alicePriv, repoCfg); err != nil {
		t.Fatal(err)
	}
	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SealSlot(alicePriv, repoID, alice, master)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.PutObject(ctx, identity.SlotKey(alice.Fingerprint), bytes.NewReader(env)); err != nil {
		t.Fatal(err)
	}
	sub := master.DeriveSubkeys()
	headsPath := filepath.Join(t.TempDir(), "heads.json")
	return &fixture{
		repo: repo, repoCfg: repoCfg, repoID: repoID,
		master: master, sub: sub,
		alice: alice, alicePriv: alicePriv,
		trust: trust, trusted: map[string][]byte{alice.Fingerprint.String(): alice.SignPublic},
		headsPath: headsPath,
	}
}

func writeFile(t *testing.T, dir, name, data string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// commitBackup runs one backup of src and commits its snapshot for sourceID,
// returning the snapshot ID.
func commitBackup(t *testing.T, fx *fixture, src, sourceID string, parent []backup.FileEntry, parentStart time.Time, parentID string) (string, []backup.FileEntry) {
	t.Helper()
	ctx := t.Context()
	res, err := backup.Backup(ctx, fx.repo, backup.Options{
		Source: src, RepositoryID: fx.repoID, Master: fx.master,
		SourceID: sourceID, Parent: parent, ParentStart: parentStart,
		Chunking: testParams(), TargetPackSize: 1 << 20, ECC: "medium",
	})
	if err != nil {
		t.Fatal(err)
	}
	files := make([]manifest.File, 0, len(res.Files))
	for _, e := range res.Files {
		files = append(files, manifest.File{
			Path: e.Path, Type: e.Type, Mode: e.Mode, UID: e.UID, GID: e.GID,
			Size: e.Size, Inode: e.Inode, Mtime: e.Mtime, Ctime: e.Ctime,
			Target: e.Target, Chunks: e.Chunks,
		})
	}
	id, err := manifest.Commit(ctx, fx.repo, fx.sub.Data, fx.alicePriv, manifest.CommitParams{
		RepositoryID: fx.repoID, SourceID: sourceID, Parent: parentID,
		Identity: fx.alice.Fingerprint.String(), CreatedAt: res.StartedAt, Files: files,
		ECC: "medium",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Return parent entries for the next incremental run.
	return id, append([]backup.FileEntry{}, res.Files...)
}

func TestVerifyStandardPasses(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", "hello")
	first, parent := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	_ = first
	_ = parent
	report, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if report.Snapshots != 1 || report.Sources != 1 {
		t.Fatalf("report = %+v, want 1 snapshot and 1 source", report)
	}
	if len(report.Tips) != 1 || report.Tips["laptop"] != first {
		t.Fatalf("tips = %v, want laptop=%s", report.Tips, first)
	}
	if len(report.NoHeadSources) != 1 {
		t.Fatalf("first verify should report no head, got %+v", report)
	}
	// Second run has a head record and reports none missing.
	report2, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	})
	if err != nil {
		t.Fatalf("second verify failed: %v", err)
	}
	if len(report2.NoHeadSources) != 0 {
		t.Fatalf("second verify NoHeadSources = %v, want none", report2.NoHeadSources)
	}
}

func TestVerifyDeepPasses(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", strings.Repeat("data", 500))
	commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	report, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		Deep: true, HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	})
	if err != nil {
		t.Fatalf("deep verify failed: %v", err)
	}
	if report.Snapshots != 1 {
		t.Fatalf("snapshots = %d, want 1", report.Snapshots)
	}
}

func TestVerifySingleSnapshot(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", "one")
	first, parent := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	writeFile(t, src, "b.txt", "two")
	m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, first, func(string) ([]byte, error) {
		return fx.alice.SignPublic, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	parentEntries := make([]backup.FileEntry, 0, len(m.Files))
	for _, e := range m.Files {
		parentEntries = append(parentEntries, backup.FileEntry{Path: e.Path, Type: e.Type, Mode: e.Mode, UID: e.UID, GID: e.GID, Size: e.Size, Inode: e.Inode, Mtime: e.Mtime, Ctime: e.Ctime, Target: e.Target, Chunks: e.Chunks})
	}
	_ = parent
	second, _ := commitBackup(t, fx, src, "laptop", parentEntries, m.CreatedAt, first)
	report, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		SnapshotID: second, HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	})
	if err != nil {
		t.Fatalf("single verify failed: %v", err)
	}
	if report.Snapshots != 1 {
		t.Fatalf("snapshots = %d, want 1 for single verify", report.Snapshots)
	}
}

func TestVerifyDetectsTamperedChunk(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", strings.Repeat("x", 2000))
	commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	keys, err := fx.repo.List(t.Context(), "packs/")
	if err != nil || len(keys) == 0 {
		t.Fatalf("no packs: %v", keys)
	}
	r, err := fx.repo.GetObject(t.Context(), keys[0])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := fx.repo.PutObject(t.Context(), keys[0], bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		Deep: true, HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	})
	if err == nil {
		t.Fatal("deep verify accepted a tampered chunk")
	}
	if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("tampered error = %v, want integrity failure", err)
	}
}

func TestVerifyRejectsUntrustedSigner(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	// Mallory creates her own identity and commits a snapshot with it.
	malloryStore := identity.NewStore(filepath.Join(t.TempDir(), "mallory-store"))
	mallory, err := malloryStore.Create("mallory", []byte("mallory-pw"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	malloryPriv, err := malloryStore.LoadPrivate(mallory.Fingerprint, []byte("mallory-pw"))
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	writeFile(t, src, "evil.txt", "mallory was here")
	res, err := backup.Backup(t.Context(), fx.repo, backup.Options{
		Source: src, RepositoryID: fx.repoID, Master: fx.master,
		SourceID: "mallory-box", Chunking: testParams(), TargetPackSize: 1 << 20, ECC: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	files := make([]manifest.File, 0, len(res.Files))
	for _, e := range res.Files {
		files = append(files, manifest.File{Path: e.Path, Type: e.Type, Mode: e.Mode, Size: e.Size, Mtime: e.Mtime, Ctime: e.Ctime, Target: e.Target, Chunks: e.Chunks})
	}
	if _, err := manifest.Commit(t.Context(), fx.repo, fx.sub.Data, malloryPriv, manifest.CommitParams{
		RepositoryID: fx.repoID, SourceID: "mallory-box", Identity: mallory.Fingerprint.String(),
		CreatedAt: time.Now().UTC(), Files: files, ECC: "off",
	}); err != nil {
		t.Fatal(err)
	}
	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	})
	if err == nil {
		t.Fatal("verify accepted Mallory's snapshot")
	}
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("mallory error = %v, want untrusted signer", err)
	}
}

func TestVerifyDetectsFork(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", "v1")
	first, _ := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, first, func(string) ([]byte, error) {
		return fx.alice.SignPublic, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	files := make([]manifest.File, 0, len(m.Files))
	for _, e := range m.Files {
		files = append(files, manifest.File{Path: e.Path, Type: e.Type, Mode: e.Mode, Size: e.Size, Mtime: e.Mtime, Ctime: e.Ctime, Chunks: e.Chunks})
	}
	// Two children of the same parent: a forked chain.
	for _, extra := range []string{"b1.txt", "b2.txt"} {
		files2 := append(append([]manifest.File{}, files...), manifest.File{Path: extra, Type: manifest.TypeFile, Mode: 0o644, Size: 1, Mtime: time.Now().UTC(), Ctime: time.Now().UTC()})
		if _, err := manifest.Commit(t.Context(), fx.repo, fx.sub.Data, fx.alicePriv, manifest.CommitParams{
			RepositoryID: fx.repoID, SourceID: "laptop", Parent: first,
			Identity: fx.alice.Fingerprint.String(), CreatedAt: time.Now().UTC(), Files: files2, ECC: "off",
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	})
	if err == nil {
		t.Fatal("verify accepted a forked chain")
	}
	if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("fork error = %v, want integrity failure", err)
	}
}

func TestVerifyDetectsRollback(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", "v1")
	first, parent := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, first, func(string) ([]byte, error) {
		return fx.alice.SignPublic, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = parent
	parentEntries := make([]backup.FileEntry, 0, len(m.Files))
	for _, e := range m.Files {
		parentEntries = append(parentEntries, backup.FileEntry{Path: e.Path, Type: e.Type, Mode: e.Mode, Size: e.Size, Mtime: e.Mtime, Ctime: e.Ctime, Chunks: e.Chunks})
	}
	writeFile(t, src, "b.txt", "v2")
	second, _ := commitBackup(t, fx, src, "laptop", parentEntries, m.CreatedAt, first)
	// Establish the head at the tip.
	if _, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	}); err != nil {
		t.Fatal(err)
	}
	// Delete the newest snapshot: truncation must be detected against the
	// head record.
	if err := fx.repo.DeleteObject(t.Context(), manifest.SnapshotPrefix+second); err != nil {
		t.Fatal(err)
	}
	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	})
	if err == nil {
		t.Fatal("verify accepted deletion of the newest snapshot")
	}
	if !errors.Is(err, pverrors.ErrRollback) {
		t.Fatalf("rollback error = %v, want rollback detection", err)
	}
}

func TestVerifyRejectsRevokedSigner(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", "hello")
	commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	env, err := identity.SignRevocation(fx.alicePriv, fx.alice.Fingerprint, "lost laptop", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.VerifyRevocation(env, fx.alice.SignPublic); err != nil {
		t.Fatal(err)
	}
	if err := fx.trust.AddRevocation(fx.alice.Fingerprint, env); err != nil {
		t.Fatal(err)
	}
	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: 4096,
	})
	if err == nil {
		t.Fatal("verify accepted a revoked signer")
	}
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("revoked error = %v, want untrusted signer", err)
	}
}

func TestHeadsRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "heads.json")
	id := strings.Repeat("ab", 32)
	if err := verify.UpdateHead(path, "laptop", id, testTime); err != nil {
		t.Fatal(err)
	}
	heads, err := verify.LoadHeads(path)
	if err != nil {
		t.Fatal(err)
	}
	if heads["laptop"].Snapshot != id {
		t.Fatalf("head = %q, want %q", heads["laptop"].Snapshot, id)
	}
	// Missing file loads empty.
	empty, err := verify.LoadHeads(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("missing heads = %v, err %v", empty, err)
	}
}

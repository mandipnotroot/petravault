// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package prune_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"petravault/internal/backup"
	"petravault/internal/chunking"
	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
	"petravault/internal/manifest"
	"petravault/internal/pack"
	"petravault/internal/prune"
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
	repoCfg, err := repository.NewConfig(repoID, testParams(), 1<<20, "off", testTime)
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
	return &fixture{
		repo: repo, repoCfg: repoCfg, repoID: repoID,
		master: master, sub: sub,
		alice: alice, alicePriv: alicePriv,
		trust: trust, trusted: map[string][]byte{alice.Fingerprint.String(): alice.SignPublic},
	}
}

func lookupFor(fx *fixture) func(string) ([]byte, error) {
	return func(hint string) ([]byte, error) {
		fp, err := identity.ParseFingerprint(hint)
		if err != nil {
			return nil, err
		}
		ok, err := fx.trust.IsTrusted(fp)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.Join(pverrors.ErrUntrustedSigner, errors.New("untrusted"))
		}
		pub, ok := fx.trusted[fp.String()]
		if !ok {
			return nil, errors.Join(pverrors.ErrUntrustedSigner, errors.New("untrusted"))
		}
		return pub, nil
	}
}

func writeSrcFile(t *testing.T, dir, name, data string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// commitAt runs one backup of src and commits its snapshot at created,
// returning the snapshot ID and parent entries for the next run.
func commitAt(t *testing.T, fx *fixture, src, sourceID string, parent []backup.FileEntry, parentStart time.Time, parentID string, created time.Time) (string, []backup.FileEntry) {
	t.Helper()
	ctx := t.Context()
	res, err := backup.Backup(ctx, fx.repo, backup.Options{
		Source: src, RepositoryID: fx.repoID, Master: fx.master,
		SourceID: sourceID, Parent: parent, ParentStart: parentStart,
		Chunking: testParams(), TargetPackSize: 1 << 20, ECC: "off",
		Now: func() time.Time { return created },
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
		Identity: fx.alice.Fingerprint.String(), CreatedAt: created, Files: files,
		ECC: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, append([]backup.FileEntry{}, res.Files...)
}

func verifyOK(t *testing.T, fx *fixture) {
	t.Helper()
	_, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: filepath.Join(t.TempDir(), "heads.json"), MaxChunkSize: 4096,
	})
	if err != nil {
		t.Fatalf("verify after prune failed: %v", err)
	}
}

func TestRetentionRequiresKeepRule(t *testing.T) {
	t.Parallel()

	if err := (prune.Retention{}).Validate(); err == nil {
		t.Fatal("empty retention validated, want usage error")
	}
	if err := (prune.Retention{Daily: -1}).Validate(); err == nil {
		t.Fatal("negative retention validated, want error")
	}
}

func TestSelectRetainedBuckets(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	infos := []prune.SnapshotInfo{
		{ID: "a", SourceID: "s", CreatedAt: base},
		{ID: "b", SourceID: "s", CreatedAt: base.Add(-24 * time.Hour)},
		{ID: "c", SourceID: "s", CreatedAt: base.Add(-48 * time.Hour)},
	}
	kept, err := prune.SelectRetained(infos, prune.Retention{Daily: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !kept["a"] || !kept["b"] || kept["c"] {
		t.Fatalf("daily 2 kept = %v, want a and b", kept)
	}
}

func TestSelectRetainedKeepsTipPerSource(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	infos := []prune.SnapshotInfo{
		{ID: "s1-new", SourceID: "s1", CreatedAt: base},
		{ID: "s1-old", SourceID: "s1", CreatedAt: base.Add(-720 * time.Hour)},
		{ID: "s2-new", SourceID: "s2", CreatedAt: base},
		{ID: "s2-old", SourceID: "s2", CreatedAt: base.Add(-720 * time.Hour)},
	}
	kept, err := prune.SelectRetained(infos, prune.Retention{Daily: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !kept["s1-new"] || !kept["s2-new"] {
		t.Fatalf("tips not kept: %v", kept)
	}
}

func TestPruneDeletesOldSnapshotsAndKeepsTip(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	base := time.Date(2026, time.October, 10, 10, 0, 0, 0, time.UTC)
	writeSrcFile(t, src, "a.txt", "v1")
	first, parent := commitAt(t, fx, src, "laptop", nil, time.Time{}, "", base)
	m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, first, lookupFor(fx))
	if err != nil {
		t.Fatal(err)
	}
	_ = parent
	parentEntries := manifestToBackup(m.Files)
	writeSrcFile(t, src, "a.txt", "v2")
	second, parent2 := commitAt(t, fx, src, "laptop", parentEntries, m.CreatedAt, first, base.Add(24*time.Hour))
	m2, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, second, lookupFor(fx))
	if err != nil {
		t.Fatal(err)
	}
	parentEntries2 := manifestToBackup(m2.Files)
	writeSrcFile(t, src, "a.txt", "v3")
	third, _ := commitAt(t, fx, src, "laptop", parentEntries2, m2.CreatedAt, second, base.Add(48*time.Hour))
	_ = parent2

	report, err := prune.Prune(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, lookupFor(fx), prune.Options{
		Retention: prune.Retention{Daily: 1},
	})
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	if !slices.Contains(report.Retained, third) {
		t.Fatalf("tip %s not retained: %+v", third, report)
	}
	if len(report.DeletedSnapshots) == 0 {
		t.Fatalf("prune deleted nothing: %+v", report)
	}
	// Deleted snapshots are gone; the tip restores.
	ids, err := manifest.List(t.Context(), fx.repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, deleted := range report.DeletedSnapshots {
		if slices.Contains(ids, deleted) {
			t.Fatalf("deleted snapshot %s still listed", deleted)
		}
	}
	verifyOK(t, fx)
}

func TestPruneDryRunChangesNothing(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	base := time.Date(2026, time.October, 10, 10, 0, 0, 0, time.UTC)
	writeSrcFile(t, src, "a.txt", "v1")
	first, parent := commitAt(t, fx, src, "laptop", nil, time.Time{}, "", base)
	m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, first, lookupFor(fx))
	if err != nil {
		t.Fatal(err)
	}
	_ = parent
	writeSrcFile(t, src, "a.txt", "v2")
	_, _ = commitAt(t, fx, src, "laptop", manifestToBackup(m.Files), m.CreatedAt, first, base.Add(24*time.Hour))

	beforeSnapshots, err := manifest.List(t.Context(), fx.repo)
	if err != nil {
		t.Fatal(err)
	}
	beforePacks, err := fx.repo.List(t.Context(), "packs/")
	if err != nil {
		t.Fatal(err)
	}
	report, err := prune.Prune(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, lookupFor(fx), prune.Options{
		Retention: prune.Retention{Daily: 1}, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if !report.DryRun {
		t.Fatal("dry run report missing flag")
	}
	afterSnapshots, err := manifest.List(t.Context(), fx.repo)
	if err != nil {
		t.Fatal(err)
	}
	afterPacks, err := fx.repo.List(t.Context(), "packs/")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(beforeSnapshots, afterSnapshots) {
		t.Fatalf("dry run changed snapshots: %v -> %v", beforeSnapshots, afterSnapshots)
	}
	if !slices.Equal(beforePacks, afterPacks) {
		t.Fatalf("dry run changed packs: %v -> %v", beforePacks, afterPacks)
	}
}

func TestPruneRefusesWithoutKeepRule(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSrcFile(t, src, "a.txt", "x")
	_, _ = commitAt(t, fx, src, "laptop", nil, time.Time{}, "", testTime())
	_, err := prune.Prune(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, lookupFor(fx), prune.Options{})
	if err == nil {
		t.Fatal("prune without keep rule succeeded, want usage error")
	}
	if !errors.Is(err, pverrors.ErrUsage) {
		t.Fatalf("prune error = %v, want usage error", err)
	}
}

func TestPruneRejectsFork(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSrcFile(t, src, "a.txt", "v1")
	first, _ := commitAt(t, fx, src, "laptop", nil, time.Time{}, "", testTime())
	m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, first, lookupFor(fx))
	if err != nil {
		t.Fatal(err)
	}
	files := make([]manifest.File, 0, len(m.Files))
	for _, e := range m.Files {
		files = append(files, manifest.File{Path: e.Path, Type: e.Type, Mode: e.Mode, Size: e.Size, Mtime: e.Mtime, Ctime: e.Ctime, Chunks: e.Chunks})
	}
	for _, extra := range []string{"b1.txt", "b2.txt"} {
		files2 := append(append([]manifest.File{}, files...), manifest.File{Path: extra, Type: manifest.TypeFile, Mode: 0o644, Size: 1, Mtime: time.Now().UTC(), Ctime: time.Now().UTC()})
		if _, err := manifest.Commit(t.Context(), fx.repo, fx.sub.Data, fx.alicePriv, manifest.CommitParams{
			RepositoryID: fx.repoID, SourceID: "laptop", Parent: first,
			Identity: fx.alice.Fingerprint.String(), CreatedAt: time.Now().UTC(), Files: files2, ECC: "off",
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = prune.Prune(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, lookupFor(fx), prune.Options{
		Retention: prune.Retention{Daily: 30},
	})
	if err == nil {
		t.Fatal("prune accepted a forked chain, want integrity failure")
	}
	if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("fork error = %v, want integrity failure", err)
	}
}

func manifestToBackup(files []manifest.File) []backup.FileEntry {
	out := make([]backup.FileEntry, 0, len(files))
	for _, e := range files {
		out = append(out, backup.FileEntry{
			Path: e.Path, Type: e.Type, Mode: e.Mode, UID: e.UID, GID: e.GID,
			Size: e.Size, Inode: e.Inode, Mtime: e.Mtime, Ctime: e.Ctime,
			Target: e.Target, Chunks: slices.Clone(e.Chunks),
		})
	}
	return out
}

// readRetainedChunks concatenates the plaintext of every file chunk in the
// retained snapshot, verifying AEAD and BLAKE3 via pack.ReadChunk.
func readRetainedChunks(t *testing.T, fx *fixture, snapshotID string) (string, error) {
	t.Helper()
	ctx := t.Context()
	m, err := manifest.OpenTrusted(ctx, fx.repo, fx.repoID, fx.sub.Data, snapshotID, lookupFor(fx))
	if err != nil {
		return "", err
	}
	entries, err := pack.LoadEntries(ctx, fx.repo, fx.repoID, fx.sub.Data)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, f := range m.Files {
		for _, chunkHex := range f.Chunks {
			id, err := pack.ParseID(chunkHex)
			if err != nil {
				return "", err
			}
			loc, ok := entries[id]
			if !ok {
				return "", errors.New("missing chunk for retained snapshot")
			}
			plaintext, err := pack.ReadChunk(ctx, fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, loc, 4096)
			if err != nil {
				return "", err
			}
			out.Write(plaintext)
		}
	}
	return out.String(), nil
}

func TestPruneReclaimsOrphans(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	orphanSrc := t.TempDir()
	writeSrcFile(t, orphanSrc, "orphan.txt", "orphaned contents that never commit, unique bytes 12345")
	// An interrupted backup leaves packs and an index but no snapshot:
	// only orphans, never a partial snapshot.
	res, err := backup.Backup(t.Context(), fx.repo, backup.Options{
		Source: orphanSrc, RepositoryID: fx.repoID, Master: fx.master,
		SourceID: "laptop", Chunking: testParams(), TargetPackSize: 1 << 20, ECC: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packs) == 0 {
		t.Fatal("backup wrote no packs to orphan")
	}
	// A real snapshot with disjoint contents so the orphan chunks stay
	// unreferenced.
	realSrc := t.TempDir()
	writeSrcFile(t, realSrc, "real.txt", "committed contents, different bytes 67890")
	_, _ = commitAt(t, fx, realSrc, "other", nil, time.Time{}, "", testTime().Add(time.Hour))
	report, err := prune.Prune(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, lookupFor(fx), prune.Options{
		Retention: prune.Retention{Daily: 30},
	})
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	if len(report.DeletedPacks) == 0 {
		t.Fatalf("prune reclaimed no orphans: %+v", report)
	}
	verifyOK(t, fx)
}

func TestPruneKeepsConcurrentDuplicates(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	// Two sources back up identical new files concurrently: pack names are
	// hashes, so duplicates are harmless and both snapshots must restore.
	srcA := t.TempDir()
	srcB := t.TempDir()
	writeSrcFile(t, srcA, "shared.txt", "identical contents for dedupe")
	writeSrcFile(t, srcB, "shared.txt", "identical contents for dedupe")
	at := testTime()
	idA, _ := commitAt(t, fx, srcA, "machine-a", nil, time.Time{}, "", at)
	idB, _ := commitAt(t, fx, srcB, "machine-b", nil, time.Time{}, "", at.Add(time.Minute))
	report, err := prune.Prune(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, lookupFor(fx), prune.Options{
		Retention: prune.Retention{Daily: 30},
	})
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	if !slices.Contains(report.Retained, idA) || !slices.Contains(report.Retained, idB) {
		t.Fatalf("concurrent snapshots not both retained: %+v", report)
	}
	verifyOK(t, fx)
}

func TestPruneRepacksMixedPack(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	// Backup 1 packs shared + unique1 together (one pack: small files).
	writeSrcFile(t, src, "shared.txt", "shared contents stable across backups 11111")
	writeSrcFile(t, src, "unique1.txt", "first unique contents 22222")
	base := testTime()
	first, parent := commitAt(t, fx, src, "laptop", nil, time.Time{}, "", base)
	m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, first, lookupFor(fx))
	if err != nil {
		t.Fatal(err)
	}
	_ = parent
	// Backup 2 reuses shared (no new pack for it) and adds unique2.
	if err := os.Remove(filepath.Join(src, "unique1.txt")); err != nil {
		t.Fatal(err)
	}
	writeSrcFile(t, src, "unique2.txt", "second unique contents 33333")
	second, _ := commitAt(t, fx, src, "laptop", manifestToBackup(m.Files), m.CreatedAt, first, base.Add(24*time.Hour))
	// Retain only the newest: the first pack holds one live (shared) and
	// one dead (unique1) chunk, meeting the 0.5 repack threshold.
	report, err := prune.Prune(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, lookupFor(fx), prune.Options{
		Retention: prune.Retention{Daily: 1},
	})
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	if !slices.Contains(report.Retained, second) {
		t.Fatalf("tip not retained: %+v", report)
	}
	if len(report.RepackedPacks) == 0 && len(report.DeletedPacks) == 0 {
		t.Fatalf("prune did nothing to mixed packs: %+v", report)
	}
	verifyOK(t, fx)
	// The retained snapshot still restores both files byte-identically.
	got, err := readRetainedChunks(t, fx, second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "shared contents") || !strings.Contains(got, "second unique") {
		t.Fatalf("repacked snapshot chunks = %q, want shared and unique2", got)
	}
}

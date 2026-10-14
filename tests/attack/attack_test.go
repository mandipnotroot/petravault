// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package attack_test

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
	"petravault/internal/compression"
	"petravault/internal/crypto"
	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
	"petravault/internal/manifest"
	"petravault/internal/pack"
	"petravault/internal/recovery"
	"petravault/internal/repository"
	"petravault/internal/restore"
	"petravault/internal/scheduler"
	"petravault/internal/verify"
)

// TestAttackModifyChunkBlob covers DESIGN.md §13: modifying a byte of an
// encrypted chunk blob must fail AEAD authentication.
func TestAttackModifyChunkBlob(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "data.bin", strings.Repeat("chunk-blob victim data ", 200))
	snap, entries := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	_ = snap
	_ = entries

	merged, err := pack.LoadEntries(t.Context(), fx.repo, fx.repoID, fx.sub.Data)
	if err != nil {
		t.Fatal(err)
	}
	var victim pack.Entry
	for _, e := range merged {
		victim = e
		break
	}
	if victim.Pack == "" {
		t.Fatal("no index entries to attack")
	}
	// Control: the intact blob reads back.
	if _, err := pack.ReadChunk(t.Context(), fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, victim, compression.DefaultMaxSize); err != nil {
		t.Fatalf("intact chunk failed to read: %v", err)
	}

	// Damage a byte inside the victim blob itself: victim.Offset is the
	// absolute file offset of the sealed blob, so tampering there breaks
	// the blob's AEAD authentication. Tampering a different pack, or only
	// the pack header, would leave this ranged read succeeding.
	raw := readObject(t, fx, victim.Pack)
	if victim.Offset < 0 || victim.Offset >= int64(len(raw)) {
		t.Fatalf("victim offset %d out of range in %d-byte pack", victim.Offset, len(raw))
	}
	overwriteObject(t, fx, victim.Pack, flipByte(raw, int(victim.Offset)))

	_, err = pack.ReadChunk(t.Context(), fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, victim, compression.DefaultMaxSize)
	requireIntegrity(t, err, "ranged read of a tampered chunk blob")

	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		Deep: true, HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	})
	requireIntegrity(t, err, "deep verification of a tampered chunk blob")
}

// TestAttackModifySnapshot covers DESIGN.md §13: modifying a snapshot
// object must fail signature or AEAD verification.
func TestAttackModifySnapshot(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "a.txt", "snapshot victim")
	snap, _ := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")

	key := manifest.SnapshotPrefix + snap
	raw := readObject(t, fx, key)
	overwriteObject(t, fx, key, flipByte(raw, len(raw)/2))

	_, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, snap, trustedLookup(fx))
	requireIntegrity(t, err, "opening a tampered snapshot object")

	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	})
	requireIntegrity(t, err, "verifying a tampered snapshot object")
}

// TestAttackUnauthorizedSigner covers DESIGN.md §13: a snapshot signed by
// Mallory, who is not in the client trust list, must be rejected.
func TestAttackUnauthorizedSigner(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	mallory, malloryPriv := createMember(t, fx, "mallory", "mallory-password-1")

	src := t.TempDir()
	writeSourceFile(t, src, "evil.txt", "mallory was here")
	res, err := backup.Backup(t.Context(), fx.repo, backup.Options{
		Source: src, RepositoryID: fx.repoID, Master: fx.master,
		SourceID: "mallory-box", Chunking: testChunkingParams(), TargetPackSize: 1 << 20, ECC: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Commit(t.Context(), fx.repo, fx.sub.Data, malloryPriv, manifest.CommitParams{
		RepositoryID: fx.repoID, SourceID: "mallory-box", Identity: mallory.Fingerprint.String(),
		CreatedAt: res.StartedAt, Files: backupEntriesToManifest(res.Files), ECC: "off",
	}); err != nil {
		t.Fatal(err)
	}

	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	})
	if err == nil {
		t.Fatal("verification accepted Mallory's snapshot, want rejection")
	}
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("mallory error = %v, want an untrusted-signer failure", err)
	}
	requireIntegrity(t, err, "Mallory's snapshot")
}

// TestAttackRepoIdentitiesCopyIgnored covers DESIGN.md §13: Mallory adding
// her key to the repository's identities/ copy must not change the
// client-pinned trust list.
func TestAttackRepoIdentitiesCopyIgnored(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "a.txt", "alice data")
	commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")

	mallory, _ := createMember(t, fx, "mallory", "mallory-password-2")
	malloryPub, err := identity.MarshalPublic(mallory)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.repo.PutObject(t.Context(), identity.AdvisoryKey(mallory.Fingerprint), bytes.NewReader(malloryPub)); err != nil {
		t.Fatal(err)
	}

	if ok, err := fx.trust.IsTrusted(mallory.Fingerprint); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("repository-side identities/ copy granted trust, want it ignored")
	}

	// Alice's history still verifies: the advisory copy changed nothing.
	if _, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	}); err != nil {
		t.Fatalf("verification failed after advisory-key injection: %v", err)
	}
}

// TestAttackReplayOldSnapshot covers DESIGN.md §13: replaying an old
// snapshot as the latest must be detected as rollback within its source
// chain via the client-local head record.
func TestAttackReplayOldSnapshot(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "a.txt", "v1")
	first, parent := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, first, trustedLookup(fx))
	if err != nil {
		t.Fatal(err)
	}
	parentEntries := make([]backup.FileEntry, 0, len(m.Files))
	for _, e := range m.Files {
		parentEntries = append(parentEntries, backup.FileEntry{
			Path: e.Path, Type: e.Type, Mode: e.Mode, Size: e.Size,
			Mtime: e.Mtime, Ctime: e.Ctime, Target: e.Target, Chunks: e.Chunks,
		})
	}
	_ = parent
	writeSourceFile(t, src, "b.txt", "v2")
	second, _ := commitBackup(t, fx, src, "laptop", parentEntries, m.CreatedAt, first)

	// Establish the head at the tip.
	if _, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	}); err != nil {
		t.Fatal(err)
	}
	// Attacker deletes the newest snapshot and replays the old one as
	// latest. The remaining chain is internally consistent, so only the
	// head record can detect the truncation.
	if err := fx.repo.DeleteObject(t.Context(), manifest.SnapshotPrefix+second); err != nil {
		t.Fatal(err)
	}

	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		SnapshotID: first, HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	})
	if err == nil {
		t.Fatal("verification accepted a replayed old snapshot, want rollback detection")
	}
	if !errors.Is(err, pverrors.ErrRollback) {
		t.Fatalf("replay error = %v, want a rollback failure", err)
	}
	requireIntegrity(t, err, "replayed old snapshot")

	// Without a head record (first use) the truncated chain looks valid,
	// proving the head is what detects the replay.
	if _, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		MaxChunkSize: compression.DefaultMaxSize,
	}); err != nil {
		t.Fatalf("headless verification of the truncated chain failed: %v", err)
	}
}

// TestAttackReplayAcrossRepository covers DESIGN.md §13: a valid snapshot
// replayed into a different repository must be rejected on repository_id
// mismatch.
func TestAttackReplayAcrossRepository(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "a.txt", "cross-repo victim")
	snap, _ := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")

	sealed := readObject(t, fx, manifest.SnapshotPrefix+snap)
	otherRepoID, err := repository.GenerateID()
	if err != nil {
		t.Fatal(err)
	}

	// Control: the snapshot verifies under its own repository.
	if err := manifest.VerifySnapshot(sealed, fx.repoID, fx.sub.Data, snap, fx.alice.SignPublic); err != nil {
		t.Fatalf("control snapshot failed to verify: %v", err)
	}

	err = manifest.VerifySnapshot(sealed, otherRepoID, fx.sub.Data, snap, fx.alice.SignPublic)
	requireIntegrity(t, err, "snapshot replayed into another repository")
}

// TestAttackRevokedSigner covers DESIGN.md §13: a revoked signer
// attempting a new signature must be rejected.
func TestAttackRevokedSigner(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "a.txt", "before revocation")
	commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")

	env, err := identity.SignRevocation(fx.alicePriv, fx.alice.Fingerprint, "key lost", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.trust.AddRevocation(fx.alice.Fingerprint, env); err != nil {
		t.Fatal(err)
	}

	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	})
	if err == nil {
		t.Fatal("verification accepted a revoked signer's history, want rejection")
	}
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("revoked history error = %v, want an untrusted-signer failure", err)
	}

	// A new signature after revocation is rejected the same way.
	writeSourceFile(t, src, "b.txt", "after revocation")
	res, err := backup.Backup(t.Context(), fx.repo, backup.Options{
		Source: src, RepositoryID: fx.repoID, Master: fx.master,
		SourceID: "laptop", Chunking: testChunkingParams(), TargetPackSize: 1 << 20, ECC: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Commit(t.Context(), fx.repo, fx.sub.Data, fx.alicePriv, manifest.CommitParams{
		RepositoryID: fx.repoID, SourceID: "laptop", Identity: fx.alice.Fingerprint.String(),
		CreatedAt: res.StartedAt, Files: backupEntriesToManifest(res.Files), ECC: "off",
	}); err != nil {
		t.Fatal(err)
	}
	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	})
	requireIntegrity(t, err, "new signature by a revoked signer")
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("revoked signer error = %v, want an untrusted-signer failure", err)
	}
}

// TestAttackSwapChunkBlobs covers DESIGN.md §13: swapping chunk blobs
// between packs or offsets must fail AEAD authentication because the chunk
// ID is bound in the associated data.
func TestAttackSwapChunkBlobs(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	ctx := t.Context()
	first := []byte("first blob contents for swap test")
	// Keep the second blob under the repository maximum chunk size so the
	// control reads pass with the repository cap.
	second := bytes.Repeat([]byte("second blob contents "), 30)

	idA, err := crypto.KeyedSum(fx.sub.ChunkID, first)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := crypto.KeyedSum(fx.sub.ChunkID, second)
	if err != nil {
		t.Fatal(err)
	}
	w := pack.NewWriter(fx.repoID, fx.sub.Data, 0)
	if err := w.Add(idA, first); err != nil {
		t.Fatal(err)
	}
	if err := w.Add(idB, second); err != nil {
		t.Fatal(err)
	}
	packKey, err := w.Flush(ctx, fx.repo, "off")
	if err != nil {
		t.Fatal(err)
	}
	entries := w.Entries()
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}

	// Control: intact locations read back.
	for i, e := range entries {
		want := first
		if i == 1 {
			want = second
		}
		got, err := pack.ReadChunk(ctx, fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, e, compression.DefaultMaxSize)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("control chunk mismatch")
		}
	}

	// A blob read at another blob's offset fails: the chunk ID in the
	// associated data does not match the bytes at that offset.
	swapped := entries[0]
	swapped.Offset = entries[1].Offset
	swapped.Length = entries[1].Length
	_, err = pack.ReadChunk(ctx, fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, swapped, compression.DefaultMaxSize)
	requireIntegrity(t, err, "chunk blob swapped between offsets")

	// A blob moved to another pack fails the same way.
	third := []byte("third blob in another pack")
	idC, err := crypto.KeyedSum(fx.sub.ChunkID, third)
	if err != nil {
		t.Fatal(err)
	}
	w2 := pack.NewWriter(fx.repoID, fx.sub.Data, 0)
	if err := w2.Add(idC, third); err != nil {
		t.Fatal(err)
	}
	otherPack, err := w2.Flush(ctx, fx.repo, "off")
	if err != nil {
		t.Fatal(err)
	}
	otherEntries := w2.Entries()
	cross := entries[0]
	cross.Pack = otherPack
	cross.Offset = otherEntries[0].Offset
	cross.Length = otherEntries[0].Length
	_ = packKey
	_, err = pack.ReadChunk(ctx, fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, cross, compression.DefaultMaxSize)
	requireIntegrity(t, err, "chunk blob swapped between packs")
}

// TestAttackEditRepositoryConfig covers DESIGN.md §13: editing
// repository.json (downgrading the suite or disabling ECC) must be
// rejected as an invalid signature or untrusted signer.
func TestAttackEditRepositoryConfig(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	if _, _, err := repository.ReadConfig(t.Context(), fx.repo, fx.trusted); err != nil {
		t.Fatalf("control config failed to verify: %v", err)
	}

	raw := readObject(t, fx, repository.ConfigKey)
	overwriteObject(t, fx, repository.ConfigKey, flipByte(raw, len(raw)/2))
	_, _, err := repository.ReadConfig(t.Context(), fx.repo, fx.trusted)
	requireIntegrity(t, err, "tampered repository config")

	// Restore the valid config, then try a downgrade (ECC off) signed by
	// Mallory, who is not trusted.
	if err := repository.WriteConfig(t.Context(), fx.repo, fx.alicePriv, fx.repoCfg); err != nil {
		t.Fatal(err)
	}
	mallory, malloryPriv := createMember(t, fx, "mallory", "mallory-password-3")
	_ = mallory
	downgraded := fx.repoCfg
	downgraded.ECC = "off"
	if err := repository.WriteConfig(t.Context(), fx.repo, malloryPriv, downgraded); err != nil {
		t.Fatal(err)
	}
	_, _, err = repository.ReadConfig(t.Context(), fx.repo, fx.trusted)
	requireIntegrity(t, err, "downgraded repository config from an untrusted signer")
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("downgrade error = %v, want an untrusted-signer failure", err)
	}
}

// TestAttackForgedKeySlot covers DESIGN.md §13: Mallory creating a key
// slot for Bob containing her own master key must be rejected because the
// granter is not in Bob's trust list.
func TestAttackForgedKeySlot(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	bob, bobPriv := createMember(t, fx, "bob", "bob-password-1")
	mallory, malloryPriv := createMember(t, fx, "mallory", "mallory-password-4")

	// Alice grants Bob read access.
	granted, err := identity.SealSlot(fx.alicePriv, fx.repoID, bob, fx.master)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.repo.PutObject(t.Context(), identity.SlotKey(bob.Fingerprint), bytes.NewReader(granted)); err != nil {
		t.Fatal(err)
	}

	// Bob trusts only Alice.
	bobTrustDir := filepath.Join(t.TempDir(), "bob-trust")
	bobTrust := identity.NewTrustStore(bobTrustDir)
	if err := bobTrust.Add(fx.alice); err != nil {
		t.Fatal(err)
	}
	bobLookup := func(granter string) ([]byte, error) {
		fp, err := identity.ParseFingerprint(granter)
		if err != nil {
			return nil, err
		}
		ok, err := bobTrust.IsTrusted(fp)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.Join(pverrors.ErrUntrustedSigner, errors.New("unknown slot granter"))
		}
		if fp.Equal(fx.alice.Fingerprint) {
			return fx.alice.SignPublic, nil
		}
		return nil, errors.Join(pverrors.ErrUntrustedSigner, errors.New("unknown slot granter"))
	}
	bobKEM := bobPriv.KEMPrivate()
	// Control: the legitimate grant opens.
	opened, err := identity.OpenSlotTrusted(granted, fx.repoID, bob.Fingerprint, bobKEM, bobLookup)
	if err != nil {
		t.Fatalf("control slot failed to open: %v", err)
	}
	if !opened.Equal(fx.master) {
		t.Fatal("control slot opened to a different master key")
	}

	// Mallory seals her own master key to Bob and overwrites Bob's slot,
	// signing as herself.
	malloryMaster, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_ = mallory
	forged, err := identity.SealSlot(malloryPriv, fx.repoID, bob, malloryMaster)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.repo.PutObject(t.Context(), identity.SlotKey(bob.Fingerprint), bytes.NewReader(forged)); err != nil {
		t.Fatal(err)
	}
	_, err = identity.OpenSlotTrusted(forged, fx.repoID, bob.Fingerprint, bobKEM, bobLookup)
	requireIntegrity(t, err, "forged key slot from an untrusted granter")
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("forged slot error = %v, want an untrusted-signer failure", err)
	}

	// Repository-wide verification also rejects the forged slot.
	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, bobTrust, map[string][]byte{
		fx.alice.Fingerprint.String(): fx.alice.SignPublic,
	}, verify.Options{MaxChunkSize: compression.DefaultMaxSize})
	requireIntegrity(t, err, "repository verification of a forged key slot")
}

// TestAttackDeleteNewestSnapshot covers DESIGN.md §13: deleting the
// newest snapshot of a source must be detected against the client's head
// record.
func TestAttackDeleteNewestSnapshot(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "a.txt", "v1")
	first, parent := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, first, trustedLookup(fx))
	if err != nil {
		t.Fatal(err)
	}
	_ = parent
	parentEntries := make([]backup.FileEntry, 0, len(m.Files))
	for _, e := range m.Files {
		parentEntries = append(parentEntries, backup.FileEntry{
			Path: e.Path, Type: e.Type, Mode: e.Mode, Size: e.Size,
			Mtime: e.Mtime, Ctime: e.Ctime, Chunks: e.Chunks,
		})
	}
	writeSourceFile(t, src, "b.txt", "v2")
	second, _ := commitBackup(t, fx, src, "laptop", parentEntries, m.CreatedAt, first)

	if _, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fx.repo.DeleteObject(t.Context(), manifest.SnapshotPrefix+second); err != nil {
		t.Fatal(err)
	}
	_, err = verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, verify.Options{
		HeadsPath: fx.headsPath, MaxChunkSize: compression.DefaultMaxSize,
	})
	if err == nil {
		t.Fatal("verification accepted deletion of the newest snapshot, want rollback detection")
	}
	if !errors.Is(err, pverrors.ErrRollback) {
		t.Fatalf("deletion error = %v, want a rollback failure", err)
	}
	requireIntegrity(t, err, "deleted newest snapshot")
}

// TestAttackUnsafeRestorePaths covers DESIGN.md §13: manifest paths with
// .., absolute paths, or symlinks pointing outside the destination must be
// rejected at restore, with nothing written outside the destination.
func TestAttackUnsafeRestorePaths(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "ok.txt", "benign")
	goodSnap, _ := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	goodManifest, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, goodSnap, trustedLookup(fx))
	if err != nil {
		t.Fatal(err)
	}
	// Control: the benign snapshot restores.
	controlDest := t.TempDir()
	if err := restore.Restore(t.Context(), fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, goodManifest, controlDest, restore.Options{MaxChunkSize: compression.DefaultMaxSize}); err != nil {
		t.Fatalf("control restore failed: %v", err)
	}

	malicious := []struct {
		name  string
		files []manifest.File
	}{
		{
			name: "dotdot",
			files: []manifest.File{
				{Path: "../evil-attack.txt", Type: manifest.TypeFile, Mode: 0o644, Size: 0},
			},
		},
		{
			name: "absolute",
			files: []manifest.File{
				{Path: "/tmp/evil-attack-absolute.txt", Type: manifest.TypeFile, Mode: 0o644, Size: 0},
			},
		},
		{
			name: "symlink-absolute",
			files: []manifest.File{
				{Path: "link", Type: manifest.TypeSymlink, Target: "/etc/passwd"},
			},
		},
		{
			name: "symlink-escape",
			files: []manifest.File{
				{Path: "sub/link", Type: manifest.TypeSymlink, Target: "../../evil-attack-escape.txt"},
			},
		},
	}
	for _, tt := range malicious {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			snap, err := manifest.Commit(t.Context(), fx.repo, fx.sub.Data, fx.alicePriv, manifest.CommitParams{
				RepositoryID: fx.repoID, SourceID: "attacker-source-" + tt.name,
				Identity:  fx.alice.Fingerprint.String(),
				CreatedAt: testTime(), Files: tt.files, ECC: "off",
			})
			if err != nil {
				t.Fatal(err)
			}
			m, err := manifest.OpenTrusted(t.Context(), fx.repo, fx.repoID, fx.sub.Data, snap, trustedLookup(fx))
			if err != nil {
				t.Fatal(err)
			}
			parent := t.TempDir()
			dest := filepath.Join(parent, "dest")
			err = restore.Restore(t.Context(), fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, m, dest, restore.Options{MaxChunkSize: compression.DefaultMaxSize})
			requireIntegrity(t, err, "restore of "+tt.name)
			// Nothing may escape the destination.
			for _, outside := range []string{
				filepath.Join(parent, "evil-attack.txt"),
				"/tmp/evil-attack-absolute.txt",
				filepath.Join(parent, "evil-attack-escape.txt"),
			} {
				if _, statErr := os.Stat(outside); statErr == nil {
					t.Fatalf("%s wrote outside the destination to %s", tt.name, outside)
				}
			}
		})
	}
}

// TestAttackWrongKeystorePassword covers DESIGN.md §13: unlocking the
// keystore with the wrong password must fail with no partial decryption.
func TestAttackWrongKeystorePassword(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	id, err := fx.store.Create("victim", []byte("correct-password-1"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.LoadPrivate(id.Fingerprint, []byte("wrong-password-1")); err == nil {
		t.Fatal("keystore opened with the wrong password, want failure")
	}
}

// TestAttackNoClientKeys covers DESIGN.md §13: a copy of the repository
// without client keys must hold no private key material, and its key slots
// must not open.
func TestAttackNoClientKeys(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "a.txt", "no-keys victim")
	commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")

	// Walk the repository storage (not the keystore): no private halves.
	repoRoot := fx.repo.Root()
	var foundPrivate bool
	if err := filepath.WalkDir(repoRoot, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, "private.sealed") {
			foundPrivate = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if foundPrivate {
		t.Fatal("repository holds private key material, want none")
	}

	// A fresh client with no private key cannot load one and cannot open
	// the sealed slot.
	emptyStore := identity.NewStore(filepath.Join(t.TempDir(), "empty-keystore"))
	if _, err := emptyStore.LoadPrivate(fx.alice.Fingerprint, []byte("test-password-attack")); err == nil {
		t.Fatal("empty keystore loaded a private key, want failure")
	}
	slotKeys, err := fx.repo.List(t.Context(), identity.SlotPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(slotKeys) == 0 {
		t.Fatal("no key slots to attack")
	}
	r, err := fx.repo.GetObject(t.Context(), slotKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	env, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	stranger, strangerPriv := createMember(t, fx, "stranger", "stranger-password-1")
	_ = stranger
	strangerKEM := strangerPriv.KEMPrivate()
	_, err = identity.OpenSlot(env, fx.repoID, fx.alice.Fingerprint, strangerKEM, fx.alice.SignPublic)
	requireIntegrity(t, err, "key slot opened with the wrong private key")
}

// TestAttackKeyedIDsHidePlaintext covers DESIGN.md §13: hashing a known
// file offline and searching the repository must find no match, because
// chunk IDs are keyed.
func TestAttackKeyedIDsHidePlaintext(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	plaintext := "known file for confirmation attack " + strings.Repeat("x", 40)
	src := t.TempDir()
	writeSourceFile(t, src, "known.txt", plaintext)
	_, entries := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")
	if len(entries) == 0 {
		t.Fatal("no backup entries to attack")
	}
	var recorded string
	for _, e := range entries {
		if e.Path == "known.txt" {
			if len(e.Chunks) == 0 {
				t.Fatal("known file recorded no chunks")
			}
			recorded = e.Chunks[0]
		}
	}
	if recorded == "" {
		t.Fatal("known file missing from the backup")
	}

	// The attacker hashes the known file without the repository keys.
	plainSum := crypto.Sum256([]byte(plaintext))
	plainHex := pack.FormatID(plainSum)
	keyedSum, err := crypto.KeyedSum(fx.sub.ChunkID, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	keyedHex := pack.FormatID(keyedSum)
	if plainHex == keyedHex {
		t.Fatal("keyed and unkeyed hashes coincide, test is vacuous")
	}
	if recorded != keyedHex {
		t.Fatalf("recorded chunk %s does not match the keyed hash %s", recorded, keyedHex)
	}

	// Search every stored object for the unkeyed hash: it must be absent.
	for _, prefix := range []string{pack.PackPrefix, pack.IndexPrefix, manifest.SnapshotPrefix} {
		keys, err := fx.repo.List(t.Context(), prefix)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if strings.HasSuffix(k, ".ecc") {
				continue
			}
			raw := readObject(t, fx, k)
			if containsHex(raw, plainHex) {
				t.Fatalf("unkeyed hash %s found in %s: confirmation attack succeeded", plainHex, k)
			}
		}
	}
}

// TestAttackRepairWithinBudget covers DESIGN.md §13: corrupting or
// deleting a shard within the parity budget must be detected by the shard
// checksum, reconstructed, and AEAD re-verified.
func TestAttackRepairWithinBudget(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "big.bin", strings.Repeat("repairable shard contents ", 800))
	snap, _ := commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")

	packKeys, err := fx.repo.List(t.Context(), pack.PackPrefix)
	if err != nil {
		t.Fatal(err)
	}
	indexKeys, err := fx.repo.List(t.Context(), pack.IndexPrefix)
	if err != nil {
		t.Fatal(err)
	}
	snapKeys := []string{manifest.SnapshotPrefix + snap}
	packKeys = filterSidecars(packKeys)
	indexKeys = filterSidecars(indexKeys)
	if len(packKeys) == 0 || len(indexKeys) == 0 {
		t.Fatal("need a pack, an index, and a snapshot to attack")
	}

	// One damaged byte in each object type must repair and re-verify.
	packRaw := readObject(t, fx, packKeys[0])
	packSidecar := readObject(t, fx, packKeys[0]+".ecc")
	damagedPack := flipByte(packRaw, len(packRaw)/2)
	if err := erasure.Verify(damagedPack, packSidecar); err == nil {
		t.Fatal("parity accepted a damaged pack, want detection")
	}
	fixedPack, err := erasure.Repair(damagedPack, packSidecar)
	if err != nil {
		t.Fatalf("repair within budget failed: %v", err)
	}
	if err := pack.VerifyPack(fixedPack, fx.repoID, fx.sub.Data, packKeys[0]); err != nil {
		t.Fatalf("repaired pack failed AEAD verification: %v", err)
	}

	indexRaw := readObject(t, fx, indexKeys[0])
	indexSidecar := readObject(t, fx, indexKeys[0]+".ecc")
	damagedIndex := flipByte(indexRaw, len(indexRaw)/2)
	if err := erasure.Verify(damagedIndex, indexSidecar); err == nil {
		t.Fatal("parity accepted a damaged index, want detection")
	}
	fixedIndex, err := erasure.Repair(damagedIndex, indexSidecar)
	if err != nil {
		t.Fatalf("index repair within budget failed: %v", err)
	}
	if err := pack.VerifyIndex(fixedIndex, fx.repoID, fx.sub.Data, indexKeys[0]); err != nil {
		t.Fatalf("repaired index failed AEAD verification: %v", err)
	}

	snapRaw := readObject(t, fx, snapKeys[0])
	snapSidecar := readObject(t, fx, snapKeys[0]+".ecc")
	damagedSnap := flipByte(snapRaw, len(snapRaw)/2)
	if err := erasure.Verify(damagedSnap, snapSidecar); err == nil {
		t.Fatal("parity accepted a damaged snapshot, want detection")
	}
	fixedSnap, err := erasure.Repair(damagedSnap, snapSidecar)
	if err != nil {
		t.Fatalf("snapshot repair within budget failed: %v", err)
	}
	if err := manifest.VerifySnapshot(fixedSnap, fx.repoID, fx.sub.Data, snap, fx.alice.SignPublic); err != nil {
		t.Fatalf("repaired snapshot failed verification: %v", err)
	}
}

// TestAttackUnrecoverableBeyondBudget covers DESIGN.md §13: corrupting
// more shards than parity covers must report a clear unrecoverable error.
func TestAttackUnrecoverableBeyondBudget(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	src := t.TempDir()
	writeSourceFile(t, src, "big.bin", strings.Repeat("unrecoverable shard contents ", 800))
	commitBackup(t, fx, src, "laptop", nil, time.Time{}, "")

	packKeys, err := fx.repo.List(t.Context(), pack.PackPrefix)
	if err != nil {
		t.Fatal(err)
	}
	packKeys = filterSidecars(packKeys)
	if len(packKeys) == 0 {
		t.Fatal("no packs to attack")
	}
	raw := readObject(t, fx, packKeys[0])
	sidecarRaw := readObject(t, fx, packKeys[0]+".ecc")
	sidecar, err := erasure.Decode(sidecarRaw)
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.M < 1 {
		t.Fatal("sidecar has no parity budget to exceed")
	}
	shardSize := erasure.ShardSize(len(raw), sidecar.K)
	// Damage one byte in M+1 distinct shards.
	damaged := bytes.Clone(raw)
	for i := range sidecar.M + 1 {
		offset := i * shardSize
		if offset >= len(damaged) {
			t.Fatalf("object too small to damage %d shards", sidecar.M+1)
		}
		damaged[offset] ^= 0x01
	}
	_, err = erasure.Repair(damaged, sidecarRaw)
	if err == nil {
		t.Fatal("repair beyond budget succeeded, want failure")
	}
	if !errors.Is(err, pverrors.ErrUnrecoverable) {
		t.Fatalf("beyond-budget error = %v, want an unrecoverable failure", err)
	}
	requireIntegrity(t, err, "damage beyond the parity budget")
}

// TestAttackModifyScheduleJob covers DESIGN.md §13: modifying a schedule
// job file (or loosening its permissions) must cause the job to be
// refused.
func TestAttackModifyScheduleJob(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	job := scheduler.Job{
		Name: "daily-documents", Source: "/tmp/src", Repository: "/tmp/repo",
		Frequency: scheduler.FrequencyDaily, Time: "02:00", Attempts: 1,
	}
	if err := scheduler.SaveJob(dir, job); err != nil {
		t.Fatal(err)
	}
	path, err := scheduler.JobPath(dir, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.LoadJob(path); err != nil {
		t.Fatalf("control job failed to load: %v", err)
	}

	// Attacker adds an unknown (secret) field.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if !strings.HasSuffix(trimmed, "}") {
		t.Fatal("job file does not end in }")
	}
	forged := strings.TrimSuffix(trimmed, "}") + `,"password":"hunter2"}`
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.LoadJob(path); err == nil {
		t.Fatal("loaded a job with an unknown field, want refusal")
	}

	// Restore the valid job, then loosen its permissions.
	if err := scheduler.SaveJob(dir, job); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.LoadJob(path); err == nil {
		t.Fatal("loaded a group/world-readable job file, want refusal")
	}

	// Restore the valid job, then rewrite it with an invalid frequency.
	if err := scheduler.SaveJob(dir, job); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	forged = strings.Replace(string(raw), `"daily"`, `"minutely"`, 1)
	if forged == string(raw) {
		t.Fatal("could not forge the job frequency")
	}
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.LoadJob(path); err == nil {
		t.Fatal("loaded a job with an invalid frequency, want refusal")
	}
}

// TestAttackTrustListTamperedOrForged covers DESIGN.md §5.2: a hostile
// repository can withhold or roll back a published trust list but can
// neither read nor alter it. Tampering the sealed copy must fail recovery,
// and a revocation smuggled inside an otherwise valid list but signed by an
// unknown key must be rejected rather than stored.
func TestAttackTrustListTamperedOrForged(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	bob, _ := createMember(t, fx, "bob", "bob-password-trustlist-attack")
	if err := fx.trust.Add(bob); err != nil {
		t.Fatal(err)
	}
	env, err := identity.PublishTrustList(fx.alicePriv, fx.trust, testTime)
	if err != nil {
		t.Fatal(err)
	}
	key := identity.TrustListKey(fx.alice.Fingerprint)
	if err := fx.repo.PutObject(t.Context(), key, bytes.NewReader(env)); err != nil {
		t.Fatal(err)
	}

	// Control: the published copy recovers.
	raw := readObject(t, fx, key)
	fresh := identity.NewTrustStore(filepath.Join(t.TempDir(), "fresh-trust"))
	if _, err := identity.RecoverTrustList(raw, fx.alicePriv, fresh); err != nil {
		t.Fatalf("control trust-list recovery failed: %v", err)
	}

	// Attacker flips a byte of the repository copy: the outer signature
	// must fail.
	overwriteObject(t, fx, key, flipByte(raw, len(raw)/2))
	tampered := readObject(t, fx, key)
	freshTampered := identity.NewTrustStore(filepath.Join(t.TempDir(), "fresh-tampered"))
	_, err = identity.RecoverTrustList(tampered, fx.alicePriv, freshTampered)
	requireIntegrity(t, err, "tampered trust-list snapshot")

	// Attacker smuggles a forged revocation into an otherwise valid list.
	// Mallory signs Bob's revocation but is never trusted; the publisher
	// embeds it (AddRevocation checks the target, not the signer), signs
	// the outer seal honestly, and recovery must still refuse it.
	mallory, malloryPriv := createMember(t, fx, "mallory", "mallory-password-trustlist-attack")
	_ = mallory
	forged, err := identity.SignRevocation(malloryPriv, bob.Fingerprint, "forged", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.trust.AddRevocation(bob.Fingerprint, forged); err != nil {
		t.Fatal(err)
	}
	forgedEnv, err := identity.PublishTrustList(fx.alicePriv, fx.trust, testTime)
	if err != nil {
		t.Fatal(err)
	}
	freshForged := identity.NewTrustStore(filepath.Join(t.TempDir(), "fresh-forged"))
	_, err = identity.RecoverTrustList(forgedEnv, fx.alicePriv, freshForged)
	requireIntegrity(t, err, "trust list carrying a forged revocation")
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("forged revocation error = %v, want an untrusted-signer failure", err)
	}
}

// TestAttackMemberRosterForgery covers DESIGN.md §5.2: the shared member
// roster proposes trust but never grants access. A roster signed by an
// untrusted publisher, a tampered roster, or a roster replayed into another
// repository must all be rejected.
func TestAttackMemberRosterForgery(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	bob, _ := createMember(t, fx, "bob", "bob-password-roster-attack")
	if err := fx.trust.Add(bob); err != nil {
		t.Fatal(err)
	}
	env, err := identity.PublishMembers(fx.alicePriv, fx.trust, fx.sub.Data, fx.repoID, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.repo.PutObject(t.Context(), identity.MembersKey, bytes.NewReader(env)); err != nil {
		t.Fatal(err)
	}

	lookup := func(publisher string) ([]byte, error) {
		fp, err := identity.ParseFingerprint(publisher)
		if err != nil {
			return nil, err
		}
		ok, err := fx.trust.IsTrusted(fp)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.Join(pverrors.ErrUntrustedSigner, errors.New("unknown roster publisher"))
		}
		id, err := fx.trust.TrustedPublic(fp)
		if err != nil {
			return nil, err
		}
		return id.SignPublic, nil
	}

	// Control: a new machine trusting only Alice adopts Bob.
	bobTrustDir := filepath.Join(t.TempDir(), "bob-trust")
	bobTrust := identity.NewTrustStore(bobTrustDir)
	if err := bobTrust.Add(fx.alice); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.AdoptMembers(readObject(t, fx, identity.MembersKey), fx.sub.Data, fx.repoID, bobTrust, lookup); err != nil {
		t.Fatalf("control roster adoption failed: %v", err)
	}

	// Mallory publishes her own roster; Bob's client trusts only Alice.
	mallory, malloryPriv := createMember(t, fx, "mallory", "mallory-password-roster-attack")
	malloryTrust := identity.NewTrustStore(filepath.Join(t.TempDir(), "mallory-trust"))
	if err := malloryTrust.Add(mallory); err != nil {
		t.Fatal(err)
	}
	forged, err := identity.PublishMembers(malloryPriv, malloryTrust, fx.sub.Data, fx.repoID, testTime)
	if err != nil {
		t.Fatal(err)
	}
	fresh := identity.NewTrustStore(filepath.Join(t.TempDir(), "fresh-trust"))
	if err := fresh.Add(fx.alice); err != nil {
		t.Fatal(err)
	}
	_, err = identity.AdoptMembers(forged, fx.sub.Data, fx.repoID, fresh, lookup)
	requireIntegrity(t, err, "roster from an untrusted publisher")
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("forged roster error = %v, want an untrusted-signer failure", err)
	}

	// Tampered roster bytes must fail.
	rosterRaw := readObject(t, fx, identity.MembersKey)
	tampered := flipByte(rosterRaw, len(rosterRaw)/2)
	_, err = identity.AdoptMembers(tampered, fx.sub.Data, fx.repoID, fresh, lookup)
	requireIntegrity(t, err, "tampered member roster")

	// Roster replayed into another repository binds the wrong repository id.
	otherRepoID, err := repository.GenerateID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = identity.AdoptMembers(readObject(t, fx, identity.MembersKey), fx.sub.Data, otherRepoID, fresh, lookup)
	requireIntegrity(t, err, "roster replayed into another repository")
}

// TestAttackRecoveryBundleTamperedOrForged covers DESIGN.md §5.2: the
// offline recovery bundle is password-encrypted and never lives in the
// repository. Tampering, importing under the wrong identity, or smuggling a
// revocation signed by an unknown key must all fail closed.
func TestAttackRecoveryBundleTamperedOrForged(t *testing.T) {
	t.Parallel()

	fx := newFixture(t)
	bob, _ := createMember(t, fx, "bob", "bob-password-bundle-attack")
	if err := fx.trust.Add(bob); err != nil {
		t.Fatal(err)
	}
	headsDir := t.TempDir()
	bundlePassword := []byte("bundle-password-attack")
	fileBytes, _, err := recovery.Export(fx.store, fx.trust, headsDir, fx.alice.Fingerprint, bundlePassword, testTime)
	if err != nil {
		t.Fatal(err)
	}

	newEnv := func() (*identity.Store, *identity.TrustStore, string) {
		root := t.TempDir()
		return identity.NewStore(filepath.Join(root, "identities")),
			identity.NewTrustStore(filepath.Join(root, "trust")),
			filepath.Join(root, "heads")
	}

	// Tampered bundle bytes must fail authentication.
	tampered := bytes.Clone(fileBytes)
	tampered[len(tampered)/2] ^= 0x01
	freshStore, freshTrust, freshHeads := newEnv()
	_, err = recovery.Import(freshStore, freshTrust, freshHeads, tampered, bundlePassword, []byte("test-password-attack"), fx.alice.Fingerprint)
	requireIntegrity(t, err, "tampered recovery bundle")

	// A bundle for Alice must not import as Bob.
	freshStore, freshTrust, freshHeads = newEnv()
	_, err = recovery.Import(freshStore, freshTrust, freshHeads, fileBytes, bundlePassword, []byte("test-password-attack"), bob.Fingerprint)
	requireIntegrity(t, err, "recovery bundle imported under the wrong identity")

	// A revocation signed by an unknown key smuggled into the bundle must
	// be rejected even though the outer password box is intact.
	mallory, malloryPriv := createMember(t, fx, "mallory", "mallory-password-bundle-attack")
	_ = mallory
	forged, err := identity.SignRevocation(malloryPriv, bob.Fingerprint, "forged", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.trust.AddRevocation(bob.Fingerprint, forged); err != nil {
		t.Fatal(err)
	}
	forgedBytes, _, err := recovery.Export(fx.store, fx.trust, headsDir, fx.alice.Fingerprint, bundlePassword, testTime)
	if err != nil {
		t.Fatal(err)
	}
	freshStore, freshTrust, freshHeads = newEnv()
	_, err = recovery.Import(freshStore, freshTrust, freshHeads, forgedBytes, bundlePassword, []byte("test-password-attack"), fx.alice.Fingerprint)
	requireIntegrity(t, err, "recovery bundle carrying a forged revocation")
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("forged bundle revocation error = %v, want an untrusted-signer failure", err)
	}
}

func filterSidecars(keys []string) []string {
	out := keys[:0]
	for _, k := range keys {
		if strings.HasSuffix(k, ".ecc") {
			continue
		}
		out = append(out, k)
	}
	return out
}

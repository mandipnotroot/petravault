// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package attack_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"petravault/internal/backup"
	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
	"petravault/internal/manifest"
	"petravault/internal/pack"
	"petravault/internal/recovery"
	"petravault/internal/repository"
	"petravault/internal/restore"
	"petravault/internal/verify"
)

func TestAuditLocalRepositorySymlinkEscape(t *testing.T) {
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Remove(filepath.Join(repo.Root(), "locks")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo.Root(), "locks")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := repo.PutObjectIfAbsent(t.Context(), "locks/sentinel", bytes.NewBufferString("dummy")); err == nil {
		t.Error("repository write followed an escaping parent symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "sentinel")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside sentinel was created: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "sentinel"), []byte("unchanged dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r, err := repo.GetObject(t.Context(), "locks/sentinel"); err == nil {
		_ = r.Close()
		t.Error("repository read followed an escaping parent symlink")
	}
	if r, err := repo.GetRange(t.Context(), "locks/sentinel", 0, 1); err == nil {
		_ = r.Close()
		t.Error("repository range followed an escaping parent symlink")
	}
	if err := repo.PutObject(t.Context(), "locks/sentinel", bytes.NewBufferString("replacement")); err == nil {
		t.Error("repository replacement followed an escaping parent symlink")
	}
	if err := repo.DeleteObject(t.Context(), "locks/sentinel"); err == nil {
		t.Error("repository deletion followed an escaping parent symlink")
	}
	if raw, err := os.ReadFile(filepath.Join(outside, "sentinel")); err != nil || string(raw) != "unchanged dummy" {
		t.Fatalf("outside sentinel changed: %q, err=%v", raw, err)
	}
	if err := os.Symlink(filepath.Join(outside, "sentinel"), filepath.Join(repo.Root(), "leaf")); err != nil {
		t.Fatal(err)
	}
	if r, err := repo.GetObject(t.Context(), "leaf"); err == nil {
		_ = r.Close()
		t.Error("repository read followed an escaping leaf symlink")
	}
}

func TestAuditUnicodeRecursiveExclusion(t *testing.T) {
	for _, pattern := range []string{"**/?.key", "**/[é].key", "**/[à-ê].key"} {
		m, err := backup.NewMatcher([]string{pattern})
		if err != nil {
			t.Fatal(err)
		}
		if !m.Excluded("a/b/é.key", false) {
			t.Errorf("%q did not exclude a Unicode filename", pattern)
		}
	}
}

func TestAuditEntireRecordedSourceDeleted(t *testing.T) {
	for _, otherSource := range []bool{false, true} {
		name := "empty-repository"
		if otherSource {
			name = "another-source-survives"
		}
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t)
			src := t.TempDir()
			writeSourceFile(t, src, "dummy.txt", "dummy backup")
			id, _ := commitBackup(t, fx, src, "deleted-source", nil, time.Time{}, "")
			if otherSource {
				commitBackup(t, fx, src, "surviving-source", nil, time.Time{}, "")
			}
			opts := verify.Options{HeadsPath: fx.headsPath, MaxChunkSize: 4096}
			if _, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, opts); err != nil {
				t.Fatal(err)
			}
			if err := fx.repo.DeleteObject(t.Context(), manifest.SnapshotPrefix+id); err != nil {
				t.Fatal(err)
			}
			if _, err := verify.Verify(t.Context(), fx.repo, fx.repoCfg, fx.sub.Data, fx.sub.ChunkID, fx.trust, fx.trusted, opts); !errors.Is(err, pverrors.ErrRollback) {
				t.Fatalf("deletion of the whole recorded source: %v, want rollback", err)
			}
		})
	}
}

func TestAuditRemovedRevocationsSurviveRecovery(t *testing.T) {
	fx := newFixture(t)
	bob, _ := createMember(t, fx, "bob", "dummy-bob-password")
	if err := fx.trust.Add(bob); err != nil {
		t.Fatal(err)
	}
	env, err := identity.SignRevocation(fx.alicePriv, bob.Fingerprint, "dummy revocation", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.trust.AddRevocation(bob.Fingerprint, env); err != nil {
		t.Fatal(err)
	}
	if err := fx.trust.Remove(bob.Fingerprint); err != nil {
		t.Fatal(err)
	}
	t.Run("published-list", func(t *testing.T) {
		raw, err := identity.PublishTrustList(fx.alicePriv, fx.trust, testTime)
		if err != nil {
			t.Fatal(err)
		}
		dest := identity.NewTrustStore(t.TempDir())
		if _, err := identity.RecoverTrustList(raw, fx.alicePriv, dest); err != nil {
			t.Fatal(err)
		}
		if revoked, err := dest.IsRevoked(bob.Fingerprint); err != nil || !revoked {
			t.Fatalf("removed member's revocation lost: revoked=%v err=%v", revoked, err)
		}
	})
	t.Run("offline-bundle", func(t *testing.T) {
		raw, _, err := recovery.Export(fx.store, fx.trust, fx.alice.Fingerprint, []byte("dummy-bundle"), testTime)
		if err != nil {
			t.Fatal(err)
		}
		dest := identity.NewTrustStore(t.TempDir())
		if _, err := recovery.Import(identity.NewStore(t.TempDir()), dest, raw, []byte("dummy-bundle"), []byte("test-password-attack"), fx.alice.Fingerprint); err != nil {
			t.Fatal(err)
		}
		if revoked, err := dest.IsRevoked(bob.Fingerprint); err != nil || !revoked {
			t.Fatalf("removed member's revocation lost: revoked=%v err=%v", revoked, err)
		}
	})
}

func TestAuditRejectedRecoveryDoesNotGrantTrust(t *testing.T) {
	fx := newFixture(t)
	bob, _ := createMember(t, fx, "bob", "dummy-bob-password")
	carol, carolPriv := createMember(t, fx, "carol", "dummy-carol-password")
	for _, id := range []*identity.Identity{bob, carol} {
		if err := fx.trust.Add(id); err != nil {
			t.Fatal(err)
		}
	}
	env, err := identity.SignRevocation(carolPriv, bob.Fingerprint, "dummy revocation", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.trust.AddRevocation(bob.Fingerprint, env); err != nil {
		t.Fatal(err)
	}
	if err := fx.trust.Remove(carol.Fingerprint); err != nil {
		t.Fatal(err)
	}
	raw, err := identity.PublishTrustList(fx.alicePriv, fx.trust, testTime)
	if err != nil {
		t.Fatal(err)
	}
	dest := identity.NewTrustStore(t.TempDir())
	_, recoverErr := identity.RecoverTrustList(raw, fx.alicePriv, dest)
	if trusted, err := dest.IsTrusted(bob.Fingerprint); err != nil || trusted {
		t.Fatalf("recovery result %v left revoked member trusted=%v, err=%v", recoverErr, trusted, err)
	}
	bundle, _, err := recovery.Export(fx.store, fx.trust, fx.alice.Fingerprint, []byte("dummy-bundle"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	bundleDest := identity.NewTrustStore(t.TempDir())
	_, importErr := recovery.Import(identity.NewStore(t.TempDir()), bundleDest, bundle, []byte("dummy-bundle"), []byte("test-password-attack"), fx.alice.Fingerprint)
	if trusted, err := bundleDest.IsTrusted(bob.Fingerprint); err != nil || trusted {
		t.Fatalf("bundle result %v left revoked member trusted=%v, err=%v", importErr, trusted, err)
	}
}

func TestAuditPruneSurvivorAuthenticatesBlobs(t *testing.T) {
	fx := newFixture(t)
	w := pack.NewWriter(fx.repoID, fx.sub.Data, 1<<20)
	plain := []byte("dummy retained chunk")
	id, err := crypto.KeyedSum(fx.sub.ChunkID, plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Add(id, plain); err != nil {
		t.Fatal(err)
	}
	key, err := w.Flush(t.Context(), fx.repo, "off")
	if err != nil {
		t.Fatal(err)
	}
	poisoned := readObject(t, fx, key)
	poisoned[len(poisoned)-1] ^= 1
	poisonKey := pack.PackPrefix + pack.FormatID(crypto.Sum256(poisoned))
	overwriteObject(t, fx, poisonKey, poisoned)
	if err := pack.VerifyPack(poisoned, fx.repoID, fx.sub.Data, poisonKey); !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("fixture must have an invalid blob: %v", err)
	}
	if _, err := pack.ListPackEntries(t.Context(), fx.repo, fx.repoID, fx.sub.Data, poisonKey); !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("maintenance accepted a forged survivor: %v", err)
	}
}

func TestAuditECCRebuildPreservesRequiredRecovery(t *testing.T) {
	fx := newFixture(t)
	w := pack.NewWriter(fx.repoID, fx.sub.Data, 1<<20)
	plain := []byte("dummy repairable chunk")
	id, err := crypto.KeyedSum(fx.sub.ChunkID, plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Add(id, plain); err != nil {
		t.Fatal(err)
	}
	key, err := w.Flush(t.Context(), fx.repo, "medium")
	if err != nil {
		t.Fatal(err)
	}
	damaged := readObject(t, fx, key)
	damaged[len(damaged)-1] ^= 1
	overwriteObject(t, fx, key, damaged)
	check := func(key string, raw []byte) error { return pack.VerifyPack(raw, fx.repoID, fx.sub.Data, key) }
	if err := repository.Rebuild(t.Context(), fx.repo, "off", check); !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("rebuild discarded required recovery material: %v", err)
	}
	repaired, err := repository.RepairObject(t.Context(), fx.repo, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := check(key, repaired); err != nil {
		t.Fatalf("old recovery material no longer repairs the object: %v", err)
	}
}

func TestAuditComposedSymlinkEscape(t *testing.T) {
	fx := newFixture(t)
	m := manifest.Manifest{RepositoryID: fx.repoID, Files: []manifest.File{
		{Path: "a", Type: manifest.TypeSymlink, Target: "b/../outside.txt"},
		{Path: "b", Type: manifest.TypeSymlink, Target: "."},
	}}
	if err := restore.Restore(t.Context(), fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, m, t.TempDir(), restore.Options{}); !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("restore accepted a composed escaping symlink: %v", err)
	}
}

func TestAuditStaleHeadUpdateCannotRegress(t *testing.T) {
	file := filepath.Join(t.TempDir(), "heads.json")
	old := strings.Repeat("ab", 32)
	newer := strings.Repeat("cd", 32)
	if err := verify.UpdateHead(file, "source", old, testTime); err != nil {
		t.Fatal(err)
	}
	expected, err := verify.LoadHeads(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify.UpdateHead(file, "source", newer, testTime); err != nil {
		t.Fatal(err)
	}
	if err := verify.CompareAndUpdateTips(file, map[string]string{"source": old}, expected, testTime); !errors.Is(err, pverrors.ErrRollback) {
		t.Fatalf("stale head update: %v, want rollback rejection", err)
	}
	heads, err := verify.LoadHeads(file)
	if err != nil || heads["source"].Snapshot != newer {
		t.Fatalf("newer head was lost: %v, err=%v", heads, err)
	}
}

func TestAuditSafeRelativeSymlinkStillRestores(t *testing.T) {
	fx := newFixture(t)
	m := manifest.Manifest{RepositoryID: fx.repoID, Files: []manifest.File{
		{Path: "dir", Type: manifest.TypeDir, Mode: 0o755},
		{Path: "dir/link", Type: manifest.TypeSymlink, Target: "../target"},
		{Path: "target", Type: manifest.TypeFile},
	}}
	dest := t.TempDir()
	if err := restore.Restore(t.Context(), fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, m, dest, restore.Options{}); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(dest, "dir", "link")); err != nil || target != "../target" {
		t.Fatalf("safe relative link changed: %q, err=%v", target, err)
	}
}

func TestAuditPartialRestoreDoesNotLeaveEscapingLink(t *testing.T) {
	fx := newFixture(t)
	dest := t.TempDir()
	if err := os.Symlink(".", filepath.Join(dest, "b")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	m := manifest.Manifest{RepositoryID: fx.repoID, Files: []manifest.File{
		{Path: "a", Type: manifest.TypeSymlink, Target: "b/../outside.txt"},
		{Path: "b", Type: manifest.TypeSymlink, Target: "dir"},
		{Path: "dir", Type: manifest.TypeDir, Mode: 0o755},
	}}
	if err := restore.Restore(t.Context(), fx.repo, fx.repoID, fx.sub.Data, fx.sub.ChunkID, m, dest, restore.Options{}); err == nil {
		t.Fatal("restore unexpectedly replaced an existing link")
	}
	if _, err := os.Lstat(filepath.Join(dest, "a")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed restore left the escaping link: %v", err)
	}
}

func TestAuditConcurrentHeadUpdatesPreserveSources(t *testing.T) {
	file := filepath.Join(t.TempDir(), "heads.json")
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, source := range []string{"first", "second"} {
		wg.Go(func() {
			<-start
			var err error
			deadline := time.Now().Add(2 * time.Second)
			for {
				err = verify.CompareAndUpdateTips(file, map[string]string{source: strings.Repeat("ab", 32)}, nil, testTime)
				if err == nil || !errors.Is(err, os.ErrExist) || time.Now().After(deadline) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			results <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	heads, err := verify.LoadHeads(file)
	if err != nil || len(heads) != 2 {
		t.Fatalf("concurrent source update lost a record: %v, err=%v", heads, err)
	}
}

func TestAuditLocalRepositoryRootReplacement(t *testing.T) {
	parent := t.TempDir()
	name := filepath.Join(parent, "repository")
	repo, err := repository.Init(name)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	moved := filepath.Join(parent, "moved-repository")
	if err := os.Rename(name, moved); err != nil {
		t.Skipf("open-directory rename unavailable: %v", err)
	}
	if err := os.Symlink(outside, name); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := repo.PutObject(t.Context(), "locks/dummy", bytes.NewBufferString("dummy")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "locks", "dummy")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root replacement redirected a write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "locks", "dummy")); err != nil {
		t.Fatalf("write did not stay with the opened repository: %v", err)
	}
}

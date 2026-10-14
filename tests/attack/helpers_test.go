// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package attack_test exercises the attack-simulation table in DESIGN.md
// §13. Each test names one row of that table and asserts the expected
// rejection or recovery. The suite runs a real local repository end to
// end: identity creation, repository init, backup, signed snapshot commit,
// verification, and restore.
package attack_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"petravault/internal/backup"
	"petravault/internal/chunking"
	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
	"petravault/internal/manifest"
	"petravault/internal/repository"
)

func testChunkingParams() chunking.Params {
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
	store     *identity.Store
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
	alice, err := store.Create("alice", []byte("test-password-attack"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	trust := identity.NewTrustStore(trustDir)
	if err := trust.Add(alice); err != nil {
		t.Fatal(err)
	}
	alicePriv, err := store.LoadPrivate(alice.Fingerprint, []byte("test-password-attack"))
	if err != nil {
		t.Fatal(err)
	}
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repoID, err := repository.GenerateID()
	if err != nil {
		t.Fatal(err)
	}
	repoCfg, err := repository.NewConfig(repoID, testChunkingParams(), 1<<20, "medium", testTime)
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
		repo:      repo,
		repoCfg:   repoCfg,
		repoID:    repoID,
		master:    master,
		sub:       sub,
		alice:     alice,
		alicePriv: alicePriv,
		store:     store,
		trust:     trust,
		trusted:   map[string][]byte{alice.Fingerprint.String(): alice.SignPublic},
		headsPath: headsPath,
	}
}

func writeSourceFile(t *testing.T, dir, name, data string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func backupEntriesToManifest(in []backup.FileEntry) []manifest.File {
	out := make([]manifest.File, 0, len(in))
	for _, e := range in {
		out = append(out, manifest.File{
			Path:   e.Path,
			Type:   e.Type,
			Mode:   e.Mode,
			UID:    e.UID,
			GID:    e.GID,
			Size:   e.Size,
			Inode:  e.Inode,
			Mtime:  e.Mtime,
			Ctime:  e.Ctime,
			Target: e.Target,
			Chunks: e.Chunks,
		})
	}
	return out
}

// commitBackup backs up src for sourceID and commits the snapshot, returning
// the snapshot ID hex and the backup entries for the next incremental run.
func commitBackup(t *testing.T, fx *fixture, src, sourceID string, parent []backup.FileEntry, parentStart time.Time, parentID string) (string, []backup.FileEntry) {
	t.Helper()
	ctx := t.Context()
	res, err := backup.Backup(ctx, fx.repo, backup.Options{
		Source:         src,
		RepositoryID:   fx.repoID,
		Master:         fx.master,
		SourceID:       sourceID,
		Parent:         parent,
		ParentStart:    parentStart,
		Chunking:       testChunkingParams(),
		TargetPackSize: 1 << 20,
		ECC:            "medium",
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := manifest.Commit(ctx, fx.repo, fx.sub.Data, fx.alicePriv, manifest.CommitParams{
		RepositoryID: fx.repoID,
		SourceID:     sourceID,
		Parent:       parentID,
		Identity:     fx.alice.Fingerprint.String(),
		CreatedAt:    res.StartedAt,
		Files:        backupEntriesToManifest(res.Files),
		ECC:          "medium",
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, res.Files
}

func readObject(t *testing.T, fx *fixture, key string) []byte {
	t.Helper()
	r, err := fx.repo.GetObject(t.Context(), key)
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

func overwriteObject(t *testing.T, fx *fixture, key string, data []byte) {
	t.Helper()
	if err := fx.repo.PutObject(t.Context(), key, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
}

func flipByte(raw []byte, offset int) []byte {
	out := bytes.Clone(raw)
	out[offset] ^= 0x01
	return out
}

func requireIntegrity(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s accepted, want an integrity failure", what)
	}
	if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("%s error = %v, want a failure wrapping ErrIntegrity", what, err)
	}
	if got := pverrors.ExitCode(err); got != pverrors.ExitIntegrity {
		t.Fatalf("%s exit code = %d, want %d", what, got, pverrors.ExitIntegrity)
	}
}

func trustedLookup(fx *fixture) func(string) ([]byte, error) {
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
			return nil, errors.Join(pverrors.ErrUntrustedSigner, errors.New("untrusted snapshot signer"))
		}
		pub, ok := fx.trusted[fp.String()]
		if !ok {
			return nil, errors.Join(pverrors.ErrUntrustedSigner, errors.New("untrusted snapshot signer"))
		}
		return pub, nil
	}
}

func createMember(t *testing.T, fx *fixture, name, password string) (*identity.Identity, *identity.PrivateIdentity) {
	t.Helper()
	id, err := fx.store.Create(name, []byte(password), testTime)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := fx.store.LoadPrivate(id.Fingerprint, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	return id, priv
}

func containsHex(haystack []byte, hexID string) bool {
	return bytes.Contains(haystack, []byte(hexID))
}

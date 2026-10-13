// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"petravault/internal/backup"
	"petravault/internal/chunking"
	"petravault/internal/config"
	"petravault/internal/crypto"
	"petravault/internal/identity"
	"petravault/internal/manifest"
	"petravault/internal/repository"
	"petravault/internal/verify"

	pverrors "petravault/internal/errors"
)

// resolveRepoPath picks the repository for every command except init and
// refuses S3 addresses until the S3 backend lands (phase 9).
func resolveRepoPath(cfg config.Config, flag string) (string, error) {
	repoPath := cfg.ResolveRepository(flag)
	if repoPath == "" {
		return "", fmt.Errorf("%w: no repository selected (use --repository, PETRAVAULT_REPOSITORY, or default_repository)", pverrors.ErrUsage)
	}
	if strings.HasPrefix(repoPath, "s3:") {
		return "", fmt.Errorf("%w: s3 repositories are not supported yet", pverrors.ErrUsage)
	}
	return repoPath, nil
}

// openVerifiedRepo opens the local repository and verifies its signed
// config against the client-local trust list. It returns the repository,
// its verified config, and the trust material callers need to open key
// slots and snapshots.
func openVerifiedRepo(ctx context.Context, repoPath string) (*repository.Local, repository.Config, *identity.TrustStore, map[string][]byte, error) {
	repo := repository.NewLocal(repoPath)
	trust := identity.NewTrustStore(trustDir())
	trusted, err := listTrustedSigners(trust)
	if err != nil {
		return nil, repository.Config{}, nil, nil, err
	}
	repoCfg, _, err := repository.ReadConfig(ctx, repo, trusted)
	if err != nil {
		return nil, repository.Config{}, nil, nil, err
	}
	return repo, repoCfg, trust, trusted, nil
}

// openMaster unlocks the signer's private identity and opens its key slot,
// proving the signer holds read access. The granter must be in the client's
// own trust list; a slot signed by anyone else is refused.
func openMaster(ctx context.Context, f *flags, cfg config.Config, repo *repository.Local, trust *identity.TrustStore, repoID string) (crypto.SecretKey, *identity.PrivateIdentity, *identity.Identity, error) {
	signer, err := resolveSigner(f, cfg)
	if err != nil {
		return crypto.SecretKey{}, nil, nil, err
	}
	password, err := identity.ReadPassword(ctx, "Enter password for identity: ")
	if err != nil {
		return crypto.SecretKey{}, nil, nil, err
	}
	defer clear(password)
	priv, err := identity.NewStore(keystoreDir()).LoadPrivate(signer.Fingerprint, password)
	if err != nil {
		return crypto.SecretKey{}, nil, nil, err
	}
	master, err := openGranterSlot(ctx, repo, trust, repoID, priv)
	if err != nil {
		return crypto.SecretKey{}, nil, nil, err
	}
	return master, priv, signer, nil
}

// trustedLookup returns a manifest signer lookup over the client-local
// trust list. Unknown or revoked identities map to ErrUntrustedSigner; the
// hint is never trusted until verification with the looked-up key succeeds.
func trustedLookup(trust *identity.TrustStore, trusted map[string][]byte) func(string) ([]byte, error) {
	return func(hint string) ([]byte, error) {
		fp, err := identity.ParseFingerprint(hint)
		if err != nil {
			return nil, err
		}
		ok, err := trust.IsTrusted(fp)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: snapshot signer %s", pverrors.ErrUntrustedSigner, fp.Grouped())
		}
		pub, ok := trusted[fp.String()]
		if !ok {
			return nil, fmt.Errorf("%w: snapshot signer %s", pverrors.ErrUntrustedSigner, fp.Grouped())
		}
		return pub, nil
	}
}

// headsPathForRepo returns the client-local head-record file for repoID.
func headsPathForRepo(repoID string) (string, error) {
	return verify.HeadsPath(config.StateDir(), repoID)
}

// chunkingFromConfig returns the frozen chunking parameters recorded at
// init. Switching algorithms later only costs dedup efficiency; existing
// snapshots always restore.
func chunkingFromConfig(repoCfg repository.Config) chunking.Params {
	return chunking.Params{
		MinSize:     repoCfg.ChunkMin,
		AverageSize: repoCfg.ChunkAverage,
		MaxSize:     repoCfg.ChunkMax,
	}
}

// backupToManifest converts backup file entries to manifest entries. The
// two structs share their JSON shape by design; the conversion stays
// explicit so neither orchestration layer imports the other.
func backupToManifest(files []backup.FileEntry) []manifest.File {
	out := make([]manifest.File, 0, len(files))
	for _, e := range files {
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
			Chunks: slices.Clone(e.Chunks),
		})
	}
	return out
}

// manifestToBackup converts manifest entries to backup parent entries for
// the unchanged-file fast path.
func manifestToBackup(files []manifest.File) []backup.FileEntry {
	out := make([]backup.FileEntry, 0, len(files))
	for _, e := range files {
		out = append(out, backup.FileEntry{
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
			Chunks: slices.Clone(e.Chunks),
		})
	}
	return out
}

// parentForSource finds the current tip snapshot for sourceID among trusted
// snapshots. Untrusted snapshots are skipped: a backup never reuses chunk
// lists from a signer the client does not trust. It returns the tip ID
// (empty for the first backup), its entries for the fast path, and its
// creation time for the racily-clean guard. A forked chain is an integrity
// failure, never a silent pick of a winner.
func parentForSource(ctx context.Context, repo *repository.Local, repoID, sourceID string, dataKey crypto.SecretKey, trust *identity.TrustStore, trusted map[string][]byte) (string, []backup.FileEntry, time.Time, error) {
	ids, err := manifest.List(ctx, repo)
	if err != nil {
		return "", nil, time.Time{}, err
	}
	lookup := trustedLookup(trust, trusted)
	type candidate struct {
		id string
		m  manifest.Manifest
	}
	var owned []candidate
	for _, id := range ids {
		m, err := manifest.OpenTrusted(ctx, repo, repoID, dataKey, id, lookup)
		if err != nil {
			if errors.Is(err, pverrors.ErrUntrustedSigner) || errors.Is(err, pverrors.ErrBadSignature) {
				continue
			}
			return "", nil, time.Time{}, fmt.Errorf("read parent snapshots: %w", err)
		}
		if m.SourceID != sourceID {
			continue
		}
		owned = append(owned, candidate{id: id, m: m})
	}
	if len(owned) == 0 {
		return "", nil, time.Time{}, nil
	}
	byID := make(map[string]candidate, len(owned))
	for _, c := range owned {
		byID[c.id] = c
	}
	children := make(map[string][]string)
	var roots []string
	for _, c := range owned {
		if c.m.Parent == "" {
			roots = append(roots, c.id)
			continue
		}
		parent := strings.ToLower(strings.TrimSpace(c.m.Parent))
		if _, ok := byID[parent]; !ok {
			return "", nil, time.Time{}, fmt.Errorf("%w: parent %s of %s is missing", pverrors.ErrIntegrity, parent, c.id)
		}
		children[parent] = append(children[parent], c.id)
	}
	if len(roots) > 1 {
		return "", nil, time.Time{}, fmt.Errorf("%w: source %q has %d roots: chain is forked", pverrors.ErrIntegrity, sourceID, len(roots))
	}
	for parent, kids := range children {
		if len(kids) > 1 {
			slices.Sort(kids)
			return "", nil, time.Time{}, fmt.Errorf("%w: source %q parent %s has %d children: chain is forked", pverrors.ErrIntegrity, sourceID, parent, len(kids))
		}
	}
	isParent := make(map[string]bool)
	for parent := range children {
		isParent[parent] = true
	}
	var tips []string
	for _, c := range owned {
		if !isParent[c.id] {
			tips = append(tips, c.id)
		}
	}
	if len(tips) != 1 {
		return "", nil, time.Time{}, fmt.Errorf("%w: source %q has %d tips, want 1", pverrors.ErrIntegrity, sourceID, len(tips))
	}
	tip := byID[tips[0]]
	return tip.id, manifestToBackup(tip.m.Files), tip.m.CreatedAt, nil
}

// defaultSourceID returns flag or the machine hostname.
func defaultSourceID(flag string) (string, error) {
	if strings.TrimSpace(flag) != "" {
		return strings.TrimSpace(flag), nil
	}
	name, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("resolve source id: %w", err)
	}
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%w: hostname is empty (use --source-id)", pverrors.ErrUsage)
	}
	return name, nil
}

// eccForRun returns the per-run ECC setting: the flag when set, otherwise
// the repository default.
func eccForRun(flag string, repoCfg repository.Config) string {
	return cmp.Or(strings.TrimSpace(flag), repoCfg.ECC)
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// resolveRepoPath picks the repository for every command except init:
// --repository, then PETRAVAULT_REPOSITORY, then default_repository.
func resolveRepoPath(cfg config.Config, flag string) (string, error) {
	repoPath := cfg.ResolveRepository(flag)
	if repoPath == "" {
		return "", fmt.Errorf("%w: no repository selected (use --repository, PETRAVAULT_REPOSITORY, or default_repository; run `petravault init <path>` to create one)", pverrors.ErrUsage)
	}
	return repoPath, nil
}

// s3OptionsForConfig maps the human-edited S3 settings to client options.
// Credentials never appear here; the SDK-standard chain supplies them
// (DESIGN.md §7, §8).
func s3OptionsForConfig(cfg config.Config) repository.S3Options {
	return repository.S3Options{
		Profile: cfg.S3.Profile,
		Region:  cfg.S3.Region,
	}
}

// openRepo opens the repository at repoPath: an S3 repository for
// s3:<bucket>[/<prefix>] addresses, a local one otherwise (DESIGN.md §8).
func openRepo(ctx context.Context, cfg config.Config, repoPath string) (repository.Repository, error) {
	return repository.Open(ctx, repoPath, s3OptionsForConfig(cfg))
}

// openVerifiedRepo opens the repository and verifies its signed
// config against the client-local trust list. It returns the repository,
// its verified config, and the trust material callers need to open key
// slots and snapshots. A config signed by a revoked or removed key is
// refused outright (DESIGN.md §5): a surviving trusted member re-signs it
// with `ecc set`.
func openVerifiedRepo(ctx context.Context, cfg config.Config, repoPath string) (repository.Repository, repository.Config, *identity.TrustStore, map[string][]byte, error) {
	repo, err := openRepo(ctx, cfg, repoPath)
	if err != nil {
		return nil, repository.Config{}, nil, nil, err
	}
	trust := identity.NewTrustStore(trustDir())
	trusted, err := listTrustedSigners(trust)
	if err != nil {
		return nil, repository.Config{}, nil, nil, err
	}
	repoCfg, signer, err := repository.ReadConfig(ctx, repo, trusted)
	if err != nil {
		return nil, repository.Config{}, nil, nil, err
	}
	if err := requireTrustedConfigSigner(trust, signer); err != nil {
		return nil, repository.Config{}, nil, nil, err
	}
	return repo, repoCfg, trust, trusted, nil
}

// requireTrustedConfigSigner refuses a repository config whose signer is
// revoked or removed from the client-local trust list. Revocation
// disqualifies new trust unconditionally; history stays readable only after
// a surviving member re-signs the config.
func requireTrustedConfigSigner(trust *identity.TrustStore, signer string) error {
	fp, err := identity.ParseFingerprint(signer)
	if err != nil {
		return err
	}
	ok, err := trust.IsTrusted(fp)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: repository config signer %s is revoked or removed (have a surviving member re-sign it with `ecc set`)", pverrors.ErrUntrustedSigner, fp.Grouped())
	}
	return nil
}

// unlockPrivate prompts for the keystore password and loads the private
// identity for fp. The password buffer is cleared before return; the
// caller owns the returned identity and must Zero it when finished.
func unlockPrivate(ctx context.Context, fp identity.Fingerprint, prompt string) (*identity.PrivateIdentity, error) {
	password, err := identity.ReadPassword(ctx, prompt)
	if err != nil {
		return nil, err
	}
	defer clear(password)
	return identity.NewStore(keystoreDir()).LoadPrivate(fp, password)
}

// openMaster unlocks the signer's private identity and opens its key slot,
// proving the signer holds read access. The granter must be in the client's
// own trust list; a slot signed by anyone else is refused.
func openMaster(ctx context.Context, f *flags, cfg config.Config, repo repository.Repository, trust *identity.TrustStore, repoID string) (crypto.SecretKey, *identity.PrivateIdentity, *identity.Identity, error) {
	signer, err := resolveSigner(f, cfg)
	if err != nil {
		return crypto.SecretKey{}, nil, nil, err
	}
	priv, err := unlockPrivate(ctx, signer.Fingerprint, "Enter password for identity: ")
	if err != nil {
		return crypto.SecretKey{}, nil, nil, err
	}
	master, err := openGranterSlot(ctx, repo, trust, repoID, priv)
	if err != nil {
		return crypto.SecretKey{}, nil, nil, err
	}
	return master, priv, signer, nil
}

// withGCLock acquires the maintenance lock for operation, starts its
// heartbeat, runs fn, then stops the heartbeat and releases the lock.
// Contention fails closed with refuseMsg (usage error); release failures
// are logged, never silently ignored. Callers that must wait out backups
// (prune) do so inside fn to keep the documented lock ordering
// (DESIGN.md §10.2); callers that must not wait (ecc rebuild) omit it.
func withGCLock(ctx context.Context, repo repository.Repository, operation, holder, refuseMsg string, logger *slog.Logger, fn func() error) error {
	acquired, err := repository.TryAcquireGCLock(ctx, repo, operation, holder, repository.DefaultHost(), repository.DefaultLockTTL, time.Now)
	if err != nil {
		return err
	}
	if !acquired {
		return fmt.Errorf("%w: %s", pverrors.ErrUsage, refuseMsg)
	}
	stop := repository.StartHeartbeat(ctx, repo, repository.GCLockKey, operation, holder, repository.DefaultHost(), repository.DefaultHeartbeatInterval, time.Now, logger)
	defer func() {
		stop()
		if err := repository.ReleaseGCLock(ctx, repo); err != nil {
			logger.WarnContext(ctx, "release maintenance lock failed", slog.Any("error", err))
		}
	}()
	return fn()
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
func parentForSource(ctx context.Context, repo repository.Repository, repoID, sourceID string, dataKey crypto.SecretKey, trust *identity.TrustStore, trusted map[string][]byte) (string, []backup.FileEntry, time.Time, error) {
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
	for _, c := range owned {
		if c.m.Parent == "" {
			continue
		}
		parent := strings.ToLower(strings.TrimSpace(c.m.Parent))
		if _, ok := byID[parent]; !ok {
			// Pruned history: the parent is gone and this snapshot is a
			// new root. Not an error (see prune package docs).
			continue
		}
		children[parent] = append(children[parent], c.id)
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

// resolveSnapshotID accepts a snapshot ID or the keyword "latest" (any
// case). "latest" resolves to the newest trusted snapshot by creation time
// so operators can restore or verify without copying IDs.
func resolveSnapshotID(ctx context.Context, repo repository.Repository, repoID string, dataKey crypto.SecretKey, trust *identity.TrustStore, trusted map[string][]byte, input string) (string, error) {
	if strings.EqualFold(strings.TrimSpace(input), "latest") {
		return latestSnapshotID(ctx, repo, repoID, dataKey, trust, trusted)
	}
	id, err := manifest.ParseSnapshotID(input)
	if err != nil {
		return "", fmt.Errorf("%w: %w (use a snapshot ID or `latest`)", pverrors.ErrUsage, err)
	}
	return manifest.FormatSnapshotID(id), nil
}

// latestSnapshotID returns the newest trusted snapshot by creation time.
// Untrusted or damaged snapshots are skipped, mirroring snapshots list;
// when none remain it fails closed instead of guessing.
func latestSnapshotID(ctx context.Context, repo repository.Repository, repoID string, dataKey crypto.SecretKey, trust *identity.TrustStore, trusted map[string][]byte) (string, error) {
	ids, err := manifest.List(ctx, repo)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("%w: no snapshots (back up first)", pverrors.ErrUsage)
	}
	lookup := trustedLookup(trust, trusted)
	type candidate struct {
		id      string
		created time.Time
	}
	var best *candidate
	for _, id := range ids {
		m, err := manifest.OpenTrusted(ctx, repo, repoID, dataKey, id, lookup)
		if err != nil {
			continue
		}
		if best == nil || m.CreatedAt.After(best.created) {
			best = &candidate{id: id, created: m.CreatedAt}
		}
	}
	if best == nil {
		return "", fmt.Errorf("%w: no trusted snapshots (run verify to see why)", pverrors.ErrUntrustedSigner)
	}
	return best.id, nil
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"petravault/internal/backup"
	"petravault/internal/crypto"
	"petravault/internal/identity"
	"petravault/internal/manifest"
	"petravault/internal/prune"
	"petravault/internal/repository"
	"petravault/internal/verify"

	pverrors "petravault/internal/errors"
)

// backupParams configures one backup execution shared by the manual backup
// command and scheduled jobs (DESIGN.md §11). Scheduling reuses this exact
// pipeline; there is no separate, weaker code path.
type backupParams struct {
	Source        string
	SourceID      string
	Excludes      []string
	ExcludeFile   string
	ExcludeCaches bool
	OneFileSystem bool
	ForceRescan   bool
	ECC           string
	VerifyAfter   bool
}

// backupOutcome describes one committed backup.
type backupOutcome struct {
	SnapshotID string
	Files      int
	NewChunks  int
	Reused     int
	Packs      int
	Warnings   []string
}

// executeBackup runs one backup with the repository lock protocol (write
// backup marker, check gc.lock, read indexes), commits the snapshot, updates
// the client-local head record, and optionally verifies the new snapshot.
// It returns the outcome; when files were skipped the returned error wraps
// ErrWarnings while the outcome stays usable (exit code 3).
func executeBackup(ctx context.Context, repo repository.Repository, repoCfg repository.Config, trust *identity.TrustStore, trusted map[string][]byte, master crypto.SecretKey, priv *identity.PrivateIdentity, signer *identity.Identity, params backupParams, logger *slog.Logger) (backupOutcome, error) {
	var outcome backupOutcome
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	sid, err := defaultSourceID(params.SourceID)
	if err != nil {
		return outcome, err
	}
	// Lock ordering: write backup-<id>, then check for gc.lock, then read
	// indexes. If prune holds the lock, remove the marker and retry with
	// backoff (DESIGN.md §10.2).
	backupID, err := repository.NewBackupID()
	if err != nil {
		return outcome, err
	}
	holder := "backup-" + sid + "-" + backupID[:8]
	host := repository.DefaultHost()
	if err := waitForMaintenance(ctx, repo, backupID, holder, host, logger); err != nil {
		return outcome, err
	}
	stopHeartbeat := repository.StartHeartbeat(ctx, repo, repository.BackupLockPrefix+backupID, repository.OperationBackup, holder, host, repository.DefaultHeartbeatInterval, time.Now, logger)
	defer func() {
		stopHeartbeat()
		if err := repository.RemoveBackupMarker(context.WithoutCancel(ctx), repo, backupID); err != nil {
			logger.WarnContext(ctx, "remove backup marker failed", slog.Any("error", err))
		}
	}()
	sub := master.DeriveSubkeys()
	defer sub.Zero()
	parentID, parentFiles, parentStart, err := parentForSource(ctx, repo, repoCfg.RepositoryID, sid, sub.Data, trust, trusted)
	if err != nil {
		return outcome, err
	}
	eccSetting := eccForRun(params.ECC, repoCfg)
	res, backupErr := backup.Backup(ctx, repo, backup.Options{
		Source:         params.Source,
		RepositoryID:   repoCfg.RepositoryID,
		Master:         master,
		SourceID:       sid,
		Parent:         parentFiles,
		ParentStart:    parentStart,
		Chunking:       chunkingFromConfig(repoCfg),
		Excludes:       params.Excludes,
		ExcludeFile:    params.ExcludeFile,
		ExcludeCaches:  params.ExcludeCaches,
		OneFileSystem:  params.OneFileSystem,
		ForceRescan:    params.ForceRescan,
		TargetPackSize: repoCfg.PackSize,
		ECC:            eccSetting,
		Logger:         logger,
	})
	if backupErr != nil && !errors.Is(backupErr, pverrors.ErrWarnings) {
		return outcome, backupErr
	}
	snapshotID, err := manifest.Commit(ctx, repo, sub.Data, priv, manifest.CommitParams{
		RepositoryID: repoCfg.RepositoryID,
		SourceID:     sid,
		Parent:       parentID,
		Identity:     signer.Fingerprint.String(),
		CreatedAt:    res.StartedAt,
		Files:        backupToManifest(res.Files),
		ECC:          eccSetting,
	})
	if err != nil {
		return outcome, err
	}
	headsPath, err := headsPathForRepo(repoCfg.RepositoryID)
	if err != nil {
		return outcome, err
	}
	if err := verify.UpdateHead(headsPath, sid, snapshotID, nil); err != nil {
		return outcome, err
	}
	logger.InfoContext(ctx, "backup committed",
		slog.String("snapshot", snapshotID),
		slog.String("source", sid),
		slog.Int("files", len(res.Files)),
		slog.Int("new_chunks", res.NewChunks),
		slog.Int("reused_files", res.ReusedFiles))
	outcome = backupOutcome{
		SnapshotID: snapshotID,
		Files:      len(res.Files),
		NewChunks:  res.NewChunks,
		Reused:     res.ReusedFiles,
		Packs:      len(res.Packs),
		Warnings:   res.Warnings,
	}
	if params.VerifyAfter {
		if err := verifyOne(ctx, repo, repoCfg, sub.Data, sub.ChunkID, trust, trusted, snapshotID, headsPath, false, repoCfg.ChunkMax, logger); err != nil {
			return outcome, err
		}
	}
	// Warnings without a verification failure still map to exit 3.
	if backupErr != nil {
		return outcome, backupErr
	}
	return outcome, nil
}

// pruneAfterJob runs retention after a successful scheduled backup under
// the maintenance lock. A lock held by another prune or rebuild skips
// pruning with a log rather than failing the backup (DESIGN.md §11.1).
func pruneAfterJob(ctx context.Context, repo repository.Repository, repoCfg repository.Config, trust *identity.TrustStore, trusted map[string][]byte, master crypto.SecretKey, retention prune.Retention, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	holder := "prune-" + repository.DefaultHost()
	acquired, err := repository.TryAcquireGCLock(ctx, repo, repository.OperationPrune, holder, repository.DefaultHost(), repository.DefaultLockTTL, time.Now)
	if err != nil {
		return err
	}
	if !acquired {
		logger.InfoContext(ctx, "maintenance lock held, skipping scheduled prune")
		return nil
	}
	stop := repository.StartHeartbeat(ctx, repo, repository.GCLockKey, repository.OperationPrune, holder, repository.DefaultHost(), repository.DefaultHeartbeatInterval, time.Now, logger)
	defer func() {
		stop()
		if err := repository.ReleaseGCLock(ctx, repo); err != nil {
			logger.WarnContext(ctx, "release maintenance lock failed", slog.Any("error", err))
		}
	}()
	if err := repository.WaitForBackups(ctx, repo, repository.DefaultLockTTL, repository.DefaultPruneWaitTimeout, time.Now); err != nil {
		return err
	}
	sub := master.DeriveSubkeys()
	defer sub.Zero()
	report, err := prune.Prune(ctx, repo, repoCfg, sub.Data, sub.ChunkID, trustedLookup(trust, trusted), prune.Options{
		Retention: retention,
		Logger:    logger,
	})
	if err != nil {
		return err
	}
	logger.InfoContext(ctx, "scheduled prune finished",
		slog.Int("retained", len(report.Retained)),
		slog.Int("deleted_snapshots", len(report.DeletedSnapshots)),
		slog.Int("deleted_packs", len(report.DeletedPacks)))
	return nil
}

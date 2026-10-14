// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"petravault/internal/config"
	"petravault/internal/crypto"
	"petravault/internal/identity"
	"petravault/internal/repository"
	"petravault/internal/verify"

	"github.com/spf13/cobra"

	pverrors "petravault/internal/errors"
)

func newBackupCmd(f *flags) *cobra.Command {
	var (
		excludes      []string
		excludeFile   string
		excludeCaches bool
		oneFileSystem bool
		forceRescan   bool
		sourceID      string
		ecc           string
		wantVerify    bool
		wantNoVerify  bool
	)
	cmd := &cobra.Command{
		Use:   "backup <source>",
		Short: "Back up a directory tree",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if wantVerify && wantNoVerify {
				return fmt.Errorf("%w: --verify and --no-verify are mutually exclusive", pverrors.ErrUsage)
			}
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			repoPath, err := resolveRepoPath(cfg, f.repository)
			if err != nil {
				return err
			}
			repo, repoCfg, trust, trusted, err := openVerifiedRepo(cmd.Context(), cfg, repoPath)
			if err != nil {
				return err
			}
			master, priv, signer, err := openMaster(cmd.Context(), f, cfg, repo, trust, repoCfg.RepositoryID)
			if err != nil {
				return err
			}
			defer master.Zero()
			sid, err := defaultSourceID(sourceID)
			if err != nil {
				return err
			}
			outcome, backupErr := executeBackup(cmd.Context(), repo, repoCfg, trust, trusted, master, priv, signer, backupParams{
				Source:        args[0],
				SourceID:      sid,
				Excludes:      excludes,
				ExcludeFile:   excludeFile,
				ExcludeCaches: excludeCaches,
				OneFileSystem: oneFileSystem,
				ForceRescan:   forceRescan,
				ECC:           ecc,
				VerifyAfter:   shouldVerifyAfterBackup(cfg, wantVerify, wantNoVerify),
			}, logger)
			if backupErr != nil && !errors.Is(backupErr, pverrors.ErrWarnings) {
				return backupErr
			}
			if outcome.SnapshotID != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "snapshot %s\nsource: %s\nfiles: %d  new_chunks: %d  reused: %d  packs: %d\n",
					outcome.SnapshotID, sid, outcome.Files, outcome.NewChunks, outcome.Reused, outcome.Packs)
				for _, w := range outcome.Warnings {
					fmt.Fprintf(cmd.OutOrStdout(), "warning: %s\n", w)
				}
				if shouldVerifyAfterBackup(cfg, wantVerify, wantNoVerify) {
					fmt.Fprintln(cmd.OutOrStdout(), "verify: ok")
				}
			}
			// Warnings without a verification failure still map to exit 3.
			if backupErr != nil {
				return backupErr
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&excludes, "exclude", nil, "exclude glob (repeatable)")
	cmd.Flags().StringVar(&excludeFile, "exclude-file", "", "file with one exclude glob per line")
	cmd.Flags().BoolVar(&excludeCaches, "exclude-caches", false, "skip directories holding CACHEDIR.TAG")
	cmd.Flags().BoolVar(&oneFileSystem, "one-file-system", false, "refuse to cross mount points")
	cmd.Flags().BoolVar(&forceRescan, "force-rescan", false, "disable the unchanged-file fast path")
	cmd.Flags().StringVar(&sourceID, "source-id", "", "source name (defaults to hostname)")
	cmd.Flags().StringVar(&ecc, "ecc", "", "erasure profile for this run: off, low, medium, high, or <N>% (defaults to the repository setting)")
	cmd.Flags().BoolVar(&wantVerify, "verify", false, "verify the new snapshot after backup")
	cmd.Flags().BoolVar(&wantNoVerify, "no-verify", false, "skip verify-after-backup")
	return cmd
}

// shouldVerifyAfterBackup resolves the flag/config precedence for
// verify-after-backup: --verify forces on, --no-verify forces off,
// otherwise the global verify_after_backup setting applies (default true).
func shouldVerifyAfterBackup(cfg config.Config, wantVerify, wantNoVerify bool) bool {
	if wantVerify {
		return true
	}
	if wantNoVerify {
		return false
	}
	if cfg.VerifyAfterBackup == nil {
		return true
	}
	return *cfg.VerifyAfterBackup
}

// waitForMaintenance writes the backup marker, checks for gc.lock, and
// retries with exponential backoff when prune holds the lock. The marker
// is removed before each retry so prune never waits on a backup that is
// itself waiting (DESIGN.md §10.2).
func waitForMaintenance(ctx context.Context, repo repository.Repository, backupID, holder, host string, logger *slog.Logger) error {
	backoff := 200 * time.Millisecond
	for attempt := range repository.DefaultBackupRetryAttempts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := repository.WriteBackupMarker(ctx, repo, backupID, holder, host, time.Now); err != nil {
			return err
		}
		held, err := repository.GCLockHeld(ctx, repo, repository.DefaultLockTTL, time.Now)
		if err != nil {
			_ = repository.RemoveBackupMarker(ctx, repo, backupID)
			return err
		}
		if !held {
			return nil
		}
		_ = repository.RemoveBackupMarker(ctx, repo, backupID)
		if attempt+1 >= repository.DefaultBackupRetryAttempts {
			break
		}
		logger.InfoContext(ctx, "maintenance lock held, retrying backup",
			slog.Int("attempt", attempt+1),
			slog.Duration("backoff", backoff))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return fmt.Errorf("%w: maintenance lock is held, backup aborted", pverrors.ErrUsage)
}

// verifyOne runs a standard or deep verification of one snapshot. It is
// shared by backup --verify and the verify command so both enforce the
// same signature, trust, history, and chunk checks.
func verifyOne(ctx context.Context, repo repository.Repository, repoCfg repository.Config, dataKey, chunkIDKey crypto.SecretKey, trust *identity.TrustStore, trusted map[string][]byte, snapshotID, headsPath string, deep bool, maxChunk int, logger *slog.Logger) error {
	_, err := verify.Verify(ctx, repo, repoCfg, dataKey, chunkIDKey, trust, trusted, verify.Options{
		SnapshotID:   snapshotID,
		Deep:         deep,
		HeadsPath:    headsPath,
		MaxChunkSize: maxChunk,
		Logger:       logger,
	})
	return err
}

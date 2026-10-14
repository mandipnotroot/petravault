// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"log/slog"
	"time"

	"petravault/internal/prune"
	"petravault/internal/repository"

	"github.com/spf13/cobra"

	pverrors "petravault/internal/errors"
)

func newPruneCmd(f *flags) *cobra.Command {
	var (
		keepDaily   int
		keepWeekly  int
		keepMonthly int
		dryRun      bool
	)
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Apply retention and garbage-collect unreferenced data",
		Long: `Apply retention (--keep-daily/--keep-weekly/--keep-monthly) and garbage-collect ` +
			`unreferenced chunks. Packs with only dead chunks are deleted, mostly-dead packs are ` +
			`repacked, indexes are compacted, and pruned snapshots are removed. The newest ` +
			`snapshot of every source is always kept. At least one --keep-* rule is required. ` +
			`Prune takes the maintenance lock and aborts without deleting anything while a backup is in flight.`,
		Example: `  petravault prune --keep-daily 30 --keep-weekly 12 --keep-monthly 12 -r /tmp/pv-repo
  petravault prune --keep-daily 7 --dry-run -r /tmp/pv-repo`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			retention := prune.Retention{Daily: keepDaily, Weekly: keepWeekly, Monthly: keepMonthly}
			if err := retention.Validate(); err != nil {
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
			master, _, _, err := openMaster(cmd.Context(), f, cfg, repo, trust, repoCfg.RepositoryID)
			if err != nil {
				return err
			}
			defer master.Zero()
			sub := master.DeriveSubkeys()
			defer sub.Zero()
			if dryRun {
				report, err := prune.Prune(cmd.Context(), repo, repoCfg, sub.Data, sub.ChunkID, trustedLookup(trust, trusted), prune.Options{
					Retention: retention,
					DryRun:    true,
					Logger:    logger,
				})
				if err != nil {
					return err
				}
				printPruneReport(cmd, report, true)
				return nil
			}
			holder := "prune-" + repository.DefaultHost()
			acquired, err := repository.TryAcquireGCLock(cmd.Context(), repo, repository.OperationPrune, holder, repository.DefaultHost(), repository.DefaultLockTTL, time.Now)
			if err != nil {
				return err
			}
			if !acquired {
				return fmt.Errorf("%w: maintenance lock is held, refusing to prune", pverrors.ErrUsage)
			}
			stop := repository.StartHeartbeat(cmd.Context(), repo, repository.GCLockKey, repository.OperationPrune, holder, repository.DefaultHost(), repository.DefaultHeartbeatInterval, time.Now, logger)
			defer stop()
			defer func() {
				if err := repository.ReleaseGCLock(cmd.Context(), repo); err != nil {
					logger.WarnContext(cmd.Context(), "release maintenance lock failed", slog.Any("error", err))
				}
			}()
			if err := repository.WaitForBackups(cmd.Context(), repo, repository.DefaultLockTTL, repository.DefaultPruneWaitTimeout, time.Now); err != nil {
				return err
			}
			report, err := prune.Prune(cmd.Context(), repo, repoCfg, sub.Data, sub.ChunkID, trustedLookup(trust, trusted), prune.Options{
				Retention: retention,
				Logger:    logger,
			})
			if err != nil {
				return err
			}
			printPruneReport(cmd, report, false)
			logger.InfoContext(cmd.Context(), "prune finished",
				slog.Int("retained", len(report.Retained)),
				slog.Int("deleted_snapshots", len(report.DeletedSnapshots)),
				slog.Int("deleted_packs", len(report.DeletedPacks)))
			return nil
		},
	}
	cmd.Flags().IntVar(&keepDaily, "keep-daily", 0, "keep this many daily snapshots per source")
	cmd.Flags().IntVar(&keepWeekly, "keep-weekly", 0, "keep this many weekly snapshots per source")
	cmd.Flags().IntVar(&keepMonthly, "keep-monthly", 0, "keep this many monthly snapshots per source")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview deletions without changing the repository")
	return cmd
}

func printPruneReport(cmd *cobra.Command, report prune.Report, dryRun bool) {
	out := cmd.OutOrStdout()
	prefix := ""
	if dryRun {
		prefix = "would "
	}
	fmt.Fprintf(out, "retained: %d  %sdeleted snapshots: %d  %sdeleted packs: %d  repacked: %d  new packs: %d\n",
		len(report.Retained), prefix, len(report.DeletedSnapshots), prefix, len(report.DeletedPacks), len(report.RepackedPacks), len(report.NewPacks))
	for _, id := range report.DeletedSnapshots {
		fmt.Fprintf(out, "%sdelete snapshot %s\n", prefix, id)
	}
	for _, key := range report.DeletedPacks {
		fmt.Fprintf(out, "%sdelete pack %s\n", prefix, key)
	}
	for _, key := range report.NewPacks {
		fmt.Fprintf(out, "new pack %s\n", key)
	}
	if report.NewIndex != "" {
		fmt.Fprintf(out, "new index %s\n", report.NewIndex)
	}
	if dryRun {
		fmt.Fprintln(out, "dry run: no changes made")
	} else {
		fmt.Fprintln(out, "prune: ok")
	}
}

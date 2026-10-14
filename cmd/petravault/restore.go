// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"log/slog"

	"petravault/internal/manifest"
	prestore "petravault/internal/restore"
	"petravault/internal/verify"

	"github.com/spf13/cobra"

	pverrors "petravault/internal/errors"
)

func newRestoreCmd(f *flags) *cobra.Command {
	var (
		includes  []string
		overwrite bool
	)
	cmd := &cobra.Command{
		Use:   "restore <snapshot-id|latest> <destination>",
		Short: "Restore a snapshot to a directory",
		Long: `Restore a snapshot to a directory. Use 'latest' for the newest trusted snapshot:
  petravault restore latest ./restore`,
		Example: `  petravault restore latest ./restore
  petravault restore <snapshot-id> ./restore --include Documents/report.pdf`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			master, _, _, err := openMaster(cmd.Context(), f, cfg, repo, trust, repoCfg.RepositoryID)
			if err != nil {
				return err
			}
			defer master.Zero()
			sub := master.DeriveSubkeys()
			defer sub.Zero()
			hexID, err := resolveSnapshotID(cmd.Context(), repo, repoCfg.RepositoryID, sub.Data, trust, trusted, args[0])
			if err != nil {
				return err
			}
			dest := args[1]
			if dest == "" {
				return fmt.Errorf("%w: destination is empty", pverrors.ErrUsage)
			}
			// Verify signature, trust, and history before reading any
			// chunk (DESIGN.md §9). A single-snapshot verification checks
			// the requested snapshot's source chain and head record.
			headsPath, err := headsPathForRepo(repoCfg.RepositoryID)
			if err != nil {
				return err
			}
			if _, err := verify.Verify(cmd.Context(), repo, repoCfg, sub.Data, sub.ChunkID, trust, trusted, verify.Options{
				SnapshotID:   hexID,
				Deep:         false,
				HeadsPath:    headsPath,
				MaxChunkSize: repoCfg.ChunkMax,
				Logger:       logger,
			}); err != nil {
				return err
			}
			m, err := manifest.OpenTrusted(cmd.Context(), repo, repoCfg.RepositoryID, sub.Data, hexID, trustedLookup(trust, trusted))
			if err != nil {
				return err
			}
			if err := prestore.Restore(cmd.Context(), repo, repoCfg.RepositoryID, sub.Data, sub.ChunkID, m, dest, prestore.Options{
				Includes:     includes,
				Overwrite:    overwrite,
				MaxChunkSize: repoCfg.ChunkMax,
			}); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "restore finished",
				slog.String("snapshot", hexID),
				slog.String("destination", dest))
			fmt.Fprintf(cmd.OutOrStdout(), "restored %s to %s\n", hexID, dest)
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&includes, "include", nil, "restore only this path (repeatable)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace existing files")
	return cmd
}

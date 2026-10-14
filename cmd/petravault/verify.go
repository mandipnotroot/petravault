// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"log/slog"
	"slices"

	"petravault/internal/verify"

	"github.com/spf13/cobra"
)

func newVerifyCmd(f *flags) *cobra.Command {
	var deep bool
	cmd := &cobra.Command{
		Use:   "verify [<snapshot-id|latest>]",
		Short: "Verify repository integrity",
		Long: `Verify repository integrity. With no argument it verifies the whole repository;
with 'latest' it verifies the newest trusted snapshot.`,
		Example: `  petravault verify
  petravault verify latest
  petravault verify --deep`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			repoPath, err := resolveRepoPath(cfg, f.repository)
			if err != nil {
				return err
			}
			repo, repoCfg, trust, trusted, err := openVerifiedRepo(cmd.Context(), cfg, repoPath, logger)
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
			only := ""
			if len(args) == 1 {
				only, err = resolveSnapshotID(cmd.Context(), repo, repoCfg.RepositoryID, sub.Data, trust, trusted, args[0])
				if err != nil {
					return err
				}
			}
			headsPath, err := headsPathForRepo(repoCfg.RepositoryID)
			if err != nil {
				return err
			}
			report, err := verify.Verify(cmd.Context(), repo, repoCfg, sub.Data, sub.ChunkID, trust, trusted, verify.Options{
				SnapshotID:   only,
				Deep:         deep,
				HeadsPath:    headsPath,
				MaxChunkSize: repoCfg.ChunkMax,
				Logger:       logger,
			})
			if err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "verify finished",
				slog.Int("snapshots", report.Snapshots),
				slog.Bool("deep", deep))
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "snapshots: %d  packs: %d  indexes: %d  slots: %d  sources: %d\n",
				report.Snapshots, report.Packs, report.Indexes, report.Slots, report.Sources)
			tips := make([]string, 0, len(report.Tips))
			for source, tip := range report.Tips {
				tips = append(tips, source+"="+tip)
			}
			slices.Sort(tips)
			for _, t := range tips {
				fmt.Fprintf(out, "tip %s\n", t)
			}
			for _, w := range report.Warnings {
				fmt.Fprintf(out, "warning: %s\n", w)
			}
			for _, s := range report.NoHeadSources {
				fmt.Fprintf(out, "note: source %q has no head record; chain consistency only\n", s)
			}
			if deep {
				fmt.Fprintln(out, "deep verify: ok")
			} else {
				fmt.Fprintln(out, "verify: ok")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&deep, "deep", false, "check ECC parity, AEAD, decompression, and chunk hashes")
	return cmd
}

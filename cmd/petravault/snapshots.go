// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"petravault/internal/identity"
	"petravault/internal/manifest"

	"github.com/spf13/cobra"
)

func newSnapshotsCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshots",
		Short: "List and inspect snapshots",
		Long: `List and inspect snapshots. With no subcommand it lists snapshots,
the most common action, so 'petravault snapshots' means 'petravault snapshots list'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSnapshotsList(cmd, f)
		},
	}
	cmd.AddCommand(newSnapshotsListCmd(f))
	cmd.AddCommand(newSnapshotsShowCmd(f))
	return cmd
}

func newSnapshotsListCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List snapshots in the repository",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSnapshotsList(cmd, f)
		},
	}
}

func runSnapshotsList(cmd *cobra.Command, f *flags) error {
	cfg, _, err := setup(f, cmd.ErrOrStderr())
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
	master, priv, _, err := openMaster(cmd.Context(), f, cfg, repo, trust, repoCfg.RepositoryID)
	if err != nil {
		return err
	}
	defer master.Zero()
	defer priv.Zero()
	sub := master.DeriveSubkeys()
	defer sub.Zero()
	ids, err := manifest.List(cmd.Context(), repo)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no snapshots")
		return nil
	}
	lookup := trustedLookup(trust, trusted)
	type row struct {
		id      string
		source  string
		created string
		signer  string
	}
	var rows []row
	for _, id := range ids {
		m, err := manifest.OpenTrusted(cmd.Context(), repo, repoCfg.RepositoryID, sub.Data, id, lookup)
		if err != nil {
			// An untrusted or damaged snapshot still lists by ID
			// so operators can see it; verify explains why.
			rows = append(rows, row{id: id, source: "?", created: "?", signer: "untrusted"})
			continue
		}
		signer := m.Identity
		if fp, err := identity.ParseFingerprint(m.Identity); err == nil {
			signer = fp.Grouped()
		}
		rows = append(rows, row{
			id:      id,
			source:  m.SourceID,
			created: m.CreatedAt.Format("2006-01-02T15:04:05Z"),
			signer:  signer,
		})
	}
	slices.SortFunc(rows, func(a, b row) int {
		if c := cmp.Compare(a.source, b.source); c != 0 {
			return c
		}
		return cmp.Compare(a.created, b.created)
	})
	for _, r := range rows {
		fmt.Fprintf(cmd.OutOrStdout(), "%s  %q  %s  %s\n", r.id, r.source, r.created, r.signer)
	}
	return nil
}

func newSnapshotsShowCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "show <snapshot-id|latest>",
		Short: "Show one snapshot manifest",
		Long:  `Show one snapshot manifest. Use 'latest' for the newest trusted snapshot.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := setup(f, cmd.ErrOrStderr())
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
			master, priv, _, err := openMaster(cmd.Context(), f, cfg, repo, trust, repoCfg.RepositoryID)
			if err != nil {
				return err
			}
			defer master.Zero()
			defer priv.Zero()
			sub := master.DeriveSubkeys()
			defer sub.Zero()
			hexID, err := resolveSnapshotID(cmd.Context(), repo, repoCfg.RepositoryID, sub.Data, trust, trusted, args[0])
			if err != nil {
				return err
			}
			m, err := manifest.OpenTrusted(cmd.Context(), repo, repoCfg.RepositoryID, sub.Data, hexID, trustedLookup(trust, trusted))
			if err != nil {
				return err
			}
			payload, err := m.Marshal()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "snapshot: %s\nsource: %q\nparent: %s\ncreated: %s\nidentity: %s\nfiles: %d\n",
				hexID, m.SourceID, cmp.Or(m.Parent, "-"), m.CreatedAt.Format("2006-01-02T15:04:05Z"), m.Identity, len(m.Files))
			fmt.Fprintf(out, "payload_sha256: %s\n", strings.ToLower(manifest.FormatSnapshotID(manifest.SnapshotID(payload))))
			for _, fe := range m.Files {
				fmt.Fprintf(out, "%s  %q  %d\n", fe.Type, fe.Path, fe.Size)
			}
			return nil
		},
	}
}

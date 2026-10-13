// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"log/slog"
	"os"

	"petravault/internal/config"
	"petravault/internal/identity"

	"github.com/spf13/cobra"

	pverrors "petravault/internal/errors"
)

func newTrustCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage trusted identities",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newTrustListCmd(f))
	cmd.AddCommand(newTrustAddCmd(f))
	cmd.AddCommand(newTrustRemoveCmd(f))
	cmd.AddCommand(newTrustRevokeCmd(f))
	return cmd
}

func newTrustListCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List trusted identities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, _, err := setup(f, cmd.ErrOrStderr()); err != nil {
				return err
			}
			trust := identity.NewTrustStore(trustDir())
			listed, err := trust.List()
			if err != nil {
				return err
			}
			if len(listed) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no trusted identities")
				return nil
			}
			for _, id := range listed {
				revoked, err := trust.IsRevoked(id.Fingerprint)
				if err != nil {
					return err
				}
				marker := ""
				if revoked {
					marker = "  (revoked)"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s%s\n",
					id.Fingerprint.Grouped(), id.Name,
					id.CreatedAt.Format("2006-01-02T15:04:05Z"), marker)
			}
			return nil
		},
	}
}

func newTrustAddCmd(f *flags) *cobra.Command {
	var fromFile string
	var grantRead bool
	cmd := &cobra.Command{
		Use:   "add <fingerprint>",
		Short: "Trust an identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if grantRead {
				return fmt.Errorf("%w: --grant-read is not supported yet (phase 6 key slots)", pverrors.ErrUsage)
			}
			fp, err := identity.ParseFingerprint(args[0])
			if err != nil {
				return err
			}
			var id *identity.Identity
			if fromFile != "" {
				data, err := os.ReadFile(fromFile)
				if err != nil {
					return fmt.Errorf("read public key file: %w", err)
				}
				if len(data) > 1<<20 {
					return fmt.Errorf("%w: public key file too large", pverrors.ErrUsage)
				}
				id, err = identity.ParsePublic(data)
				if err != nil {
					return err
				}
				if !id.Fingerprint.Equal(fp) {
					return fmt.Errorf("public key file names %s, want %s: %w",
						id.Fingerprint.Grouped(), fp.Grouped(), pverrors.ErrIntegrity)
				}
			} else {
				id, err = identity.NewStore(keystoreDir()).LoadPublic(fp)
				if err != nil {
					return fmt.Errorf("%w: run `petravault identity import <file.pub>` first or pass --from <file.pub>", err)
				}
			}
			// Show the full fingerprint before accepting (DESIGN.md §5.1).
			fmt.Fprintf(cmd.OutOrStdout(), "trusting identity %q\nfingerprint: %s\n", id.Name, id.Fingerprint.Grouped())
			if err := identity.NewTrustStore(trustDir()).Add(id); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "identity trusted",
				slog.String("name", id.Name),
				slog.String("fingerprint", id.Fingerprint.Grouped()))
			return nil
		},
	}
	cmd.Flags().StringVar(&fromFile, "from", "", "public key file to trust")
	cmd.Flags().BoolVar(&grantRead, "grant-read", false, "also seal the repository key (phase 6)")
	return cmd
}

func newTrustRemoveCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <fingerprint>",
		Short: "Remove a trusted identity (revocations stay)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, _, err := setup(f, cmd.ErrOrStderr()); err != nil {
				return err
			}
			fp, err := identity.ParseFingerprint(args[0])
			if err != nil {
				return err
			}
			if err := identity.NewTrustStore(trustDir()).Remove(fp); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", fp.Grouped())
			return nil
		},
	}
}

func newTrustRevokeCmd(f *flags) *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "revoke <fingerprint>",
		Short: "Revoke an identity (self or by a trusted signer)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if reason == "" {
				return fmt.Errorf("%w: --reason is required", pverrors.ErrUsage)
			}
			target, err := identity.ParseFingerprint(args[0])
			if err != nil {
				return err
			}
			signer, err := resolveSigner(f, cfg)
			if err != nil {
				return err
			}
			password, err := identity.ReadPassword(cmd.Context(), "Enter password for signing identity: ")
			if err != nil {
				return err
			}
			defer clear(password)
			priv, err := identity.NewStore(keystoreDir()).LoadPrivate(signer.Fingerprint, password)
			if err != nil {
				return err
			}
			env, err := identity.SignRevocation(priv, target, reason, nil)
			if err != nil {
				return err
			}
			if _, err := identity.VerifyRevocation(env, priv.Public.SignPublic); err != nil {
				return err
			}
			if err := identity.NewTrustStore(trustDir()).AddRevocation(target, env); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "identity revoked",
				slog.String("target", target.Grouped()),
				slog.String("signer", signer.Fingerprint.Grouped()))
			fmt.Fprintf(cmd.OutOrStdout(), "revoked %s (signed by %s)\n", target.Grouped(), signer.Fingerprint.Grouped())
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "reason for revocation (required)")
	return cmd
}

// resolveSigner picks the revoking identity from --identity, then
// default_identity, then the single owned identity.
func resolveSigner(f *flags, cfg config.Config) (*identity.Identity, error) {
	store := identity.NewStore(keystoreDir())
	query := f.identity
	if query == "" {
		query = cfg.DefaultIdentity
	}
	if query != "" {
		return store.Find(query)
	}
	listed, err := store.List()
	if err != nil {
		return nil, err
	}
	var owned []identity.Identity
	for _, e := range listed {
		if e.Owned {
			owned = append(owned, e.Identity)
		}
	}
	if len(owned) == 1 {
		id := owned[0]
		return &id, nil
	}
	return nil, fmt.Errorf("%w: no identity selected (use --identity or set default_identity)", pverrors.ErrUsage)
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"petravault/internal/config"
	"petravault/internal/identity"
	"petravault/internal/recovery"

	"github.com/spf13/cobra"
)

func newRecoveryCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recovery",
		Short: "Back up and restore the client recovery bundle",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newRecoveryExportCmd(f))
	cmd.AddCommand(newRecoveryImportCmd(f))
	return cmd
}

func newRecoveryExportCmd(f *flags) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "export --output <file>",
		Short: "Export the recovery bundle (identity, trust)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if output == "" {
				return errors.New("no output file given (use --output <file> outside the repository and any backup source)")
			}
			signer, err := resolveSigner(f, cfg)
			if err != nil {
				return err
			}
			password, err := identity.ReadPasswordConfirm(cmd.Context(), "Enter bundle password: ", "Confirm bundle password: ")
			if err != nil {
				return err
			}
			defer clear(password)
			store := identity.NewStore(keystoreDir())
			fileBytes, summary, err := recovery.Export(store, identity.NewTrustStore(trustDir()), signer.Fingerprint, password, nil)
			if err != nil {
				return err
			}
			if err := writeExclusive(output, fileBytes, 0o600); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "recovery bundle exported",
				slog.String("fingerprint", signer.Fingerprint.Grouped()))
			fmt.Fprintf(cmd.OutOrStdout(), "exported recovery bundle for %s to %s\n", signer.Fingerprint.Grouped(), output)
			fmt.Fprintf(cmd.OutOrStdout(), "holds: identity, %d trusted, %d revoked\n", summary.Trusted, summary.Revoked)
			fmt.Fprintf(cmd.OutOrStdout(), "store it off-machine, keep the password in your manager, re-export after trust changes\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "output file (never inside the repository or a backup source)")
	return cmd
}

func newRecoveryImportCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Restore the client from a recovery bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			ownerFP, err := resolveImportIdentity(f, cfg)
			if err != nil {
				return err
			}
			fileBytes, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read recovery bundle: %w", err)
			}
			if len(fileBytes) > 1<<20 {
				return errors.New("recovery bundle too large")
			}
			bundlePassword, err := identity.ReadPassword(cmd.Context(), "Enter bundle password: ")
			if err != nil {
				return err
			}
			defer clear(bundlePassword)
			identityPassword, err := identity.ReadPassword(cmd.Context(), "Enter identity password: ")
			if err != nil {
				return err
			}
			defer clear(identityPassword)
			summary, err := recovery.Import(identity.NewStore(keystoreDir()), identity.NewTrustStore(trustDir()), fileBytes, bundlePassword, identityPassword, ownerFP)
			if err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "recovery bundle imported",
				slog.String("fingerprint", ownerFP.Grouped()))
			fmt.Fprintf(cmd.OutOrStdout(), "imported recovery bundle for %s: identity verified, %d trusted, %d revoked\n",
				summary.Owner.Grouped(), summary.Trusted, summary.Revoked)
			fmt.Fprintf(cmd.OutOrStdout(), "run verify to re-check the repository before trusting it\n")
		fmt.Fprintf(cmd.OutOrStdout(), "re-confirm revocations with the team if this bundle is old: it restores past trust decisions, never new ones\n")
			return nil
		},
	}
	return cmd
}

// writeExclusive creates path with perm, refusing to overwrite.
func writeExclusive(path string, data []byte, perm os.FileMode) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer out.Close()
	if _, err := out.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	return nil
}

// resolveImportIdentity resolves the bundle owner without touching the
// keystore: after a full wipe there is nothing to look up, so a parseable
// fingerprint is accepted directly (the bundle itself must still name it,
// or import fails closed). Names resolve through the keystore as usual.
func resolveImportIdentity(f *flags, cfg config.Config) (identity.Fingerprint, error) {
	query := f.identity
	if query == "" {
		query = cfg.DefaultIdentity
	}
	if query != "" {
		if fp, err := identity.ParseFingerprint(query); err == nil {
			return fp, nil
		}
		id, err := identity.NewStore(keystoreDir()).Find(query)
		if err != nil {
			return identity.Fingerprint{}, err
		}
		return id.Fingerprint, nil
	}
	return identity.Fingerprint{}, errors.New("no identity selected (use --identity)")
}

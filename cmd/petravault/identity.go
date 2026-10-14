// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"petravault/internal/config"
	"petravault/internal/identity"

	"github.com/spf13/cobra"

	pverrors "petravault/internal/errors"
)

// keystoreDir returns the client-side keystore root
// ($XDG_DATA_HOME/petravault/identities).
func keystoreDir() string {
	return filepath.Join(config.DataDir(), "petravault", "identities")
}

// trustDir returns the client-local trust root
// ($XDG_CONFIG_HOME/petravault/trust).
func trustDir() string {
	return filepath.Join(config.Dir(), "petravault", "trust")
}

func newIdentityCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage local identities",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newIdentityCreateCmd(f))
	cmd.AddCommand(newIdentityListCmd(f))
	cmd.AddCommand(newIdentityExportCmd(f))
	cmd.AddCommand(newIdentityImportCmd(f))
	return cmd
}

func newIdentityCreateCmd(f *flags) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new local identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			identityName := strings.TrimSpace(name)
			if identityName == "" {
				identityName = defaultIdentityName()
			}
			password, err := identity.ReadPasswordConfirm(cmd.Context(), "Enter password for new identity: ", "Confirm password: ")
			if err != nil {
				return err
			}
			defer clear(password)
			store := identity.NewStore(keystoreDir())
			id, err := store.Create(identityName, password, nil)
			if err != nil {
				return err
			}
			if err := identity.NewTrustStore(trustDir()).Add(id); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "identity created",
				slog.String("name", identityName),
				slog.String("fingerprint", id.Fingerprint.Grouped()))
			fmt.Fprintf(cmd.OutOrStdout(), "created identity %q\nfingerprint: %s\n", identityName, id.Fingerprint.Grouped())
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "identity name (defaults to the OS user name)")
	return cmd
}

func newIdentityListCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List local identities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, _, err := setup(f, cmd.ErrOrStderr()); err != nil {
				return err
			}
			listed, err := identity.NewStore(keystoreDir()).List()
			if err != nil {
				return err
			}
			if len(listed) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no identities")
				return nil
			}
			for _, e := range listed {
				owned := "imported"
				if e.Owned {
					owned = "owned"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s  %s\n",
					e.Identity.Fingerprint.Grouped(), e.Identity.Name,
					e.Identity.CreatedAt.Format("2006-01-02T15:04:05Z"), owned)
			}
			return nil
		},
	}
}

func newIdentityExportCmd(f *flags) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "export <fingerprint>",
		Short: "Export an identity's public keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, _, err := setup(f, cmd.ErrOrStderr()); err != nil {
				return err
			}
			fp, err := identity.ParseFingerprint(args[0])
			if err != nil {
				return err
			}
			store := identity.NewStore(keystoreDir())
			if output == "" {
				return store.Export(fp, cmd.OutOrStdout())
			}
			out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return fmt.Errorf("open output: %w", err)
			}
			defer out.Close()
			if err := store.Export(fp, out); err != nil {
				return err
			}
			if err := out.Sync(); err != nil {
				return fmt.Errorf("sync output: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exported %s to %s\n", fp.Grouped(), output)
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "output file (defaults to stdout)")
	return cmd
}

func newIdentityImportCmd(f *flags) *cobra.Command {
	var trustSelf bool
	cmd := &cobra.Command{
		Use:   "import <file.pub>",
		Short: "Import an identity's public keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read public key file: %w", err)
			}
			if len(data) > 1<<20 {
				return fmt.Errorf("%w: public key file too large", pverrors.ErrUsage)
			}
			id, err := identity.NewStore(keystoreDir()).Import(data)
			if err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "identity imported",
				slog.String("name", id.Name),
				slog.String("fingerprint", id.Fingerprint.Grouped()))
			fmt.Fprintf(cmd.OutOrStdout(), "imported identity %q\nfingerprint: %s\n",
				id.Name, id.Fingerprint.Grouped())
			if !trustSelf {
				fmt.Fprintf(cmd.OutOrStdout(), "verify the fingerprint out of band, then run: petravault trust add %s\n",
					id.Fingerprint.String())
				return nil
			}
			// --trust repeats the trust-add verification (the fingerprint
			// is recomputed inside Add and a mismatch fails closed), so
			// importing a swapped file still fails. Use it only for your
			// own previously verified keys when cloning to a new machine;
			// anyone else's key still needs the out-of-band check above.
			if err := identity.NewTrustStore(trustDir()).Add(id); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "identity self-trusted",
				slog.String("name", id.Name),
				slog.String("fingerprint", id.Fingerprint.Grouped()))
			fmt.Fprintf(cmd.OutOrStdout(), "trusted %s\n", id.Fingerprint.Grouped())
			return nil
		},
	}
	cmd.Flags().BoolVar(&trustSelf, "trust", false, "also add to the local trust store (only for your own keys when cloning to a new machine)")
	return cmd
}

// defaultIdentityName prefers the OS user name and falls back to "default".
func defaultIdentityName() string {
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
		return strings.TrimSpace(u.Username)
	}
	return "default"
}

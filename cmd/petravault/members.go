// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
	"petravault/internal/repository"

	"github.com/spf13/cobra"
)

func newMembersCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "members",
		Short: "Publish or adopt the shared member roster",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newMembersPublishCmd(f))
	cmd.AddCommand(newMembersSyncCmd(f))
	return cmd
}

// trustHint is the exact recovery command appended to ErrUntrustedSigner
// failures in the roster flow. The fingerprint to approve is either named by
// the wrapped error (slot granter, roster publisher) or discovered via the
// list command (repository config, which names no key when nothing verifies).
// Approval must stay out of band: the hint never suggests trusting a
// fingerprint taken from the repository itself without an independent check,
// so blind copy-paste (TOFU) is not taught. Fingerprints are public and safe
// to name in errors; key material never appears here.
func trustHint(repoPath string, named bool) string {
	if named {
		return "(verify that fingerprint out of band, then run `petravault trust sync <fingerprint> -r \"" + repoPath + "\"` with the named fingerprint and retry)"
	}
	return "(run `petravault trust sync -r \"" + repoPath + "\"` to list advisory copies, verify the repository creator's fingerprint out of band, then run `petravault trust sync <fingerprint> -r \"" + repoPath + "\"` to approve it)"
}

// withTrustHint appends trustHint to ErrUntrustedSigner failures and passes
// anything else through untouched. Wrapping uses %w, so errors.Is and the
// exit-code mapping (exit 4) are preserved.
func withTrustHint(err error, repoPath string, named bool) error {
	if err == nil || !errors.Is(err, pverrors.ErrUntrustedSigner) {
		return err
	}
	return fmt.Errorf("%w %s", err, trustHint(repoPath, named))
}

// openRosterData opens the signer's own slot and derives the data key the
// roster is sealed under, alongside the verified repository config. Callers
// zero both keys when finished. repoPath only feeds the trust hints above;
// it is never used as a trust decision.
func openRosterData(ctx context.Context, repo repository.Repository, trust *identity.TrustStore, priv *identity.PrivateIdentity, repoPath string) (repository.Config, crypto.SecretKey, crypto.SecretKey, error) {
	trusted, err := listTrustedSigners(trust)
	if err != nil {
		return repository.Config{}, crypto.SecretKey{}, crypto.SecretKey{}, err
	}
	repoCfg, configSigner, err := repository.ReadConfig(ctx, repo, trusted)
	if err != nil {
		return repository.Config{}, crypto.SecretKey{}, crypto.SecretKey{}, withTrustHint(err, repoPath, false)
	}
	if err := requireTrustedConfigSigner(trust, configSigner); err != nil {
		return repository.Config{}, crypto.SecretKey{}, crypto.SecretKey{}, err
	}
	master, err := openGranterSlot(ctx, repo, trust, repoCfg.RepositoryID, priv)
	if err != nil {
		return repository.Config{}, crypto.SecretKey{}, crypto.SecretKey{}, withTrustHint(err, repoPath, true)
	}
	return repoCfg, master, master.DeriveSubkeys().Data, nil
}

func newMembersPublishCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "publish",
		Short: "Publish the member roster for onboarding",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			repoPath, err := resolveRepoPath(cfg, f.repository)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			repo, err := openRepo(ctx, cfg, repoPath)
			if err != nil {
				return err
			}
			signer, err := resolveSigner(f, cfg)
			if err != nil {
				return err
			}
			password, err := identity.ReadPassword(ctx, "Enter password for publishing identity: ")
			if err != nil {
				return err
			}
			defer clear(password)
			priv, err := identity.NewStore(keystoreDir()).LoadPrivate(signer.Fingerprint, password)
			if err != nil {
				return err
			}
			defer priv.Zero()
			trust := identity.NewTrustStore(trustDir())
			repoCfg, master, dataKey, err := openRosterData(ctx, repo, trust, priv, repoPath)
			if err != nil {
				return err
			}
			defer master.Zero()
			defer dataKey.Zero()
			env, err := identity.PublishMembers(priv, trust, dataKey, repoCfg.RepositoryID, nil)
			if err != nil {
				return err
			}
			if err := repo.PutObject(ctx, identity.MembersKey, bytes.NewReader(env)); err != nil {
				return fmt.Errorf("publish members: %w", err)
			}
			logger.InfoContext(ctx, "member roster published",
				slog.String("publisher", priv.Fingerprint().Grouped()))
			fmt.Fprintf(cmd.OutOrStdout(), "published member roster for %s\nre-publish after trust changes so onboarding stays fresh\n",
				priv.Fingerprint().Grouped())
			return nil
		},
	}
}

func newMembersSyncCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Adopt the published member roster",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			repoPath, err := resolveRepoPath(cfg, f.repository)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			repo, err := openRepo(ctx, cfg, repoPath)
			if err != nil {
				return err
			}
			signer, err := resolveSigner(f, cfg)
			if err != nil {
				return err
			}
			password, err := identity.ReadPassword(ctx, "Enter password for syncing identity: ")
			if err != nil {
				return err
			}
			defer clear(password)
			priv, err := identity.NewStore(keystoreDir()).LoadPrivate(signer.Fingerprint, password)
			if err != nil {
				return err
			}
			defer priv.Zero()
			trust := identity.NewTrustStore(trustDir())
			repoCfg, master, dataKey, err := openRosterData(ctx, repo, trust, priv, repoPath)
			if err != nil {
				return err
			}
			defer master.Zero()
			defer dataKey.Zero()
			r, err := repo.GetObject(ctx, identity.MembersKey)
			if err != nil {
				return fmt.Errorf("read member roster: %w (a member must run `members publish` first)", err)
			}
			defer r.Close()
			env, err := io.ReadAll(r)
			if err != nil {
				return fmt.Errorf("read member roster: %w", err)
			}
			summary, err := identity.AdoptMembers(env, dataKey, repoCfg.RepositoryID, trust, func(publisher string) ([]byte, error) {
				fp, err := identity.ParseFingerprint(publisher)
				if err != nil {
					return nil, err
				}
				id, err := trust.TrustedPublic(fp)
				if err != nil {
					return nil, err
				}
				return id.SignPublic, nil
			})
			if err != nil {
				return withTrustHint(err, repoPath, true)
			}
			logger.InfoContext(ctx, "member roster adopted",
				slog.String("publisher", summary.Publisher.Grouped()),
				slog.Int("adopted", summary.Adopted))
			fmt.Fprintf(cmd.OutOrStdout(), "adopted %d new members from %s (published %s)\n",
				summary.Adopted, summary.Publisher.Grouped(),
				summary.ExportedAt.Format("2006-01-02T15:04:05Z"))
			fmt.Fprintf(cmd.OutOrStdout(), "re-publish duty stays with the granter\n")
			if warning := identity.ExportAgeWarning(summary.ExportedAt, nil); warning != "" {
				logger.WarnContext(ctx, "member roster is stale", slog.String("warning", warning))
				fmt.Fprintf(cmd.OutOrStdout(), "warning: %s\n", warning)
			}
			return nil
		},
	}
}

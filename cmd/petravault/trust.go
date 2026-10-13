// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"petravault/internal/config"
	"petravault/internal/crypto"
	"petravault/internal/identity"
	"petravault/internal/repository"

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
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			fp, err := identity.ParseFingerprint(args[0])
			if err != nil {
				return err
			}
			id, err := loadMemberIdentity(fromFile, fp)
			if err != nil {
				return err
			}
			// Show the full fingerprint before accepting (DESIGN.md §5.1).
			fmt.Fprintf(cmd.OutOrStdout(), "trusting identity %q\nfingerprint: %s\n", id.Name, id.Fingerprint.Grouped())
			trust := identity.NewTrustStore(trustDir())
			if err := trust.Add(id); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "identity trusted",
				slog.String("name", id.Name),
				slog.String("fingerprint", id.Fingerprint.Grouped()))
			if !grantRead {
				return nil
			}
			if err := grantReadAccess(cmd, f, cfg, logger, trust, id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "granted read access to %s\n", id.Fingerprint.Grouped())
			return nil
		},
	}
	cmd.Flags().StringVar(&fromFile, "from", "", "public key file to trust")
	cmd.Flags().BoolVar(&grantRead, "grant-read", false, "also seal the repository key to this identity")
	return cmd
}

// loadMemberIdentity obtains the member's public keys from a .pub file or
// the local keystore and accepts them only if their hash equals the
// fingerprint the user confirmed (DESIGN.md §5.1).
func loadMemberIdentity(fromFile string, fp identity.Fingerprint) (*identity.Identity, error) {
	var id *identity.Identity
	var err error
	if fromFile != "" {
		var data []byte
		data, err = os.ReadFile(fromFile)
		if err != nil {
			return nil, fmt.Errorf("read public key file: %w", err)
		}
		if len(data) > 1<<20 {
			return nil, fmt.Errorf("%w: public key file too large", pverrors.ErrUsage)
		}
		id, err = identity.ParsePublic(data)
		if err != nil {
			return nil, err
		}
		if !id.Fingerprint.Equal(fp) {
			return nil, fmt.Errorf("public key file names %s, want %s: %w",
				id.Fingerprint.Grouped(), fp.Grouped(), pverrors.ErrIntegrity)
		}
		return id, nil
	}
	id, err = identity.NewStore(keystoreDir()).LoadPublic(fp)
	if err != nil {
		return nil, fmt.Errorf("%w: run `petravault identity import <file.pub>` first or pass --from <file.pub>", err)
	}
	return id, nil
}

// grantReadAccess seals the repository master key to the newly trusted
// member and publishes the slot plus an advisory public copy
// (DESIGN.md §4.2). The granter must already hold read access: the master
// key is opened from the granter's own slot, never generated or shared out
// of band.
func grantReadAccess(cmd *cobra.Command, f *flags, cfg config.Config, logger *slog.Logger, trust *identity.TrustStore, member *identity.Identity) error {
	ctx := cmd.Context()
	repoPath := cfg.ResolveRepository(f.repository)
	if repoPath == "" {
		return fmt.Errorf("%w: no repository selected (use --repository, PETRAVAULT_REPOSITORY, or default_repository)", pverrors.ErrUsage)
	}
	repo, err := openRepo(ctx, cfg, repoPath)
	if err != nil {
		return err
	}
	trusted, err := listTrustedSigners(trust)
	if err != nil {
		return err
	}
	repoCfg, _, err := repository.ReadConfig(ctx, repo, trusted)
	if err != nil {
		return err
	}
	granter, err := resolveSigner(f, cfg)
	if err != nil {
		return err
	}
	granted, err := trust.IsTrusted(granter.Fingerprint)
	if err != nil {
		return err
	}
	if !granted {
		return fmt.Errorf("%w: granter %s is not trusted", pverrors.ErrUntrustedSigner, granter.Fingerprint.Grouped())
	}
	password, err := identity.ReadPassword(ctx, "Enter password for granting identity: ")
	if err != nil {
		return err
	}
	defer clear(password)
	granterPriv, err := identity.NewStore(keystoreDir()).LoadPrivate(granter.Fingerprint, password)
	if err != nil {
		return err
	}
	master, err := openGranterSlot(ctx, repo, trust, repoCfg.RepositoryID, granterPriv)
	if err != nil {
		return err
	}
	defer master.Zero()
	env, err := identity.SealSlot(granterPriv, repoCfg.RepositoryID, member, master)
	if err != nil {
		return err
	}
	if err := repo.PutObject(ctx, identity.SlotKey(member.Fingerprint), bytes.NewReader(env)); err != nil {
		return fmt.Errorf("write key slot for %s: %w", member.Fingerprint.Grouped(), err)
	}
	pubBytes, err := identity.MarshalPublic(member)
	if err != nil {
		return err
	}
	if err := repo.PutObject(ctx, identity.AdvisoryKey(member.Fingerprint), bytes.NewReader(pubBytes)); err != nil {
		return fmt.Errorf("write advisory copy for %s: %w", member.Fingerprint.Grouped(), err)
	}
	logger.InfoContext(ctx, "read access granted",
		slog.String("member", member.Fingerprint.Grouped()),
		slog.String("granter", granter.Fingerprint.Grouped()))
	return nil
}

// openGranterSlot opens the granter's own slot, proving the granter holds
// read access. The granter must be in the client's own trust list; a slot
// signed by anyone else is refused (DESIGN.md §4.2, §5.2).
func openGranterSlot(ctx context.Context, repo repository.Repository, trust *identity.TrustStore, repositoryID string, granterPriv *identity.PrivateIdentity) (crypto.SecretKey, error) {
	key := identity.SlotKey(granterPriv.Fingerprint())
	r, err := repo.GetObject(ctx, key)
	if err != nil {
		return crypto.SecretKey{}, fmt.Errorf("read key slot for %s: %w", granterPriv.Fingerprint().Grouped(), err)
	}
	defer r.Close()
	env, err := io.ReadAll(r)
	if err != nil {
		return crypto.SecretKey{}, fmt.Errorf("read key slot for %s: %w", granterPriv.Fingerprint().Grouped(), err)
	}
	return identity.OpenSlotTrusted(env, repositoryID, granterPriv.Fingerprint(), granterPriv.KEMPrivate(), func(granter string) ([]byte, error) {
		fp, err := identity.ParseFingerprint(granter)
		if err != nil {
			return nil, err
		}
		id, err := trust.TrustedPublic(fp)
		if err != nil {
			return nil, err
		}
		return id.SignPublic, nil
	})
}

// listTrustedSigners builds the fingerprint-to-signing-key map for
// repository config verification from the client-local trust list. Revoked
// entries are included here so historical configs stay openable; the granter
// itself must still be currently trusted (IsTrusted) to grant read access.
func listTrustedSigners(trust *identity.TrustStore) (map[string][]byte, error) {
	listed, err := trust.List()
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(listed))
	for _, id := range listed {
		out[id.Fingerprint.String()] = id.SignPublic
	}
	return out, nil
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

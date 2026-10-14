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
	"strings"

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
	cmd.AddCommand(newTrustPublishCmd(f))
	cmd.AddCommand(newTrustRecoverCmd(f))
	cmd.AddCommand(newTrustSyncCmd(f))
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
	var grantAccess bool
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
			if !grantAccess {
				return nil
			}
			if err := grantMemberAccess(cmd, f, cfg, logger, trust, id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "granted access to %s\n", id.Fingerprint.Grouped())
			return nil
		},
	}
	cmd.Flags().StringVar(&fromFile, "from", "", "public key file to trust")
	cmd.Flags().BoolVar(&grantAccess, "grant-access", false, "also seal the repository key to this identity (full member: reads and backs up)")
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

// grantMemberAccess seals the repository master key to the newly trusted
// member and publishes the slot plus an advisory public copy
// (DESIGN.md §4.2). The granter must already hold read access: the master
// key is opened from the granter's own slot, never generated or shared out
// of band.
func grantMemberAccess(cmd *cobra.Command, f *flags, cfg config.Config, logger *slog.Logger, trust *identity.TrustStore, member *identity.Identity) error {
	ctx := cmd.Context()
	repoPath, err := resolveRepoPath(cfg, f.repository)
	if err != nil {
		return err
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
			// Only a currently trusted signer (or the key itself for
			// self-revocation) may revoke: an unknown local key must not
			// disqualify arbitrary targets in the local store.
			store := identity.NewTrustStore(trustDir())
			if !signer.Fingerprint.Equal(target) {
				trusted, err := store.IsTrusted(signer.Fingerprint)
				if err != nil {
					return err
				}
				if !trusted {
					return fmt.Errorf("%w: revocation signer %s is not trusted", pverrors.ErrUntrustedSigner, signer.Fingerprint.Grouped())
				}
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

func newTrustPublishCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "publish",
		Short: "Publish your trust view to the repository for recovery",
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
			trust := identity.NewTrustStore(trustDir())
			env, err := identity.PublishTrustList(priv, trust, nil)
			if err != nil {
				return err
			}
			key := identity.TrustListKey(priv.Fingerprint())
			if err := repo.PutObject(ctx, key, bytes.NewReader(env)); err != nil {
				return fmt.Errorf("publish trust list: %w", err)
			}
			logger.InfoContext(ctx, "trust list published",
				slog.String("owner", priv.Fingerprint().Grouped()))
			fmt.Fprintf(cmd.OutOrStdout(), "published trust list for %s\nre-publish after trust changes so recovery stays fresh\n",
				priv.Fingerprint().Grouped())
			return nil
		},
	}
}

func newTrustRecoverCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Recover your trust store from the repository copy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := setup(f, cmd.ErrOrStderr())
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
			owner, err := resolveSigner(f, cfg)
			if err != nil {
				return err
			}
			password, err := identity.ReadPassword(ctx, "Enter password for recovering identity: ")
			if err != nil {
				return err
			}
			defer clear(password)
			priv, err := identity.NewStore(keystoreDir()).LoadPrivate(owner.Fingerprint, password)
			if err != nil {
				return err
			}
			r, err := repo.GetObject(ctx, identity.TrustListKey(owner.Fingerprint))
			if err != nil {
				return fmt.Errorf("read published trust list for %s: %w (publish it first with `trust publish`)",
					owner.Fingerprint.Grouped(), err)
			}
			defer r.Close()
			env, err := io.ReadAll(r)
			if err != nil {
				return fmt.Errorf("read published trust list for %s: %w", owner.Fingerprint.Grouped(), err)
			}
			trust := identity.NewTrustStore(trustDir())
			summary, err := identity.RecoverTrustList(env, priv, trust)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "recovered trust list for %s: %d trusted, %d revoked (published %s)\n",
				summary.Owner.Grouped(), summary.Trusted, summary.Revoked,
				summary.ExportedAt.Format("2006-01-02T15:04:05Z"))
			fmt.Fprintf(cmd.OutOrStdout(), "re-confirm revocations with your team if this looks old, then run verify to re-learn heads\n")
			return nil
		},
	}
	return cmd
}

func newTrustSyncCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "sync [fingerprint...]",
		Short: "List repo members, or trust listed ones from their repo copies",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			trust := identity.NewTrustStore(trustDir())
			if len(args) == 0 {
				return listRepoMembers(ctx, cmd, repo, trust)
			}
			for _, raw := range args {
				fp, err := identity.ParseFingerprint(raw)
				if err != nil {
					return err
				}
				if err := approveRepoMember(ctx, cmd, repo, trust, logger, fp); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// listRepoMembers shows every advisory repo copy with its local trust state.
// The repo copy is a hint for discovery; nothing is trusted by listing it.
func listRepoMembers(ctx context.Context, cmd *cobra.Command, repo repository.Repository, trust *identity.TrustStore) error {
	keys, err := repo.List(ctx, identity.IdentityPrefix)
	if err != nil {
		return fmt.Errorf("list repo members: %w", err)
	}
	if len(keys) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no members in repository")
		return nil
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		fp, err := identity.ParseFingerprint(strings.TrimSuffix(strings.TrimPrefix(key, identity.IdentityPrefix), identity.IdentitySuffix))
		if err != nil {
			continue
		}
		name := "?"
		if pub := fetchRepoMember(ctx, repo, fp); pub != nil {
			name = pub.Name
		}
		slot, _ := repo.Exists(ctx, identity.SlotKey(fp))
		status := "untrusted"
		if revoked, err := trust.IsRevoked(fp); err == nil && revoked {
			status = "revoked"
		} else if ok, err := trust.IsTrusted(fp); err == nil && ok {
			status = "trusted"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  slot:%t  %s\n", fp.Grouped(), name, slot, status)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "approve with: petravault trust sync <fingerprint> (verify it out of band first)")
	return nil
}

// approveRepoMember trusts one repo member from its advisory copy. The copy
// is accepted only when its hash equals the typed fingerprint, the same
// check `trust add` performs, so a swapped repo copy fails closed.
func approveRepoMember(ctx context.Context, cmd *cobra.Command, repo repository.Repository, trust *identity.TrustStore, logger *slog.Logger, fp identity.Fingerprint) error {
	id := fetchRepoMember(ctx, repo, fp)
	if id == nil {
		return fmt.Errorf("%w: no repo copy for %s", pverrors.ErrUsage, fp.Grouped())
	}
	if !id.Fingerprint.Equal(fp) {
		return fmt.Errorf("repo copy names %s, want %s: %w",
			id.Fingerprint.Grouped(), fp.Grouped(), pverrors.ErrIntegrity)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "trusting identity %q\nfingerprint: %s\n", id.Name, id.Fingerprint.Grouped())
	if err := trust.Add(id); err != nil {
		return err
	}
	logger.InfoContext(ctx, "identity trusted from repo copy",
		slog.String("name", id.Name),
		slog.String("fingerprint", id.Fingerprint.Grouped()))
	fmt.Fprintf(cmd.OutOrStdout(), "trusted %s\n", id.Fingerprint.Grouped())
	return nil
}

// fetchRepoMember returns the advisory repo copy for fp, or nil when it is
// missing or corrupt. Corruption fails the single approval, never the list.
func fetchRepoMember(ctx context.Context, repo repository.Repository, fp identity.Fingerprint) *identity.Identity {
	r, err := repo.GetObject(ctx, identity.AdvisoryKey(fp))
	if err != nil {
		return nil
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil
	}
	id, err := identity.ParsePublic(raw)
	if err != nil {
		return nil
	}
	return id
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

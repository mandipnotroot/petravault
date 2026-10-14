// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"petravault/internal/crypto"
	"petravault/internal/erasure"
	"petravault/internal/identity"
	"petravault/internal/manifest"
	"petravault/internal/pack"
	"petravault/internal/repository"

	"github.com/spf13/cobra"

	pverrors "petravault/internal/errors"
)

func newECCCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ecc",
		Short: "Manage erasure-coding protection",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newECCSetCmd(f))
	cmd.AddCommand(newECCRebuildCmd(f))
	return cmd
}

func newECCSetCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <off|low|medium|high|N%>",
		Short: "Change the default erasure profile for new objects",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			params, err := erasure.Parse(args[0])
			if err != nil {
				return err
			}
			repoPath, err := resolveRepoPath(cfg, f.repository)
			if err != nil {
				return err
			}
			repo, err := openRepo(cmd.Context(), cfg, repoPath)
			if err != nil {
				return err
			}
			trust := identity.NewTrustStore(trustDir())
			trusted, err := listTrustedSigners(trust)
			if err != nil {
				return err
			}
			repoCfg, _, err := repository.ReadConfig(cmd.Context(), repo, trusted)
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
			repoCfg.ECC = params.Setting
			if err := repoCfg.Validate(); err != nil {
				return err
			}
			if err := repository.WriteConfig(cmd.Context(), repo, priv, repoCfg); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "erasure default changed",
				slog.String("ecc", params.Describe()))
			fmt.Fprintf(cmd.OutOrStdout(), "ecc default: %s\n", params.Describe())
			fmt.Fprintln(cmd.OutOrStdout(), "existing objects keep their old parity; run `petravault ecc rebuild` to re-protect them")
			return nil
		},
	}
}

func newECCRebuildCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "rebuild",
		Short: "Re-protect existing objects with the current erasure setting",
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
			repo, err := openRepo(cmd.Context(), cfg, repoPath)
			if err != nil {
				return err
			}
			trust := identity.NewTrustStore(trustDir())
			trusted, err := listTrustedSigners(trust)
			if err != nil {
				return err
			}
			repoCfg, _, err := repository.ReadConfig(cmd.Context(), repo, trusted)
			if err != nil {
				return err
			}
			signer, err := resolveSigner(f, cfg)
			if err != nil {
				return err
			}
			password, err := identity.ReadPassword(cmd.Context(), "Enter password for reading identity: ")
			if err != nil {
				return err
			}
			defer clear(password)
			priv, err := identity.NewStore(keystoreDir()).LoadPrivate(signer.Fingerprint, password)
			if err != nil {
				return err
			}
			master, err := openGranterSlot(cmd.Context(), repo, trust, repoCfg.RepositoryID, priv)
			if err != nil {
				return err
			}
			defer master.Zero()
			sub := master.DeriveSubkeys()
			defer sub.Zero()
			// ecc rebuild takes gc.lock so it cannot overlap a prune, but
			// it does not wait for backup markers: backups keep running
			// while it holds the lock (DESIGN.md §10.2).
			holder := "ecc-rebuild-" + repository.DefaultHost()
			acquired, err := repository.TryAcquireGCLock(cmd.Context(), repo, repository.OperationECCRebuild, holder, repository.DefaultHost(), repository.DefaultLockTTL, time.Now)
			if err != nil {
				return err
			}
			if !acquired {
				return fmt.Errorf("%w: maintenance lock is held, refusing to rebuild", pverrors.ErrUsage)
			}
			stop := repository.StartHeartbeat(cmd.Context(), repo, repository.GCLockKey, repository.OperationECCRebuild, holder, repository.DefaultHost(), repository.DefaultHeartbeatInterval, time.Now, logger)
			defer stop()
			defer func() {
				if err := repository.ReleaseGCLock(cmd.Context(), repo); err != nil {
					logger.WarnContext(cmd.Context(), "release maintenance lock failed", slog.Any("error", err))
				}
			}()
			verify := rebuildVerifier(repoCfg.RepositoryID, sub.Data, trust, trusted)
			if err := repository.Rebuild(cmd.Context(), repo, repoCfg.ECC, verify); err != nil {
				return err
			}
			params, err := erasure.Resolve(repoCfg.ECC)
			if err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "erasure rebuild finished",
				slog.String("ecc", params.Describe()))
			fmt.Fprintf(cmd.OutOrStdout(), "rebuilt erasure protection: %s\n", params.Describe())
			return nil
		},
	}
}

// rebuildVerifier AEAD-verifies repaired object bytes by family: packs and
// indexes with the data key, snapshots with the data key plus the signer's
// client-trusted public key (DESIGN.md §4.5, §5.2).
func rebuildVerifier(repoID string, dataKey crypto.SecretKey, trust *identity.TrustStore, trusted map[string][]byte) func(string, []byte) error {
	return func(objectKey string, objectBytes []byte) error {
		switch {
		case strings.HasPrefix(objectKey, pack.PackPrefix):
			return pack.VerifyPack(objectBytes, repoID, dataKey, objectKey)
		case strings.HasPrefix(objectKey, pack.IndexPrefix):
			return pack.VerifyIndex(objectBytes, repoID, dataKey, objectKey)
		case strings.HasPrefix(objectKey, manifest.SnapshotPrefix):
			return verifyRebuiltSnapshot(objectKey, objectBytes, repoID, dataKey, trust, trusted)
		default:
			return fmt.Errorf("%w: unknown object %q", pverrors.ErrUsage, objectKey)
		}
	}
}

func verifyRebuiltSnapshot(objectKey string, objectBytes []byte, repoID string, dataKey crypto.SecretKey, trust *identity.TrustStore, trusted map[string][]byte) error {
	id, ok := strings.CutPrefix(objectKey, manifest.SnapshotPrefix)
	if !ok {
		return fmt.Errorf("%w: unexpected snapshot key %q", pverrors.ErrUsage, objectKey)
	}
	hexID := strings.ToLower(strings.TrimSpace(id))
	// Peek at the unverified identity hint to resolve the signer's
	// client-trusted key; the hint is never trusted until VerifySnapshot
	// succeeds with the looked-up key.
	envPlain, err := dataKey.Open(objectBytes, crypto.AssociatedData(repoID, manifest.ObjectSnapshot, hexID))
	if err != nil {
		return fmt.Errorf("open snapshot %s: %w", hexID, err)
	}
	signPub, err := snapshotSigner(envPlain, trust, trusted)
	if err != nil {
		return err
	}
	return manifest.VerifySnapshot(objectBytes, repoID, dataKey, hexID, signPub)
}

// snapshotSigner resolves the snapshot signer's public key from the
// unverified envelope's identity hint against the client-local trust list.
func snapshotSigner(envPlain []byte, trust *identity.TrustStore, trusted map[string][]byte) ([]byte, error) {
	identityHint, err := manifest.UnverifiedIdentity(envPlain)
	if err != nil {
		return nil, err
	}
	fp, err := identity.ParseFingerprint(identityHint)
	if err != nil {
		return nil, err
	}
	if !isTrustedFingerprint(trust, fp) {
		return nil, fmt.Errorf("%w: snapshot signer %s", pverrors.ErrUntrustedSigner, fp.Grouped())
	}
	signPub, ok := trusted[fp.String()]
	if !ok {
		return nil, fmt.Errorf("%w: snapshot signer %s", pverrors.ErrUntrustedSigner, fp.Grouped())
	}
	return signPub, nil
}

func isTrustedFingerprint(trust *identity.TrustStore, fp identity.Fingerprint) bool {
	ok, err := trust.IsTrusted(fp)
	return err == nil && ok
}

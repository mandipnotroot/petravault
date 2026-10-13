// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Command petravault is the Petravault backup CLI. It only wires
// dependencies and maps errors to exit codes; business logic lives in
// internal/... (DESIGN.md §2, GO_GUIDELINES.md §5).
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"petravault/internal/chunking"
	"petravault/internal/config"
	"petravault/internal/crypto"
	"petravault/internal/erasure"
	"petravault/internal/identity"
	"petravault/internal/repository"

	"github.com/spf13/cobra"

	pverrors "petravault/internal/errors"
)

// version is set at build time via -ldflags -X.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(pverrors.ExitCode(err))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	//nolint:contextcheck // cobra delivers ctx via ExecuteContext/cmd.Context(),
	// not via constructors; RunE closures use cmd.Context() idiomatically.
	root := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	return root.ExecuteContext(ctx)
}

// flags holds the global CLI flags (DESIGN.md §16).
type flags struct {
	repository string
	configPath string
	identity   string
	logLevel   string
}

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	var f flags

	root := &cobra.Command{
		Use:           "petravault",
		Short:         "Secure incremental backup",
		SilenceUsage:  true,
		SilenceErrors: true, // main prints the error once and maps it to an exit code
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
	})
	root.PersistentFlags().StringVarP(&f.repository, "repository", "r", "", "repository path or s3:bucket[/prefix]")
	root.PersistentFlags().StringVar(&f.configPath, "config", "", "path to config.yaml")
	root.PersistentFlags().StringVar(&f.identity, "identity", "", "identity to use")
	root.PersistentFlags().StringVar(&f.logLevel, "log-level", "", "debug, info, warn, error")

	root.AddCommand(newInitCmd(&f))
	root.AddCommand(newInfoCmd(&f))
	root.AddCommand(newBackupCmd(&f))
	root.AddCommand(newSnapshotsCmd(&f))
	root.AddCommand(newRestoreCmd(&f))
	root.AddCommand(newVerifyCmd(&f))
	root.AddCommand(newECCCmd(&f))
	root.AddCommand(newIdentityCmd(&f))
	root.AddCommand(newTrustCmd(&f))
	root.AddCommand(newVersionCmd())
	return root
}

// setup loads the config with flag precedence and returns a logger honoring
// the effective log level. Diagnostics go to stderr; results go to stdout.
func setup(f *flags, stderr io.Writer) (config.Config, *slog.Logger, error) {
	cfg, err := config.Load(config.Options{
		ConfigPath:      f.configPath,
		FlagRepository:  f.repository,
		FlagLogLevel:    f.logLevel,
		FlagIdentity:    f.identity,
		FlagConcurrency: 0,
	})
	if err != nil {
		return config.Config{}, nil, err
	}
	level, err := parseLevel(cfg.LogLevel)
	if err != nil {
		return config.Config{}, nil, err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	return cfg, logger, nil
}

func newInitCmd(f *flags) *cobra.Command {
	var ecc string
	cmd := &cobra.Command{
		Use:   "init [path|s3:bucket[/prefix]]",
		Short: "Create a new repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			path := args[0]
			creator, err := resolveSigner(f, cfg)
			if err != nil {
				return err
			}
			password, err := identity.ReadPassword(cmd.Context(), "Enter password for repository creator: ")
			if err != nil {
				return err
			}
			defer clear(password)
			creatorPriv, err := identity.NewStore(keystoreDir()).LoadPrivate(creator.Fingerprint, password)
			if err != nil {
				return err
			}
			var repo repository.Repository
			if repository.IsS3Address(path) {
				repo, err = repository.OpenS3(cmd.Context(), path, s3OptionsForConfig(cfg))
				if err != nil {
					return err
				}
			} else {
				repo, err = repository.Init(path)
				if err != nil {
					return err
				}
			}
			if err := initRepository(cmd.Context(), repo, creatorPriv, creator, ecc); err != nil {
				return err
			}
			params, err := erasure.Resolve(ecc)
			if err != nil {
				return err
			}
			logger.Info("repository initialized",
				slog.String("path", path),
				slog.String("ecc", params.Describe()))
			fmt.Fprintf(cmd.OutOrStdout(), "initialized repository at %s\necc: %s\n", path, params.Describe())
			return nil
		},
	}
	cmd.Flags().StringVar(&ecc, "ecc", "medium", "erasure profile: off, low, medium, high, or <N>%")
	return cmd
}

// initRepository creates the repository ID, master key, signed config, and
// creator key slot (DESIGN.md §4.2, §8). It refuses to overwrite an existing
// config: re-initializing with a new master key would orphan every backup.
func initRepository(ctx context.Context, repo repository.Repository, creatorPriv *identity.PrivateIdentity, creator *identity.Identity, ecc string) error {
	exists, err := repo.Exists(ctx, repository.ConfigKey)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: repository is already initialized", pverrors.ErrUsage)
	}
	repositoryID, err := repository.GenerateID()
	if err != nil {
		return err
	}
	repoCfg, err := repository.NewConfig(repositoryID, chunking.DefaultParams(), 0, ecc, nil)
	if err != nil {
		return err
	}
	if err := repository.WriteConfig(ctx, repo, creatorPriv, repoCfg); err != nil {
		return err
	}
	master, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	defer master.Zero()
	env, err := identity.SealSlot(creatorPriv, repositoryID, creator, master)
	if err != nil {
		return err
	}
	if err := repo.PutObject(ctx, identity.SlotKey(creator.Fingerprint), bytes.NewReader(env)); err != nil {
		return fmt.Errorf("write key slot: %w", err)
	}
	pubBytes, err := identity.MarshalPublic(creator)
	if err != nil {
		return err
	}
	if err := repo.PutObject(ctx, identity.AdvisoryKey(creator.Fingerprint), bytes.NewReader(pubBytes)); err != nil {
		return fmt.Errorf("write advisory copy: %w", err)
	}
	return nil
}

func newInfoCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show the selected repository",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			repoPath := cfg.ResolveRepository(f.repository)
			if repoPath == "" {
				return fmt.Errorf("%w: no repository selected (use --repository, PETRAVAULT_REPOSITORY, or default_repository)", pverrors.ErrUsage)
			}
			repo, err := openRepo(cmd.Context(), cfg, repoPath)
			if err != nil {
				return err
			}
			trusted, err := listTrustedSigners(identity.NewTrustStore(trustDir()))
			if err != nil {
				return err
			}
			repoCfg, signer, err := repository.ReadConfig(cmd.Context(), repo, trusted)
			if err != nil {
				return err
			}
			params, err := erasure.Resolve(repoCfg.ECC)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "repository: %s\n", repoPath)
			fmt.Fprintf(out, "repository_id: %s\n", repoCfg.RepositoryID)
			fmt.Fprintf(out, "crypto_suite: %s\n", repoCfg.CryptoSuite)
			fmt.Fprintf(out, "chunking: %s (%s)\n", repoCfg.ChunkingAlgorithm, repoCfg.ChunkingLibraryVersion)
			fmt.Fprintf(out, "pack_size: %d\n", repoCfg.PackSize)
			fmt.Fprintf(out, "ecc: %s\n", params.Describe())
			fmt.Fprintf(out, "signed_by: %s\n", signer)
			return nil
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "petravault %s\n", version)
			return nil
		},
	}
}

func parseLevel(s string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo, fmt.Errorf("%w: invalid log level %q", pverrors.ErrUsage, s)
	}
	return level, nil
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Command petravault is the Petravault backup CLI. It only wires
// dependencies and maps errors to exit codes; business logic lives in
// internal/... (DESIGN.md §2, GO_GUIDELINES.md §5).
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"petravault/internal/config"
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
	return &cobra.Command{
		Use:   "init [path]",
		Short: "Create a new local repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			path := args[0]
			if strings.HasPrefix(path, "s3:") {
				return fmt.Errorf("%w: s3 repositories are not supported yet", pverrors.ErrUsage)
			}
			repo, err := repository.Init(path)
			if err != nil {
				return err
			}
			logger.Info("repository initialized", slog.String("path", repo.Root()))
			fmt.Fprintf(cmd.OutOrStdout(), "initialized repository at %s\n", repo.Root())
			return nil
		},
	}
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
			fmt.Fprintf(cmd.OutOrStdout(), "repository: %s\n", repoPath)
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

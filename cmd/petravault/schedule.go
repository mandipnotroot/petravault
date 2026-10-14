// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"petravault/internal/config"
	"petravault/internal/prune"
	"petravault/internal/scheduler"

	"github.com/spf13/cobra"

	pverrors "petravault/internal/errors"
)

func newScheduleCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage scheduled backups",
		Long: `Manage unattended backup jobs. Jobs share the manual backup pipeline; ` +
			`schedules, retries, and retention are the only additions. ` +
			`Scheduled runs cannot prompt for passwords: set PETRAVAULT_PASSWORD_COMMAND ` +
			`or a mode-0600 PETRAVAULT_PASSWORD_FILE (see the daemon help).`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newScheduleAddCmd(f))
	cmd.AddCommand(newScheduleListCmd(f))
	cmd.AddCommand(newScheduleStatusCmd(f))
	cmd.AddCommand(newScheduleRemoveCmd(f))
	cmd.AddCommand(newScheduleEnableCmd(f))
	cmd.AddCommand(newScheduleDisableCmd(f))
	cmd.AddCommand(newScheduleRunCmd(f))
	cmd.AddCommand(newScheduleDaemonCmd(f))
	return cmd
}

// scheduleDirs resolves the job-definition and state directories from the
// XDG base directories (DESIGN.md §7).
func scheduleDirs() (string, string) {
	return scheduler.ScheduleDir(config.Dir()), scheduler.StateDir(config.StateDir())
}

func newScheduleAddCmd(f *flags) *cobra.Command {
	var (
		name         string
		source       string
		daily        string
		weekly       string
		hourly       bool
		keepDaily    int
		keepWeekly   int
		keepMonthly  int
		wantVerify   bool
		wantNoVerify bool
		retry        int
		sourceID     string
		ecc          string
		disabled     bool
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a scheduled backup job",
		Example: `  petravault schedule add --name daily-documents --source ~/Documents ` +
			`--daily 02:00 --keep-daily 30 --keep-weekly 12 --keep-monthly 12`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if wantVerify && wantNoVerify {
				return fmt.Errorf("%w: --verify and --no-verify are mutually exclusive", pverrors.ErrUsage)
			}
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			job, err := buildJob(f, cfg, scheduleAddParams{
				name: name, source: source, daily: daily, weekly: weekly, hourly: hourly,
				keepDaily: keepDaily, keepWeekly: keepWeekly, keepMonthly: keepMonthly,
				wantVerify: wantVerify, wantNoVerify: wantNoVerify,
				retry: retry, sourceID: sourceID, ecc: ecc, disabled: disabled,
			})
			if err != nil {
				return err
			}
			scheduleDir, stateDir := scheduleDirs()
			if err := scheduler.SaveJob(scheduleDir, job); err != nil {
				return err
			}
			now := time.Now()
			state, err := scheduler.EnsureState(stateDir, job, now)
			if err != nil {
				return err
			}
			statePath, err := scheduler.StatePath(stateDir, job.Name)
			if err != nil {
				return err
			}
			if err := scheduler.SaveState(statePath, state); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "schedule job added",
				slog.String("job", job.Name),
				slog.String("frequency", job.Frequency),
				slog.Time("next_run", state.NextRun))
			fmt.Fprintf(cmd.OutOrStdout(), "added job %q\nnext run: %s\n",
				job.Name, state.NextRun.Format("2006-01-02T15:04:05Z"))
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "job name (letters, digits, ., _, -, +)")
	cmd.Flags().StringVar(&source, "source", "", "directory tree to back up")
	cmd.Flags().StringVar(&daily, "daily", "", "daily run time as HH:MM")
	cmd.Flags().StringVar(&weekly, "weekly", "", "weekly run as \"WEEKDAY HH:MM\" (e.g. \"mon 02:00\")")
	cmd.Flags().BoolVar(&hourly, "hourly", false, "run at the top of every hour")
	cmd.Flags().IntVar(&keepDaily, "keep-daily", 0, "keep this many daily snapshots per source (prune after backup)")
	cmd.Flags().IntVar(&keepWeekly, "keep-weekly", 0, "keep this many weekly snapshots per source")
	cmd.Flags().IntVar(&keepMonthly, "keep-monthly", 0, "keep this many monthly snapshots per source")
	cmd.Flags().BoolVar(&wantVerify, "verify", false, "verify the new snapshot after backup")
	cmd.Flags().BoolVar(&wantNoVerify, "no-verify", false, "skip verify-after-backup")
	cmd.Flags().IntVar(&retry, "retry", 0, "attempts per run (0 selects the default of 3, max 10)")
	cmd.Flags().StringVar(&sourceID, "source-id", "", "source name (defaults to hostname)")
	cmd.Flags().StringVar(&ecc, "ecc", "", "erasure profile for this job: off, low, medium, high, or <N>%")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create the job disabled")
	return cmd
}

// scheduleAddParams carries schedule add flag values.
type scheduleAddParams struct {
	name         string
	source       string
	daily        string
	weekly       string
	hourly       bool
	keepDaily    int
	keepWeekly   int
	keepMonthly  int
	wantVerify   bool
	wantNoVerify bool
	retry        int
	sourceID     string
	ecc          string
	disabled     bool
}

// buildJob validates add flags into a scheduler.Job. The repository comes
// from --repository, then default_repository; the identity comes from
// --identity, then default_identity (both global flags, DESIGN.md §7).
func buildJob(f *flags, cfg config.Config, p scheduleAddParams) (scheduler.Job, error) {
	set := 0
	var frequency, jobTime, weekday string
	if strings.TrimSpace(p.daily) != "" {
		set++
		frequency, jobTime = scheduler.FrequencyDaily, strings.TrimSpace(p.daily)
	}
	if strings.TrimSpace(p.weekly) != "" {
		set++
		day, hm, ok := strings.Cut(strings.TrimSpace(p.weekly), " ")
		if !ok {
			return scheduler.Job{}, fmt.Errorf("%w: --weekly wants \"WEEKDAY HH:MM\" (e.g. \"mon 02:00\")", pverrors.ErrUsage)
		}
		frequency, weekday, jobTime = scheduler.FrequencyWeekly, strings.TrimSpace(day), strings.TrimSpace(hm)
	}
	if p.hourly {
		set++
		frequency = scheduler.FrequencyHourly
	}
	if set != 1 {
		return scheduler.Job{}, fmt.Errorf("%w: pass exactly one of --daily, --weekly, --hourly", pverrors.ErrUsage)
	}
	repoPath := cmp.Or(f.repository, cfg.DefaultRepository)
	if strings.TrimSpace(repoPath) == "" {
		return scheduler.Job{}, fmt.Errorf("%w: no repository selected (use --repository or default_repository)", pverrors.ErrUsage)
	}
	if strings.TrimSpace(p.source) == "" {
		return scheduler.Job{}, fmt.Errorf("%w: --source is required", pverrors.ErrUsage)
	}
	var retention *scheduler.Retention
	if p.keepDaily != 0 || p.keepWeekly != 0 || p.keepMonthly != 0 {
		retention = &scheduler.Retention{Daily: p.keepDaily, Weekly: p.keepWeekly, Monthly: p.keepMonthly}
	}
	var verify *bool
	if p.wantVerify {
		verify = new(true)
	} else if p.wantNoVerify {
		verify = new(false)
	}
	enabled := !p.disabled
	job := scheduler.Job{
		Name:       strings.TrimSpace(p.name),
		Source:     p.source,
		Repository: repoPath,
		Frequency:  frequency,
		Time:       jobTime,
		Weekday:    weekday,
		SourceID:   strings.TrimSpace(p.sourceID),
		Identity:   cmp.Or(f.identity, cfg.DefaultIdentity),
		ECC:        strings.TrimSpace(p.ecc),
		Retention:  retention,
		Verify:     verify,
		Enabled:    &enabled,
		Attempts:   p.retry,
	}
	if err := job.Validate(); err != nil {
		return scheduler.Job{}, err
	}
	return job, nil
}

func newScheduleListCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List scheduled backup jobs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, _, err := setup(f, cmd.ErrOrStderr()); err != nil {
				return err
			}
			scheduleDir, _ := scheduleDirs()
			jobs, err := scheduler.ListJobs(scheduleDir)
			if err != nil {
				return err
			}
			if len(jobs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no scheduled jobs")
				return nil
			}
			for _, job := range jobs {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s  %s  %s\n",
					job.Name, enabledMarker(job), scheduleSummary(job), job.Repository, job.Source)
			}
			return nil
		},
	}
}

func newScheduleStatusCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show job state (last run, failures, next run)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, _, err := setup(f, cmd.ErrOrStderr()); err != nil {
				return err
			}
			scheduleDir, stateDir := scheduleDirs()
			jobs, err := scheduler.ListJobs(scheduleDir)
			if err != nil {
				return err
			}
			if len(jobs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no scheduled jobs")
				return nil
			}
			for _, job := range jobs {
				state, err := scheduler.EnsureState(stateDir, job, time.Now())
				if err != nil {
					return fmt.Errorf("job %q: %w", job.Name, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  last_run:%s  failures:%d  next_run:%s\n",
					job.Name, enabledMarker(job),
					formatStateTime(state.LastRun), state.FailureCount,
					formatStateTime(state.NextRun))
			}
			return nil
		},
	}
}

func newScheduleRemoveCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a scheduled backup job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, _, err := setup(f, cmd.ErrOrStderr()); err != nil {
				return err
			}
			name := args[0]
			if err := scheduler.ValidateName(name); err != nil {
				return err
			}
			scheduleDir, stateDir := scheduleDirs()
			jobPath, err := scheduler.JobPath(scheduleDir, name)
			if err != nil {
				return err
			}
			if _, err := scheduler.LoadJob(jobPath); err != nil {
				return err
			}
			if err := os.Remove(jobPath); err != nil {
				return fmt.Errorf("remove schedule job: %w", err)
			}
			statePath, err := scheduler.StatePath(stateDir, name)
			if err != nil {
				return err
			}
			_ = os.Remove(statePath)
			lockPath, err := scheduler.LockPath(stateDir, name)
			if err == nil {
				_ = os.Remove(lockPath)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed job %q\n", name)
			return nil
		},
	}
}

func newScheduleEnableCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "enable <name>",
		Short: "Enable a scheduled backup job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if err := setJobEnabled(args[0], true); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "schedule job enabled", slog.String("job", args[0]))
			fmt.Fprintf(cmd.OutOrStdout(), "enabled job %q\n", args[0])
			return nil
		},
	}
}

func newScheduleDisableCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "disable <name>",
		Short: "Disable a scheduled backup job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if err := setJobEnabled(args[0], false); err != nil {
				return err
			}
			logger.InfoContext(cmd.Context(), "schedule job disabled", slog.String("job", args[0]))
			fmt.Fprintf(cmd.OutOrStdout(), "disabled job %q\n", args[0])
			return nil
		},
	}
}

// setJobEnabled flips the enabled flag and rewrites the job file (0600).
func setJobEnabled(name string, enabled bool) error {
	scheduleDir, _ := scheduleDirs()
	jobPath, err := scheduler.JobPath(scheduleDir, name)
	if err != nil {
		return err
	}
	job, err := scheduler.LoadJob(jobPath)
	if err != nil {
		return err
	}
	job.Enabled = &enabled
	return scheduler.SaveJob(scheduleDir, job)
}

func newScheduleRunCmd(f *flags) *cobra.Command {
	return &cobra.Command{
		Use:   "run [<name>]",
		Short: "Run due jobs once (or one job immediately)",
		Long: `Run all currently due jobs once and exit (suitable for a system ` +
			`cron entry every few minutes); with a name, run that one job immediately ` +
			`even when it is not due. Exits non-zero when any job fails. ` +
			`Unattended unlock uses PETRAVAULT_PASSWORD_COMMAND, then a mode-0600 ` +
			`PETRAVAULT_PASSWORD_FILE; there is no interactive prompt in cron.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			scheduleDir, stateDir := scheduleDirs()
			runner := scheduleRunner(f, cfg, logger)
			now := time.Now()
			if len(args) == 1 {
				return runOneNow(cmd, logger, scheduleDir, stateDir, args[0], now, runner)
			}
			jobs, err := scheduler.ListJobs(scheduleDir)
			if err != nil {
				return err
			}
			states := make(map[string]scheduler.State, len(jobs))
			for _, job := range jobs {
				state, err := scheduler.EnsureState(stateDir, job, now)
				if err != nil {
					return fmt.Errorf("job %q: %w", job.Name, err)
				}
				states[job.Name] = state
			}
			updated, results, errs := scheduler.RunDue(cmd.Context(), jobs, states, stateDir, now, runner, logger)
			if err := saveStates(stateDir, updated); err != nil {
				return err
			}
			printRunResults(cmd, results, errs)
			if len(errs) != 0 {
				return joinJobErrors(errs)
			}
			if len(results) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no jobs due")
			}
			return nil
		},
	}
}

// runOneNow runs one job immediately, even when it is not due or is
// disabled. An explicit run is a manual override; the overlap lock still
// applies and a held lock fails the run rather than queuing it.
func runOneNow(cmd *cobra.Command, logger *slog.Logger, scheduleDir, stateDir, name string, now time.Time, runner scheduler.Runner) error {
	jobPath, err := scheduler.JobPath(scheduleDir, name)
	if err != nil {
		return err
	}
	job, err := scheduler.LoadJob(jobPath)
	if err != nil {
		return err
	}
	lock, err := scheduler.TryLock(stateDir, job.Name)
	if err != nil {
		return fmt.Errorf("job %q: %w", job.Name, err)
	}
	defer func() {
		_ = lock.Unlock()
	}()
	state, err := scheduler.EnsureState(stateDir, job, now)
	if err != nil {
		return fmt.Errorf("job %q: %w", job.Name, err)
	}
	updated, result, runErr := scheduler.RunOne(cmd.Context(), job, state, runner, logger)
	statePath, err := scheduler.StatePath(stateDir, job.Name)
	if err != nil {
		return err
	}
	if err := scheduler.SaveState(statePath, updated); err != nil {
		return err
	}
	if runErr != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "job %q failed: %v\n", job.Name, runErr)
		return fmt.Errorf("job %q: %w", job.Name, runErr)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "job %q snapshot %s\n", job.Name, cmp.Or(result.SnapshotID, "none"))
	return nil
}

func newScheduleDaemonCmd(f *flags) *cobra.Command {
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run due jobs in a foreground loop",
		Long: `Run scheduled jobs in a foreground loop until interrupted ` +
			`(suitable for systemd, launchd, a Windows service, or a container). ` +
			`Missed runs execute once as catch-up. Unattended unlock uses ` +
			`PETRAVAULT_PASSWORD_COMMAND, then a mode-0600 PETRAVAULT_PASSWORD_FILE.`,
		Example: `  PETRAVAULT_PASSWORD_FILE=~/.config/petravault/pw petravault schedule daemon`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, logger, err := setup(f, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if interval <= 0 {
				interval = scheduler.DefaultPollInterval
			}
			scheduleDir, stateDir := scheduleDirs()
			logger.InfoContext(cmd.Context(), "schedule daemon started",
				slog.Duration("interval", interval))
			return scheduler.Daemon(cmd.Context(), scheduleDir, stateDir, interval, scheduleRunner(f, cfg, logger), logger)
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", scheduler.DefaultPollInterval, "poll interval for due jobs")
	return cmd
}

// scheduleRunner wires one scheduled backup attempt to the real pipeline:
// verified repository, unlocked key slot, backup, verify-after-backup, and
// retention prune. It returns the committed snapshot ID.
func scheduleRunner(f *flags, cfg config.Config, logger *slog.Logger) scheduler.Runner {
	return func(ctx context.Context, job scheduler.Job) (string, error) {
		start := time.Now()
		repoPath := cmp.Or(job.Repository, cfg.ResolveRepository(f.repository))
		if strings.TrimSpace(repoPath) == "" {
			return "", fmt.Errorf("%w: job %q has no repository", pverrors.ErrUsage, job.Name)
		}
		repo, repoCfg, trust, trusted, err := openVerifiedRepo(ctx, cfg, repoPath)
		if err != nil {
			return "", err
		}
		effective := *f
		if strings.TrimSpace(job.Identity) != "" {
			effective.identity = job.Identity
		}
		master, priv, signer, err := openMaster(ctx, &effective, cfg, repo, trust, repoCfg.RepositoryID)
		if err != nil {
			return "", err
		}
		defer master.Zero()
		outcome, backupErr := executeBackup(ctx, repo, repoCfg, trust, trusted, master, priv, signer, backupParams{
			Source:      job.Source,
			SourceID:    job.SourceID,
			ECC:         job.ECC,
			VerifyAfter: job.ShouldVerify(cfg.VerifyAfterBackup),
		}, logger)
		if backupErr != nil && !errors.Is(backupErr, pverrors.ErrWarnings) {
			return outcome.SnapshotID, backupErr
		}
		// A backup that finished with warnings still committed: warnings
		// are logged, not retried, and the snapshot ID is returned.
		for _, w := range outcome.Warnings {
			logger.WarnContext(ctx, "backup warning", slog.String("job", job.Name), slog.String("warning", w))
		}
		if job.Retention != nil {
			retention := prune.Retention{Daily: job.Retention.Daily, Weekly: job.Retention.Weekly, Monthly: job.Retention.Monthly}
			if err := pruneAfterJob(ctx, repo, repoCfg, trust, trusted, master, retention, logger); err != nil {
				return outcome.SnapshotID, err
			}
		}
		elapsed := time.Since(start)
		logger.InfoContext(ctx, "scheduled job attempt finished",
			slog.String("job", job.Name),
			slog.String("snapshot", cmp.Or(outcome.SnapshotID, "none")),
			slog.Duration("duration", elapsed))
		if backupErr != nil {
			// Warnings only: success with a warnings-shaped error would
			// trigger a pointless retry, so swallow it here. The manual
			// backup command still surfaces warnings as exit code 3.
			return outcome.SnapshotID, nil
		}
		return outcome.SnapshotID, nil
	}
}

// saveStates persists updated job states after a run.
func saveStates(stateDir string, states map[string]scheduler.State) error {
	var errs []error
	for _, name := range slices.Sorted(slices.Values(collectStateNames(states))) {
		path, err := scheduler.StatePath(stateDir, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := scheduler.SaveState(path, states[name]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func collectStateNames(states map[string]scheduler.State) []string {
	out := make([]string, 0, len(states))
	for name := range states {
		out = append(out, name)
	}
	return out
}

// printRunResults reports per-job snapshots and failures to stdout.
func printRunResults(cmd *cobra.Command, results map[string]scheduler.Result, errs map[string]error) {
	for _, name := range slices.Sorted(slices.Values(collectResultNames(results, errs))) {
		if err, ok := errs[name]; ok {
			fmt.Fprintf(cmd.OutOrStdout(), "job %q failed: %v\n", name, err)
			continue
		}
		fmt.Fprintf(cmd.OutOrStdout(), "job %q snapshot %s\n", name, cmp.Or(results[name].SnapshotID, "none"))
	}
}

func collectResultNames(results map[string]scheduler.Result, errs map[string]error) []string {
	seen := make(map[string]bool)
	for name := range results {
		seen[name] = true
	}
	for name := range errs {
		seen[name] = true
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	return out
}

// joinJobErrors combines per-job failures preserving error matching (exit
// codes map integrity failures to 4 even when joined).
func joinJobErrors(errs map[string]error) error {
	out := make([]error, 0, len(errs))
	for _, name := range slices.Sorted(slices.Values(collectErrNames(errs))) {
		out = append(out, fmt.Errorf("job %q: %w", name, errs[name]))
	}
	return errors.Join(out...)
}

func collectErrNames(errs map[string]error) []string {
	out := make([]string, 0, len(errs))
	for name := range errs {
		out = append(out, name)
	}
	return out
}

func enabledMarker(job scheduler.Job) string {
	if job.IsEnabled() {
		return "enabled"
	}
	return "disabled"
}

func scheduleSummary(job scheduler.Job) string {
	switch job.Frequency {
	case scheduler.FrequencyHourly:
		return "hourly"
	case scheduler.FrequencyWeekly:
		return "weekly " + job.Weekday + " " + job.Time
	default:
		return "daily " + job.Time
	}
}

func formatStateTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

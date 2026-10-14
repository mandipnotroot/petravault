// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package scheduler implements unattended backup jobs (DESIGN.md §11).
// Jobs are client-side JSON files: definitions live under
// $XDG_CONFIG_HOME/petravault/schedule/*.json and run state under
// $XDG_STATE_HOME/petravault/schedule/*.state.json (DESIGN.md §7).
// Scheduling reuses the manual backup pipeline; there is no separate,
// weaker code path. Actual backup work is injected as a Runner so this
// package stays testable without a repository and the thin CLI layer in
// cmd/petravault wires the real backup, prune, and verify calls.
package scheduler

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	json "encoding/json/v2"

	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
)

// Scheduling frequencies.
const (
	FrequencyDaily  = "daily"
	FrequencyWeekly = "weekly"
	FrequencyHourly = "hourly"
)

// Retry and daemon defaults (DESIGN.md §11.1).
const (
	// DefaultAttempts bounds transient-failure retries per job run.
	DefaultAttempts = 3
	// MaxAttempts caps an explicitly configured attempt count.
	MaxAttempts = 10
	// RetryBaseDelay is the base exponential backoff between attempts:
	// attempt i sleeps min(RetryBaseDelay<<i, maxRetryDelay).
	RetryBaseDelay = 30 * time.Second
	// maxRetryDelay caps the exponential backoff.
	maxRetryDelay = 10 * time.Minute
	// DefaultPollInterval paces schedule daemon ticks.
	DefaultPollInterval = 30 * time.Second
	// StateVersion is the *.state.json format version.
	StateVersion = 1
)

// ErrLocked reports that a job is already running elsewhere on this
// machine. Callers skip the job rather than failing it.
var ErrLocked = errors.New("job is already running")

// Retention selects snapshots to keep after a successful scheduled backup
// (DESIGN.md §11.1, §11.3). It mirrors prune.Retention without importing
// the prune package: each field counts distinct UTC buckets to keep per
// source, zero disables that bucket, and at least one field must be
// positive when retention is configured.
type Retention struct {
	Daily   int `json:"daily,omitzero"`
	Weekly  int `json:"weekly,omitzero"`
	Monthly int `json:"monthly,omitzero"`
}

// Validate rejects negative counts and the empty rule set.
func (r Retention) Validate() error {
	if r.Daily < 0 || r.Weekly < 0 || r.Monthly < 0 {
		return fmt.Errorf("%w: retention counts must not be negative", pverrors.ErrUsage)
	}
	if r.Daily == 0 && r.Weekly == 0 && r.Monthly == 0 {
		return fmt.Errorf("%w: retention needs at least one keep rule", pverrors.ErrUsage)
	}
	return nil
}

// Job is one scheduled backup (DESIGN.md §11.1). Verify and Enabled are
// pointers so an omitted value is distinguishable from an explicit false:
// a nil Verify falls back to the global verify_after_backup setting, and a
// nil Enabled means enabled. Attempts == 0 selects DefaultAttempts.
type Job struct {
	Name       string     `json:"name"`
	Source     string     `json:"source"`
	Repository string     `json:"repository"`
	Frequency  string     `json:"frequency"`
	Time       string     `json:"time,omitempty"`
	Weekday    string     `json:"weekday,omitempty"`
	SourceID   string     `json:"source_id,omitempty"`
	Identity   string     `json:"identity,omitempty"`
	ECC        string     `json:"ecc,omitempty"`
	Retention  *Retention `json:"retention,omitempty"`
	Verify     *bool      `json:"verify,omitempty"`
	Enabled    *bool      `json:"enabled,omitempty"`
	Attempts   int        `json:"attempts,omitzero"`
}

// IsEnabled reports whether the job runs on schedule. Omitted means enabled.
func (j Job) IsEnabled() bool {
	return j.Enabled == nil || *j.Enabled
}

// AttemptsFor returns the configured attempt count or the default.
func (j Job) AttemptsFor() int {
	if j.Attempts <= 0 {
		return DefaultAttempts
	}
	return j.Attempts
}

// ShouldVerify resolves verify-after-backup for the job: the job flag wins,
// otherwise the global setting applies (default true).
func (j Job) ShouldVerify(global *bool) bool {
	if j.Verify != nil {
		return *j.Verify
	}
	if global == nil {
		return true
	}
	return *global
}

// Validate checks the job without touching storage. Unknown frequencies,
// malformed times, and negative retention fail closed.
func (j Job) Validate() error {
	if err := ValidateName(j.Name); err != nil {
		return err
	}
	if strings.TrimSpace(j.Source) == "" {
		return fmt.Errorf("%w: job %q has an empty source", pverrors.ErrUsage, j.Name)
	}
	if strings.TrimSpace(j.Repository) == "" {
		return fmt.Errorf("%w: job %q has an empty repository", pverrors.ErrUsage, j.Name)
	}
	switch strings.ToLower(strings.TrimSpace(j.Frequency)) {
	case FrequencyDaily:
		if _, _, err := ParseTime(j.Time); err != nil {
			return fmt.Errorf("job %q: %w", j.Name, err)
		}
		if strings.TrimSpace(j.Weekday) != "" {
			return fmt.Errorf("%w: job %q is daily but sets weekday", pverrors.ErrUsage, j.Name)
		}
	case FrequencyWeekly:
		if _, _, err := ParseTime(j.Time); err != nil {
			return fmt.Errorf("job %q: %w", j.Name, err)
		}
		if _, err := ParseWeekday(j.Weekday); err != nil {
			return fmt.Errorf("job %q: %w", j.Name, err)
		}
	case FrequencyHourly:
		if strings.TrimSpace(j.Time) != "" {
			return fmt.Errorf("%w: job %q is hourly but sets time", pverrors.ErrUsage, j.Name)
		}
		if strings.TrimSpace(j.Weekday) != "" {
			return fmt.Errorf("%w: job %q is hourly but sets weekday", pverrors.ErrUsage, j.Name)
		}
	default:
		return fmt.Errorf("%w: job %q has frequency %q, want daily, weekly, or hourly", pverrors.ErrUsage, j.Name, j.Frequency)
	}
	if j.Attempts < 0 || j.Attempts > MaxAttempts {
		return fmt.Errorf("%w: job %q has attempts %d, want 0 (default) through %d", pverrors.ErrUsage, j.Name, j.Attempts, MaxAttempts)
	}
	if j.Attempts == 0 {
		// Default applies; nothing to check.
	} else if j.Attempts < 1 {
		return fmt.Errorf("%w: job %q has attempts %d, want at least 1", pverrors.ErrUsage, j.Name, j.Attempts)
	}
	if strings.TrimSpace(j.ECC) != "" {
		if _, err := erasure.Parse(j.ECC); err != nil {
			return fmt.Errorf("job %q: %w", j.Name, err)
		}
	}
	if j.Retention != nil {
		if err := j.Retention.Validate(); err != nil {
			return fmt.Errorf("job %q: %w", j.Name, err)
		}
	}
	return nil
}

// State is the mutable run state for one job, kept separately from the job
// definition (DESIGN.md §7, §11.1).
type State struct {
	LastRun      time.Time `json:"last_run,omitzero"`
	LastSuccess  time.Time `json:"last_success,omitzero"`
	LastFailure  time.Time `json:"last_failure,omitzero"`
	FailureCount int       `json:"failure_count,omitzero"`
	NextRun      time.Time `json:"next_run"`
}

// stateFile is the wire form of the per-job state file.
type stateFile struct {
	Version int   `json:"version"`
	State   State `json:"state"`
}

// Validate checks the state without touching storage.
func (s State) Validate() error {
	if s.NextRun.IsZero() {
		return fmt.Errorf("%w: state has no next run", pverrors.ErrUsage)
	}
	if s.FailureCount < 0 {
		return fmt.Errorf("%w: state has negative failure count", pverrors.ErrUsage)
	}
	return nil
}

// ValidateName rejects empty names and anything that is not a safe single
// path segment. Job names become file names, so separators, dots, and
// whitespace-only names fail closed.
func ValidateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: job name is empty", pverrors.ErrUsage)
	}
	if name != strings.TrimSpace(name) {
		return fmt.Errorf("%w: job name %q has surrounding whitespace", pverrors.ErrUsage, name)
	}
	if !filepath.IsLocal(name) || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return fmt.Errorf("%w: invalid job name %q", pverrors.ErrUsage, name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == '+':
		default:
			return fmt.Errorf("%w: invalid job name %q: use letters, digits, ., _, -, +", pverrors.ErrUsage, name)
		}
	}
	return nil
}

// ParseTime parses an HH:MM wall-clock time.
func ParseTime(s string) (int, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("%w: invalid time %q: want HH:MM", pverrors.ErrUsage, s)
	}
	hour, err := atoi2(parts[0], 23, "hour")
	if err != nil {
		return 0, 0, fmt.Errorf("%w: invalid time %q: %w", pverrors.ErrUsage, s, err)
	}
	min, err := atoi2(parts[1], 59, "minute")
	if err != nil {
		return 0, 0, fmt.Errorf("%w: invalid time %q: %w", pverrors.ErrUsage, s, err)
	}
	return hour, min, nil
}

func atoi2(s string, max int, what string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("%s is empty", what)
	}
	n := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%s %q is not numeric", what, s)
		}
		n = n*10 + int(s[i]-'0')
	}
	if n > max {
		return 0, fmt.Errorf("%s %d out of range", what, n)
	}
	// HH:MM fields are exactly two digits; a single digit is still
	// accepted for convenience, longer fields are rejected.
	if len(s) > 2 {
		return 0, fmt.Errorf("%s %q is too long", what, s)
	}
	return n, nil
}

// ParseWeekday parses a full or abbreviated English weekday name,
// case-insensitively.
func ParseWeekday(s string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sunday", "sun":
		return time.Sunday, nil
	case "monday", "mon":
		return time.Monday, nil
	case "tuesday", "tue", "tues":
		return time.Tuesday, nil
	case "wednesday", "wed":
		return time.Wednesday, nil
	case "thursday", "thu", "thur", "thurs":
		return time.Thursday, nil
	case "friday", "fri":
		return time.Friday, nil
	case "saturday", "sat":
		return time.Saturday, nil
	default:
		return time.Sunday, fmt.Errorf("%w: invalid weekday %q", pverrors.ErrUsage, s)
	}
}

// NextRun returns the first scheduled time strictly after from. Daily and
// weekly times are wall-clock times in from's location; hourly runs at the
// top of every hour.
func NextRun(job Job, from time.Time) (time.Time, error) {
	if err := job.Validate(); err != nil {
		return time.Time{}, err
	}
	loc := from.Location()
	if loc == nil {
		loc = time.UTC
	}
	switch strings.ToLower(strings.TrimSpace(job.Frequency)) {
	case FrequencyHourly:
		return from.In(loc).Truncate(time.Hour).Add(time.Hour), nil
	case FrequencyDaily:
		hour, min, err := ParseTime(job.Time)
		if err != nil {
			return time.Time{}, err
		}
		y, m, d := from.In(loc).Date()
		candidate := time.Date(y, m, d, hour, min, 0, 0, loc)
		if !candidate.After(from) {
			candidate = candidate.Add(24 * time.Hour)
		}
		return candidate, nil
	case FrequencyWeekly:
		hour, min, err := ParseTime(job.Time)
		if err != nil {
			return time.Time{}, err
		}
		want, err := ParseWeekday(job.Weekday)
		if err != nil {
			return time.Time{}, err
		}
		y, m, d := from.In(loc).Date()
		candidate := time.Date(y, m, d, hour, min, 0, 0, loc)
		for range 8 {
			if candidate.Weekday() == want && candidate.After(from) {
				return candidate, nil
			}
			candidate = candidate.Add(24 * time.Hour)
		}
		return time.Time{}, fmt.Errorf("%w: cannot find next weekly run", pverrors.ErrUsage)
	default:
		return time.Time{}, fmt.Errorf("%w: unknown frequency %q", pverrors.ErrUsage, job.Frequency)
	}
}

// Due reports whether the job should run now. Catch-up falls out of this:
// a job whose NextRun passed while the machine was off is due once at the
// next start, and its NextRun is recomputed from the run time, never once
// per missed interval (DESIGN.md §11.1).
func Due(state State, now time.Time) bool {
	return !now.Before(state.NextRun)
}

// Backoff returns the delay before attempt (zero-based): 30s, 1m, 2m, …
// capped at 10 minutes.
func Backoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := RetryBaseDelay << attempt
	if d <= 0 || d > maxRetryDelay {
		return maxRetryDelay
	}
	return d
}

// IsTransient reports whether a failed attempt is worth retrying. Usage
// errors are misconfiguration: retrying cannot help, so they fail fast.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	return !errors.Is(err, pverrors.ErrUsage)
}

// ScheduleDir returns the job-definition directory under configDir.
func ScheduleDir(configDir string) string {
	return filepath.Join(configDir, "petravault", "schedule")
}

// StateDir returns the job-state directory under stateDir.
func StateDir(stateDir string) string {
	return filepath.Join(stateDir, "petravault", "schedule")
}

// JobPath returns the definition file for name after validating it.
func JobPath(dir, name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("%w: schedule directory is empty", pverrors.ErrUsage)
	}
	return filepath.Join(dir, name+".json"), nil
}

// StatePath returns the state file for name after validating it.
func StatePath(dir, name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("%w: schedule state directory is empty", pverrors.ErrUsage)
	}
	return filepath.Join(dir, name+".state.json"), nil
}

// LockPath returns the overlap lock file for name.
func LockPath(dir, name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("%w: schedule state directory is empty", pverrors.ErrUsage)
	}
	return filepath.Join(dir, name+".lock"), nil
}

// LoadJob reads and validates one job file. Group/world-readable files and
// unknown fields are refused (DESIGN.md §11.2, §12).
func LoadJob(path string) (Job, error) {
	if err := checkJobPermissions(path); err != nil {
		return Job{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Job{}, fmt.Errorf("read schedule job: %w", err)
	}
	if len(raw) > 1<<20 {
		return Job{}, fmt.Errorf("%w: schedule job %s too large", pverrors.ErrUsage, path)
	}
	var job Job
	if err := json.Unmarshal(raw, &job, json.RejectUnknownMembers(true)); err != nil {
		return Job{}, fmt.Errorf("decode schedule job %s: %w", path, err)
	}
	if err := job.Validate(); err != nil {
		return Job{}, err
	}
	return job, nil
}

// SaveJob validates and durably writes one job file with mode 0600.
func SaveJob(dir string, job Job) error {
	if err := job.Validate(); err != nil {
		return err
	}
	path, err := JobPath(dir, job.Name)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal schedule job: %w", err)
	}
	return writeDurable(path, raw, 0o600)
}

// ListJobs returns every valid job in dir, sorted by name. A missing
// directory means no jobs yet. A corrupt job fails the listing rather than
// being silently skipped.
func ListJobs(dir string) ([]Job, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list schedule jobs: %w", err)
	}
	var out []Job
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".state.json") {
			continue
		}
		job, err := LoadJob(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	slices.SortFunc(out, func(a, b Job) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// LoadState reads one state file. A missing file returns the zero State;
// the caller initializes NextRun via EnsureState. Present files must be
// mode 0600 like job files.
func LoadState(path string) (State, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return State{}, nil
		}
		return State{}, fmt.Errorf("stat schedule state: %w", err)
	}
	if err := checkJobPermissions(path); err != nil {
		return State{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return State{}, fmt.Errorf("read schedule state: %w", err)
	}
	var wire stateFile
	if err := json.Unmarshal(raw, &wire, json.RejectUnknownMembers(true)); err != nil {
		return State{}, fmt.Errorf("decode schedule state %s: %w", path, err)
	}
	if wire.Version != StateVersion {
		return State{}, fmt.Errorf("schedule state %s has version %d, want %d", path, wire.Version, StateVersion)
	}
	return wire.State, nil
}

// SaveState durably writes one state file with mode 0600.
func SaveState(path string, state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(stateFile{Version: StateVersion, State: state})
	if err != nil {
		return fmt.Errorf("marshal schedule state: %w", err)
	}
	return writeDurable(path, raw, 0o600)
}

// EnsureState loads the state for job, initializing NextRun from now when
// the state is missing or holds no NextRun.
func EnsureState(stateDir string, job Job, now time.Time) (State, error) {
	path, err := StatePath(stateDir, job.Name)
	if err != nil {
		return State{}, err
	}
	state, err := LoadState(path)
	if err != nil {
		return State{}, err
	}
	if state.NextRun.IsZero() {
		next, err := NextRun(job, now)
		if err != nil {
			return State{}, err
		}
		state.NextRun = next.UTC()
		if err := SaveState(path, state); err != nil {
			return State{}, err
		}
	}
	return state, nil
}

// Runner performs one backup attempt for job and returns the committed
// snapshot ID. It is injected so the scheduler core stays testable without
// a repository; cmd/petravault wires the real backup, prune, and verify
// pipeline (DESIGN.md §11).
type Runner func(ctx context.Context, job Job) (string, error)

// Result describes one finished job run.
type Result struct {
	// SnapshotID is the committed snapshot, empty when nothing was committed.
	SnapshotID string
	// Duration covers the successful attempt (or the last failed attempt).
	Duration time.Duration
	// Attempts counts the tries used.
	Attempts int
}

// RunOne executes one job run with bounded retry and exponential backoff,
// then advances NextRun from the finish time so missed intervals collapse
// to a single catch-up run. It returns the updated state; the caller saves
// it. Every attempt is logged with job name, snapshot ID, duration, and
// error (DESIGN.md §11.1).
func RunOne(ctx context.Context, job Job, state State, runner Runner, logger *slog.Logger) (State, Result, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if runner == nil {
		return state, Result{}, errors.New("scheduler: runner is nil")
	}
	attempts := job.AttemptsFor()
	var (
		result     Result
		lastErr    error
		snapshotID string
	)
	for attempt := range attempts {
		if err := ctx.Err(); err != nil {
			return state, result, err
		}
		start := time.Now()
		snapshotID, lastErr = runner(ctx, job)
		elapsed := time.Since(start)
		result = Result{SnapshotID: snapshotID, Duration: elapsed, Attempts: attempt + 1}
		if lastErr == nil {
			now := time.Now().UTC()
			next, err := NextRun(job, now)
			if err != nil {
				return state, result, err
			}
			state.LastRun = now
			state.LastSuccess = now
			state.FailureCount = 0
			state.NextRun = next.UTC()
			logger.InfoContext(ctx, "scheduled backup succeeded",
				slog.String("job", job.Name),
				slog.String("snapshot", cmp.Or(snapshotID, "none")),
				slog.Duration("duration", elapsed),
				slog.Int("attempt", attempt+1))
			return state, result, nil
		}
		logger.WarnContext(ctx, "scheduled backup attempt failed",
			slog.String("job", job.Name),
			slog.Int("attempt", attempt+1),
			slog.Int("attempts", attempts),
			slog.Duration("duration", elapsed),
			slog.Any("error", lastErr))
		if !IsTransient(lastErr) || attempt+1 >= attempts {
			break
		}
		if err := sleepCtx(ctx, Backoff(attempt)); err != nil {
			return state, result, err
		}
	}
	now := time.Now().UTC()
	next, err := NextRun(job, now)
	if err != nil {
		return state, result, lastErr
	}
	state.LastRun = now
	state.LastFailure = now
	state.FailureCount++
	state.NextRun = next.UTC()
	logger.ErrorContext(ctx, "scheduled backup failed",
		slog.String("job", job.Name),
		slog.String("snapshot", cmp.Or(snapshotID, "none")),
		slog.Int("attempts", result.Attempts),
		slog.Any("error", lastErr))
	return state, result, lastErr
}

// RunDue runs every enabled, due job once in sorted order, skipping jobs
// whose overlap lock is held. It returns the updated states, per-job
// results, and per-job errors keyed by job name.
func RunDue(ctx context.Context, jobs []Job, states map[string]State, lockDir string, now time.Time, runner Runner, logger *slog.Logger) (map[string]State, map[string]Result, map[string]error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	out := make(map[string]State, len(jobs))
	for _, j := range jobs {
		if s, ok := states[j.Name]; ok {
			out[j.Name] = s
		}
	}
	results := make(map[string]Result)
	errs := make(map[string]error)
	sorted := slices.Clone(jobs)
	slices.SortFunc(sorted, func(a, b Job) int { return strings.Compare(a.Name, b.Name) })
	for _, job := range sorted {
		if err := ctx.Err(); err != nil {
			errs[job.Name] = err
			return out, results, errs
		}
		state, ok := out[job.Name]
		if !ok {
			next, err := NextRun(job, now)
			if err != nil {
				errs[job.Name] = err
				continue
			}
			state = State{NextRun: next.UTC()}
			out[job.Name] = state
		}
		if !job.IsEnabled() || !Due(state, now) {
			continue
		}
		lock, err := TryLock(lockDir, job.Name)
		if err != nil {
			if errors.Is(err, ErrLocked) {
				logger.InfoContext(ctx, "scheduled job still running, skipping",
					slog.String("job", job.Name))
				continue
			}
			errs[job.Name] = err
			continue
		}
		updated, result, runErr := RunOne(ctx, job, state, runner, logger)
		_ = lock.Unlock()
		out[job.Name] = updated
		results[job.Name] = result
		if runErr != nil {
			errs[job.Name] = runErr
		}
	}
	return out, results, errs
}

// Daemon runs due jobs every poll interval until ctx is cancelled. It
// loads jobs and states on every tick so schedule add/remove take effect
// without restarting. Missed runs execute once as catch-up.
func Daemon(ctx context.Context, scheduleDir, stateDir string, poll time.Duration, runner Runner, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if poll <= 0 {
		poll = DefaultPollInterval
	}
	if runner == nil {
		return errors.New("scheduler: runner is nil")
	}
	for {
		if err := DaemonTick(ctx, scheduleDir, stateDir, time.Now(), runner, logger); err != nil {
			// A tick failure is logged, not fatal: the next tick retries.
			// Context cancellation still stops the daemon below.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			logger.WarnContext(ctx, "schedule tick failed", slog.Any("error", err))
		}
		if err := sleepCtx(ctx, poll); err != nil {
			// Context cancellation stops the daemon gracefully; the
			// sleep error itself carries no additional meaning.
			return nil //nolint:nilerr
		}
	}
}

// DaemonTick loads jobs, ensures states, runs due jobs, and saves updated
// states. It is the unit-testable body of Daemon. A corrupt job file is
// recorded as a tick error but does not stop the remaining jobs.
func DaemonTick(ctx context.Context, scheduleDir, stateDir string, now time.Time, runner Runner, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	jobs, loadErrs := loadJobsTolerant(scheduleDir, logger)
	states := make(map[string]State, len(jobs))
	var stateErrs []error
	for _, job := range jobs {
		state, err := EnsureState(stateDir, job, now)
		if err != nil {
			stateErrs = append(stateErrs, fmt.Errorf("job %q: %w", job.Name, err))
			continue
		}
		states[job.Name] = state
	}
	runnable := make([]Job, 0, len(jobs))
	for _, job := range jobs {
		if _, ok := states[job.Name]; ok {
			runnable = append(runnable, job)
		}
	}
	updated, _, errs := RunDue(ctx, runnable, states, stateDir, now, runner, logger)
	var saveErrs []error
	for name, state := range updated {
		path, err := StatePath(stateDir, name)
		if err != nil {
			saveErrs = append(saveErrs, err)
			continue
		}
		if err := SaveState(path, state); err != nil {
			saveErrs = append(saveErrs, err)
		}
	}
	return errors.Join(errors.Join(loadErrs...), errors.Join(stateErrs...), errors.Join(collectErrs(errs)...), errors.Join(saveErrs...))
}

// loadJobsTolerant lists job files like ListJobs but skips corrupt files
// with a warning instead of failing the whole tick, so one bad file cannot
// stop every scheduled job. The CLI list command keeps using strict
// ListJobs to surface corruption to operators.
func loadJobsTolerant(dir string, logger *slog.Logger) ([]Job, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("list schedule jobs: %w", err)}
	}
	var out []Job
	var errs []error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".state.json") {
			continue
		}
		job, err := LoadJob(filepath.Join(dir, name))
		if err != nil {
			logger.Warn("skipping corrupt schedule job", slog.String("file", name), slog.Any("error", err))
			errs = append(errs, fmt.Errorf("schedule job %s: %w", name, err))
			continue
		}
		out = append(out, job)
	}
	slices.SortFunc(out, func(a, b Job) int { return strings.Compare(a.Name, b.Name) })
	return out, errs
}

func collectErrs(m map[string]error) []error {
	out := make([]error, 0, len(m))
	for _, name := range slices.Sorted(maps.Keys(m)) {
		out = append(out, fmt.Errorf("job %q: %w", name, m[name]))
	}
	return out
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// checkJobPermissions refuses schedule files readable by group or others.
// Job and state files must be mode 0600 (DESIGN.md §11.2, §12).
func checkJobPermissions(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat schedule file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("schedule file %s: permissions %v too open, want 0600", path, fi.Mode().Perm())
	}
	return nil
}

func writeDurable(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create schedule dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "schedule-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp schedule file: %w", err)
	}
	tmpName := tmp.Name()
	writeErr := func() error {
		if _, err := tmp.Write(data); err != nil {
			return fmt.Errorf("write temp schedule file: %w", err)
		}
		if err := tmp.Chmod(perm); err != nil {
			return fmt.Errorf("chmod temp schedule file: %w", err)
		}
		if err := tmp.Sync(); err != nil {
			return fmt.Errorf("sync temp schedule file: %w", err)
		}
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("close temp schedule file: %w", err)
		}
		if err := os.Rename(tmpName, path); err != nil {
			return fmt.Errorf("install schedule file: %w", err)
		}
		return syncScheduleDir(filepath.Dir(path))
	}()
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return writeErr
	}
	return nil
}

func syncScheduleDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

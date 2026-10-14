// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package scheduler_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"petravault/internal/scheduler"

	pverrors "petravault/internal/errors"
)

func testJob(name string) scheduler.Job {
	return scheduler.Job{
		Name:       name,
		Source:     "/tmp/src",
		Repository: "/tmp/repo",
		Frequency:  scheduler.FrequencyDaily,
		Time:       "02:00",
		Attempts:   1,
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	valid := testJob("daily-docs")
	valid.Retention = &scheduler.Retention{Daily: 7}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid job: %v", err)
	}

	weekly := testJob("weekly-docs")
	weekly.Frequency = scheduler.FrequencyWeekly
	weekly.Weekday = "monday"
	if err := weekly.Validate(); err != nil {
		t.Fatalf("valid weekly job: %v", err)
	}

	hourly := testJob("hourly-docs")
	hourly.Frequency = scheduler.FrequencyHourly
	hourly.Time = ""
	if err := hourly.Validate(); err != nil {
		t.Fatalf("valid hourly job: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*scheduler.Job)
	}{
		{"empty name", func(j *scheduler.Job) { j.Name = "" }},
		{"bad name slash", func(j *scheduler.Job) { j.Name = "a/b" }},
		{"bad name dots", func(j *scheduler.Job) { j.Name = ".." }},
		{"empty source", func(j *scheduler.Job) { j.Source = "" }},
		{"empty repository", func(j *scheduler.Job) { j.Repository = "" }},
		{"bad frequency", func(j *scheduler.Job) { j.Frequency = "minutely" }},
		{"bad time", func(j *scheduler.Job) { j.Time = "25:00" }},
		{"bad time shape", func(j *scheduler.Job) { j.Time = "noon" }},
		{"daily with weekday", func(j *scheduler.Job) { j.Weekday = "monday" }},
		{"hourly with time", func(j *scheduler.Job) { hourly := *j; hourly.Frequency = scheduler.FrequencyHourly; *j = hourly }},
		{"negative attempts", func(j *scheduler.Job) { j.Attempts = -1 }},
		{"too many attempts", func(j *scheduler.Job) { j.Attempts = 99 }},
		{"bad ecc", func(j *scheduler.Job) { j.ECC = "ultra" }},
		{"empty retention", func(j *scheduler.Job) { j.Retention = &scheduler.Retention{} }},
		{"negative retention", func(j *scheduler.Job) { j.Retention = &scheduler.Retention{Daily: -1} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j := testJob("job")
			tc.mutate(&j)
			if err := j.Validate(); err == nil {
				t.Fatalf("Validate accepted %s", tc.name)
			} else if !errors.Is(err, pverrors.ErrUsage) {
				t.Fatalf("Validate(%s) = %v, want usage error", tc.name, err)
			}
		})
	}

	weeklyBad := testJob("weekly-bad")
	weeklyBad.Frequency = scheduler.FrequencyWeekly
	weeklyBad.Weekday = "funday"
	if err := weeklyBad.Validate(); err == nil {
		t.Fatal("weekly job with bad weekday validated")
	}
}

func TestNextRunDaily(t *testing.T) {
	t.Parallel()

	job := testJob("daily")
	loc := time.UTC
	// Before today's run: today at 02:00.
	from := time.Date(2026, time.October, 14, 1, 0, 0, 0, loc)
	next, err := scheduler.NextRun(job, from)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, time.October, 14, 2, 0, 0, 0, loc)
	if !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
	// After today's run: tomorrow.
	from = time.Date(2026, time.October, 14, 3, 0, 0, 0, loc)
	next, err = scheduler.NextRun(job, from)
	if err != nil {
		t.Fatal(err)
	}
	want = time.Date(2026, time.October, 15, 2, 0, 0, 0, loc)
	if !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
	// Exactly at run time: strictly after, so tomorrow.
	from = time.Date(2026, time.October, 14, 2, 0, 0, 0, loc)
	next, err = scheduler.NextRun(job, from)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Equal(want) {
		t.Fatalf("next at boundary = %v, want %v", next, want)
	}
}

func TestNextRunWeekly(t *testing.T) {
	t.Parallel()

	job := testJob("weekly")
	job.Frequency = scheduler.FrequencyWeekly
	job.Weekday = "wednesday"
	job.Time = "02:00"
	// Wednesday 2026-10-14 is a Wednesday.
	from := time.Date(2026, time.October, 14, 1, 0, 0, 0, time.UTC)
	next, err := scheduler.NextRun(job, from)
	if err != nil {
		t.Fatal(err)
	}
	if next.Weekday() != time.Wednesday || next.Hour() != 2 {
		t.Fatalf("next = %v, want Wednesday 02:00", next)
	}
	from = time.Date(2026, time.October, 14, 3, 0, 0, 0, time.UTC)
	next, err = scheduler.NextRun(job, from)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, time.October, 21, 2, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
}

func TestNextRunHourly(t *testing.T) {
	t.Parallel()

	job := testJob("hourly")
	job.Frequency = scheduler.FrequencyHourly
	job.Time = ""
	from := time.Date(2026, time.October, 14, 10, 15, 0, 0, time.UTC)
	next, err := scheduler.NextRun(job, from)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, time.October, 14, 11, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
}

func TestDueAndCatchUp(t *testing.T) {
	t.Parallel()

	job := testJob("catchup")
	now := time.Date(2026, time.October, 14, 10, 0, 0, 0, time.UTC)
	next, err := scheduler.NextRun(job, now)
	if err != nil {
		t.Fatal(err)
	}
	state := scheduler.State{NextRun: next}
	if scheduler.Due(state, now) {
		t.Fatal("job due before its next run")
	}
	// A machine that was off for days runs once at the next start, not
	// once per missed interval.
	late := next.Add(72 * time.Hour)
	if !scheduler.Due(state, late) {
		t.Fatal("overdue job is not due")
	}
	calls := 0
	runner := func(_ context.Context, _ scheduler.Job) (string, error) {
		calls++
		return "snap", nil
	}
	updated, _, err := scheduler.RunOne(context.Background(), job, state, runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (single catch-up, not per missed interval)", calls)
	}
	later, err := scheduler.NextRun(job, updated.LastRun)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.NextRun.Equal(later.UTC()) {
		t.Fatalf("next = %v, want %v", updated.NextRun, later)
	}
}

func TestBackoff(t *testing.T) {
	t.Parallel()

	if got := scheduler.Backoff(0); got != 30*time.Second {
		t.Fatalf("backoff(0) = %v, want 30s", got)
	}
	if got := scheduler.Backoff(1); got != time.Minute {
		t.Fatalf("backoff(1) = %v, want 1m", got)
	}
	if got := scheduler.Backoff(100); got != 10*time.Minute {
		t.Fatalf("backoff(100) = %v, want capped 10m", got)
	}
}

func TestIsTransient(t *testing.T) {
	t.Parallel()

	if scheduler.IsTransient(nil) {
		t.Fatal("nil error is transient")
	}
	if scheduler.IsTransient(pverrors.ErrUsage) {
		t.Fatal("usage error should not be transient")
	}
	if !scheduler.IsTransient(errors.New("boom")) {
		t.Fatal("generic error should be transient")
	}
	if !scheduler.IsTransient(pverrors.ErrIntegrity) {
		t.Fatal("integrity error should be retried, not silently dropped")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	job := testJob("roundtrip")
	job.Retention = &scheduler.Retention{Daily: 7}
	if err := scheduler.SaveJob(dir, job); err != nil {
		t.Fatal(err)
	}
	path, err := scheduler.JobPath(dir, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("job mode = %v, want 0600", fi.Mode().Perm())
	}
	got, err := scheduler.LoadJob(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != job.Name || got.Time != job.Time || got.Retention == nil || got.Retention.Daily != 7 {
		t.Fatalf("round trip = %+v, want %+v", got, job)
	}
	listed, err := scheduler.ListJobs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Name != job.Name {
		t.Fatalf("listed = %+v, want one job", listed)
	}
}

func TestLoadJobRefusesLoosePermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	job := testJob("loose")
	if err := scheduler.SaveJob(dir, job); err != nil {
		t.Fatal(err)
	}
	path, err := scheduler.JobPath(dir, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.LoadJob(path); err == nil {
		t.Fatal("loaded a group/world-readable job file")
	}
}

func TestLoadJobRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "evil.json")
	body := `{"name":"evil","source":"/s","repository":"/r","frequency":"hourly","password":"hunter2"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.LoadJob(path); err == nil {
		t.Fatal("loaded a job with unknown (secret) fields")
	}
}

func TestStateRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path, err := scheduler.StatePath(dir, "job")
	if err != nil {
		t.Fatal(err)
	}
	// Missing state loads empty so EnsureState can initialize it.
	state, err := scheduler.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !state.NextRun.IsZero() {
		t.Fatalf("missing state = %+v, want zero", state)
	}
	job := testJob("job")
	now := time.Date(2026, time.October, 14, 10, 0, 0, 0, time.UTC)
	ensured, err := scheduler.EnsureState(dir, job, now)
	if err != nil {
		t.Fatal(err)
	}
	if ensured.NextRun.IsZero() {
		t.Fatal("ensured state has no next run")
	}
	if err := scheduler.SaveState(path, ensured); err != nil {
		t.Fatal(err)
	}
	loaded, err := scheduler.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.NextRun.Equal(ensured.NextRun) {
		t.Fatalf("state next = %v, want %v", loaded.NextRun, ensured.NextRun)
	}
}

func TestRunOneSuccessAndFailure(t *testing.T) {
	t.Parallel()

	job := testJob("runonce")
	job.Attempts = 1
	state := scheduler.State{NextRun: time.Now().Add(-time.Hour)}
	runner := func(_ context.Context, _ scheduler.Job) (string, error) {
		return "abc123", nil
	}
	updated, result, err := scheduler.RunOne(context.Background(), job, state, runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.SnapshotID != "abc123" || result.Attempts != 1 {
		t.Fatalf("result = %+v", result)
	}
	if updated.FailureCount != 0 || updated.LastSuccess.IsZero() {
		t.Fatalf("state after success = %+v", updated)
	}

	failer := func(_ context.Context, _ scheduler.Job) (string, error) {
		return "", errors.New("boom")
	}
	updated, _, err = scheduler.RunOne(context.Background(), job, state, failer, nil)
	if err == nil {
		t.Fatal("failing runner succeeded")
	}
	if updated.FailureCount != 1 || updated.LastFailure.IsZero() {
		t.Fatalf("state after failure = %+v", updated)
	}
}

func TestRunOneRetriesTransient(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		job := testJob("retry")
		job.Attempts = 3
		state := scheduler.State{NextRun: time.Now().Add(-time.Hour)}
		calls := 0
		runner := func(_ context.Context, _ scheduler.Job) (string, error) {
			calls++
			if calls < 3 {
				return "", errors.New("transient")
			}
			return "snap", nil
		}
		updated, result, err := scheduler.RunOne(t.Context(), job, state, runner, nil)
		if err != nil {
			t.Fatal(err)
		}
		if calls != 3 || result.Attempts != 3 {
			t.Fatalf("calls = %d result = %+v, want 3 attempts", calls, result)
		}
		if updated.FailureCount != 0 {
			t.Fatalf("state = %+v, want reset failure count", updated)
		}
	})
}

func TestRunOneNoRetryOnUsage(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		job := testJob("noretry")
		job.Attempts = 3
		state := scheduler.State{NextRun: time.Now().Add(-time.Hour)}
		calls := 0
		runner := func(_ context.Context, _ scheduler.Job) (string, error) {
			calls++
			return "", pverrors.ErrUsage
		}
		_, _, err := scheduler.RunOne(t.Context(), job, state, runner, nil)
		if err == nil {
			t.Fatal("usage error succeeded")
		}
		if calls != 1 {
			t.Fatalf("calls = %d, want 1 (usage errors fail fast)", calls)
		}
	})
}

func TestRunDueSkipsDisabledAndFuture(t *testing.T) {
	t.Parallel()

	now := time.Now()
	due := testJob("due")
	due.Attempts = 1
	future := testJob("future")
	future.Attempts = 1
	disabled := testJob("off")
	disabled.Enabled = new(false)
	disabled.Attempts = 1

	jobs := []scheduler.Job{due, future, disabled}
	states := map[string]scheduler.State{
		"due":    {NextRun: now.Add(-time.Minute)},
		"future": {NextRun: now.Add(time.Hour)},
		"off":    {NextRun: now.Add(-time.Minute)},
	}
	var ran []string
	runner := func(_ context.Context, j scheduler.Job) (string, error) {
		ran = append(ran, j.Name)
		return "snap", nil
	}
	updated, results, errs := scheduler.RunDue(context.Background(), jobs, states, t.TempDir(), now, runner, nil)
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if len(ran) != 1 || ran[0] != "due" {
		t.Fatalf("ran = %v, want [due]", ran)
	}
	if _, ok := results["due"]; !ok {
		t.Fatal("no result for due job")
	}
	if updated["due"].FailureCount != 0 {
		t.Fatalf("due state = %+v", updated["due"])
	}
}

func TestRunDueSkipsLockedJob(t *testing.T) {
	t.Parallel()

	now := time.Now()
	job := testJob("locked")
	job.Attempts = 1
	lockDir := t.TempDir()
	lockPath, err := scheduler.LockPath(lockDir, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	_ = lockPath
	// Hold the overlap lock out of band: RunDue must skip, not fail.
	held, err := scheduler.TryLock(lockDir, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Unlock()

	states := map[string]scheduler.State{job.Name: {NextRun: now.Add(-time.Minute)}}
	called := false
	runner := func(_ context.Context, _ scheduler.Job) (string, error) {
		called = true
		return "snap", nil
	}
	_, _, errs := scheduler.RunDue(context.Background(), []scheduler.Job{job}, states, lockDir, now, runner, nil)
	if len(errs) != 0 {
		t.Fatalf("errs = %v, want none (locked jobs are skipped)", errs)
	}
	if called {
		t.Fatal("runner ran while the overlap lock was held")
	}
}

func TestDaemonTickRunsDueAndSavesState(t *testing.T) {
	t.Parallel()

	scheduleDir := t.TempDir()
	stateDir := t.TempDir()
	job := testJob("daemon-job")
	if err := scheduler.SaveJob(scheduleDir, job); err != nil {
		t.Fatal(err)
	}
	// Force the job due by writing a past NextRun.
	past := scheduler.State{NextRun: time.Now().Add(-time.Hour)}
	statePath, err := scheduler.StatePath(stateDir, job.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.SaveState(statePath, past); err != nil {
		t.Fatal(err)
	}
	runner := func(_ context.Context, _ scheduler.Job) (string, error) {
		return "snap", nil
	}
	if err := scheduler.DaemonTick(context.Background(), scheduleDir, stateDir, time.Now(), runner, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := scheduler.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LastSuccess.IsZero() || loaded.FailureCount != 0 {
		t.Fatalf("state after tick = %+v", loaded)
	}
	if !loaded.NextRun.After(time.Now()) {
		t.Fatalf("next run = %v, want future", loaded.NextRun)
	}
}

func TestJobNameValidation(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "a/b", `a\b`, ".", "..", "../evil", "has space", "semi;colon", "quote\""} {
		if err := scheduler.ValidateName(bad); err == nil {
			t.Fatalf("ValidateName(%q) succeeded", bad)
		}
	}
	if err := scheduler.ValidateName("daily-documents_1"); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
}

func TestShouldVerify(t *testing.T) {
	t.Parallel()

	job := testJob("v")
	if !job.ShouldVerify(nil) {
		t.Fatal("nil global should default to true")
	}
	off := false
	if job.ShouldVerify(&off) {
		t.Fatal("global false honored")
	}
	job.Verify = new(true)
	if !job.ShouldVerify(&off) {
		t.Fatal("job verify overrides global")
	}
}

func TestListJobsRejectsCorrupt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := scheduler.SaveJob(dir, testJob("good")); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"name": 123}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.ListJobs(dir); err == nil {
		t.Fatal("listed corrupt jobs without error")
	}
}

func TestRetentionValidation(t *testing.T) {
	t.Parallel()

	if err := (scheduler.Retention{Daily: 1}).Validate(); err != nil {
		t.Fatalf("valid retention: %v", err)
	}
	if err := (scheduler.Retention{}).Validate(); err == nil {
		t.Fatal("empty retention validated")
	}
	if err := (scheduler.Retention{Daily: -1}).Validate(); err == nil {
		t.Fatal("negative retention validated")
	}
}

func TestTimeAndWeekdayParsing(t *testing.T) {
	t.Parallel()

	if _, _, err := scheduler.ParseTime("02:00"); err != nil {
		t.Fatalf("valid time: %v", err)
	}
	for _, bad := range []string{"", "2", "24:00", "02:60", "ab:cd", "2:00:00"} {
		if _, _, err := scheduler.ParseTime(bad); err == nil {
			t.Fatalf("ParseTime(%q) succeeded", bad)
		}
	}
	if _, err := scheduler.ParseWeekday("Monday"); err != nil {
		t.Fatalf("valid weekday: %v", err)
	}
	if _, err := scheduler.ParseWeekday("mon"); err != nil {
		t.Fatalf("abbreviated weekday: %v", err)
	}
	if _, err := scheduler.ParseWeekday("funday"); err == nil {
		t.Fatal("bad weekday parsed")
	}
}

func TestEnabledDefault(t *testing.T) {
	t.Parallel()

	job := testJob("enabled-default")
	if !job.IsEnabled() {
		t.Fatal("omitted enabled should mean enabled")
	}
	job.Enabled = new(false)
	if job.IsEnabled() {
		t.Fatal("explicit false should disable")
	}
}

func TestSecretFieldsRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, field := range []string{"password", "secret", "private_key"} {
		path := filepath.Join(dir, field+".json")
		body := `{"name":"x","source":"/s","repository":"/r","frequency":"hourly","` + field + `":"value"}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := scheduler.LoadJob(path); err == nil {
			t.Fatalf("job with %q field loaded", field)
		} else if !strings.Contains(err.Error(), "decode") && !strings.Contains(err.Error(), "unknown") {
			t.Logf("job with %q rejected as %v (want unknown-field error)", field, err)
		}
	}
}

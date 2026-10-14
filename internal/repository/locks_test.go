// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository_test

import (
	"testing"
	"testing/synctest"
	"time"

	"petravault/internal/repository"
)

func lockRepo(t *testing.T) *repository.Local {
	t.Helper()
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestBackupMarkerRoundTrip(t *testing.T) {
	t.Parallel()

	repo := lockRepo(t)
	ctx := t.Context()
	now := time.Date(2026, time.October, 14, 10, 0, 0, 0, time.UTC)
	if err := repository.WriteBackupMarker(ctx, repo, "abc123", "holder", "host", func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	markers, err := repository.ListBackupMarkers(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(markers) != 1 || markers[0].Lock.Holder != "holder" {
		t.Fatalf("markers = %+v, want one holder", markers)
	}
	if err := repository.RemoveBackupMarker(ctx, repo, "abc123"); err != nil {
		t.Fatal(err)
	}
	markers, err = repository.ListBackupMarkers(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(markers) != 0 {
		t.Fatalf("markers after remove = %+v, want none", markers)
	}
}

func TestBackupMarkerRejectsBadID(t *testing.T) {
	t.Parallel()

	repo := lockRepo(t)
	ctx := t.Context()
	for _, id := range []string{"", "../evil", "a/b", "a\\b"} {
		if err := repository.WriteBackupMarker(ctx, repo, id, "h", "host", nil); err == nil {
			t.Fatalf("WriteBackupMarker(%q) succeeded, want error", id)
		}
	}
}

func TestGCLockAcquireRelease(t *testing.T) {
	t.Parallel()

	repo := lockRepo(t)
	ctx := t.Context()
	now := time.Date(2026, time.October, 14, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	acquired, err := repository.TryAcquireGCLock(ctx, repo, repository.OperationPrune, "prune-1", "host", repository.DefaultLockTTL, nowFn)
	if err != nil || !acquired {
		t.Fatalf("first acquire = %v, %v; want true, nil", acquired, err)
	}
	acquired, err = repository.TryAcquireGCLock(ctx, repo, repository.OperationPrune, "prune-2", "host", repository.DefaultLockTTL, nowFn)
	if err != nil || acquired {
		t.Fatalf("second acquire = %v, %v; want false, nil", acquired, err)
	}
	held, err := repository.GCLockHeld(ctx, repo, repository.DefaultLockTTL, nowFn)
	if err != nil || !held {
		t.Fatalf("held = %v, %v; want true, nil", held, err)
	}
	if err := repository.ReleaseGCLock(ctx, repo); err != nil {
		t.Fatal(err)
	}
	held, err = repository.GCLockHeld(ctx, repo, repository.DefaultLockTTL, nowFn)
	if err != nil || held {
		t.Fatalf("held after release = %v, %v; want false, nil", held, err)
	}
}

func TestGCLockRejectsBadOperation(t *testing.T) {
	t.Parallel()

	repo := lockRepo(t)
	ctx := t.Context()
	if _, err := repository.TryAcquireGCLock(ctx, repo, "backup", "h", "host", repository.DefaultLockTTL, nil); err == nil {
		t.Fatal("acquire with backup operation succeeded, want error")
	}
}

func TestGCLockStaleIsReaped(t *testing.T) {
	t.Parallel()

	repo := lockRepo(t)
	ctx := t.Context()
	old := time.Date(2026, time.October, 14, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return old }
	acquired, err := repository.TryAcquireGCLock(ctx, repo, repository.OperationPrune, "crashed", "host", time.Minute, nowFn)
	if err != nil || !acquired {
		t.Fatalf("first acquire = %v, %v", acquired, err)
	}
	// An hour later the lock is stale and anyone may take it.
	later := old.Add(time.Hour)
	acquired, err = repository.TryAcquireGCLock(ctx, repo, repository.OperationECCRebuild, "next", "host", time.Minute, func() time.Time { return later })
	if err != nil || !acquired {
		t.Fatalf("stale acquire = %v, %v; want true, nil", acquired, err)
	}
	lock, err := repository.ReadGCLock(ctx, repo)
	if err != nil || lock == nil || lock.Operation != repository.OperationECCRebuild {
		t.Fatalf("lock after stale reap = %+v, err %v", lock, err)
	}
}

func TestWaitForBackupsEmpty(t *testing.T) {
	t.Parallel()

	repo := lockRepo(t)
	ctx := t.Context()
	if err := repository.WaitForBackups(ctx, repo, time.Minute, time.Minute, nil); err != nil {
		t.Fatalf("wait with no markers = %v, want nil", err)
	}
}

func TestWaitForBackupsReapsStale(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		repo := lockRepo(t)
		ctx := t.Context()
		old := time.Now().Add(-time.Hour)
		if err := repository.WriteBackupMarker(ctx, repo, "stale-1", "h", "host", func() time.Time { return old }); err != nil {
			t.Fatal(err)
		}
		if err := repository.WaitForBackups(ctx, repo, time.Minute, time.Minute, nil); err != nil {
			t.Fatalf("wait with stale marker = %v, want nil", err)
		}
		markers, err := repository.ListBackupMarkers(ctx, repo)
		if err != nil {
			t.Fatal(err)
		}
		if len(markers) != 0 {
			t.Fatalf("stale markers remain: %+v", markers)
		}
	})
}

func TestWaitForBackupsTimesOutOnLive(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		repo := lockRepo(t)
		ctx := t.Context()
		if err := repository.WriteBackupMarker(ctx, repo, "live-1", "h", "host", nil); err != nil {
			t.Fatal(err)
		}
		// A live marker never clears: bounded wait aborts without
		// deleting anything.
		if err := repository.WaitForBackups(ctx, repo, time.Hour, 500*time.Millisecond, nil); err == nil {
			t.Fatal("wait with live marker succeeded, want timeout")
		}
		markers, err := repository.ListBackupMarkers(ctx, repo)
		if err != nil {
			t.Fatal(err)
		}
		if len(markers) != 1 {
			t.Fatalf("live marker was deleted: %+v", markers)
		}
	})
}

func TestBackupMarkerOrdering(t *testing.T) {
	t.Parallel()

	// Backup writes its marker before checking gc.lock, and prune writes
	// gc.lock before listing markers: at least one side always sees the
	// other. This test pins the order: marker first, then gc check.
	repo := lockRepo(t)
	ctx := t.Context()
	if err := repository.WriteBackupMarker(ctx, repo, "order-1", "h", "host", nil); err != nil {
		t.Fatal(err)
	}
	held, err := repository.GCLockHeld(ctx, repo, repository.DefaultLockTTL, nil)
	if err != nil || held {
		t.Fatalf("gc held = %v, %v; want false, nil", held, err)
	}
	acquired, err := repository.TryAcquireGCLock(ctx, repo, repository.OperationPrune, "prune", "host", repository.DefaultLockTTL, nil)
	if err != nil || !acquired {
		t.Fatalf("prune acquire = %v, %v", acquired, err)
	}
	live, err := repository.LiveBackupMarkers(ctx, repo, repository.DefaultLockTTL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 {
		t.Fatalf("prune sees %d live markers, want 1", len(live))
	}
}

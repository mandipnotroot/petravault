// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	json "encoding/json/v2"

	pverrors "petravault/internal/errors"
)

// Maintenance lock protocol (DESIGN.md §10.2). Lock objects live under
// locks/: locks/gc.lock is exclusive (prune or ecc-rebuild) and
// locks/backup-<id> marks one running backup (shared). Creation via
// PutObjectIfAbsent is the compare-and-swap on both backends (local O_EXCL,
// S3 If-None-Match "*"; see the AWS SDK PutObjectInput.IfNoneMatch docs:
// a lost race returns 412 Precondition Failed or 409
// ConditionalRequestConflict, which S3Repository maps to (false, nil)).
// Each object records its holder, host, operation, and timestamps, is
// heartbeat-refreshed while its holder runs, and is considered abandoned
// after its TTL, after which anyone may remove it.
//
// Ordering matters and has tests: a backup writes its marker, then checks
// for gc.lock, then reads indexes; prune writes gc.lock, then lists
// markers (DESIGN.md §10.2, GO_GUIDELINES.md §10).
const (
	// GCLockKey is the exclusive maintenance lock (prune or ecc-rebuild).
	GCLockKey = "locks/gc.lock"
	// BackupLockPrefix scopes one marker per running backup.
	BackupLockPrefix = "locks/backup-"
	// LockVersion is the lock object format version.
	LockVersion = 1

	// OperationPrune and OperationECCRebuild own gc.lock;
	// OperationBackup owns backup markers.
	OperationPrune      = "prune"
	OperationECCRebuild = "ecc-rebuild"
	OperationBackup     = "backup"

	// DefaultLockTTL considers a lock abandoned after its holder stops
	// refreshing it (e.g. the holder crashed).
	DefaultLockTTL = 10 * time.Minute
	// DefaultHeartbeatInterval refreshes a held lock.
	DefaultHeartbeatInterval = time.Minute
	// DefaultPruneWaitTimeout bounds how long prune waits for in-flight
	// backups before aborting without deleting anything.
	DefaultPruneWaitTimeout = 5 * time.Minute
	// DefaultBackupRetryAttempts bounds backup retries when gc.lock is held.
	DefaultBackupRetryAttempts = 5
)

// Lock is one lock object. Times are UTC.
type Lock struct {
	Version   int       `json:"version"`
	Holder    string    `json:"holder"`
	Host      string    `json:"host"`
	Operation string    `json:"operation"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NamedLock pairs a repository key with its decoded lock.
type NamedLock struct {
	Key  string
	Lock Lock
}

// Validate checks l without touching storage. Unknown operations fail
// closed.
func (l Lock) Validate() error {
	if l.Version != LockVersion {
		return fmt.Errorf("lock has version %d, want %d", l.Version, LockVersion)
	}
	if strings.TrimSpace(l.Holder) == "" {
		return fmt.Errorf("%w: lock holder is empty", pverrors.ErrUsage)
	}
	if strings.TrimSpace(l.Host) == "" {
		return fmt.Errorf("%w: lock host is empty", pverrors.ErrUsage)
	}
	switch l.Operation {
	case OperationPrune, OperationECCRebuild, OperationBackup:
	default:
		return fmt.Errorf("%w: unknown lock operation %q", pverrors.ErrUsage, l.Operation)
	}
	if l.CreatedAt.IsZero() || l.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: lock timestamps are missing", pverrors.ErrUsage)
	}
	return nil
}

// IsStale reports whether l was last refreshed more than ttl ago according
// to now. Stale locks may be removed by anyone.
func IsStale(l Lock, now time.Time, ttl time.Duration) bool {
	if ttl <= 0 {
		ttl = DefaultLockTTL
	}
	return now.UTC().Sub(l.UpdatedAt.UTC()) > ttl
}

// NewBackupID returns a unique backup marker ID: 16 random bytes from
// crypto/rand hex encoded (per GO_GUIDELINES.md §7, randomness is
// crypto/rand only).
func NewBackupID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate backup id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// BackupKey returns the marker key for id. IDs containing path separators
// are rejected: marker keys are untrusted input when listed back.
func BackupKey(id string) (string, error) {
	if strings.TrimSpace(id) == "" {
		return "", fmt.Errorf("%w: backup id is empty", pverrors.ErrUsage)
	}
	if strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return "", fmt.Errorf("%w: invalid backup id %q", pverrors.ErrUsage, id)
	}
	if id == "." || id == ".." {
		return "", fmt.Errorf("%w: invalid backup id %q", pverrors.ErrUsage, id)
	}
	key := BackupLockPrefix + id
	if !isLocalKey(key) {
		return "", fmt.Errorf("%w: invalid backup id %q", pverrors.ErrUsage, id)
	}
	return key, nil
}

func isLocalKey(key string) bool {
	// filepath.IsLocal rejects absolute paths and ".." escapes; lock IDs
	// must also avoid "/" so one marker is one object.
	if strings.Contains(key, "\\") {
		return false
	}
	for segment := range strings.SplitSeq(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// DefaultHost returns the machine hostname for lock records, falling back
// to "unknown" when it cannot be resolved.
func DefaultHost() string {
	if name, err := os.Hostname(); err == nil && strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return "unknown"
}

// WriteBackupMarker creates locks/backup-<id> with PutObjectIfAbsent. The
// caller must check for gc.lock only after this returns, then read indexes
// (DESIGN.md §10.2).
func WriteBackupMarker(ctx context.Context, repo Repository, id, holder, host string, now func() time.Time) error {
	if repo == nil {
		return errors.New("write backup marker: repository is nil")
	}
	key, err := BackupKey(id)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	if now != nil {
		at = now().UTC()
	}
	if strings.TrimSpace(holder) == "" {
		holder = id
	}
	if strings.TrimSpace(host) == "" {
		host = DefaultHost()
	}
	lock := Lock{
		Version: LockVersion, Holder: holder, Host: host,
		Operation: OperationBackup, CreatedAt: at, UpdatedAt: at,
	}
	if err := lock.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(lock)
	if err != nil {
		return fmt.Errorf("marshal backup marker: %w", err)
	}
	created, err := repo.PutObjectIfAbsent(ctx, key, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("write backup marker: %w", err)
	}
	if !created {
		return fmt.Errorf("%w: backup marker %s already exists", pverrors.ErrUsage, key)
	}
	return nil
}

// RemoveBackupMarker deletes locks/backup-<id>. Deleting a missing marker
// is not an error: the marker may have been reaped as stale.
func RemoveBackupMarker(ctx context.Context, repo Repository, id string) error {
	if repo == nil {
		return errors.New("remove backup marker: repository is nil")
	}
	key, err := BackupKey(id)
	if err != nil {
		return err
	}
	if err := repo.DeleteObject(ctx, key); err != nil {
		return fmt.Errorf("remove backup marker: %w", err)
	}
	return nil
}

// ListBackupMarkers returns all decoded backup markers in sorted key order.
// Corrupt markers fail closed: they abort the listing rather than being
// silently skipped.
func ListBackupMarkers(ctx context.Context, repo Repository) ([]NamedLock, error) {
	if repo == nil {
		return nil, errors.New("list backup markers: repository is nil")
	}
	keys, err := repo.List(ctx, BackupLockPrefix)
	if err != nil {
		return nil, fmt.Errorf("list backup markers: %w", err)
	}
	var out []NamedLock
	for _, key := range keys {
		if strings.HasSuffix(key, ".ecc") {
			continue
		}
		if !strings.HasPrefix(key, BackupLockPrefix) {
			continue
		}
		lock, err := readLock(ctx, repo, key)
		if err != nil {
			return nil, err
		}
		if lock.Operation != OperationBackup {
			return nil, fmt.Errorf("%w: marker %s holds operation %q", pverrors.ErrIntegrity, key, lock.Operation)
		}
		out = append(out, NamedLock{Key: key, Lock: lock})
	}
	slices.SortFunc(out, func(a, b NamedLock) int { return strings.Compare(a.Key, b.Key) })
	return out, nil
}

// LiveBackupMarkers returns the markers that are not stale according to
// now and ttl. Stale markers may be reaped by anyone.
func LiveBackupMarkers(ctx context.Context, repo Repository, ttl time.Duration, now func() time.Time) ([]NamedLock, error) {
	markers, err := ListBackupMarkers(ctx, repo)
	if err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	if now != nil {
		at = now().UTC()
	}
	var live []NamedLock
	for _, m := range markers {
		if !IsStale(m.Lock, at, ttl) {
			live = append(live, m)
		}
	}
	return live, nil
}

// ReapStaleBackupMarkers deletes stale backup markers. It is called by
// prune before waiting, so crashed backups do not block maintenance
// forever.
func ReapStaleBackupMarkers(ctx context.Context, repo Repository, ttl time.Duration, now func() time.Time) error {
	markers, err := ListBackupMarkers(ctx, repo)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	if now != nil {
		at = now().UTC()
	}
	for _, m := range markers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if IsStale(m.Lock, at, ttl) {
			if err := repo.DeleteObject(ctx, m.Key); err != nil {
				return fmt.Errorf("reap stale marker %s: %w", m.Key, err)
			}
		}
	}
	return nil
}

// ReadGCLock returns the decoded gc.lock, or nil when no lock exists. A
// corrupt lock fails closed as an integrity error: prune must abort rather
// than delete under a lock it cannot understand.
func ReadGCLock(ctx context.Context, repo Repository) (*Lock, error) {
	if repo == nil {
		return nil, errors.New("read gc lock: repository is nil")
	}
	exists, err := repo.Exists(ctx, GCLockKey)
	if err != nil {
		return nil, fmt.Errorf("stat gc lock: %w", err)
	}
	if !exists {
		return nil, nil
	}
	lock, err := readLock(ctx, repo, GCLockKey)
	if err != nil {
		return nil, err
	}
	return &lock, nil
}

// GCLockHeld reports whether a live (non-stale) gc.lock exists.
func GCLockHeld(ctx context.Context, repo Repository, ttl time.Duration, now func() time.Time) (bool, error) {
	lock, err := ReadGCLock(ctx, repo)
	if err != nil {
		return false, err
	}
	if lock == nil {
		return false, nil
	}
	at := time.Now().UTC()
	if now != nil {
		at = now().UTC()
	}
	return !IsStale(*lock, at, ttl), nil
}

// TryAcquireGCLock creates gc.lock when no live lock exists. A stale lock
// is reaped and acquisition retried once; a lost race returns (false, nil).
// operation is prune or ecc-rebuild; anything else fails closed.
func TryAcquireGCLock(ctx context.Context, repo Repository, operation, holder, host string, ttl time.Duration, now func() time.Time) (bool, error) {
	if repo == nil {
		return false, errors.New("acquire gc lock: repository is nil")
	}
	if operation != OperationPrune && operation != OperationECCRebuild {
		return false, fmt.Errorf("%w: unknown gc operation %q", pverrors.ErrUsage, operation)
	}
	at := time.Now().UTC()
	if now != nil {
		at = now().UTC()
	}
	if strings.TrimSpace(holder) == "" {
		return false, fmt.Errorf("%w: gc lock holder is empty", pverrors.ErrUsage)
	}
	if strings.TrimSpace(host) == "" {
		host = DefaultHost()
	}
	lock := Lock{
		Version: LockVersion, Holder: holder, Host: host,
		Operation: operation, CreatedAt: at, UpdatedAt: at,
	}
	if err := lock.Validate(); err != nil {
		return false, err
	}
	raw, err := json.Marshal(lock)
	if err != nil {
		return false, fmt.Errorf("marshal gc lock: %w", err)
	}
	created, err := repo.PutObjectIfAbsent(ctx, GCLockKey, bytes.NewReader(raw))
	if err != nil {
		return false, fmt.Errorf("acquire gc lock: %w", err)
	}
	if created {
		return true, nil
	}
	existing, err := readLock(ctx, repo, GCLockKey)
	if err != nil {
		return false, err
	}
	if !IsStale(existing, at, ttl) {
		return false, nil
	}
	// Abandoned: anyone may remove it, then retry once. A lost race
	// returns false, never an overwrite.
	if err := repo.DeleteObject(ctx, GCLockKey); err != nil {
		return false, fmt.Errorf("reap stale gc lock: %w", err)
	}
	created, err = repo.PutObjectIfAbsent(ctx, GCLockKey, bytes.NewReader(raw))
	if err != nil {
		return false, fmt.Errorf("acquire gc lock: %w", err)
	}
	return created, nil
}

// ReleaseGCLock deletes gc.lock. Deleting a missing lock is not an error.
func ReleaseGCLock(ctx context.Context, repo Repository) error {
	if repo == nil {
		return errors.New("release gc lock: repository is nil")
	}
	if err := repo.DeleteObject(ctx, GCLockKey); err != nil {
		return fmt.Errorf("release gc lock: %w", err)
	}
	return nil
}

// RefreshGCLock overwrites gc.lock with a fresh UpdatedAt. Only the holder
// refreshes its own lock from its heartbeat goroutine; the write is a plain
// PutObject because creation already won the compare-and-swap. The refresh
// refuses when the stored holder differs, so a stale heartbeat cannot
// clobber a lock taken over after a reap.
func RefreshGCLock(ctx context.Context, repo Repository, operation, holder, host string, now func() time.Time) error {
	if repo == nil {
		return errors.New("refresh gc lock: repository is nil")
	}
	existing, err := readLock(ctx, repo, GCLockKey)
	if err != nil {
		return err
	}
	// Host is recorded at acquire time and never overwritten by a
	// refresh; it stays a parameter so heartbeats keep their shape.
	_ = host
	if strings.TrimSpace(holder) != "" && existing.Holder != holder {
		return fmt.Errorf("%w: gc lock held by %q, not %q", pverrors.ErrUsage, existing.Holder, holder)
	}
	if strings.TrimSpace(operation) != "" && existing.Operation != operation {
		return fmt.Errorf("%w: gc lock holds operation %q, not %q", pverrors.ErrUsage, existing.Operation, operation)
	}
	at := time.Now().UTC()
	if now != nil {
		at = now().UTC()
	}
	existing.UpdatedAt = at
	if err := existing.Validate(); err != nil {
		return err
	}
	if err := existing.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(existing)
	if err != nil {
		return fmt.Errorf("marshal gc lock: %w", err)
	}
	if err := repo.PutObject(ctx, GCLockKey, bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("refresh gc lock: %w", err)
	}
	return nil
}

// RefreshBackupMarker overwrites one backup marker with a fresh UpdatedAt.
func RefreshBackupMarker(ctx context.Context, repo Repository, id string, now func() time.Time) error {
	if repo == nil {
		return errors.New("refresh backup marker: repository is nil")
	}
	key, err := BackupKey(id)
	if err != nil {
		return err
	}
	existing, err := readLock(ctx, repo, key)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	if now != nil {
		at = now().UTC()
	}
	existing.UpdatedAt = at
	if err := existing.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(existing)
	if err != nil {
		return fmt.Errorf("marshal backup marker: %w", err)
	}
	if err := repo.PutObject(ctx, key, bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("refresh backup marker: %w", err)
	}
	return nil
}

// WaitForBackups polls live backup markers until none remain or timeout
// elapses. Stale markers are reaped first. A timeout returns an error and
// the caller must abort without deleting anything. Sleeps use time.Sleep so
// testing/synctest advances the fake clock in tests.
func WaitForBackups(ctx context.Context, repo Repository, ttl, timeout time.Duration, now func() time.Time) error {
	if ttl <= 0 {
		ttl = DefaultLockTTL
	}
	if timeout <= 0 {
		timeout = DefaultPruneWaitTimeout
	}
	nowFn := now
	if nowFn == nil {
		nowFn = time.Now
	}
	deadline := nowFn().UTC().Add(timeout)
	if err := ReapStaleBackupMarkers(ctx, repo, ttl, nowFn); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		live, err := LiveBackupMarkers(ctx, repo, ttl, nowFn)
		if err != nil {
			return err
		}
		if len(live) == 0 {
			return nil
		}
		if !nowFn().UTC().Before(deadline) {
			return fmt.Errorf("%w: %d backup(s) in flight, refusing to prune", pverrors.ErrUsage, len(live))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// StartHeartbeat refreshes key every interval until stop is called. The
// goroutine is owned by the lock holder and stop must run before the lock
// is released (GO_GUIDELINES.md §10). Failures are logged, never returned:
// a missed heartbeat only risks the lock looking stale to others.
func StartHeartbeat(ctx context.Context, repo Repository, key, operation, holder, host string, interval time.Duration, now func() time.Time, logger *slog.Logger) (stop func()) {
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				var err error
				if key == GCLockKey {
					err = RefreshGCLock(ctx, repo, operation, holder, host, now)
				} else {
					id, ok := strings.CutPrefix(key, BackupLockPrefix)
					if !ok {
						logger.WarnContext(ctx, "heartbeat for unknown lock key", slog.String("key", key))
						return
					}
					err = RefreshBackupMarker(ctx, repo, id, now)
				}
				if err != nil {
					logger.WarnContext(ctx, "lock refresh failed", slog.String("key", key), slog.Any("error", err))
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func readLock(ctx context.Context, repo Repository, key string) (Lock, error) {
	r, err := repo.GetObject(ctx, key)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Lock{}, fmt.Errorf("%w: lock %s is missing", pverrors.ErrIntegrity, key)
		}
		return Lock{}, fmt.Errorf("read lock %s: %w", key, err)
	}
	defer r.Close()
	// Locks are tiny JSON; cap the read so a hostile repository cannot
	// OOM the reader with a giant lock object.
	raw, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return Lock{}, fmt.Errorf("read lock %s: %w", key, err)
	}
	var lock Lock
	if err := json.Unmarshal(raw, &lock, json.RejectUnknownMembers(true)); err != nil {
		return Lock{}, fmt.Errorf("%w: lock %s is corrupt: %w", pverrors.ErrIntegrity, key, err)
	}
	lock.CreatedAt = lock.CreatedAt.UTC()
	lock.UpdatedAt = lock.UpdatedAt.UTC()
	if err := lock.Validate(); err != nil {
		return Lock{}, fmt.Errorf("lock %s: %w", key, err)
	}
	return lock, nil
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package verify

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	json "encoding/json/v2"

	pverrors "petravault/internal/errors"
	"petravault/internal/manifest"
)

// HeadsVersion is the head-record file format version.
const HeadsVersion = 1

// Head records the tip snapshot a client has seen for one source
// (DESIGN.md §9). Each client keeps one record per source and repository in
// its local state; verify and restore fail when a recorded head is missing
// or is neither the current tip nor one of its ancestors, which detects
// rollback and truncation. A record is reset only by explicit operator
// action, never automatically.
type Head struct {
	// Snapshot is the head snapshot ID hex.
	Snapshot string `json:"snapshot"`
	// UpdatedAt is the last update time in UTC.
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// headsFile is the wire form of the per-repository head store.
type headsFile struct {
	Version int             `json:"version"`
	Heads   map[string]Head `json:"heads"`
}

// HeadsPath returns the client-local head-record file for repositoryID under
// stateDir ($XDG_STATE_HOME/petravault/heads/<repository_id>.json,
// DESIGN.md §9). The repository ID is hex from init and never contains path
// separators; anything else fails closed.
func HeadsPath(stateDir, repositoryID string) (string, error) {
	if strings.TrimSpace(stateDir) == "" {
		return "", fmt.Errorf("%w: state directory is empty", pverrors.ErrUsage)
	}
	if strings.TrimSpace(repositoryID) == "" {
		return "", fmt.Errorf("%w: repository id is empty", pverrors.ErrUsage)
	}
	name := repositoryID + ".json"
	if !filepath.IsLocal(name) {
		return "", fmt.Errorf("%w: invalid repository id", pverrors.ErrUsage)
	}
	return filepath.Join(stateDir, "petravault", "heads", name), nil
}

// LoadHeads reads the head store at path. A missing file means first use of
// the repository: it returns an empty map, not an error.
func LoadHeads(path string) (map[string]Head, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]Head{}, nil
		}
		return nil, fmt.Errorf("read head records: %w", err)
	}
	var wire headsFile
	if err := json.Unmarshal(raw, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode head records: %w", err)
	}
	if wire.Version != HeadsVersion {
		return nil, fmt.Errorf("head records have version %d, want %d", wire.Version, HeadsVersion)
	}
	if wire.Heads == nil {
		return map[string]Head{}, nil
	}
	for source, h := range wire.Heads {
		if strings.TrimSpace(source) == "" {
			return nil, fmt.Errorf("%w: head records hold an empty source", pverrors.ErrUsage)
		}
		if _, err := manifest.ParseSnapshotID(h.Snapshot); err != nil {
			return nil, fmt.Errorf("head records for %q: %w", source, err)
		}
	}
	return wire.Heads, nil
}

// SaveHeads stores heads at path with a durable write. The file holds only
// snapshot IDs (hashes of encrypted manifests), but it is still written
// 0600 like other client state.
func SaveHeads(path string, heads map[string]Head) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: head-record path is empty", pverrors.ErrUsage)
	}
	wire := headsFile{Version: HeadsVersion, Heads: map[string]Head{}}
	for source, h := range heads {
		if strings.TrimSpace(source) == "" {
			return fmt.Errorf("%w: head records hold an empty source", pverrors.ErrUsage)
		}
		if _, err := manifest.ParseSnapshotID(h.Snapshot); err != nil {
			return fmt.Errorf("head records for %q: %w", source, err)
		}
		h.UpdatedAt = h.UpdatedAt.UTC()
		wire.Heads[source] = h
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("marshal head records: %w", err)
	}
	if err := writeDurable(path, raw, 0o600); err != nil {
		return err
	}
	return nil
}

// UpdateHead records snapshotID as the head for sourceID in the store at
// path. now supplies the update time; nil means time.Now.
func UpdateHead(path, sourceID, snapshotID string, now func() time.Time) error {
	if strings.TrimSpace(sourceID) == "" {
		return fmt.Errorf("%w: source id is empty", pverrors.ErrUsage)
	}
	if _, err := manifest.ParseSnapshotID(snapshotID); err != nil {
		return err
	}
	return UpdateTips(path, map[string]string{sourceID: snapshotID}, now)
}

// UpdateTips records every current tip in heads. It is called after a
// successful backup or verify (DESIGN.md §9).
func UpdateTips(path string, tips map[string]string, now func() time.Time) error {
	return updateTips(path, tips, nil, false, now)
}

// CompareAndUpdateTips advances only heads unchanged since the caller checked
// their history. Concurrent newer observations must never be overwritten by
// a stale repository view. Unrelated sources are preserved.
func CompareAndUpdateTips(path string, tips map[string]string, expected map[string]Head, now func() time.Time) error {
	return updateTips(path, tips, expected, true, now)
}

func updateTips(path string, tips map[string]string, expected map[string]Head, compare bool, now func() time.Time) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: head-record path is empty", pverrors.ErrUsage)
	}
	if now == nil {
		now = time.Now
	}
	// Exclusive creation serializes every read-modify-write across processes
	// on all supported platforms. A crash leaves a fail-closed lock for the
	// operator to remove only after confirming no writer remains.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create head-record dir: %w", err)
	}
	lock := path + ".lock"
	if err := os.Mkdir(lock, 0o700); err != nil {
		return fmt.Errorf("lock head records (retry if another operation is running): %w", err)
	}
	defer os.Remove(lock)
	heads, err := LoadHeads(path)
	if err != nil {
		return err
	}
	at := now().UTC()
	for source, tip := range tips {
		if strings.TrimSpace(source) == "" {
			return fmt.Errorf("%w: source id is empty", pverrors.ErrUsage)
		}
		if _, err := manifest.ParseSnapshotID(tip); err != nil {
			return err
		}
		if compare && heads[source].Snapshot != expected[source].Snapshot && heads[source].Snapshot != tip {
			return fmt.Errorf("%w: source %q head changed during operation; retry", pverrors.ErrRollback, source)
		}
		heads[source] = Head{Snapshot: strings.ToLower(strings.TrimSpace(tip)), UpdatedAt: at}
	}
	return SaveHeads(path, heads)
}

func writeDurable(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create head-record dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "heads-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp head records: %w", err)
	}
	tmpName := tmp.Name()
	writeErr := func() error {
		if _, err := tmp.Write(data); err != nil {
			return fmt.Errorf("write temp head records: %w", err)
		}
		if err := tmp.Chmod(perm); err != nil {
			return fmt.Errorf("chmod temp head records: %w", err)
		}
		if err := tmp.Sync(); err != nil {
			return fmt.Errorf("sync temp head records: %w", err)
		}
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("close temp head records: %w", err)
		}
		if err := os.Rename(tmpName, path); err != nil {
			return fmt.Errorf("install head records: %w", err)
		}
		return syncHeadDir(filepath.Dir(path))
	}()
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return writeErr
	}
	return nil
}

func syncHeadDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

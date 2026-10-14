// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Layout subdirectories of a local repository (DESIGN.md §8).
var layoutDirs = []string{
	"config",
	"keys",
	"identities",
	"revocations",
	"snapshots",
	"packs",
	"indexes",
	"locks",
}

// Local is a Repository backed by a filesystem directory. The directory may
// sit on a NAS shared by several machines, so cross-machine coordination
// uses lock objects (PutObjectIfAbsent), never local flock (DESIGN.md §10.2).
type Local struct {
	root string
}

// NewLocal opens the repository at root, which must already exist (see Init).
func NewLocal(root string) *Local {
	return &Local{root: root}
}

// Init creates the repository layout at root and returns it. It is
// idempotent: running it twice keeps the existing repository.
func Init(root string) (*Local, error) {
	for _, dir := range layoutDirs {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	return NewLocal(root), nil
}

// Root returns the repository directory.
func (l *Local) Root() string {
	return l.root
}

// PutObject implements Repository with a durable write: temp file in the
// same directory, Sync, Close, Rename, then Sync the directory (DESIGN.md §8).
func (l *Local) PutObject(_ context.Context, key string, r io.Reader) error {
	path, err := l.resolve(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create parent: %w", err)
	}
	return writeDurable(filepath.Dir(path), filepath.Base(path), r)
}

// PutObjectIfAbsent implements Repository. O_EXCL creation is the
// compare-and-swap: an existing key returns (false, nil). The write is
// durable and atomic: bytes go to a temp file in the same directory and
// are installed with a hard link, so concurrent readers never observe a
// torn object and a failed write never leaves a partial file behind that
// would poison future CAS attempts (DESIGN.md §8, GO_GUIDELINES.md §11).
func (l *Local) PutObjectIfAbsent(_ context.Context, key string, r io.Reader) (bool, error) {
	path, err := l.resolve(key)
	if err != nil {
		return false, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("create parent: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("create temp for %s: %w", key, err)
	}
	tmpName := tmp.Name()
	// On any failure before install, remove the temp file. After a
	// successful link the temp path is unlinked separately.
	writeErr := func() error {
		if _, err := io.Copy(tmp, r); err != nil {
			return fmt.Errorf("write %s: %w", key, err)
		}
		if err := tmp.Sync(); err != nil {
			return fmt.Errorf("sync %s: %w", key, err)
		}
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("close %s: %w", key, err)
		}
		return nil
	}()
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return false, writeErr
	}
	// Link installs the temp content at the target atomically and fails
	// when the target already exists, which is the compare-and-swap.
	if err := os.Link(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("install %s: %w", key, err)
	}
	_ = os.Remove(tmpName)
	if err := syncDir(dir); err != nil {
		return false, fmt.Errorf("sync dir for %s: %w", key, err)
	}
	return true, nil
}

// GetObject implements Repository.
func (l *Local) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	path, err := l.resolve(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", key, err)
	}
	return f, nil
}

// GetRange implements Repository with a single seek plus a capped reader.
func (l *Local) GetRange(_ context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	if offset < 0 || length < 0 {
		return nil, fmt.Errorf("invalid range offset=%d length=%d for %s", offset, length, key)
	}
	path, err := l.resolve(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", key, err)
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("seek %s: %w", key, err)
	}
	return &rangeReader{f: f, r: io.LimitReader(f, length)}, nil
}

// DeleteObject implements Repository. A missing key is not an error.
func (l *Local) DeleteObject(_ context.Context, key string) error {
	path, err := l.resolve(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete %s: %w", key, err)
	}
	return nil
}

// Exists implements Repository.
func (l *Local) Exists(_ context.Context, key string) (bool, error) {
	path, err := l.resolve(key)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", key, err)
	}
	return true, nil
}

// List implements Repository. Names use "/" separators and are sorted.
func (l *Local) List(_ context.Context, prefix string) ([]string, error) {
	var out []string
	root := l.root
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		// Crash leftovers from durable writes (<name>.tmp-*) live in the
		// same directory; they are never repository objects.
		if strings.Contains(name, ".tmp-") {
			return nil
		}
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", prefix, err)
	}
	return slices.Sorted(slices.Values(out)), nil
}

// resolve maps a repository key to a filesystem path. Keys are untrusted
// input when read back from storage, so anything that could escape the root
// is rejected (filepath.IsLocal).
func (l *Local) resolve(key string) (string, error) {
	if key == "" || key == "." || !filepath.IsLocal(key) {
		return "", fmt.Errorf("invalid object key %q", key)
	}
	return filepath.Join(l.root, filepath.FromSlash(key)), nil
}

func writeDurable(dir, name string, r io.Reader) (err error) {
	tmp, err := os.CreateTemp(dir, name+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = io.Copy(tmp, r); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// rangeReader caps a ranged read and closes the underlying file.
type rangeReader struct {
	f *os.File
	r io.Reader
}

func (r *rangeReader) Read(p []byte) (int, error) {
	return r.r.Read(p)
}

func (r *rangeReader) Close() error {
	return r.f.Close()
}

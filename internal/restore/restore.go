// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package restore re-creates a source tree from a verified snapshot
// (DESIGN.md §9). A verified manifest is still treated as untrusted input
// to the filesystem: paths are rejected unless filepath.IsLocal, symlinks
// never leave the destination via os.Root, each file is written under a
// temporary name and renamed into place, existing files are kept unless
// --overwrite is given, ownership is restored only when running as root,
// setuid/setgid bits are never restored, and decompression is capped at the
// repository maximum chunk size.
package restore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"petravault/internal/compression"
	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/manifest"
	"petravault/internal/pack"
	"petravault/internal/repository"
)

// Options configures one restore run.
type Options struct {
	// Includes restricts the restore to matching paths. Empty restores
	// everything. Each entry is a slash-separated manifest path or a
	// directory prefix; parent directories of matches are created
	// implicitly.
	Includes []string
	// Overwrite replaces existing files. Without it, an existing
	// destination file is an error.
	Overwrite bool
	// MaxChunkSize caps decompression of any single chunk
	// (DESIGN.md §9). Non-positive selects the pack default cap.
	MaxChunkSize int
	// FileModeMask restricts restored permission bits. Zero selects 0o777
	// with setuid/setgid cleared.
	FileModeMask os.FileMode
}

// Restore re-creates m under dest. The manifest must already be verified
// (signature, trust, history): this function verifies chunks (AEAD, BLAKE3)
// before writing any file bytes, and rejects unsafe paths with an error
// wrapping ErrIntegrity so tampered manifests map to exit code 4.
func Restore(ctx context.Context, repo repository.Repository, repoID string, dataKey, chunkIDKey crypto.SecretKey, m manifest.Manifest, dest string, opts Options) error {
	if repo == nil {
		return errors.New("restore: repository is nil")
	}
	if strings.TrimSpace(repoID) == "" {
		return fmt.Errorf("%w: restore: repository id is empty", pverrors.ErrUsage)
	}
	if strings.TrimSpace(dest) == "" {
		return fmt.Errorf("%w: restore: destination is empty", pverrors.ErrUsage)
	}
	if m.RepositoryID != repoID {
		return fmt.Errorf("%w: restore: manifest names repository %q, want %q", pverrors.ErrIntegrity, m.RepositoryID, repoID)
	}
	maxChunk := opts.MaxChunkSize
	if maxChunk <= 0 {
		maxChunk = compression.DefaultMaxSize
	}
	mask := opts.FileModeMask
	if mask == 0 {
		mask = 0o777
	}
	// Clear setuid/setgid/sticky outside the nine permission bits is
	// enforced by os.Root.OpenFile; mask here drops setuid/setgid so a
	// crafted manifest can never restore them (DESIGN.md §9).
	includes, err := normalizeIncludes(opts.Includes)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := pack.LoadEntries(ctx, repo, repoID, dataKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	defer root.Close()

	selected := selectEntries(m.Files, includes)
	if len(includes) > 0 && len(selected) == 0 {
		return fmt.Errorf("%w: no snapshot paths match --include", pverrors.ErrUsage)
	}
	for _, f := range m.Files {
		if !isSelected(f.Path, includes) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateManifestPath(f.Path); err != nil {
			return err
		}
		if f.Type == manifest.TypeSymlink {
			if err := validateSymlinkTarget(f.Path, f.Target); err != nil {
				return err
			}
		}
	}
	// Manifest entries map to OS paths after FromSlash: distinct entries
	// must not collide there, or one would silently win under --overwrite.
	seen := make(map[string]string, len(selected))
	for _, f := range selected {
		osPath := filepath.FromSlash(f.Path)
		if prev, ok := seen[osPath]; ok {
			return fmt.Errorf("%w: manifest paths %q and %q collide", pverrors.ErrIntegrity, prev, f.Path)
		}
		seen[osPath] = f.Path
	}
	destinationLink := func(name string) (string, error) {
		info, err := root.Lstat(filepath.FromSlash(name))
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return "", nil
		}
		return root.Readlink(filepath.FromSlash(name))
	}
	if err := manifest.ValidateSymlinkTargets(selected, destinationLink); err != nil {
		return err
	}
	// Create directories first so parents exist before files.
	for _, f := range selected {
		if f.Type != manifest.TypeDir {
			continue
		}
		osPath := filepath.FromSlash(f.Path)
		if err := root.MkdirAll(osPath, 0o750); err != nil {
			return fmt.Errorf("create directory %s: %w", f.Path, err)
		}
	}
	// Restore files before symlinks: a symlink created earlier in the same
	// run must never redirect a file write, even though os.Root already
	// confines everything to the destination.
	restored := 0
	var installedLinks []manifest.File
	for _, pass := range []string{manifest.TypeFile, manifest.TypeSymlink} {
		for _, f := range selected {
			if f.Type != pass {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			switch f.Type {
			case manifest.TypeSymlink:
				// Do not assume a later link will be installed: a failure
				// there must not leave an earlier escaping link behind.
				installedLinks = append(installedLinks, f)
				if err := manifest.ValidateSymlinkTargets(installedLinks, destinationLink); err != nil {
					return err
				}
				if err := restoreSymlink(root, f, opts.Overwrite); err != nil {
					return err
				}
				restored++
			case manifest.TypeFile:
				if err := restoreFile(ctx, repo, repoID, dataKey, chunkIDKey, entries, root, f, maxChunk, mask, opts.Overwrite); err != nil {
					return err
				}
				restored++
			default:
				return fmt.Errorf("%w: manifest holds invalid type %q for %q", pverrors.ErrIntegrity, f.Type, f.Path)
			}
		}
	}
	for _, f := range selected {
		if f.Type == manifest.TypeDir {
			continue
		}
		if f.Type != manifest.TypeFile && f.Type != manifest.TypeSymlink {
			return fmt.Errorf("%w: manifest holds invalid type %q for %q", pverrors.ErrIntegrity, f.Type, f.Path)
		}
	}
	// Apply directory metadata last so file creation does not clobber
	// directory mtimes. Reverse order restores parents after children.
	for _, f := range slices.Backward(selected) {
		if f.Type != manifest.TypeDir {
			continue
		}
		if err := applyDirMeta(root, f, mask); err != nil {
			return err
		}
	}
	if restored == 0 && len(selected) != 0 {
		// Only directories matched; not an error.
		return nil
	}
	return nil
}

func normalizeIncludes(includes []string) ([]string, error) {
	out := make([]string, 0, len(includes))
	for _, inc := range includes {
		t := strings.TrimSpace(inc)
		if t == "" {
			return nil, fmt.Errorf("%w: empty --include value", pverrors.ErrUsage)
		}
		// Accept both slash and OS separators from the CLI.
		slash := filepath.ToSlash(t)
		slash = strings.Trim(slash, "/")
		if slash == "" || slash == "." {
			return nil, fmt.Errorf("%w: invalid --include %q", pverrors.ErrUsage, inc)
		}
		if !filepath.IsLocal(filepath.FromSlash(slash)) {
			return nil, fmt.Errorf("%w: invalid --include %q: must be a local path", pverrors.ErrUsage, inc)
		}
		out = append(out, slash)
	}
	return out, nil
}

func selectEntries(files []manifest.File, includes []string) []manifest.File {
	if len(includes) == 0 {
		return slices.Clone(files)
	}
	out := make([]manifest.File, 0, len(files))
	for _, f := range files {
		if isSelected(f.Path, includes) {
			out = append(out, f)
		}
	}
	return out
}

// isSelected reports whether manifest path p is covered by includes: an
// exact match, a file under an included directory, or a parent directory of
// an included path (created implicitly).
func isSelected(p string, includes []string) bool {
	if len(includes) == 0 {
		return true
	}
	for _, inc := range includes {
		if p == inc || strings.HasPrefix(p, inc+"/") || strings.HasPrefix(inc, p+"/") {
			return true
		}
	}
	return false
}

func validateManifestPath(p string) error {
	if p == "" || !filepath.IsLocal(filepath.FromSlash(p)) {
		return fmt.Errorf("%w: unsafe manifest path %q", pverrors.ErrIntegrity, p)
	}
	// Reject non-canonical slash paths (a//b, a/./b, trailing slashes):
	// they would collide after FromSlash with a distinct manifest entry.
	if cleaned := path.Clean(p); cleaned != p {
		return fmt.Errorf("%w: manifest path %q is not canonical", pverrors.ErrIntegrity, p)
	}
	if p == "." {
		return fmt.Errorf("%w: unsafe manifest path %q", pverrors.ErrIntegrity, p)
	}
	return nil
}

func validateSymlinkTarget(path, target string) error {
	if target == "" {
		return fmt.Errorf("%w: symlink %q has no target", pverrors.ErrIntegrity, path)
	}
	if filepath.IsAbs(target) {
		return fmt.Errorf("%w: symlink %q points outside the destination", pverrors.ErrIntegrity, path)
	}
	// Resolve the target relative to the link's parent directory using
	// slash semantics (manifest paths are slash-separated) and reject
	// escapes. A target like "../outside" from the top level joins to
	// "../outside", which is not local.
	parent, _, found := strings.CutLast(path, "/")
	if !found {
		parent = ""
	}
	// filepath.Join cleans; emulate it for the slash-joined form.
	joinedOS := filepath.Join(filepath.FromSlash(parent), target)
	if !filepath.IsLocal(joinedOS) {
		return fmt.Errorf("%w: symlink %q points outside the destination", pverrors.ErrIntegrity, path)
	}
	return nil
}

func restoreSymlink(root *os.Root, f manifest.File, overwrite bool) error {
	osPath := filepath.FromSlash(f.Path)
	if err := ensureParent(root, osPath); err != nil {
		return err
	}
	if _, err := root.Lstat(osPath); err == nil {
		if !overwrite {
			return fmt.Errorf("refusing to overwrite existing %s (use --overwrite)", f.Path)
		}
		// Remove, not RemoveAll: replacing a non-empty directory with a
		// symlink must never wipe a tree, crafted or otherwise.
		if err := root.Remove(osPath); err != nil {
			return fmt.Errorf("remove existing %s: %w", f.Path, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", f.Path, err)
	}
	// os.Root.Symlink does not validate the target (see stdlib docs), which
	// is why validateSymlinkTarget runs before any symlink is created.
	if err := root.Symlink(f.Target, osPath); err != nil {
		return fmt.Errorf("create symlink %s: %w", f.Path, err)
	}
	return nil
}

func restoreFile(ctx context.Context, repo repository.Repository, repoID string, dataKey, chunkIDKey crypto.SecretKey, entries map[[32]byte]pack.Entry, root *os.Root, f manifest.File, maxChunk int, mask os.FileMode, overwrite bool) error {
	osPath := filepath.FromSlash(f.Path)
	if err := ensureParent(root, osPath); err != nil {
		return err
	}
	if f.Size < 0 {
		return fmt.Errorf("%w: file %q has negative size %d", pverrors.ErrIntegrity, f.Path, f.Size)
	}
	// Refuse before fetching anything: no wasted decryption or disk I/O.
	if _, err := root.Lstat(osPath); err == nil {
		if !overwrite {
			return fmt.Errorf("refusing to overwrite existing %s (use --overwrite)", f.Path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", f.Path, err)
	}
	// Unique temp name in the same directory: never delete a file the run
	// did not create, so --include runs cannot clobber out-of-scope
	// *.petravault-tmp files, and a manifest holding both a path and its
	// temp sibling cannot collide.
	tmp, err := tempName(osPath)
	if err != nil {
		return err
	}
	w, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", f.Path, err)
	}
	writeErr := func() error {
		var total int64
		for _, hexID := range f.Chunks {
			if err := ctx.Err(); err != nil {
				return err
			}
			id, err := pack.ParseID(hexID)
			if err != nil {
				return fmt.Errorf("%w: file %q holds %w", pverrors.ErrIntegrity, f.Path, err)
			}
			loc, ok := entries[id]
			if !ok {
				return fmt.Errorf("%w: file %q references missing chunk %s", pverrors.ErrIntegrity, f.Path, hexID)
			}
			plaintext, err := pack.ReadChunk(ctx, repo, repoID, dataKey, chunkIDKey, loc, maxChunk)
			if err != nil {
				return fmt.Errorf("restore %s: %w", f.Path, err)
			}
			// Chunks must sum to the manifest size exactly; stop early
			// rather than filling disk from a lying chunk list.
			if total+int64(len(plaintext)) > f.Size {
				clear(plaintext)
				return fmt.Errorf("%w: file %q chunks exceed its size %d", pverrors.ErrIntegrity, f.Path, f.Size)
			}
			total += int64(len(plaintext))
			if _, err := w.Write(plaintext); err != nil {
				clear(plaintext)
				return fmt.Errorf("write %s: %w", f.Path, err)
			}
			clear(plaintext)
		}
		if total != f.Size {
			return fmt.Errorf("%w: file %q size %d disagrees with its chunks %d", pverrors.ErrIntegrity, f.Path, f.Size, total)
		}
		if err := w.Sync(); err != nil {
			return fmt.Errorf("sync %s: %w", f.Path, err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("close %s: %w", f.Path, err)
		}
		mode := os.FileMode(f.Mode) & mask & 0o777
		if err := root.Chmod(tmp, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", f.Path, err)
		}
		if !f.Mtime.IsZero() {
			if err := root.Chtimes(tmp, f.Mtime, f.Mtime); err != nil {
				return fmt.Errorf("set times %s: %w", f.Path, err)
			}
		}
		if err := root.Rename(tmp, osPath); err != nil {
			return fmt.Errorf("install %s: %w", f.Path, err)
		}
		// Ownership is restored only when running as root; setuid/setgid
		// bits were already cleared via the mode mask (DESIGN.md §9).
		if os.Geteuid() == 0 {
			if err := root.Chown(osPath, int(f.UID), int(f.GID)); err != nil {
				return fmt.Errorf("chown %s: %w", f.Path, err)
			}
		}
		return nil
	}()
	if writeErr != nil {
		_ = w.Close()
		_ = root.Remove(tmp)
		return writeErr
	}
	return nil
}

// tempName returns a unique temp sibling of osPath in the same directory
// so the final rename stays atomic. The random suffix keeps concurrent or
// interrupted restores from colliding and means the run never removes a
// file it did not create.
func tempName(osPath string) (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate temp name: %w", err)
	}
	return osPath + ".petravault-tmp-" + hex.EncodeToString(raw[:]), nil
}

func ensureParent(root *os.Root, osPath string) error {
	dir := filepath.Dir(osPath)
	if dir == "." || dir == "" {
		return nil
	}
	if err := root.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create parent: %w", err)
	}
	return nil
}

func applyDirMeta(root *os.Root, f manifest.File, mask os.FileMode) error {
	osPath := filepath.FromSlash(f.Path)
	mode := os.FileMode(f.Mode) & mask & 0o777
	if err := root.Chmod(osPath, mode); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("chmod %s: %w", f.Path, err)
	}
	if !f.Mtime.IsZero() {
		if err := root.Chtimes(osPath, f.Mtime, f.Mtime); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("set times %s: %w", f.Path, err)
		}
	}
	return nil
}

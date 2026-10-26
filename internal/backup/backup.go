// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package backup scans a source tree and writes deduplicated, encrypted
// packs with a per-run immutable index (DESIGN.md §2, §3). Files unchanged
// since the parent snapshot reuse their recorded chunk lists without being
// re-read (§3.4); excluded paths are never recorded (§3.5). Snapshots are
// not signed here: this package returns the file entries that the manifest
// layer signs in a later phase.
package backup

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"petravault/internal/chunking"
	"petravault/internal/crypto"
	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
	"petravault/internal/nofollow"
	"petravault/internal/pack"
	"petravault/internal/repository"
)

// File types recorded in entries.
const (
	TypeFile    = "file"
	TypeDir     = "dir"
	TypeSymlink = "symlink"
)

// racilyCleanWindow bounds the "racily clean" guard: a file whose mtime or
// ctime is newer than the parent snapshot start minus this window is always
// re-read, because a later write may land in the same timestamp tick
// (DESIGN.md §3.4).
const racilyCleanWindow = 2 * time.Second

// cachedirTag marks directories whose contents are excluded under
// --exclude-caches (https://bford.info/cachedir/).
const cachedirTag = "CACHEDIR.TAG"

// FileEntry records one source path for a snapshot. Times are UTC and
// marshal as RFC 3339; Chunks holds hex keyed chunk IDs in file order.
type FileEntry struct {
	Path   string    `json:"path"`
	Type   string    `json:"type"`
	Mode   uint32    `json:"mode,omitzero"`
	UID    uint32    `json:"uid,omitzero"`
	GID    uint32    `json:"gid,omitzero"`
	Size   int64     `json:"size,omitzero"`
	Inode  uint64    `json:"inode,omitzero"`
	Mtime  time.Time `json:"mtime,omitzero"`
	Ctime  time.Time `json:"ctime,omitzero"`
	Target string    `json:"target,omitempty"`
	Chunks []string  `json:"chunks,omitempty"`
}

// Options configures one backup run.
type Options struct {
	// Source is the directory tree to back up.
	Source string
	// RepositoryID binds every encrypted object (DESIGN.md §4.1). Later
	// phases read it from the signed repository config.
	RepositoryID string
	// Master is the repository master key. It is used, never stored.
	Master crypto.SecretKey
	// SourceID names the backed-up source; it defaults to the hostname.
	SourceID string
	// Parent holds the previous snapshot's entries for the fast path. Nil
	// means a full scan.
	Parent []FileEntry
	// ParentStart is the parent snapshot's start time for the racily-clean
	// guard. It is ignored without Parent.
	ParentStart time.Time
	// Now supplies the run start time; nil means time.Now.
	Now func() time.Time
	// Chunking overrides the chunk sizes; the zero value selects defaults.
	Chunking chunking.Params
	// Excludes holds glob patterns, ExcludeFile points at a file with one
	// glob per line, ExcludeCaches skips cachedir-tagged directories, and
	// OneFileSystem refuses to cross mount points.
	Excludes      []string
	ExcludeFile   string
	ExcludeCaches bool
	OneFileSystem bool
	// ForceRescan disables the unchanged-file fast path.
	ForceRescan bool
	// TargetPackSize overrides the pack fill target; non-positive selects
	// the pack default.
	TargetPackSize int
	// ECC selects the erasure sidecar profile for packs and the index
	// written by this run: off, low, medium, high, or <N>%. Empty selects
	// the repository default (DESIGN.md §4.5).
	ECC string
	// Logger receives progress and warnings; nil discards logs.
	Logger *slog.Logger
}

// Result describes one finished backup run.
type Result struct {
	SourceID  string
	StartedAt time.Time
	Files     []FileEntry
	NewChunks int
	Packs     []string
	// ReusedFiles counts regular files whose parent chunk lists were reused
	// without reading them (DESIGN.md §3.4).
	ReusedFiles int
	// Index is the new per-run index key, empty when the run stored no new
	// chunks and everything was deduplicated.
	Index    string
	Warnings []string
}

// Backup scans opts.Source and stores new chunks in opts' repository. Files
// that cannot be read, or that keep changing while read, are skipped with a
// recorded warning; when warnings occurred the returned error wraps
// ErrWarnings (exit code 3) while the result stays usable.
func Backup(ctx context.Context, repo repository.Repository, opts Options) (Result, error) {
	b, err := newRunner(ctx, repo, opts)
	if err != nil {
		return Result{}, err
	}
	defer b.sourceRoot.Close()
	if err := b.walk(ctx); err != nil {
		return Result{}, err
	}
	return b.finish(ctx)
}

// runner holds the mutable state of one backup run.
type runner struct {
	repo   repository.Repository
	opts   Options
	logger *slog.Logger

	sourceID   string
	sourceRoot *os.Root
	started    time.Time
	params     chunking.Params
	matcher    Matcher
	parent     map[string]FileEntry

	dataKey    crypto.SecretKey
	chunkIDKey crypto.SecretKey
	chunkerKey [32]byte

	dedup   map[[32]byte]pack.Entry
	pending map[[32]byte]bool
	writer  *pack.Writer
	target  int

	rootDev    uint64
	rootDevOK  bool
	files      []FileEntry
	newChunks  int
	reused     int
	packs      []string
	mergedUpTo int
	warnings   []string
}

func newRunner(ctx context.Context, repo repository.Repository, opts Options) (*runner, error) {
	if opts.Source == "" {
		return nil, fmt.Errorf("%w: backup source is empty", pverrors.ErrUsage)
	}
	if opts.RepositoryID == "" {
		return nil, fmt.Errorf("%w: repository id is empty", pverrors.ErrUsage)
	}
	info, err := os.Lstat(opts.Source)
	if err != nil {
		return nil, fmt.Errorf("stat source: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: backup source %s is not a directory", pverrors.ErrUsage, opts.Source)
	}
	params := opts.Chunking
	if params == (chunking.Params{}) {
		params = chunking.DefaultParams()
	}
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
	}
	if strings.TrimSpace(opts.ECC) != "" {
		if _, err := erasure.Parse(opts.ECC); err != nil {
			return nil, err
		}
	}
	patterns := slices.Clone(opts.Excludes)
	if opts.ExcludeFile != "" {
		fromFile, err := LoadExcludeFile(opts.ExcludeFile)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, fromFile...)
	}
	matcher, err := NewMatcher(patterns)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
	}
	sourceID := opts.SourceID
	if sourceID == "" {
		sourceID, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("resolve source id: %w", err)
		}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	sub := opts.Master.DeriveSubkeys()
	chunkerRaw := sub.Chunker.Bytes()
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	b := &runner{
		repo:       repo,
		opts:       opts,
		logger:     logger,
		sourceID:   sourceID,
		started:    now().UTC(),
		params:     params,
		matcher:    matcher,
		parent:     make(map[string]FileEntry, len(opts.Parent)),
		dataKey:    sub.Data,
		chunkIDKey: sub.ChunkID,
		chunkerKey: chunkerRaw,
		dedup:      make(map[[32]byte]pack.Entry),
		pending:    make(map[[32]byte]bool),
	}
	clear(chunkerRaw[:])
	for _, e := range opts.Parent {
		b.parent[e.Path] = e
	}
	if opts.OneFileSystem {
		if dev, ok := deviceOf(info); ok {
			b.rootDev, b.rootDevOK = dev, true
		} else {
			logger.WarnContext(ctx, "one-file-system requested but device ids are unavailable; crossing detection disabled")
		}
	}
	dedup, err := pack.LoadEntries(ctx, repo, opts.RepositoryID, sub.Data)
	if err != nil {
		return nil, err
	}
	b.dedup = dedup
	b.target = opts.TargetPackSize
	if b.target <= 0 {
		b.target = pack.TargetPackSize
	}
	b.writer = pack.NewWriter(opts.RepositoryID, sub.Data, b.target)
	sourceRoot, err := os.OpenRoot(opts.Source)
	if err != nil {
		return nil, fmt.Errorf("open source root: %w", err)
	}
	opened, err := sourceRoot.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = sourceRoot.Close()
		return nil, fmt.Errorf("%w: source directory changed while opening", pverrors.ErrIntegrity)
	}
	b.sourceRoot = sourceRoot
	return b, nil
}

// walk scans the source tree in lexical order.
func (b *runner) walk(ctx context.Context) error {
	return fs.WalkDir(b.sourceRoot.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			b.warn(ctx, fmt.Sprintf("skipping %q: %q", path, err))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel := path
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		info, err := b.sourceRoot.Lstat(filepath.FromSlash(rel))
		if err != nil {
			b.warn(ctx, fmt.Sprintf("skipping %q: %q", rel, err))
			return nil
		}
		isDir := info.IsDir()
		if b.matcher.Excluded(rel, isDir) {
			if isDir {
				return filepath.SkipDir
			}
			return nil
		}
		if b.opts.OneFileSystem && b.rootDevOK {
			if dev, ok := deviceOf(info); ok && dev != b.rootDev {
				b.logger.InfoContext(ctx, "skipping mount crossing", slog.String("path", rel))
				if isDir {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if isDir && b.opts.ExcludeCaches {
			if _, err := b.sourceRoot.Lstat(filepath.Join(filepath.FromSlash(rel), cachedirTag)); err == nil {
				b.logger.InfoContext(ctx, "skipping cache directory", slog.String("path", rel))
				return filepath.SkipDir
			}
		}
		entry := FileEntry{
			Path:  rel,
			Mode:  uint32(info.Mode().Perm()),
			Size:  info.Size(),
			Mtime: info.ModTime().UTC(),
			Ctime: info.ModTime().UTC(),
		}
		fillMeta(info, &entry)
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			entry.Type = TypeSymlink
			target, err := b.sourceRoot.Readlink(filepath.FromSlash(rel))
			if err != nil {
				b.warn(ctx, fmt.Sprintf("skipping symlink %q: %q", rel, err))
				return nil
			}
			entry.Target = target
			entry.Size = 0
		case isDir:
			entry.Type = TypeDir
			entry.Size = 0
		case info.Mode().IsRegular():
			entry.Type = TypeFile
			chunks, ok := b.fileChunks(ctx, path, rel, info, entry)
			if !ok {
				return nil
			}
			entry.Chunks = chunks
		default:
			b.warn(ctx, fmt.Sprintf("skipping %q: unsupported file type %s", rel, info.Mode().Type()))
			return nil
		}
		b.files = append(b.files, entry)
		return nil
	})
}

// fileChunks returns the chunk IDs for one regular file, reusing the parent
// entry when the fast path applies. ok=false means the file was skipped with
// a recorded warning.
func (b *runner) fileChunks(ctx context.Context, path, rel string, info os.FileInfo, entry FileEntry) (chunks []string, ok bool) {
	if !b.opts.ForceRescan {
		if parent, found := b.parent[rel]; found && parent.Type == TypeFile && fastPathEligible(parent, entry, b.opts.ParentStart) {
			b.reused++
			return slices.Clone(parent.Chunks), true
		}
	}
	before := statFingerprint(info)
	chunks, added, err := b.chunkFile(ctx, path, info)
	if err != nil {
		b.warn(ctx, fmt.Sprintf("skipping %q: %q", rel, err))
		b.forgetPending(added)
		return nil, false
	}
	afterInfo, err := b.sourceRoot.Lstat(filepath.FromSlash(path))
	if err != nil {
		b.warn(ctx, fmt.Sprintf("skipping %q: %q", rel, err))
		b.forgetPending(added)
		return nil, false
	}
	if statFingerprint(afterInfo) != before {
		// Changed mid-read: re-read once. First-pass blobs stay in their
		// packs as valid but unreferenced orphans for prune to reclaim;
		// only the second pass feeds the entry.
		b.forgetPending(added)
		chunks, added, err = b.chunkFile(ctx, path, afterInfo)
		if err != nil {
			b.warn(ctx, fmt.Sprintf("skipping %q: %q", rel, err))
			b.forgetPending(added)
			return nil, false
		}
		if finalInfo, err := b.sourceRoot.Lstat(filepath.FromSlash(path)); err != nil || statFingerprint(finalInfo) != statFingerprint(afterInfo) {
			b.warn(ctx, fmt.Sprintf("file %q changed during read; stored a torn copy", rel))
		}
	}
	return chunks, true
}

// chunkFile streams one file through the keyed chunker, storing new blobs
// and returning hex chunk IDs in file order plus the IDs added to the
// pending pack.
func (b *runner) chunkFile(ctx context.Context, path string, expected os.FileInfo) ([]string, [][32]byte, error) {
	f, err := nofollow.OpenInRoot(b.sourceRoot, filepath.FromSlash(path))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return nil, nil, errors.New("source file changed before opening")
	}
	chunker, err := chunking.New(f, b.params, b.chunkerKey[:])
	if err != nil {
		return nil, nil, err
	}
	var (
		chunks []string
		added  [][32]byte
	)
	for {
		if err := ctx.Err(); err != nil {
			return nil, added, err
		}
		plaintext, err := chunker.Next()
		if len(plaintext) > 0 {
			id, err := crypto.KeyedSum(b.chunkIDKey, plaintext)
			if err != nil {
				return nil, added, err
			}
			hexID := pack.FormatID(id)
			if _, known := b.dedup[id]; !known && !b.pending[id] {
				if err := b.writer.Add(id, plaintext); err != nil {
					return nil, added, err
				}
				b.pending[id] = true
				added = append(added, id)
				b.newChunks++
				if b.writer.Buffered() >= b.target {
					if err := b.flushPack(ctx); err != nil {
						return nil, added, err
					}
				}
			}
			chunks = append(chunks, hexID)
		}
		if errors.Is(err, io.EOF) {
			return chunks, added, nil
		}
		if err != nil {
			return nil, added, fmt.Errorf("read %s: %w", path, err)
		}
	}
}

// forgetPending drops still-unflushed IDs from the pending set after a torn
// read. Blobs already flushed stay as valid, unreferenced orphans.
func (b *runner) forgetPending(added [][32]byte) {
	for _, id := range added {
		delete(b.pending, id)
	}
}

// flushPack writes the pending pack and merges its entries into the dedup
// map so later files reuse just-written blobs.
func (b *runner) flushPack(ctx context.Context) error {
	key, err := b.writer.Flush(ctx, b.repo, b.opts.ECC)
	if err != nil {
		return err
	}
	if key == "" {
		return nil
	}
	b.packs = append(b.packs, key)
	for _, e := range b.writer.Entries()[b.mergedUpTo:] {
		b.dedup[e.ID] = e
		delete(b.pending, e.ID)
	}
	b.mergedUpTo = len(b.writer.Entries())
	return nil
}

// finish flushes the last pack, writes the per-run index, and assembles the
// result.
func (b *runner) finish(ctx context.Context) (Result, error) {
	if err := b.flushPack(ctx); err != nil {
		return Result{}, err
	}
	slices.SortFunc(b.files, func(a, c FileEntry) int { return cmp.Compare(a.Path, c.Path) })
	res := Result{
		SourceID:    b.sourceID,
		StartedAt:   b.started,
		Files:       b.files,
		NewChunks:   b.newChunks,
		Packs:       slices.Clone(b.packs),
		ReusedFiles: b.reused,
		Warnings:    slices.Clone(b.warnings),
	}
	if len(b.writer.Entries()) > 0 {
		indexKey, err := pack.WriteIndex(ctx, b.repo, b.opts.RepositoryID, b.dataKey, b.writer.Entries(), b.opts.ECC)
		if err != nil {
			return Result{}, err
		}
		res.Index = indexKey
	}
	b.logger.InfoContext(ctx, "backup finished",
		slog.String("source", b.sourceID),
		slog.Int("files", len(res.Files)),
		slog.Int("new_chunks", res.NewChunks),
		slog.Int("reused_files", res.ReusedFiles),
		slog.Int("packs", len(res.Packs)))
	if len(res.Warnings) > 0 {
		return res, fmt.Errorf("backup finished with %d warnings: %w", len(res.Warnings), pverrors.ErrWarnings)
	}
	return res, nil
}

// warn records a warning for the result. Paths come from the local
// filesystem, never key material or plaintext.
func (b *runner) warn(ctx context.Context, msg string) {
	b.warnings = append(b.warnings, msg)
	b.logger.WarnContext(ctx, msg)
}

// fastPathEligible reports whether the parent entry's chunk list can be
// reused without reading the file: every fingerprint field matches at full
// precision, and neither timestamp sits in the racily-clean window after the
// parent snapshot started.
func fastPathEligible(parent, current FileEntry, parentStart time.Time) bool {
	if parent.Size != current.Size || parent.Mtime.UnixNano() != current.Mtime.UnixNano() ||
		parent.Inode != current.Inode || parent.Ctime.UnixNano() != current.Ctime.UnixNano() {
		return false
	}
	cutoff := parentStart.Add(-racilyCleanWindow)
	if parent.Mtime.After(cutoff) || parent.Ctime.After(cutoff) {
		return false
	}
	for _, id := range parent.Chunks {
		if _, err := pack.ParseID(id); err != nil {
			return false
		}
	}
	return true
}

// statFingerprint reduces a stat result to the fields that detect a file
// changing under a read.
func statFingerprint(fi os.FileInfo) string {
	return strconv.FormatInt(fi.Size(), 10) + "/" + strconv.FormatInt(fi.ModTime().UnixNano(), 10)
}

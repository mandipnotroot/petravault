// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package backup_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"petravault/internal/backup"
	"petravault/internal/chunking"
	"petravault/internal/compression"
	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/pack"
	"petravault/internal/repository"
)

const testRepoID = "test-repository"

// testParams forces many small chunks so dedup and pack boundaries get
// exercised without large fixtures.
func testParams() chunking.Params {
	return chunking.Params{MinSize: 64, AverageSize: 256, MaxSize: 1024}
}

func mustMaster(t *testing.T) crypto.SecretKey {
	t.Helper()
	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return master
}

func mustRepo(t *testing.T) *repository.Local {
	t.Helper()
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

func testData(n int, seed uint64) []byte {
	out := make([]byte, n)
	x := seed
	if x == 0 {
		x = 1
	}
	for i := range out {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = byte(x)
	}
	return out
}

func runBackup(t *testing.T, repo *repository.Local, opts backup.Options) backup.Result {
	t.Helper()
	if opts.RepositoryID == "" {
		opts.RepositoryID = testRepoID
	}
	if opts.Chunking == (chunking.Params{}) {
		opts.Chunking = testParams()
	}
	if opts.SourceID == "" {
		opts.SourceID = "test-source"
	}
	res, err := backup.Backup(t.Context(), repo, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// readEntry reassembles one file entry from the repository and checks every
// chunk authenticates.
func readEntry(t *testing.T, repo *repository.Local, master crypto.SecretKey, e backup.FileEntry) []byte {
	t.Helper()
	sub := master.DeriveSubkeys()
	merged, err := pack.LoadEntries(t.Context(), repo, testRepoID, sub.Data)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for _, hexID := range e.Chunks {
		id, err := pack.ParseID(hexID)
		if err != nil {
			t.Fatal(err)
		}
		loc, ok := merged[id]
		if !ok {
			t.Fatalf("chunk %s of %s has no index entry", hexID, e.Path)
		}
		plaintext, err := pack.ReadChunk(t.Context(), repo, testRepoID, sub.Data, sub.ChunkID, loc, compression.DefaultMaxSize)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, plaintext...)
	}
	return out
}

func findEntry(files []backup.FileEntry, path string) backup.FileEntry {
	for _, e := range files {
		if e.Path == path {
			return e
		}
	}
	return backup.FileEntry{}
}

func TestBackupRoundTrip(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	src := t.TempDir()

	big := testData(5000, 1)
	writeFile(t, src, "hello.txt", []byte("hello backup"))
	writeFile(t, src, "big.bin", big)
	writeFile(t, src, "empty.txt", nil)
	writeFile(t, src, "sub/nested.txt", []byte("nested contents"))
	if err := os.MkdirAll(filepath.Join(src, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("hello.txt", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(src, "hello.txt"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := runBackup(t, repo, backup.Options{Source: src, Master: master})
	if len(res.Packs) == 0 || res.Index == "" || res.NewChunks == 0 {
		t.Fatalf("backup stored nothing: %+v", res)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", res.Warnings)
	}
	if !slices.IsSortedFunc(res.Files, comparePath) {
		t.Fatal("files are not ordered by path")
	}

	byPath := make(map[string]backup.FileEntry)
	for _, e := range res.Files {
		byPath[e.Path] = e
	}
	for _, want := range []string{"hello.txt", "big.bin", "empty.txt", "sub/nested.txt", "sub", "emptydir", "link"} {
		if _, ok := byPath[want]; !ok {
			t.Fatalf("missing entry %q in %v", want, res.Files)
		}
	}
	if got := readEntry(t, repo, master, byPath["hello.txt"]); !bytes.Equal(got, []byte("hello backup")) {
		t.Fatalf("hello.txt restored %q", got)
	}
	if got := readEntry(t, repo, master, byPath["big.bin"]); !bytes.Equal(got, big) {
		t.Fatal("big.bin mismatch after chunk round trip")
	}
	if len(byPath["empty.txt"].Chunks) != 0 {
		t.Fatal("empty file recorded chunks, want none")
	}
	link := byPath["link"]
	if link.Type != backup.TypeSymlink || link.Target != "hello.txt" {
		t.Fatalf("link = %+v, want symlink to hello.txt", link)
	}
	if byPath["hello.txt"].Mode != 0o600 {
		t.Fatalf("hello.txt mode = %o, want 600", byPath["hello.txt"].Mode)
	}
	if byPath["sub"].Type != backup.TypeDir {
		t.Fatalf("sub = %+v, want dir", byPath["sub"])
	}
}

func comparePath(a, b backup.FileEntry) int {
	switch {
	case a.Path < b.Path:
		return -1
	case a.Path > b.Path:
		return 1
	default:
		return 0
	}
}

func TestIncrementalSkipsUnchanged(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", testData(2000, 2))
	writeFile(t, src, "b.txt", testData(100, 3))

	first := runBackup(t, repo, backup.Options{Source: src, Master: master})
	// A parent start in the future clears the racily-clean window, so every
	// unchanged file must reuse its chunks.
	second := runBackup(t, repo, backup.Options{
		Source:      src,
		Master:      master,
		Parent:      first.Files,
		ParentStart: time.Now().Add(time.Hour),
	})
	if second.NewChunks != 0 || second.Index != "" || len(second.Packs) != 0 {
		t.Fatalf("incremental backup stored new objects: %+v", second)
	}
	if second.ReusedFiles != 2 {
		t.Fatalf("ReusedFiles = %d, want 2", second.ReusedFiles)
	}
	for _, e := range second.Files {
		if parent := findEntry(first.Files, e.Path); parent.Path == "" {
			t.Fatalf("unexpected file %q", e.Path)
		} else if !slices.Equal(parent.Chunks, e.Chunks) {
			t.Fatalf("file %q chunks changed without modification", e.Path)
		}
	}
}

func TestIncrementalPicksUpChanges(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	src := t.TempDir()
	writeFile(t, src, "keep.txt", testData(2000, 4))
	writeFile(t, src, "change.txt", testData(2000, 5))

	first := runBackup(t, repo, backup.Options{Source: src, Master: master})
	keepBefore := findEntry(first.Files, "keep.txt").Chunks

	writeFile(t, src, "change.txt", testData(3000, 6))
	writeFile(t, src, "new.txt", []byte("brand new"))

	second := runBackup(t, repo, backup.Options{
		Source:      src,
		Master:      master,
		Parent:      first.Files,
		ParentStart: time.Now().Add(time.Hour),
	})
	if second.ReusedFiles != 1 {
		t.Fatalf("ReusedFiles = %d, want 1 (keep.txt)", second.ReusedFiles)
	}
	if second.NewChunks == 0 || second.Index == "" {
		t.Fatal("changed files stored nothing")
	}
	if got := findEntry(second.Files, "keep.txt").Chunks; !slices.Equal(got, keepBefore) {
		t.Fatal("unchanged file chunks were not reused")
	}
	if got := readEntry(t, repo, master, findEntry(second.Files, "change.txt")); !bytes.Equal(got, testData(3000, 6)) {
		t.Fatal("changed file did not round-trip")
	}
	if got := readEntry(t, repo, master, findEntry(second.Files, "new.txt")); !bytes.Equal(got, []byte("brand new")) {
		t.Fatal("new file did not round-trip")
	}
}

func TestRacilyCleanForcesRescan(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", testData(2000, 7))

	first := runBackup(t, repo, backup.Options{Source: src, Master: master})
	// A parent start just after the file mtime keeps the file inside the
	// racily-clean window, so it must be re-read even though nothing
	// changed. Dedup still stores nothing new.
	second := runBackup(t, repo, backup.Options{
		Source:      src,
		Master:      master,
		Parent:      first.Files,
		ParentStart: first.Files[0].Mtime.Add(time.Second),
	})
	if second.ReusedFiles != 0 {
		t.Fatalf("ReusedFiles = %d, want 0 inside the racily-clean window", second.ReusedFiles)
	}
	if second.NewChunks != 0 {
		t.Fatalf("NewChunks = %d, want 0 via dedup", second.NewChunks)
	}
}

func TestForceRescan(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", testData(2000, 8))

	first := runBackup(t, repo, backup.Options{Source: src, Master: master})
	second := runBackup(t, repo, backup.Options{
		Source:      src,
		Master:      master,
		Parent:      first.Files,
		ParentStart: time.Now().Add(time.Hour),
		ForceRescan: true,
	})
	if second.ReusedFiles != 0 {
		t.Fatalf("ReusedFiles = %d, want 0 with --force-rescan", second.ReusedFiles)
	}
	if !slices.Equal(first.Files[0].Chunks, second.Files[0].Chunks) {
		t.Fatal("rescan produced different chunk IDs for unchanged content")
	}
}

func TestExcludes(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	src := t.TempDir()
	writeFile(t, src, "keep.txt", []byte("keep"))
	writeFile(t, src, "skip.log", []byte("skip"))
	writeFile(t, src, "logs/deep.log", []byte("skip"))
	writeFile(t, src, "build/out.bin", []byte("skip"))
	writeFile(t, src, "cache/data.bin", []byte("skip"))
	writeFile(t, src, "node_modules/pkg/index.js", []byte("skip"))
	if err := os.WriteFile(filepath.Join(src, "cache", "CACHEDIR.TAG"), []byte("tag"), 0o644); err != nil {
		t.Fatal(err)
	}

	excludeFile := filepath.Join(t.TempDir(), "excludes")
	if err := os.WriteFile(excludeFile, []byte("# comment\n\nnode_modules/\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runBackup(t, repo, backup.Options{
		Source:        src,
		Master:        master,
		Excludes:      []string{"*.log", "build/", "**/out.bin"},
		ExcludeFile:   excludeFile,
		ExcludeCaches: true,
	})
	paths := make([]string, 0, len(res.Files))
	for _, e := range res.Files {
		paths = append(paths, e.Path)
	}
	// logs/ itself is recorded as an (emptied) directory; only its *.log
	// contents are excluded.
	if !slices.Equal(paths, []string{"keep.txt", "logs"}) {
		t.Fatalf("files = %v, want keep.txt and the emptied logs dir", paths)
	}
}

func TestExcludePatternValidation(t *testing.T) {
	t.Parallel()

	matcher, err := backup.NewMatcher([]string{"*.log", "build/", "**/x", "[a-z].txt"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		path  string
		isDir bool
		want  bool
	}{
		{path: "a.log", want: true},
		{path: "sub/a.log", want: true},
		{path: "a.txt", want: true},
		{path: "ab.txt", want: false},
		{path: "other.bin", want: false},
		{path: "build", isDir: true, want: true},
		{path: "build", want: false},
		{path: "build/out", want: false},
		{path: "x/out.bin", want: false},
		{path: "deep/nest/out.bin", want: false},
		{path: "a.log", isDir: true, want: true},
	} {
		if got := matcher.Excluded(tt.path, tt.isDir); got != tt.want {
			t.Fatalf("Excluded(%q, dir=%v) = %v, want %v", tt.path, tt.isDir, got, tt.want)
		}
	}
	// "**/out.bin" must match at any depth, including the root.
	deep, err := backup.NewMatcher([]string{"**/out.bin"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"out.bin", "a/out.bin", "a/b/out.bin"} {
		if !deep.Excluded(p, false) {
			t.Fatalf("Excluded(%q) = false, want true", p)
		}
	}
	if deep.Excluded("a/out.binx", false) {
		t.Fatal("Excluded matched a partial name")
	}
	for _, bad := range []string{"[unclosed", "[]"} {
		if _, err := backup.NewMatcher([]string{bad}); err == nil {
			t.Fatalf("NewMatcher accepted %q, want rejection", bad)
		}
	}
}

func TestOneFileSystemKeepsSingleFilesystem(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	src := t.TempDir()
	writeFile(t, src, "a.txt", []byte("same fs"))

	res := runBackup(t, repo, backup.Options{Source: src, Master: master, OneFileSystem: true})
	if len(res.Files) != 1 {
		t.Fatalf("files = %v, want the single file", res.Files)
	}
}

func TestUnsupportedTypeWarns(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	src := t.TempDir()
	writeFile(t, src, "ok.txt", []byte("ok"))
	if err := makeFifo(filepath.Join(src, "pipe")); err != nil {
		t.Skipf("cannot create fifo: %v", err)
	}

	opts := backup.Options{Source: src, Master: master, SourceID: "warn-source", Chunking: testParams(), RepositoryID: testRepoID}
	res, err := backup.Backup(t.Context(), repo, opts)
	if err == nil {
		t.Fatal("backup with an unreadable entry succeeded without warnings, want ErrWarnings")
	}
	if !errors.Is(err, pverrors.ErrWarnings) {
		t.Fatalf("err = %v, want a warnings failure (exit 3)", err)
	}
	if got := pverrors.ExitCode(err); got != pverrors.ExitWarnings {
		t.Fatalf("ExitCode = %d, want %d", got, pverrors.ExitWarnings)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("no warnings recorded")
	}
	if len(res.Files) != 1 || res.Files[0].Path != "ok.txt" {
		t.Fatalf("files = %v, want only ok.txt", res.Files)
	}
}

func TestInvalidOptions(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	src := t.TempDir()
	writeFile(t, src, "f.txt", []byte("x"))

	for _, tt := range []struct {
		name string
		opts backup.Options
	}{
		{name: "empty source", opts: backup.Options{Master: master, RepositoryID: testRepoID}},
		{name: "file source", opts: backup.Options{Source: filepath.Join(src, "f.txt"), Master: master, RepositoryID: testRepoID}},
		{name: "missing source", opts: backup.Options{Source: filepath.Join(src, "nope"), Master: master, RepositoryID: testRepoID}},
		{name: "empty repo id", opts: backup.Options{Source: src, Master: master}},
		{name: "bad chunking", opts: backup.Options{Source: src, Master: master, RepositoryID: testRepoID, Chunking: chunking.Params{MinSize: 1}}},
		{name: "bad exclude", opts: backup.Options{Source: src, Master: master, RepositoryID: testRepoID, Excludes: []string{"[unclosed"}}},
		{name: "missing exclude file", opts: backup.Options{Source: src, Master: master, RepositoryID: testRepoID, ExcludeFile: filepath.Join(src, "nope")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := backup.Backup(t.Context(), repo, tt.opts); err == nil {
				t.Fatalf("%s accepted, want failure", tt.name)
			}
		})
	}
}

func TestEmptySource(t *testing.T) {
	t.Parallel()

	master := mustMaster(t)
	repo := mustRepo(t)
	res := runBackup(t, repo, backup.Options{Source: t.TempDir(), Master: master})
	if len(res.Files) != 0 || len(res.Packs) != 0 || res.Index != "" {
		t.Fatalf("empty backup stored objects: %+v", res)
	}
}

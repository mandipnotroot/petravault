// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package pack writes and reads content-addressed packs and immutable index
// files (DESIGN.md §8). Each chunk is compressed, then sealed as its own
// AEAD blob bound to its chunk ID, so one chunk can be fetched with a ranged
// read. A pack carries an encrypted header describing its blobs, and an
// index maps chunk IDs to pack locations. Pack and index names are the hex
// BLAKE3 hash of their finished ciphertext.
package pack

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"

	json "encoding/json/v2"

	"petravault/internal/compression"
	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/repository"
)

// Version is the pack and index format version.
const Version = 1

// TargetPackSize is the default pack size callers fill before flushing
// (~16 MiB, DESIGN.md §8).
const TargetPackSize = 16 << 20

// Object types bound into AEAD associated data (DESIGN.md §4.1). Chunk blobs
// bind their chunk ID; the pack header and index have no ID of their own,
// and swapping or renaming them is still caught because indexes reference
// packs by hash and every chunk blob binds its own ID.
const (
	ObjectChunk      = "chunk"
	ObjectPackHeader = "pack-header"
	ObjectIndex      = "index"
)

// PackPrefix and IndexPrefix are the repository key prefixes for packs and
// indexes.
const (
	PackPrefix  = "packs/"
	IndexPrefix = "indexes/"
)

// Entry maps one chunk ID to its sealed blob inside a pack. Offsets are
// absolute file offsets covering the sealed blob only.
type Entry struct {
	ID     [32]byte
	Pack   string
	Offset int64
	Length int64
}

// ChunkRef describes one blob listed in a pack header.
type ChunkRef struct {
	ID     [32]byte
	Length int64
}

// FormatID encodes a chunk, pack, or index hash as hex for associated data,
// headers, and indexes.
func FormatID(id [32]byte) string {
	return hex.EncodeToString(id[:])
}

// ParseID decodes a hex ID, failing closed on malformed input from storage.
func ParseID(s string) ([32]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != crypto.HashLength {
		return [32]byte{}, fmt.Errorf("invalid id %q: want %d hex bytes", s, crypto.HashLength)
	}
	var id [32]byte
	copy(id[:], raw)
	return id, nil
}

// chunkRef is the wire form of ChunkRef.
type chunkRef struct {
	ID     string `json:"id"`
	Length int64  `json:"length"`
}

// packHeader is the wire form of a pack header. Field order is fixed, so the
// sealed bytes are deterministic for a given chunk sequence.
type packHeader struct {
	Version   int        `json:"version"`
	Algorithm string     `json:"algorithm"`
	Chunks    []chunkRef `json:"chunks"`
}

// indexEntry is the wire form of Entry.
type indexEntry struct {
	ID     string `json:"id"`
	Pack   string `json:"pack"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}

// indexFile is the wire form of an index object.
type indexFile struct {
	Version   int          `json:"version"`
	Algorithm string       `json:"algorithm"`
	Entries   []indexEntry `json:"entries"`
}

// Writer accumulates sealed chunk blobs and flushes them as packs. It is not
// safe for concurrent use; backups process one pack stream at a time.
type Writer struct {
	repoID   string
	dataKey  crypto.SecretKey
	target   int
	ids      [][32]byte
	blobs    [][]byte
	buffered int
	packs    []string
	entries  []Entry
}

// NewWriter returns a Writer that flushes packs of about targetSize bytes. A
// non-positive targetSize selects TargetPackSize.
func NewWriter(repoID string, dataKey crypto.SecretKey, targetSize int) *Writer {
	if targetSize <= 0 {
		targetSize = TargetPackSize
	}
	return &Writer{
		repoID:  repoID,
		dataKey: dataKey,
		target:  targetSize,
	}
}

// Add compresses plaintext and buffers its sealed blob under id. Callers
// flush once Buffered reaches their pack target.
func (w *Writer) Add(id [32]byte, plaintext []byte) error {
	compressed, err := compression.Compress(plaintext)
	if err != nil {
		return err
	}
	sealed, err := w.dataKey.Seal(compressed, crypto.AssociatedData(w.repoID, ObjectChunk, FormatID(id)))
	if err != nil {
		return fmt.Errorf("seal chunk %s: %w", FormatID(id), err)
	}
	w.ids = append(w.ids, id)
	w.blobs = append(w.blobs, sealed)
	w.buffered += len(sealed)
	return nil
}

// Buffered returns the sealed bytes pending in the current pack.
func (w *Writer) Buffered() int {
	return w.buffered
}

// Pending returns the number of chunks pending in the current pack.
func (w *Writer) Pending() int {
	return len(w.blobs)
}

// Packs returns the keys of packs written so far.
func (w *Writer) Packs() []string {
	return slices.Clone(w.packs)
}

// Entries returns the index entries for every flushed chunk.
func (w *Writer) Entries() []Entry {
	return slices.Clone(w.entries)
}

// Flush writes the pending chunks as one pack and returns its key. It
// returns an empty key when nothing is pending.
func (w *Writer) Flush(ctx context.Context, repo repository.Repository) (string, error) {
	if len(w.blobs) == 0 {
		return "", nil
	}
	header := packHeader{Version: Version, Algorithm: crypto.AEADID}
	for i, id := range w.ids {
		header.Chunks = append(header.Chunks, chunkRef{ID: FormatID(id), Length: int64(len(w.blobs[i]))})
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal pack header: %w", err)
	}
	sealedHeader, err := w.dataKey.Seal(headerJSON, crypto.AssociatedData(w.repoID, ObjectPackHeader, ""))
	if err != nil {
		return "", fmt.Errorf("seal pack header: %w", err)
	}
	var file bytes.Buffer
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], uint64(len(sealedHeader)))
	file.Write(prefix[:])
	file.Write(sealedHeader)
	for _, blob := range w.blobs {
		file.Write(blob)
	}
	content := file.Bytes()
	sum := crypto.Sum256(content)
	key := PackPrefix + FormatID(sum)
	if err := repo.PutObject(ctx, key, bytes.NewReader(content)); err != nil {
		return "", fmt.Errorf("write pack %s: %w", key, err)
	}
	base := int64(8 + len(sealedHeader))
	offset := base
	for i, id := range w.ids {
		w.entries = append(w.entries, Entry{
			ID:     id,
			Pack:   key,
			Offset: offset,
			Length: int64(len(w.blobs[i])),
		})
		offset += int64(len(w.blobs[i]))
	}
	w.packs = append(w.packs, key)
	clear(w.blobs)
	w.blobs = w.blobs[:0]
	w.ids = w.ids[:0]
	w.buffered = 0
	return key, nil
}

// ListPack verifies a pack header and returns its chunk references without
// downloading every blob. Structural damage (truncation, a tampered length)
// is reported; authentication failures wrap ErrIntegrity.
func ListPack(ctx context.Context, repo repository.Repository, repoID string, dataKey crypto.SecretKey, packKey string) ([]ChunkRef, error) {
	content, err := readAll(ctx, repo, packKey, -1, -1)
	if err != nil {
		return nil, err
	}
	return parsePack(content, repoID, dataKey, packKey)
}

// ReadChunk fetches one chunk blob with a ranged read, authenticates it,
// decompresses it (capped at maxSize), and verifies its keyed ID. Every
// failure from storage, authentication, or verification is reported; tampered
// or misplaced blobs wrap ErrIntegrity and yield no plaintext.
func ReadChunk(ctx context.Context, repo repository.Repository, repoID string, dataKey, chunkIDKey crypto.SecretKey, e Entry, maxSize int) ([]byte, error) {
	if e.Pack == "" || e.Offset < 0 || e.Length <= 0 {
		return nil, fmt.Errorf("invalid index entry for chunk %s", FormatID(e.ID))
	}
	sealed, err := readAll(ctx, repo, e.Pack, e.Offset, e.Length)
	if err != nil {
		return nil, err
	}
	compressed, err := dataKey.Open(sealed, crypto.AssociatedData(repoID, ObjectChunk, FormatID(e.ID)))
	if err != nil {
		return nil, fmt.Errorf("open chunk %s: %w", FormatID(e.ID), err)
	}
	plaintext, err := compression.Decompress(compressed, maxSize)
	if err != nil {
		return nil, err
	}
	sum, err := crypto.KeyedSum(chunkIDKey, plaintext)
	if err != nil {
		return nil, err
	}
	if sum != e.ID {
		return nil, fmt.Errorf("chunk %s: %w: id mismatch after decryption", FormatID(e.ID), pverrors.ErrIntegrity)
	}
	return plaintext, nil
}

// WriteIndex seals entries as one immutable index object and returns its
// key. Entries are sorted by ID before sealing, so the stored bytes are
// deterministic.
func WriteIndex(ctx context.Context, repo repository.Repository, repoID string, dataKey crypto.SecretKey, entries []Entry) (string, error) {
	if len(entries) == 0 {
		return "", errors.New("refusing to write an empty index")
	}
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b Entry) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	file := indexFile{Version: Version, Algorithm: crypto.AEADID}
	seen := make(map[[32]byte]bool, len(sorted))
	for _, e := range sorted {
		if e.Pack == "" || e.Offset < 0 || e.Length <= 0 {
			return "", fmt.Errorf("invalid index entry for chunk %s", FormatID(e.ID))
		}
		if seen[e.ID] {
			return "", fmt.Errorf("duplicate index entry for chunk %s", FormatID(e.ID))
		}
		seen[e.ID] = true
		file.Entries = append(file.Entries, indexEntry{
			ID:     FormatID(e.ID),
			Pack:   e.Pack,
			Offset: e.Offset,
			Length: e.Length,
		})
	}
	raw, err := json.Marshal(file)
	if err != nil {
		return "", fmt.Errorf("marshal index: %w", err)
	}
	sealed, err := dataKey.Seal(raw, crypto.AssociatedData(repoID, ObjectIndex, ""))
	if err != nil {
		return "", fmt.Errorf("seal index: %w", err)
	}
	sum := crypto.Sum256(sealed)
	key := IndexPrefix + FormatID(sum)
	if err := repo.PutObject(ctx, key, bytes.NewReader(sealed)); err != nil {
		return "", fmt.Errorf("write index %s: %w", key, err)
	}
	return key, nil
}

// ReadIndex verifies and decodes one index object.
func ReadIndex(ctx context.Context, repo repository.Repository, repoID string, dataKey crypto.SecretKey, indexKey string) ([]Entry, error) {
	sealed, err := readAll(ctx, repo, indexKey, -1, -1)
	if err != nil {
		return nil, err
	}
	raw, err := dataKey.Open(sealed, crypto.AssociatedData(repoID, ObjectIndex, ""))
	if err != nil {
		return nil, fmt.Errorf("open index %s: %w", indexKey, err)
	}
	var file indexFile
	if err := json.Unmarshal(raw, &file, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode index %s: %w", indexKey, err)
	}
	if file.Version != Version {
		return nil, fmt.Errorf("index %s has version %d, want %d", indexKey, file.Version, Version)
	}
	if file.Algorithm != crypto.AEADID {
		return nil, fmt.Errorf("index %s names algorithm %q, want %q", indexKey, file.Algorithm, crypto.AEADID)
	}
	var out []Entry
	for _, we := range file.Entries {
		id, err := ParseID(we.ID)
		if err != nil {
			return nil, fmt.Errorf("index %s: %w", indexKey, err)
		}
		if we.Pack == "" || we.Offset < 0 || we.Length <= 0 {
			return nil, fmt.Errorf("index %s holds an invalid entry for chunk %s", indexKey, we.ID)
		}
		out = append(out, Entry{ID: id, Pack: we.Pack, Offset: we.Offset, Length: we.Length})
	}
	return out, nil
}

// ListIndexKeys returns the sorted keys of all index objects.
func ListIndexKeys(ctx context.Context, repo repository.Repository) ([]string, error) {
	keys, err := repo.List(ctx, IndexPrefix)
	if err != nil {
		return nil, fmt.Errorf("list indexes: %w", err)
	}
	return keys, nil
}

// LoadEntries merges every index into a chunk-ID map for dedup lookups. Keys
// are visited in sorted order and the first location wins, so concurrent
// duplicate blobs never cause an error (DESIGN.md §10.1).
func LoadEntries(ctx context.Context, repo repository.Repository, repoID string, dataKey crypto.SecretKey) (map[[32]byte]Entry, error) {
	keys, err := ListIndexKeys(ctx, repo)
	if err != nil {
		return nil, err
	}
	merged := make(map[[32]byte]Entry)
	for _, key := range keys {
		entries, err := ReadIndex(ctx, repo, repoID, dataKey, key)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if _, ok := merged[e.ID]; !ok {
				merged[e.ID] = e
			}
		}
	}
	return merged, nil
}

// parsePack verifies one pack's bytes and returns its header references.
func parsePack(content []byte, repoID string, dataKey crypto.SecretKey, packKey string) ([]ChunkRef, error) {
	if len(content) < 8 {
		return nil, fmt.Errorf("pack %s is truncated", packKey)
	}
	headerLen := binary.BigEndian.Uint64(content[:8])
	body := content[8:]
	if uint64(len(body)) < headerLen {
		return nil, fmt.Errorf("pack %s is truncated", packKey)
	}
	sealedHeader := body[:headerLen]
	raw, err := dataKey.Open(sealedHeader, crypto.AssociatedData(repoID, ObjectPackHeader, ""))
	if err != nil {
		return nil, fmt.Errorf("open pack %s header: %w", packKey, err)
	}
	var header packHeader
	if err := json.Unmarshal(raw, &header, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode pack %s header: %w", packKey, err)
	}
	if header.Version != Version {
		return nil, fmt.Errorf("pack %s has version %d, want %d", packKey, header.Version, Version)
	}
	if header.Algorithm != crypto.AEADID {
		return nil, fmt.Errorf("pack %s names algorithm %q, want %q", packKey, header.Algorithm, crypto.AEADID)
	}
	var refs []ChunkRef
	// Walk the blobs, so an inconsistent header (lengths that overrun the
	// pack or leave trailing bytes) is reported rather than trusted.
	rest := body[headerLen:]
	for _, wc := range header.Chunks {
		id, err := ParseID(wc.ID)
		if err != nil {
			return nil, fmt.Errorf("pack %s: %w", packKey, err)
		}
		if wc.Length <= 0 || int64(len(rest)) < wc.Length {
			return nil, fmt.Errorf("pack %s holds an invalid length for chunk %s", packKey, wc.ID)
		}
		refs = append(refs, ChunkRef{ID: id, Length: wc.Length})
		rest = rest[wc.Length:]
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("pack %s size %d disagrees with its header", packKey, len(content))
	}
	return refs, nil
}

// readAll reads a whole object or one byte range into memory.
func readAll(ctx context.Context, repo repository.Repository, key string, offset, length int64) ([]byte, error) {
	open := func() (io.ReadCloser, error) {
		if offset < 0 {
			return repo.GetObject(ctx, key)
		}
		return repo.GetRange(ctx, key, offset, length)
	}
	r, err := open()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	defer r.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	return buf.Bytes(), nil
}

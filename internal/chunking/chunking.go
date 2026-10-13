// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package chunking splits byte streams into content-defined chunks
// (DESIGN.md §3). Boundaries come from KFastCDC, the keyed FastCDC variant,
// so cut points are secret per repository, and chunk IDs (computed by the
// caller with crypto.KeyedSum) reveal nothing to an observer of the
// repository. The algorithm is fixed per repository: AlgorithmID is the name
// frozen in repository.json, while LibraryAlgorithm is the versioned variant
// provided by the underlying library.
package chunking

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	cdc "github.com/PlakarKorp/go-cdc-chunkers"
	_ "github.com/PlakarKorp/go-cdc-chunkers/chunkers/fastcdc"
)

// Algorithm and library identifiers (DESIGN.md §3.1, §3.3, §6). AlgorithmID
// is the name frozen in repository.json and must stay identical to
// crypto.ChunkingID; a different implementation gets a new algorithm ID, and
// renaming is a breaking change.
const (
	// AlgorithmID is the Petravault chunking algorithm name.
	AlgorithmID = "kfastcdc-v1"
	// LibraryAlgorithm is the versioned variant used from go-cdc-chunkers.
	LibraryAlgorithm = "fastcdc-v1.0.0"
	// Library is the module providing the chunker implementation.
	Library = "github.com/PlakarKorp/go-cdc-chunkers"
	// LibraryVersion is the pinned library version recorded in
	// repository.json alongside the algorithm.
	LibraryVersion = "v1.1.0"
)

// Chunk sizes in bytes (DESIGN.md §3.2). Configurable at init, then frozen in
// repository.json.
const (
	// DefaultMinSize is the default minimum chunk size (512 KiB).
	DefaultMinSize = 512 << 10
	// DefaultAverageSize is the default average (target) chunk size (1 MiB).
	DefaultAverageSize = 1 << 20
	// DefaultMaxSize is the default maximum chunk size (8 MiB).
	DefaultMaxSize = 8 << 20
)

// KeyLength is the required key length in bytes. The key is K_chunker derived
// from the repository master key (DESIGN.md §3.2, §4.1).
const KeyLength = 32

// Params configures the chunker. The zero value is invalid; use
// DefaultParams or set every field explicitly.
type Params struct {
	MinSize     int
	AverageSize int
	MaxSize     int
}

// DefaultParams returns the repository defaults from DESIGN.md §3.2.
func DefaultParams() Params {
	return Params{
		MinSize:     DefaultMinSize,
		AverageSize: DefaultAverageSize,
		MaxSize:     DefaultMaxSize,
	}
}

// Validate fails closed on missing or inconsistent sizes. The average must be
// a power of two, as required by the underlying FastCDC implementation.
func (p Params) Validate() error {
	if p.MinSize < 64 || p.MinSize > 1024*1024*1024 {
		return fmt.Errorf("invalid min chunk size %d: want 64B..1GB", p.MinSize)
	}
	if p.AverageSize < 64 || p.AverageSize > 1024*1024*1024 {
		return fmt.Errorf("invalid average chunk size %d: want 64B..1GB", p.AverageSize)
	}
	if p.MaxSize < 64 || p.MaxSize > 1024*1024*1024 {
		return fmt.Errorf("invalid max chunk size %d: want 64B..1GB", p.MaxSize)
	}
	if p.MinSize >= p.AverageSize {
		return fmt.Errorf("invalid chunk sizes: min %d must be below average %d", p.MinSize, p.AverageSize)
	}
	if p.AverageSize >= p.MaxSize {
		return fmt.Errorf("invalid chunk sizes: average %d must be below max %d", p.AverageSize, p.MaxSize)
	}
	if p.AverageSize&(p.AverageSize-1) != 0 {
		return fmt.Errorf("invalid average chunk size %d: must be a power of two", p.AverageSize)
	}
	return nil
}

// Chunker splits one byte stream into content-defined chunks.
type Chunker interface {
	// Next returns the next chunk. The slice is owned by the caller and stays
	// valid after subsequent calls. It returns io.EOF once the stream is
	// exhausted; the final chunk may arrive together with io.EOF, and an
	// empty stream yields only io.EOF.
	Next() ([]byte, error)
}

// New returns a Chunker reading r with the given sizes and key. The key must
// hold KeyLength bytes; chunking is always keyed, never unkeyed (DESIGN.md
// §3.2).
func New(r io.Reader, p Params, key []byte) (Chunker, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(key) != KeyLength {
		return nil, fmt.Errorf("invalid chunker key length %d: want %d", len(key), KeyLength)
	}
	inner, err := cdc.NewChunker(LibraryAlgorithm, r, &cdc.ChunkerOpts{
		MinSize:    p.MinSize,
		MaxSize:    p.MaxSize,
		NormalSize: p.AverageSize,
		Key:        bytes.Clone(key),
	})
	if err != nil {
		return nil, fmt.Errorf("create chunker: %w", err)
	}
	return &keyedChunker{inner: inner}, nil
}

// keyedChunker adapts the library chunker to the Chunker interface,
// copying each chunk so callers own the returned memory.
type keyedChunker struct {
	inner *cdc.Chunker
}

// Next implements Chunker.
func (c *keyedChunker) Next() ([]byte, error) {
	chunk, err := c.inner.Next()
	if len(chunk) == 0 {
		return nil, err
	}
	return bytes.Clone(chunk), err
}

// SplitAll reads r to EOF and returns every chunk. It is a convenience helper
// for tests and small inputs; large streams should consume Next directly so
// chunks are processed without holding them all in memory.
func SplitAll(r io.Reader, p Params, key []byte) ([][]byte, error) {
	c, err := New(r, p, key)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for {
		chunk, err := c.Next()
		if len(chunk) > 0 {
			out = append(out, chunk)
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("split stream: %w", err)
		}
	}
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package repository defines the storage backend seam used by every other
// package (DESIGN.md §8). Implementations share one contract: immutable,
// uniquely named objects; PutObjectIfAbsent as the compare-and-swap behind
// the lock protocol (§10.2); ranged reads so restore fetches one chunk
// without downloading a whole pack.
package repository

import (
	"context"
	"io"
)

// Repository is the storage backend interface (DESIGN.md §8).
//
// ctx is the first parameter of every method and is never stored.
// Implementations must be safe for concurrent use.
type Repository interface {
	// PutObject durably stores key. The write is visible only after it is
	// durable; overwriting an existing key replaces it atomically.
	PutObject(ctx context.Context, key string, r io.Reader) error
	// PutObjectIfAbsent stores key only when it does not exist yet and
	// reports whether it created it. Creation is the compare-and-swap
	// behind the lock protocol; a lost race returns (false, nil), never
	// an overwrite.
	PutObjectIfAbsent(ctx context.Context, key string, r io.Reader) (bool, error)
	// GetObject opens key for reading. A missing key returns an error
	// wrapping fs.ErrNotExist.
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	// GetRange opens exactly length bytes at offset within key, so one
	// chunk can be fetched out of a pack.
	GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)
	// DeleteObject removes key. Deleting a missing key is not an error.
	DeleteObject(ctx context.Context, key string) error
	// Exists reports whether key is present.
	Exists(ctx context.Context, key string) (bool, error)
	// List returns the sorted names of all keys under prefix.
	List(ctx context.Context, prefix string) ([]string, error)
}

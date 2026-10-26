// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	pverrors "petravault/internal/errors"
)

// Repository object read limits. The pack ceiling retains the 1 GiB target
// and 1 GiB chunk maxima, plus a conservative allowance for the encrypted
// header. Metadata limits bound one in-memory index or snapshot independently
// of repository size.
const (
	// MaxConfigObjectBytes caps the signed repository config envelope.
	MaxConfigObjectBytes int64 = 1 << 20
	// MaxSmallObjectBytes caps slots, advisory public keys, and revocations.
	MaxSmallObjectBytes int64 = 1 << 20
	// MaxRosterObjectBytes caps the encrypted member roster.
	MaxRosterObjectBytes int64 = 16 << 20
	// MaxTrustListObjectBytes caps a published client trust-list backup.
	MaxTrustListObjectBytes int64 = 16 << 20
	// MaxLockObjectBytes caps lock records and backup markers.
	MaxLockObjectBytes int64 = 64 << 10
	// MaxIndexObjectBytes caps one immutable index object.
	MaxIndexObjectBytes int64 = 256 << 20
	// MaxSnapshotObjectBytes caps one encrypted snapshot manifest.
	MaxSnapshotObjectBytes int64 = 256 << 20
	// MaxPackObjectBytes caps a complete pack, including its encrypted header.
	MaxPackObjectBytes int64 = 8 << 30
	// MaxChunkRangeBytes caps a sealed chunk including compression and AEAD overhead.
	MaxChunkRangeBytes int64 = 1<<30 + 1<<20 + 40
	// MaxPackSidecarBytes caps parity for a pack up to MaxPackObjectBytes.
	MaxPackSidecarBytes int64 = 11 << 30
	// MaxMetadataSidecarBytes caps parity for indexes and snapshots.
	MaxMetadataSidecarBytes int64 = 384 << 20
	// MaxUnclassifiedWriteBytes keeps generic repository writes bounded.
	MaxUnclassifiedWriteBytes int64 = 1 << 20
)

// ReadObject reads one complete repository object under its object-class
// limit. Objects over their class limit and keys with unknown classes fail
// closed as integrity errors.
func ReadObject(ctx context.Context, repo Repository, key string) ([]byte, error) {
	if repo == nil {
		return nil, errors.New("read repository object: repository is nil")
	}
	maxBytes, err := objectReadLimit(key)
	if err != nil {
		return nil, err
	}
	r, err := repo.GetObject(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", key, err)
	}
	return readAndClose(r, key, maxBytes)
}

// ReadRange reads one encrypted chunk range. The range length is checked
// before the backend request and must be satisfied exactly.
func ReadRange(ctx context.Context, repo Repository, key string, offset, length int64) ([]byte, error) {
	if repo == nil {
		return nil, errors.New("read repository range: repository is nil")
	}
	maxInt64 := int64(^uint64(0) >> 1)
	if !strings.HasPrefix(key, "packs/") || offset < 0 || length < 0 || length > MaxChunkRangeBytes ||
		(length > 0 && offset > maxInt64-(length-1)) {
		return nil, fmt.Errorf("%w: invalid chunk range for %q (offset=%d length=%d)", pverrors.ErrIntegrity, key, offset, length)
	}
	r, err := repo.GetRange(ctx, key, offset, length)
	if err != nil {
		return nil, fmt.Errorf("read range %q: %w", key, err)
	}
	raw, err := readAndClose(r, key, MaxChunkRangeBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != length {
		return nil, fmt.Errorf("%w: range %q returned %d bytes, want %d", pverrors.ErrIntegrity, key, len(raw), length)
	}
	return raw, nil
}

func objectReadLimit(key string) (int64, error) {
	if base, ok := strings.CutSuffix(key, ".ecc"); ok {
		switch {
		case strings.HasPrefix(base, "packs/"):
			return MaxPackSidecarBytes, nil
		case strings.HasPrefix(base, "indexes/"), strings.HasPrefix(base, "snapshots/"):
			return MaxMetadataSidecarBytes, nil
		default:
			return 0, fmt.Errorf("%w: unknown repository object class for %q", pverrors.ErrIntegrity, key)
		}
	}
	switch {
	case key == ConfigKey:
		return MaxConfigObjectBytes, nil
	case key == "members.json":
		return MaxRosterObjectBytes, nil
	case strings.HasPrefix(key, "locks/"):
		return MaxLockObjectBytes, nil
	case strings.HasPrefix(key, "packs/"):
		return MaxPackObjectBytes, nil
	case strings.HasPrefix(key, "indexes/"):
		return MaxIndexObjectBytes, nil
	case strings.HasPrefix(key, "snapshots/"):
		return MaxSnapshotObjectBytes, nil
	case strings.HasPrefix(key, "trust-lists/"):
		return MaxTrustListObjectBytes, nil
	case strings.HasPrefix(key, "keys/"), strings.HasPrefix(key, "identities/"), strings.HasPrefix(key, "revocations/"):
		return MaxSmallObjectBytes, nil
	default:
		return 0, fmt.Errorf("%w: unknown repository object class for %q", pverrors.ErrIntegrity, key)
	}
}

func readAndClose(r io.ReadCloser, key string, maxBytes int64) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("read %q: repository returned a nil reader", key)
	}
	raw, readErr := readBounded(r, key, maxBytes)
	closeErr := r.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %q: %w", key, closeErr)
	}
	return raw, nil
}

func readBounded(r io.Reader, key string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes == int64(^uint64(0)>>1) {
		return nil, fmt.Errorf("invalid read limit %d for %q", maxBytes, key)
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", key, err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%w: object %q exceeds its %d-byte class limit", pverrors.ErrIntegrity, key, maxBytes)
	}
	return raw, nil
}

func copyObjectForWrite(dst io.Writer, src io.Reader, key string) error {
	maxBytes, err := objectReadLimit(key)
	if err != nil {
		maxBytes = MaxUnclassifiedWriteBytes
	}
	n, err := io.Copy(dst, io.LimitReader(src, maxBytes+1))
	if err != nil {
		return err
	}
	if n > maxBytes {
		return fmt.Errorf("%w: refusing to write oversized object %q (class limit %d bytes)", pverrors.ErrUsage, key, maxBytes)
	}
	return nil
}

func readObjectForWrite(src io.Reader, key string) ([]byte, error) {
	maxBytes, err := objectReadLimit(key)
	if err != nil {
		maxBytes = MaxUnclassifiedWriteBytes
	}
	raw, err := io.ReadAll(io.LimitReader(src, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%w: refusing to write oversized object %q (class limit %d bytes)", pverrors.ErrUsage, key, maxBytes)
	}
	return raw, nil
}

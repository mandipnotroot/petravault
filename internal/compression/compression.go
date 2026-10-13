// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package compression wraps Zstandard for chunk compression (DESIGN.md §2,
// §6). Chunks are compressed before encryption, so identical plaintext still
// deduplicates after compression. Decompression is always capped, so a
// crafted blob cannot expand without bound (DESIGN.md §9).
package compression

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// DefaultMaxSize caps decompressed output at the repository maximum chunk
// size (DESIGN.md §3.2). Callers with custom chunking parameters pass their
// own cap to Decompress instead.
const DefaultMaxSize = 8 << 20

// Compress compresses src with Zstandard at the default level. The output is
// deterministic for a given library version; Petravault hashes plaintext, so
// encoder bitstream changes across library versions cost nothing.
func Compress(src []byte) ([]byte, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, fmt.Errorf("create encoder: %w", err)
	}
	defer enc.Close()
	return enc.EncodeAll(src, nil), nil
}

// Decompress returns the Zstandard decompression of src, rejecting outputs
// larger than maxSize. The cap is enforced during decoding, so the decoder
// never buffers more than maxSize+1 bytes no matter what the input claims.
func Decompress(src []byte, maxSize int) ([]byte, error) {
	if maxSize <= 0 {
		return nil, fmt.Errorf("invalid decompression limit %d: want a positive number", maxSize)
	}
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderMaxMemory(uint64(maxSize)+1),
		zstd.WithDecodeAllCapLimit(true),
	)
	if err != nil {
		return nil, fmt.Errorf("create decoder: %w", err)
	}
	defer dec.Close()
	// The destination capacity is the enforcement mechanism: with
	// WithDecodeAllCapLimit the decoder never emits more than
	// cap(dst)-len(dst) bytes, so the allocation stays bounded by the
	// caller's cap no matter what the input claims.
	out, err := dec.DecodeAll(src, make([]byte, 0, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("decompress chunk: %w", err)
	}
	if len(out) > maxSize {
		return nil, fmt.Errorf("decompressed size %d exceeds limit %d", len(out), maxSize)
	}
	return out, nil
}

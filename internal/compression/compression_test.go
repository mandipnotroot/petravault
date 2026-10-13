// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package compression_test

import (
	"bytes"
	"strings"
	"testing"

	"petravault/internal/compression"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	inputs := [][]byte{
		nil,
		{},
		[]byte("backup chunk bytes"),
		bytes.Repeat([]byte("a"), 1 << 20),
		bytes.Repeat([]byte("0123456789abcdef"), 1<<16),
	}
	for _, in := range inputs {
		compressed, err := compression.Compress(in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := compression.Decompress(compressed, compression.DefaultMaxSize)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, in) {
			t.Fatalf("round trip of %d bytes mismatched", len(in))
		}
	}
}

func TestCompressedSmallerForRepetitiveData(t *testing.T) {
	t.Parallel()

	in := bytes.Repeat([]byte("a"), 1<<20)
	compressed, err := compression.Compress(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(compressed) >= len(in) {
		t.Fatalf("compressed %d bytes, want less than %d", len(compressed), len(in))
	}
}

func TestDecompressRejectsCorruption(t *testing.T) {
	t.Parallel()

	compressed, err := compression.Compress(bytes.Repeat([]byte("data"), 1000))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(compressed)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := compression.Decompress(tampered, compression.DefaultMaxSize); err == nil {
		t.Fatal("Decompress accepted corrupted input, want failure")
	}
	if _, err := compression.Decompress([]byte("not zstd"), compression.DefaultMaxSize); err == nil {
		t.Fatal("Decompress accepted garbage, want failure")
	}
}

func TestDecompressEnforcesCap(t *testing.T) {
	t.Parallel()

	in := bytes.Repeat([]byte("a"), 1<<20)
	compressed, err := compression.Compress(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compression.Decompress(compressed, 1024); err == nil {
		t.Fatal("Decompress ignored the size cap, want failure")
	} else if !strings.Contains(err.Error(), "exceeds limit") && !strings.Contains(err.Error(), "decompress") {
		t.Fatalf("err = %v, want a size-cap failure", err)
	}
	for _, bad := range []int{0, -1} {
		if _, err := compression.Decompress(compressed, bad); err == nil {
			t.Fatalf("Decompress accepted limit %d, want rejection", bad)
		}
	}
}

func TestDecompressAtExactLimit(t *testing.T) {
	t.Parallel()

	in := bytes.Repeat([]byte("b"), 4096)
	compressed, err := compression.Compress(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := compression.Decompress(compressed, len(in))
	if err != nil {
		t.Fatalf("Decompress at the exact limit failed: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatal("Decompress at the exact limit mismatched")
	}
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package chunking_test

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"

	"petravault/internal/chunking"
	"petravault/internal/crypto"
)

// testKey is the fixed key for deterministic tests (DESIGN.md §3.3).
func testKey() []byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i)
	}
	return k[:]
}

// testParams uses small sizes so golden offsets stay readable. The same code
// path serves the repository defaults, which TestDefaultParamsDeterministic
// pins separately.
func testParams() chunking.Params {
	return chunking.Params{MinSize: 64, AverageSize: 256, MaxSize: 1024}
}

// testData returns n deterministic bytes from a fixed xorshift stream. It is
// test data only, never key material or randomness.
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

func offsetsOf(chunks [][]byte) []int {
	offs := make([]int, 0, len(chunks))
	acc := 0
	for _, c := range chunks {
		acc += len(c)
		offs = append(offs, acc)
	}
	return offs
}

func mustSplit(t *testing.T, data []byte, p chunking.Params, key []byte) [][]byte {
	t.Helper()
	chunks, err := chunking.SplitAll(bytes.NewReader(data), p, key)
	if err != nil {
		t.Fatal(err)
	}
	return chunks
}

func TestAlgorithmIDsFrozen(t *testing.T) {
	t.Parallel()

	if chunking.AlgorithmID != "kfastcdc-v1" {
		t.Fatalf("AlgorithmID = %q, want %q (renaming is a breaking change)", chunking.AlgorithmID, "kfastcdc-v1")
	}
	if chunking.AlgorithmID != crypto.ChunkingID {
		t.Fatalf("AlgorithmID = %q, crypto.ChunkingID = %q: the frozen names drifted", chunking.AlgorithmID, crypto.ChunkingID)
	}
	if chunking.LibraryAlgorithm != "fastcdc-v1.0.0" {
		t.Fatalf("LibraryAlgorithm = %q, want %q", chunking.LibraryAlgorithm, "fastcdc-v1.0.0")
	}
	if chunking.LibraryVersion != "v1.1.0" {
		t.Fatalf("LibraryVersion = %q, want %q", chunking.LibraryVersion, "v1.1.0")
	}
}

func TestDefaultParams(t *testing.T) {
	t.Parallel()

	p := chunking.DefaultParams()
	if p.MinSize != 512<<10 || p.AverageSize != 1<<20 || p.MaxSize != 8<<20 {
		t.Fatalf("DefaultParams = %+v, want min 512KiB average 1MiB max 8MiB", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("DefaultParams invalid: %v", err)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	good := testParams()
	for _, tt := range []struct {
		name   string
		mutate func(*chunking.Params)
	}{
		{name: "zero", mutate: func(p *chunking.Params) { *p = chunking.Params{} }},
		{name: "min too small", mutate: func(p *chunking.Params) { p.MinSize = 63 }},
		{name: "max too large", mutate: func(p *chunking.Params) { p.MaxSize = 1024*1024*1024 + 1 }},
		{name: "min above average", mutate: func(p *chunking.Params) { p.MinSize = p.AverageSize }},
		{name: "average above max", mutate: func(p *chunking.Params) { p.AverageSize = p.MaxSize }},
		{name: "average not power of two", mutate: func(p *chunking.Params) { p.AverageSize = 300 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := good
			tt.mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatalf("Validate(%+v) accepted bad sizes, want rejection", p)
			}
		})
	}
	if _, err := chunking.New(bytes.NewReader(nil), good, nil); err == nil {
		t.Fatal("New accepted a nil key, want rejection: chunking is always keyed")
	}
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := chunking.New(bytes.NewReader(nil), good, make([]byte, n)); err == nil {
			t.Fatalf("New accepted a %d-byte key, want rejection", n)
		}
	}
}

func TestGoldenBoundaries(t *testing.T) {
	t.Parallel()

	p := testParams()
	key := testKey()
	for _, tt := range []struct {
		name string
		data []byte
		want []int
	}{
		{name: "empty", data: nil, want: nil},
		{name: "smaller than min", data: testData(48, 1), want: []int{48}},
		{name: "exactly max", data: testData(1024, 2), want: []int{327, 668, 932, 1024}},
		{name: "highly repetitive", data: bytes.Repeat([]byte{0}, 4096), want: []int{1024, 2048, 3072, 4096}},
		{name: "random", data: testData(4096, 3), want: []int{272, 582, 884, 1143, 1415, 1623, 1889, 2152, 2464, 2851, 3028, 3333, 3630, 4046, 4096}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := offsetsOf(mustSplit(t, tt.data, p, key))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("offsets = %v, want %v (a library upgrade moved cut points: bump the algorithm ID deliberately)", got, tt.want)
			}
		})
	}
}

func TestDefaultParamsDeterministic(t *testing.T) {
	t.Parallel()

	data := testData(2<<20, 7)
	chunks := mustSplit(t, data, chunking.DefaultParams(), testKey())
	if len(chunks) != 2 || len(chunks[0]) != 1132544 || len(chunks[1]) != 964608 {
		t.Fatalf("default-params split gave %d chunks (%d, %d), want 2 (1132544, 964608)",
			len(chunks), len(chunks[0]), len(chunks[len(chunks)-1]))
	}
	again := mustSplit(t, data, chunking.DefaultParams(), testKey())
	if !slices.Equal(offsetsOf(chunks), offsetsOf(again)) {
		t.Fatal("chunking is not deterministic across runs")
	}
}

func TestKeyedBoundariesDiffer(t *testing.T) {
	t.Parallel()

	p := testParams()
	data := testData(4096, 3)
	first := offsetsOf(mustSplit(t, data, p, testKey()))
	var other [32]byte
	for i := range other {
		other[i] = byte(31 - i)
	}
	second := offsetsOf(mustSplit(t, data, p, other[:]))
	if slices.Equal(first, second) {
		t.Fatal("two keys produced identical boundaries, want keyed cut points")
	}
}

func TestSplitAllRoundTrip(t *testing.T) {
	t.Parallel()

	p := testParams()
	key := testKey()
	for _, n := range []int{0, 1, 63, 64, 1023, 1024, 3000, 9000} {
		data := testData(n, uint64(n+1))
		chunks := mustSplit(t, data, p, key)
		for i, c := range chunks {
			last := i == len(chunks)-1
			if len(c) > p.MaxSize || (len(c) < p.MinSize && !last) {
				t.Fatalf("n=%d chunk %d has size %d, want within [%d, %d]", n, i, len(c), p.MinSize, p.MaxSize)
			}
		}
		if !bytes.Equal(slices.Concat(chunks...), data) {
			t.Fatalf("n=%d chunks do not concatenate back to the input", n)
		}
	}
}

func TestNextOwnsMemory(t *testing.T) {
	t.Parallel()

	p := testParams()
	key := testKey()
	data := testData(3*p.MaxSize, 9)
	c, err := chunking.New(bytes.NewReader(data), p, key)
	if err != nil {
		t.Fatal(err)
	}
	var chunks [][]byte
	for {
		chunk, err := c.Next()
		if len(chunk) > 0 {
			chunks = append(chunks, chunk)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// The stream exceeds the chunker's internal scan buffer, so slices that
	// merely aliased it would have been overwritten by later reads.
	if !bytes.Equal(slices.Concat(chunks...), data) {
		t.Fatal("retained chunks were overwritten: Next must return owned memory")
	}
}

func FuzzChunker(f *testing.F) {
	p := testParams()
	key := testKey()
	f.Add([]byte("seed"))
	f.Add(testData(3000, 11))
	f.Fuzz(func(t *testing.T, data []byte) {
		chunks, err := chunking.SplitAll(bytes.NewReader(data), p, key)
		if err != nil {
			t.Fatalf("SplitAll: %v", err)
		}
		for i, c := range chunks {
			last := i == len(chunks)-1
			if len(c) > p.MaxSize || (len(c) < p.MinSize && !last) {
				t.Fatalf("chunk %d has size %d, want within [%d, %d]", i, len(c), p.MinSize, p.MaxSize)
			}
		}
		if !bytes.Equal(slices.Concat(chunks...), data) {
			t.Fatal("chunks do not concatenate back to the input")
		}
	})
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto_test

import (
	"encoding/hex"
	"testing"

	"petravault/internal/crypto"
)

// Official BLAKE3 test vectors (BLAKE3 team, mirrored in the zeebo/blake3
// test suite): input pattern byte(i) = i % 251, key "whats the Elvish word
// for friend", context "BLAKE3 2019-12-27 16:29:52 test vectors context".
// Only the first 32 bytes are pinned here, which is all Petravault uses.
const (
	testVectorKey     = "whats the Elvish word for friend"
	testVectorContext = "BLAKE3 2019-12-27 16:29:52 test vectors context"
)

func vectorInput(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

func mustKey(t *testing.T, b []byte) crypto.SecretKey {
	t.Helper()
	k, err := crypto.NewKeyFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustUnhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSum256KnownAnswer(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "empty",
			input: nil,
			want:  "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
		},
		{
			name:  "1024",
			input: vectorInput(1024),
			want:  "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sum := crypto.Sum256(tt.input)
			if got := hex.EncodeToString(sum[:]); got != tt.want {
				t.Fatalf("Sum256 = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestKeyedSumKnownAnswer(t *testing.T) {
	t.Parallel()

	key := mustKey(t, []byte(testVectorKey))
	sum, err := crypto.KeyedSum(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	const want = "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("KeyedSum = %s, want %s", got, want)
	}
}

func TestDeriveKeyKnownAnswer(t *testing.T) {
	t.Parallel()

	sub := crypto.DeriveKey(testVectorContext, nil)
	want := mustKey(t, mustUnhex(t, "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"))
	if !sub.Equal(want) {
		t.Fatal("DeriveKey does not match the official test vector")
	}
}

func TestKeyedSumDiffersFromPlain(t *testing.T) {
	t.Parallel()

	key := mustKey(t, []byte(testVectorKey))
	data := []byte("known file contents")
	plain := crypto.Sum256(data)
	keyed, err := crypto.KeyedSum(key, data)
	if err != nil {
		t.Fatal(err)
	}
	if plain == keyed {
		t.Fatal("keyed sum equals plain sum, want domain separation")
	}
	other, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, err := crypto.KeyedSum(other, data)
	if err != nil {
		t.Fatal(err)
	}
	if keyed == rekeyed {
		t.Fatal("different keys produced the same MAC, want key separation")
	}
}

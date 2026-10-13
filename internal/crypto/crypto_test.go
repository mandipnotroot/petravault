// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto_test

import (
	"testing"

	"petravault/internal/crypto"
)

func TestSuiteIDsFrozen(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		got  string
		want string
	}{
		{name: "suite", got: crypto.SuiteID, want: "xwing-xchacha20poly1305-v1"},
		{name: "aead", got: crypto.AEADID, want: "xchacha20poly1305-v1"},
		{name: "kem", got: crypto.KEMID, want: "mlkem768-x25519"},
		{name: "signature", got: crypto.SignatureID, want: "ml-dsa-65"},
		{name: "hash", got: crypto.HashID, want: "blake3"},
		{name: "kdf", got: crypto.KDFID, want: "argon2id"},
		{name: "chunking", got: crypto.ChunkingID, want: "kfastcdc-v1"},
		{name: "erasure", got: crypto.ErasureID, want: "reed-solomon"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Fatalf("ID = %q, want %q (renaming is a breaking change)", tt.got, tt.want)
			}
		})
	}
	if crypto.FormatVersion != 1 {
		t.Fatalf("FormatVersion = %d, want 1", crypto.FormatVersion)
	}
}

func TestDeriveSubkeysSeparated(t *testing.T) {
	t.Parallel()

	master := mustGenerate(t)
	sub := master.DeriveSubkeys()
	if sub.Data.Equal(sub.ChunkID) || sub.Data.Equal(sub.Chunker) || sub.ChunkID.Equal(sub.Chunker) {
		t.Fatal("subkeys are not separated by purpose")
	}
	again := master.DeriveSubkeys()
	if !sub.Data.Equal(again.Data) || !sub.ChunkID.Equal(again.ChunkID) || !sub.Chunker.Equal(again.Chunker) {
		t.Fatal("subkey derivation is not deterministic")
	}
	other := mustGenerate(t)
	apart := other.DeriveSubkeys()
	if sub.Data.Equal(apart.Data) || sub.ChunkID.Equal(apart.ChunkID) || sub.Chunker.Equal(apart.Chunker) {
		t.Fatal("different master keys derived the same subkey")
	}
	sub.Zero()
	apart.Zero()
	var zero crypto.SecretKey
	if !sub.Data.Equal(zero) {
		t.Fatal("Subkeys.Zero did not clear the data key")
	}
}

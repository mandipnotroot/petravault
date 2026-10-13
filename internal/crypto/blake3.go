// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"fmt"

	"github.com/zeebo/blake3"
)

// HashLength is the BLAKE3 output length in bytes used for content hashes,
// chunk IDs, and derived subkeys.
const HashLength = 32

// Sum256 returns the BLAKE3 hash of data.
func Sum256(data []byte) [32]byte {
	return blake3.Sum256(data)
}

// KeyedSum returns the keyed BLAKE3 MAC of data under key (DESIGN.md §3.2).
// Keyed chunk IDs keep an observer of the repository from hashing a known
// file to confirm it is stored.
func KeyedSum(key SecretKey, data []byte) ([32]byte, error) {
	h, err := blake3.NewKeyed(key.b[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("new keyed hash: %w", err)
	}
	if _, err := h.Write(data); err != nil {
		return [32]byte{}, fmt.Errorf("write keyed hash: %w", err)
	}
	sum := h.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out, nil
}

// DeriveKey derives a 256-bit subkey from keyMaterial under deriveContext
// with BLAKE3 derive_key. Different contexts yield independent keys, so one
// master key separates cleanly by purpose (DESIGN.md §4.1).
func DeriveKey(deriveContext string, keyMaterial []byte) SecretKey {
	var out [32]byte
	blake3.DeriveKey(deriveContext, keyMaterial, out[:])
	return SecretKey{b: out}
}

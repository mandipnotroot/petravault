// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// SaltLength is the Argon2id salt length in bytes.
const SaltLength = 16

// Params holds Argon2id parameters (DESIGN.md §4.4). Memory is in KiB, as
// argon2.IDKey expects. Params travel alongside the keystore, so existing
// stores stay openable after the defaults change.
type Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
}

// DefaultParams returns the current OWASP-recommended Argon2id parameters.
func DefaultParams() Params {
	return Params{Time: 3, Memory: 65536, Threads: 4}
}

// maxUnlockMemoryKiB caps Unlock-time allocation from hostile keystore
// files at 256 MiB: 4x headroom over the 64 MiB default this code seals
// with, while a planted file can no longer force a 1 GiB derivation.
const maxUnlockMemoryKiB = 256 << 10

// Validate fails closed on missing or unsafe parameters. The upper bounds
// also guard Unlock against a hostile keystore file claiming absurd costs as
// a memory/CPU-exhaustion vector.
func (p Params) Validate() error {
	if p.Time < 1 || p.Time > 16 {
		return fmt.Errorf("invalid argon2 time %d: want 1..16", p.Time)
	}
	if p.Memory < 1024 || p.Memory > maxUnlockMemoryKiB {
		return fmt.Errorf("invalid argon2 memory %d KiB: want 1024..%d", p.Memory, maxUnlockMemoryKiB)
	}
	if p.Threads < 1 || p.Threads > 16 {
		return fmt.Errorf("invalid argon2 threads %d: want 1..16", p.Threads)
	}
	return nil
}

// DeriveKEK derives a 256-bit key-encryption key from password and salt with
// Argon2id (RFC 9106). The password must be non-empty and the salt at least
// SaltLength bytes.
func DeriveKEK(password, salt []byte, p Params) (SecretKey, error) {
	if len(password) == 0 {
		return SecretKey{}, errors.New("password must not be empty")
	}
	if len(salt) < SaltLength {
		return SecretKey{}, fmt.Errorf("salt must be at least %d bytes, got %d", SaltLength, len(salt))
	}
	if err := p.Validate(); err != nil {
		return SecretKey{}, err
	}
	raw := argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, KeyLength)
	defer clear(raw)
	return NewKeyFromBytes(raw)
}

// RandomSalt generates SaltLength random bytes from crypto/rand.
func RandomSalt() ([]byte, error) {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"

	pverrors "petravault/internal/errors"
)

// KeyLength is the XChaCha20-Poly1305 key length in bytes (256 bits).
const KeyLength = 32

// NonceLength is the XChaCha20-Poly1305 nonce length in bytes (192 bits).
const NonceLength = 24

// SecretKey is a 256-bit secret. It never prints itself, so key material
// cannot leak through logs, errors, or debug formatting (DESIGN.md §7), and
// it can be zeroed when no longer needed (best effort in Go, §4.4).
type SecretKey struct {
	b [32]byte
}

// GenerateKey creates a fresh random 256-bit key from crypto/rand. The
// repository master key is created this way at init (DESIGN.md §4.1).
func GenerateKey() (SecretKey, error) {
	var k SecretKey
	if _, err := rand.Read(k.b[:]); err != nil {
		return SecretKey{}, fmt.Errorf("generate key: %w", err)
	}
	return k, nil
}

// NewKeyFromBytes imports exactly 32 bytes of key material and fails closed
// on any other length.
func NewKeyFromBytes(b []byte) (SecretKey, error) {
	if len(b) != KeyLength {
		return SecretKey{}, fmt.Errorf("key must be %d bytes, got %d", KeyLength, len(b))
	}
	var k SecretKey
	copy(k.b[:], b)
	return k, nil
}

// Equal reports whether k and other hold the same key material, in constant
// time.
func (k SecretKey) Equal(other SecretKey) bool {
	return subtle.ConstantTimeCompare(k.b[:], other.b[:]) == 1
}

// Zero clears the key material (best effort in Go).
func (k *SecretKey) Zero() {
	clear(k.b[:])
}

// String redacts the key material.
func (SecretKey) String() string {
	return "[redacted]"
}

// GoString redacts the key material.
func (SecretKey) GoString() string {
	return "[redacted]"
}

// LogValue redacts the key material in structured logs.
func (SecretKey) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

// Seal encrypts plaintext with a fresh random 192-bit nonce from crypto/rand
// and returns nonce || ciphertext || tag. ad must bind the fields listed in
// DESIGN.md §4.1; callers build it with AssociatedData.
func (k SecretKey) Seal(plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(k.b[:])
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	nonce := make([]byte, NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, ad), nil
}

// Open reverses Seal. Any failure returns an error wrapping ErrAuthFailed and
// no plaintext.
func (k SecretKey) Open(sealed, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(k.b[:])
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	if len(sealed) < NonceLength+aead.Overhead() {
		return nil, fmt.Errorf("open sealed blob: %w", pverrors.ErrAuthFailed)
	}
	nonce, ciphertext := sealed[:NonceLength], sealed[NonceLength:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("open sealed blob: %w", pverrors.ErrAuthFailed)
	}
	return plaintext, nil
}

// AssociatedData builds AEAD associated data binding the repository ID, the
// format version, the algorithm ID, and the object type, plus the object ID
// wherever one is known before encryption: the chunk ID for chunk blobs and
// the snapshot ID for snapshots. Packs and indexes are named by the hash of
// their finished ciphertext, so they pass an empty object ID; swapping or
// renaming them is still caught because indexes reference packs by hash and
// every chunk blob binds its own chunk ID (DESIGN.md §4.1). Fields are
// length-prefixed so the encoding is unambiguous.
func AssociatedData(repositoryID, objectType, objectID string) []byte {
	fields := []string{strconv.Itoa(FormatVersion), AEADID, repositoryID, objectType, objectID}
	var total int
	for _, f := range fields {
		total += 8 + len(f)
	}
	out := make([]byte, 0, total)
	var prefix [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(prefix[:], uint64(len(f)))
		out = append(out, prefix[:]...)
		out = append(out, f...)
	}
	return out
}

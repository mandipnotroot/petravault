// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	pverrors "petravault/internal/errors"
)

// boxVersion is the password-box envelope version.
const boxVersion = 1

// lockedBox is the JSON envelope holding one password-sealed secret. It
// carries the Argon2id parameters and salt next to the sealed blob, so the
// store stays openable after the defaults change. It holds no password
// verifier beyond what the sealed blob itself provides: opening it requires
// the password-derived KEK, and the repository holds no private keys or
// password verifiers (DESIGN.md §4.4).
type lockedBox struct {
	Version int    `json:"version"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
	Salt    []byte `json:"salt"`
	Sealed  []byte `json:"sealed"`
}

// Lock seals plaintext under a password-derived KEK (Password → Argon2id →
// KEK → XChaCha20-Poly1305, DESIGN.md §4.4) and returns the JSON envelope.
// Identity key storage (phase 4) persists these envelopes; the crypto layer
// only seals and opens the bytes.
func Lock(password, plaintext []byte) ([]byte, error) {
	salt, err := RandomSalt()
	if err != nil {
		return nil, err
	}
	params := DefaultParams()
	kek, err := DeriveKEK(password, salt, params)
	if err != nil {
		return nil, err
	}
	defer kek.Zero()
	sealed, err := kek.Seal(plaintext, keystoreAD())
	if err != nil {
		return nil, err
	}
	return json.Marshal(lockedBox{
		Version: boxVersion,
		Time:    params.Time,
		Memory:  params.Memory,
		Threads: params.Threads,
		Salt:    salt,
		Sealed:  sealed,
	})
}

// Unlock opens an envelope produced by Lock. A wrong password or a tampered
// envelope fails authentication, and a malformed envelope or unknown version
// is rejected; all cases return an error and never any plaintext.
func Unlock(password, locked []byte) ([]byte, error) {
	var box lockedBox
	dec := json.NewDecoder(bytes.NewReader(locked))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&box); err != nil {
		return nil, fmt.Errorf("decode keystore envelope: %w: %w", err, pverrors.ErrIntegrity)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%w: decode keystore envelope: trailing data", pverrors.ErrIntegrity)
	}
	if box.Version != boxVersion {
		return nil, fmt.Errorf("%w: unsupported keystore version %d: want %d", pverrors.ErrIntegrity, box.Version, boxVersion)
	}
	kek, err := DeriveKEK(password, box.Salt, Params{
		Time:    box.Time,
		Memory:  box.Memory,
		Threads: box.Threads,
	})
	if err != nil {
		return nil, err
	}
	defer kek.Zero()
	return kek.Open(box.Sealed, keystoreAD())
}

// keystoreAD binds sealed keystore blobs to their context, so a blob sealed
// for one purpose cannot be replayed as another.
func keystoreAD() []byte {
	return []byte(ContextKeystore)
}

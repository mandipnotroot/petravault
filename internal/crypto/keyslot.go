// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"crypto/hpke"
	"encoding/binary"
	"fmt"
	"strings"

	pverrors "petravault/internal/errors"
)

// Hybrid KEM suite for repository key slots (DESIGN.md §4.2, §6). The Go
// standard library's crypto/hpke provides the X-Wing KEM as
// MLKEM768X25519, so there is no ad hoc combiner: the combiner, domain
// separation, and KDF come from RFC 9180 and draft-ietf-hpke-pq, not from
// this project. The string identifiers are frozen (renaming is a breaking
// change); the numeric HPKE identifiers are pinned in tests so a future
// draft-identifier change is a detected migration, not silent breakage.
const (
	// SlotKDFID names the HPKE KDF sealing repository key slots.
	SlotKDFID = "hkdf-sha256"
	// SlotAEADID names the HPKE AEAD sealing repository key slots.
	SlotAEADID = "chacha20poly1305"
)

// SlotInfoContext separates key-slot HPKE info strings from every other
// hash or associated-data context (DESIGN.md §4.2). It is length-prefixed
// into the info input, so the encoding is unambiguous. It differs from
// ContextSlotGrant, which separates ML-DSA-65 signatures over slot
// envelopes (§4.3): one binds the HPKE seal, the other the grant signature.
const SlotInfoContext = "petravault key-slot v1"

// SlotKEM returns the X-Wing hybrid KEM used for repository key slots.
func SlotKEM() hpke.KEM {
	return hpke.MLKEM768X25519()
}

// SlotKDF returns the HPKE KDF used for repository key slots.
func SlotKDF() hpke.KDF {
	return hpke.HKDFSHA256()
}

// SlotAEAD returns the HPKE AEAD used for repository key slots.
func SlotAEAD() hpke.AEAD {
	return hpke.ChaCha20Poly1305()
}

// SlotInfo builds the HPKE info string binding a sealed master key to its
// repository and member: info = SlotInfoContext || repository_id || member
// fingerprint (DESIGN.md §4.2). Fields are length-prefixed so the encoding
// is unambiguous. The member fingerprint is the canonical string form; the
// caller is responsible for parsing it.
func SlotInfo(repositoryID, member string) []byte {
	fields := []string{SlotInfoContext, repositoryID, member}
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

// SealMaster seals the 32-byte repository master key to the member's X-Wing
// public key with HPKE base mode (HKDF-SHA256, ChaCha20-Poly1305) and the
// slot info string. It returns enc || ciphertext. The recipient key is
// validated for well-formedness, not just length; a malformed key is a
// plain error and never yields a slot.
func SealMaster(master SecretKey, recipientKEMPublic []byte, repositoryID, member string) ([]byte, error) {
	if strings.TrimSpace(repositoryID) == "" {
		return nil, fmt.Errorf("%w: seal slot: repository id is empty", pverrors.ErrUsage)
	}
	if strings.TrimSpace(member) == "" {
		return nil, fmt.Errorf("%w: seal slot: member is empty", pverrors.ErrUsage)
	}
	pub, err := SlotKEM().NewPublicKey(recipientKEMPublic)
	if err != nil {
		return nil, fmt.Errorf("seal slot: invalid recipient key: %w", err)
	}
	raw := master.Bytes()
	defer clear(raw[:])
	return hpke.Seal(pub, SlotKDF(), SlotAEAD(), SlotInfo(repositoryID, member), raw[:])
}

// OpenMaster opens a slot sealed by SealMaster. Any HPKE failure or a
// payload of the wrong length returns an error wrapping ErrAuthFailed and
// no key material: info binds the repository and member, so a slot sealed
// for another repository or member fails closed.
func OpenMaster(sealed []byte, recipientKEMPriv hpke.PrivateKey, repositoryID, member string) (SecretKey, error) {
	if recipientKEMPriv == nil {
		return SecretKey{}, fmt.Errorf("%w: open slot: recipient key is nil", pverrors.ErrUsage)
	}
	if strings.TrimSpace(repositoryID) == "" {
		return SecretKey{}, fmt.Errorf("%w: open slot: repository id is empty", pverrors.ErrUsage)
	}
	if strings.TrimSpace(member) == "" {
		return SecretKey{}, fmt.Errorf("%w: open slot: member is empty", pverrors.ErrUsage)
	}
	if len(sealed) == 0 {
		return SecretKey{}, fmt.Errorf("open slot: %w", pverrors.ErrAuthFailed)
	}
	plaintext, err := hpke.Open(recipientKEMPriv, SlotKDF(), SlotAEAD(), SlotInfo(repositoryID, member), sealed)
	if err != nil {
		return SecretKey{}, fmt.Errorf("open slot: %w", pverrors.ErrAuthFailed)
	}
	defer clear(plaintext)
	if len(plaintext) != KeyLength {
		return SecretKey{}, fmt.Errorf("open slot: %w", pverrors.ErrAuthFailed)
	}
	return NewKeyFromBytes(plaintext)
}

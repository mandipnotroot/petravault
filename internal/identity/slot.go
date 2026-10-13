// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
)

// Signed repository key slots (DESIGN.md §4.2). At init the master key is
// created and sealed to the creator's KEM public key; adding a member seals
// the same master key to that member's KEM public key. Each sealed copy is
// wrapped in a granter-signed envelope and stored at keys/<fingerprint>.slot.
// HPKE base mode does not authenticate the sender, so the envelope signature
// (context petravault slot-grant v1) is what stops Mallory from creating a
// slot for Bob containing her own master key: a client refuses to open a
// slot unless the granter is in its own trust list (§5.2).

// SlotVersion is the slot payload format version.
const SlotVersion = 1

// Repository key prefixes for slot objects and advisory public-key copies
// (DESIGN.md §8). Copies of public keys in the repository are advisory only;
// trust anchors are client-local (§5.2).
const (
	// SlotPrefix is the repository key prefix for sealed key slots.
	SlotPrefix = "keys/"
	// SlotSuffix is the repository key suffix for sealed key slots.
	SlotSuffix = ".slot"
	// IdentityPrefix is the repository key prefix for advisory public copies.
	IdentityPrefix = "identities/"
	// IdentitySuffix is the repository key suffix for advisory public copies.
	IdentitySuffix = ".pub"
)

// Slot is a verified key-slot grant: the sealed master key with the
// repository, member, and granter it was verified for. Sealed holds
// enc || ciphertext; opening it requires the member's private KEM key.
type Slot struct {
	// RepositoryID binds the slot to one repository (replay across
	// repositories fails closed).
	RepositoryID string
	// Member is the identity the master key was sealed to.
	Member Fingerprint
	// Granter is the identity that signed the grant.
	Granter Fingerprint
	// Sealed is the HPKE enc || ciphertext holding the 32-byte master key.
	Sealed []byte
}

// slotPayload is the signed bytes. Field order is fixed so the sealed bytes
// are deterministic. KEM, KDF, and AEAD name the exact HPKE suite so any
// component can be versioned and migrated without breaking old repositories
// (DESIGN.md §6); mismatches fail closed.
type slotPayload struct {
	Version      int    `json:"version"`
	RepositoryID string `json:"repository_id"`
	Member       string `json:"member"`
	Granter      string `json:"granter"`
	KEM          string `json:"kem"`
	KDF          string `json:"kdf"`
	AEAD         string `json:"aead"`
	Sealed       string `json:"sealed"`
}

// slotEnvelope stores the exact signed payload bytes (base64) with their
// signature. Verification decodes the payload and verifies the signature
// over those bytes; it never re-serializes before verifying.
type slotEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// SlotKey returns the repository key holding fp's sealed slot.
func SlotKey(fp Fingerprint) string {
	return SlotPrefix + fp.String() + SlotSuffix
}

// ParseSlotKey decodes a slot repository key back to its fingerprint.
// Anything outside keys/<fingerprint>.slot is rejected.
func ParseSlotKey(key string) (Fingerprint, error) {
	member, ok := strings.CutPrefix(key, SlotPrefix)
	if !ok {
		return Fingerprint{}, fmt.Errorf("%w: invalid slot key %q: want %q prefix", pverrors.ErrUsage, key, SlotPrefix)
	}
	raw, ok := strings.CutSuffix(member, SlotSuffix)
	if !ok {
		return Fingerprint{}, fmt.Errorf("%w: invalid slot key %q: want %q suffix", pverrors.ErrUsage, key, SlotSuffix)
	}
	fp, err := ParseFingerprint(raw)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("invalid slot key %q: %w", key, err)
	}
	return fp, nil
}

// AdvisoryKey returns the repository key holding fp's advisory public copy
// (identities/<fingerprint>.pub). Copies in the repository are advisory
// only; trust anchors are client-local (DESIGN.md §5.2).
func AdvisoryKey(fp Fingerprint) string {
	return IdentityPrefix + fp.String() + IdentitySuffix
}

// SealSlot seals master to member's KEM public key and signs the grant with
// granter under the slot-grant context. It returns the envelope bytes
// holding the exact signed payload. The master key is used, never stored.
func SealSlot(granter *PrivateIdentity, repositoryID string, member *Identity, master crypto.SecretKey) ([]byte, error) {
	if granter == nil {
		return nil, errors.New("seal slot: granter is nil")
	}
	if member == nil {
		return nil, errors.New("seal slot: member is nil")
	}
	if strings.TrimSpace(repositoryID) == "" {
		return nil, fmt.Errorf("%w: seal slot: repository id is empty", pverrors.ErrUsage)
	}
	sealed, err := crypto.SealMaster(master, member.KEMPublic, repositoryID, member.Fingerprint.String())
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(slotPayload{
		Version:      SlotVersion,
		RepositoryID: repositoryID,
		Member:       member.Fingerprint.String(),
		Granter:      granter.Fingerprint().String(),
		KEM:          crypto.KEMID,
		KDF:          crypto.SlotKDFID,
		AEAD:         crypto.SlotAEADID,
		Sealed:       base64.StdEncoding.EncodeToString(sealed),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal slot: %w", err)
	}
	sig, err := granter.Sign(crypto.ContextSlotGrant, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(slotEnvelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

// VerifySlot verifies the envelope with the granter's public signing key
// and returns the slot. A bad signature wraps ErrBadSignature (exit code 4).
// Trust is the caller's job: use OpenSlotTrusted to resolve the granter
// through the client-local trust list.
func VerifySlot(envBytes []byte, granterSignPub []byte) (*Slot, error) {
	payload, sig, err := parseSlotEnvelope(envBytes)
	if err != nil {
		return nil, err
	}
	slot, err := parseSlotPayload(payload)
	if err != nil {
		return nil, err
	}
	if err := Verify(granterSignPub, crypto.ContextSlotGrant, payload, sig); err != nil {
		return nil, err
	}
	return slot, nil
}

// OpenSlot verifies the envelope with granterSignPub, checks the slot names
// wantRepo and wantMember, and opens the sealed master key with the member's
// private KEM key. Mismatches wrap ErrIntegrity, so a valid slot cannot be
// replayed into a different repository or for a different member.
func OpenSlot(envBytes []byte, wantRepo string, wantMember Fingerprint, memberKEMPriv hpke.PrivateKey, granterSignPub []byte) (crypto.SecretKey, error) {
	slot, err := VerifySlot(envBytes, granterSignPub)
	if err != nil {
		return crypto.SecretKey{}, err
	}
	if err := slot.checkNames(wantRepo, wantMember); err != nil {
		return crypto.SecretKey{}, err
	}
	return crypto.OpenMaster(slot.Sealed, memberKEMPriv, wantRepo, slot.Member.String())
}

// OpenSlotTrusted decrypts the slot, resolves the granter's public signing
// key via lookup applied to the envelope's unverified granter hint, then
// verifies the signature. Lookup failures propagate verbatim so callers can
// return ErrUntrustedSigner for unknown or revoked granters. The hint is
// never trusted: verification with the looked-up key must succeed. The slot
// must name wantRepo and wantMember, and opening requires the member's
// private KEM key.
func OpenSlotTrusted(envBytes []byte, wantRepo string, wantMember Fingerprint, memberKEMPriv hpke.PrivateKey, lookup func(granter string) ([]byte, error)) (crypto.SecretKey, error) {
	if strings.TrimSpace(wantRepo) == "" {
		return crypto.SecretKey{}, fmt.Errorf("%w: open slot: repository id is empty", pverrors.ErrUsage)
	}
	if lookup == nil {
		return crypto.SecretKey{}, errors.New("open slot: lookup is nil")
	}
	payload, _, err := parseSlotEnvelope(envBytes)
	if err != nil {
		return crypto.SecretKey{}, err
	}
	hint, err := parseSlotPayload(payload)
	if err != nil {
		return crypto.SecretKey{}, err
	}
	granterPub, err := lookup(hint.Granter.String())
	if err != nil {
		return crypto.SecretKey{}, err
	}
	return OpenSlot(envBytes, wantRepo, wantMember, memberKEMPriv, granterPub)
}

// checkNames enforces the slot's repository and member bindings.
func (s *Slot) checkNames(wantRepo string, wantMember Fingerprint) error {
	if strings.TrimSpace(wantRepo) == "" {
		return fmt.Errorf("%w: slot repository id is empty", pverrors.ErrUsage)
	}
	if s.RepositoryID != wantRepo {
		return fmt.Errorf("%w: slot names repository %q, want %q", pverrors.ErrIntegrity, s.RepositoryID, wantRepo)
	}
	if !s.Member.Equal(wantMember) {
		return fmt.Errorf("%w: slot names member %s, want %s", pverrors.ErrIntegrity, s.Member.Grouped(), wantMember.Grouped())
	}
	return nil
}

func parseSlotEnvelope(envBytes []byte) (payload, sig []byte, err error) {
	var env slotEnvelope
	if err := json.Unmarshal(envBytes, &env, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, fmt.Errorf("decode slot: %w", err)
	}
	payload, err = base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 {
		return nil, nil, errors.New("decode slot: invalid payload")
	}
	sig, err = base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != SignSignatureSize {
		return nil, nil, fmt.Errorf("decode slot: %w: invalid signature", pverrors.ErrIntegrity)
	}
	return payload, sig, nil
}

func parseSlotPayload(payload []byte) (*Slot, error) {
	var wire slotPayload
	if err := json.Unmarshal(payload, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode slot: %w", err)
	}
	if wire.Version != SlotVersion {
		return nil, fmt.Errorf("decode slot: unsupported version %d: want %d", wire.Version, SlotVersion)
	}
	if strings.TrimSpace(wire.RepositoryID) == "" {
		return nil, fmt.Errorf("%w: slot repository id is empty", pverrors.ErrUsage)
	}
	member, err := ParseFingerprint(wire.Member)
	if err != nil {
		return nil, fmt.Errorf("decode slot: %w", err)
	}
	granter, err := ParseFingerprint(wire.Granter)
	if err != nil {
		return nil, fmt.Errorf("decode slot: %w", err)
	}
	if wire.KEM != crypto.KEMID {
		return nil, fmt.Errorf("%w: slot names kem %q, want %q", pverrors.ErrIntegrity, wire.KEM, crypto.KEMID)
	}
	if wire.KDF != crypto.SlotKDFID {
		return nil, fmt.Errorf("%w: slot names kdf %q, want %q", pverrors.ErrIntegrity, wire.KDF, crypto.SlotKDFID)
	}
	if wire.AEAD != crypto.SlotAEADID {
		return nil, fmt.Errorf("%w: slot names aead %q, want %q", pverrors.ErrIntegrity, wire.AEAD, crypto.SlotAEADID)
	}
	sealed, err := base64.StdEncoding.DecodeString(wire.Sealed)
	if err != nil || len(sealed) == 0 {
		return nil, fmt.Errorf("%w: slot has no sealed key", pverrors.ErrIntegrity)
	}
	return &Slot{
		RepositoryID: wire.RepositoryID,
		Member:       member,
		Granter:      granter,
		Sealed:       sealed,
	}, nil
}

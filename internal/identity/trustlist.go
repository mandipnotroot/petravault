// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"crypto/hpke"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
)

// Sealed trust-list snapshots (DESIGN.md §5.2). Each client may publish its
// own trust view to the repository so a lost local trust store can be rebuilt
// without repeating every out-of-band fingerprint check: the checks happened
// when each member was first added, and the signed record preserves those
// past decisions. It never makes new ones.
//
// The view is HPKE-sealed to the owner's own KEM key before signing, so only
// the owner opens it: the trust graph stays hidden from storage observers
// and ex-members alike, and recovery needs no prior trust. (Sealing to the
// shared master instead would deadlock, since opening that needs the very
// trust being recovered, and ex-members hold the master forever.) A hostile
// repository can withhold or roll back the record but can neither read nor
// alter it. Recovery from a stale list misses recent additions (safe:
// unknown signers fail closed) and recent revocations (unsafe direction), so
// RecoverTrustList reports the export time and callers tell the operator to
// re-confirm revocations.

// TrustListVersion is the trust-list payload format version.
const TrustListVersion = 1

// Repository key prefix and suffix for published trust-list snapshots
// (DESIGN.md §8). Each owner writes only its own key; readers tolerate a
// missing or stale record.
const (
	// TrustListPrefix is the repository key prefix for trust-list snapshots.
	TrustListPrefix = "trust-lists/"
	// TrustListSuffix is the repository key suffix for trust-list snapshots.
	TrustListSuffix = ".json"
)

// trustListPayload is the sealed bytes. Trusted carries base64 public files
// (each re-validated on recovery); Revoked carries base64 revocation
// envelopes (each re-checked against its target on recovery).
type trustListPayload struct {
	Version    int       `json:"version"`
	Owner      string    `json:"owner"`
	ExportedAt time.Time `json:"exported_at"`
	Trusted    []string  `json:"trusted"`
	Revoked    []string  `json:"revoked"`
}

// trustListEnvelope stores the sealed payload bytes (base64) with the
// owner's signature over them. Recovery verifies the signature, opens the
// seal, then parses the payload; it never re-serializes before verifying.
type trustListEnvelope struct {
	Sealed    string `json:"sealed"`
	Signature string `json:"signature"`
}

// TrustListSummary reports what one recovery restored.
type TrustListSummary struct {
	// Owner is the list owner the record was verified for.
	Owner Fingerprint
	// ExportedAt is when the list was published.
	ExportedAt time.Time
	// Trusted counts restored trust entries.
	Trusted int
	// Revoked counts restored revocation records.
	Revoked int
}

// TrustListKey returns the repository key holding fp's published trust list.
func TrustListKey(fp Fingerprint) string {
	return TrustListPrefix + fp.String() + TrustListSuffix
}

// ParseTrustListKey decodes a trust-list repository key back to its owner.
// Anything outside trust-lists/<fingerprint>.json is rejected.
func ParseTrustListKey(key string) (Fingerprint, error) {
	owner, ok := strings.CutPrefix(key, TrustListPrefix)
	if !ok {
		return Fingerprint{}, fmt.Errorf("%w: invalid trust-list key %q: want %q prefix", pverrors.ErrUsage, key, TrustListPrefix)
	}
	raw, ok := strings.CutSuffix(owner, TrustListSuffix)
	if !ok {
		return Fingerprint{}, fmt.Errorf("%w: invalid trust-list key %q: want %q suffix", pverrors.ErrUsage, key, TrustListSuffix)
	}
	fp, err := ParseFingerprint(raw)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("invalid trust-list key %q: %w", key, err)
	}
	return fp, nil
}

// PublishTrustList seals owner's current trust view to the owner's own KEM
// key, signs the seal, and returns the envelope bytes. Every entry is
// snapshotted, revoked or not, so recovery reproduces the full prior view.
// now supplies the export time; nil means time.Now. The owner proves itself
// by signing: possession of the signing key is the authorization, and no
// trust lookup is involved.
func PublishTrustList(owner *PrivateIdentity, trust *TrustStore, now func() time.Time) ([]byte, error) {
	if owner == nil {
		return nil, errors.New("publish trust list: owner is nil")
	}
	if trust == nil {
		return nil, errors.New("publish trust list: trust store is nil")
	}
	if now == nil {
		now = time.Now
	}
	listed, err := trust.List()
	if err != nil {
		return nil, err
	}
	payload := trustListPayload{
		Version:    TrustListVersion,
		Owner:      owner.Fingerprint().String(),
		ExportedAt: now().UTC(),
	}
	for _, id := range listed {
		pub, err := MarshalPublic(&id)
		if err != nil {
			return nil, err
		}
		payload.Trusted = append(payload.Trusted, base64.StdEncoding.EncodeToString(pub))
		revoked, err := trust.IsRevoked(id.Fingerprint)
		if err != nil {
			return nil, err
		}
		if !revoked {
			continue
		}
		env, err := trust.RevocationEnvelope(id.Fingerprint)
		if err != nil {
			return nil, err
		}
		payload.Revoked = append(payload.Revoked, base64.StdEncoding.EncodeToString(env))
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal trust list: %w", err)
	}
	sealed, err := sealTrustList(raw, owner.Public.KEMPublic, owner.Fingerprint())
	if err != nil {
		return nil, err
	}
	sig, err := owner.Sign(crypto.ContextTrustList, sealed)
	if err != nil {
		return nil, err
	}
	return json.Marshal(trustListEnvelope{
		Sealed:    base64.StdEncoding.EncodeToString(sealed),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

// RecoverTrustList verifies the envelope with the owner's public signing key,
// opens the seal with the owner's KEM private key, and restores the entries
// into store. The payload must name the owner's fingerprint, so adopting
// anyone else's list is rejected: recovery restores past decisions without
// making new ones. A bad signature wraps ErrBadSignature (exit code 4).
// Every trusted entry is re-validated (fingerprint recomputed) and every
// revocation envelope is verified against the restored keys and re-checked
// against its target before storing.
func RecoverTrustList(envBytes []byte, owner *PrivateIdentity, store *TrustStore) (*TrustListSummary, error) {
	if owner == nil {
		return nil, errors.New("recover trust list: owner is nil")
	}
	if store == nil {
		return nil, errors.New("recover trust list: trust store is nil")
	}
	sealed, sig, err := parseTrustListEnvelope(envBytes)
	if err != nil {
		return nil, err
	}
	if err := Verify(owner.Public.SignPublic, crypto.ContextTrustList, sealed, sig); err != nil {
		return nil, err
	}
	raw, err := openTrustList(sealed, owner.KEMPrivate(), owner.Fingerprint())
	if err != nil {
		return nil, err
	}
	list, err := parseTrustListPayload(raw)
	if err != nil {
		return nil, err
	}
	if !list.owner.Equal(owner.Fingerprint()) {
		return nil, fmt.Errorf("%w: trust list names owner %s, want %s", pverrors.ErrIntegrity, list.owner.Grouped(), owner.Fingerprint().Grouped())
	}
	restored := make(map[string][]byte, len(list.trusted))
	for _, raw := range list.trusted {
		pub, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: trust list holds a bad identity", pverrors.ErrIntegrity)
		}
		id, err := ParsePublic(pub)
		if err != nil {
			return nil, fmt.Errorf("recover trust list: %w", err)
		}
		if err := store.Add(id); err != nil {
			return nil, fmt.Errorf("recover trust list: %w", err)
		}
		restored[id.Fingerprint.String()] = id.SignPublic
	}
	for _, raw := range list.revoked {
		env, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(env) == 0 {
			return nil, fmt.Errorf("%w: trust list holds a bad revocation", pverrors.ErrIntegrity)
		}
		rev, err := decodeRevocationEnvelope(env)
		if err != nil {
			return nil, fmt.Errorf("recover trust list: %w", err)
		}
		signerPub, ok := restored[rev.Signer.String()]
		if !ok {
			return nil, fmt.Errorf("%w: trust list revocation signed by unknown %s", pverrors.ErrUntrustedSigner, rev.Signer.Grouped())
		}
		if _, err := VerifyRevocation(env, signerPub); err != nil {
			return nil, fmt.Errorf("recover trust list: %w", err)
		}
		if err := store.AddRevocation(rev.Fingerprint, env); err != nil {
			return nil, fmt.Errorf("recover trust list: %w", err)
		}
	}
	return &TrustListSummary{
		Owner:      list.owner,
		ExportedAt: list.exportedAt,
		Trusted:    len(list.trusted),
		Revoked:    len(list.revoked),
	}, nil
}

// parsedTrustList is a decoded trust-list payload.
type parsedTrustList struct {
	owner      Fingerprint
	exportedAt time.Time
	trusted    []string
	revoked    []string
}

func parseTrustListEnvelope(envBytes []byte) (sealed, sig []byte, err error) {
	var env trustListEnvelope
	if err := json.Unmarshal(envBytes, &env, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, fmt.Errorf("decode trust list: %w", err)
	}
	sealed, err = base64.StdEncoding.DecodeString(env.Sealed)
	if err != nil || len(sealed) == 0 {
		return nil, nil, fmt.Errorf("decode trust list: %w: invalid seal", pverrors.ErrIntegrity)
	}
	sig, err = base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != SignSignatureSize {
		return nil, nil, fmt.Errorf("decode trust list: %w: invalid signature", pverrors.ErrIntegrity)
	}
	return sealed, sig, nil
}

func parseTrustListPayload(payload []byte) (*parsedTrustList, error) {
	var wire trustListPayload
	if err := json.Unmarshal(payload, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode trust list: %w", err)
	}
	if wire.Version != TrustListVersion {
		return nil, fmt.Errorf("decode trust list: unsupported version %d: want %d", wire.Version, TrustListVersion)
	}
	owner, err := ParseFingerprint(wire.Owner)
	if err != nil {
		return nil, fmt.Errorf("decode trust list: %w", err)
	}
	if wire.ExportedAt.IsZero() {
		return nil, errors.New("decode trust list: exported_at is missing")
	}
	return &parsedTrustList{
		owner:      owner,
		exportedAt: wire.ExportedAt.UTC(),
		trusted:    wire.Trusted,
		revoked:    wire.Revoked,
	}, nil
}

// trustListInfoContext separates trust-list HPKE seals from key-slot seals:
// same suite, different purpose, so a seal for one never opens as the other.
const trustListInfoContext = "petravault trust-list v1"

// trustListInfo binds a sealed trust list to its owner with length-prefixed
// fields, so the encoding is unambiguous. Trust is machine-wide rather than
// repo-scoped, so no repository id is bound: the same recovered view applies
// wherever this machine works. A list sealed for anyone else fails closed.
func trustListInfo(owner Fingerprint) []byte {
	fields := [][]byte{[]byte(trustListInfoContext), owner[:]}
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

// sealTrustList HPKE-seals the payload to the owner's KEM public key with the
// trust-list info string. The recipient key is validated for well-formedness,
// not just length.
func sealTrustList(payload, recipientKEMPublic []byte, owner Fingerprint) ([]byte, error) {
	pub, err := crypto.SlotKEM().NewPublicKey(recipientKEMPublic)
	if err != nil {
		return nil, fmt.Errorf("seal trust list: invalid recipient key: %w", err)
	}
	return hpke.Seal(pub, crypto.SlotKDF(), crypto.SlotAEAD(), trustListInfo(owner), payload)
}

// openTrustList opens a seal produced by sealTrustList. Any HPKE failure
// wraps ErrAuthFailed and yields no plaintext: info binds the owner, so a
// list sealed for anyone else fails closed.
func openTrustList(sealed []byte, recipientKEMPriv hpke.PrivateKey, owner Fingerprint) ([]byte, error) {
	if recipientKEMPriv == nil {
		return nil, fmt.Errorf("%w: open trust list: recipient key is nil", pverrors.ErrUsage)
	}
	raw, err := hpke.Open(recipientKEMPriv, crypto.SlotKDF(), crypto.SlotAEAD(), trustListInfo(owner), sealed)
	if err != nil {
		return nil, fmt.Errorf("open trust list: %w", pverrors.ErrAuthFailed)
	}
	return raw, nil
}

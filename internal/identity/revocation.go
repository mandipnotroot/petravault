// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
)

// RevocationVersion is the revocation payload format version.
const RevocationVersion = 1

// MaxReasonLength bounds revocation reasons at creation time.
const MaxReasonLength = 1024

// Revocation disqualifies a key from verifying new snapshots (DESIGN.md
// §5.2). It is signed by another trusted identity, or by the key itself for
// self-revocation. Revoking stops trust in new signatures; it does not
// un-share a master key the member already held (§4.6).
type Revocation struct {
	// Fingerprint is the revoked identity.
	Fingerprint Fingerprint
	// Reason documents why the key was revoked.
	Reason string
	// CreatedAt is the revocation time in UTC.
	CreatedAt time.Time
	// Signer is the revoking identity.
	Signer Fingerprint
}

// revocationPayload is the signed bytes. Field order is fixed so the sealed
// bytes are deterministic.
type revocationPayload struct {
	Version     int       `json:"version"`
	Fingerprint string    `json:"fingerprint"`
	Reason      string    `json:"reason"`
	CreatedAt   time.Time `json:"created_at"`
	Signer      string    `json:"signer"`
}

// revocationEnvelope stores the exact signed payload bytes (base64) with
// their signature. Verification decodes the payload and verifies the
// signature over those bytes; it never re-serializes before verifying.
type revocationEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// SignRevocation creates a revocation of target signed by signer under the
// revocation context and returns the envelope bytes. now supplies the time;
// nil means time.Now. The reason must be non-empty.
func SignRevocation(signer *PrivateIdentity, target Fingerprint, reason string, now func() time.Time) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("sign revocation: signer is nil")
	}
	if reason == "" || len(reason) > MaxReasonLength {
		return nil, fmt.Errorf("%w: invalid revocation reason: want 1..%d chars", pverrors.ErrUsage, MaxReasonLength)
	}
	if now == nil {
		now = time.Now
	}
	created := now().UTC()
	if created.IsZero() {
		return nil, errors.New("sign revocation: creation time is missing")
	}
	payload, err := json.Marshal(revocationPayload{
		Version:     RevocationVersion,
		Fingerprint: target.String(),
		Reason:      reason,
		CreatedAt:   created,
		Signer:      signer.Fingerprint().String(),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal revocation: %w", err)
	}
	sig, err := signer.Sign(crypto.ContextRevocation, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(revocationEnvelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

// VerifyRevocation verifies the envelope with the signer's public signing
// key and returns the revocation. The signer must be trusted (or be the
// target itself for self-revocation); resolving the key is the caller's job.
// A bad signature wraps ErrBadSignature.
func VerifyRevocation(envBytes []byte, signerSignPub []byte) (*Revocation, error) {
	rev, payload, sig, err := parseRevocationEnvelope(envBytes)
	if err != nil {
		return nil, err
	}
	if err := Verify(signerSignPub, crypto.ContextRevocation, payload, sig); err != nil {
		return nil, err
	}
	return rev, nil
}

// decodeRevocationEnvelope parses the envelope and payload without verifying
// the signature. TrustStore.AddRevocation uses it to check the envelope names
// the expected target; callers must still verify before trusting.
func decodeRevocationEnvelope(envBytes []byte) (*Revocation, error) {
	rev, _, _, err := parseRevocationEnvelope(envBytes)
	return rev, err
}

// DecodeRevocation parses a revocation envelope without verifying its
// signature. Recovery paths use it to resolve the signer key from the
// restored trust view, then verify with VerifyRevocation before storing.
// Never trust the result without verifying.
func DecodeRevocation(envBytes []byte) (*Revocation, error) {
	return decodeRevocationEnvelope(envBytes)
}

func parseRevocationEnvelope(envBytes []byte) (*Revocation, []byte, []byte, error) {
	var env revocationEnvelope
	if err := json.Unmarshal(envBytes, &env, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, nil, fmt.Errorf("decode revocation: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 {
		return nil, nil, nil, errors.New("decode revocation: invalid payload")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != SignSignatureSize {
		return nil, nil, nil, fmt.Errorf("decode revocation: %w: invalid signature", pverrors.ErrIntegrity)
	}
	var wire revocationPayload
	if err := json.Unmarshal(payload, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, nil, fmt.Errorf("decode revocation: %w", err)
	}
	if wire.Version != RevocationVersion {
		return nil, nil, nil, fmt.Errorf("decode revocation: unsupported version %d: want %d", wire.Version, RevocationVersion)
	}
	fp, err := ParseFingerprint(wire.Fingerprint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode revocation: %w", err)
	}
	signer, err := ParseFingerprint(wire.Signer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode revocation: %w", err)
	}
	if wire.CreatedAt.IsZero() {
		return nil, nil, nil, errors.New("decode revocation: created_at is missing")
	}
	return &Revocation{
		Fingerprint: fp,
		Reason:      wire.Reason,
		CreatedAt:   wire.CreatedAt.UTC(),
		Signer:      signer,
	}, payload, sig, nil
}

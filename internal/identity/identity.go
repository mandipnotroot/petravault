// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package identity implements Petravault's local identities, BLAKE3
// fingerprints, and ML-DSA-65 signing (DESIGN.md §5). An identity holds a
// signing key (ML-DSA-65) and a KEM key (X-Wing) as separate keypairs, so
// compromising one does not expose the other. The fingerprint is BLAKE3 over
// a length-prefixed encoding of both public keys under a fixed
// domain-separation context, displayed in grouped base32 for reading aloud.
// Private keys live on the client, never in the repository (§4.4); public
// copies in the repository are advisory only and trust anchors are
// client-local (§5.2).
package identity

import (
	"bytes"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
)

// Version is the public-identity file format version.
const Version = 1

// FingerprintContext separates identity fingerprints from every other hash
// (DESIGN.md §5). It is length-prefixed into the hashed input, so the
// encoding is unambiguous.
const FingerprintContext = "petravault identity v1"

// Key sizes. The ML-DSA-65 sizes come from the standard library; the X-Wing
// sizes are the HPKE MLKEM768X25519 wire sizes, pinned here and in tests so a
// library change is a detected migration, not silent breakage.
const (
	// SignPublicSize is the ML-DSA-65 public key encoding length.
	SignPublicSize = mldsa.MLDSA65PublicKeySize
	// SignSeedSize is the ML-DSA-65 private key seed length.
	SignSeedSize = mldsa.PrivateKeySize
	// SignSignatureSize is the ML-DSA-65 signature length.
	SignSignatureSize = mldsa.MLDSA65SignatureSize
	// KEMPublicSize is the X-Wing public key encoding length.
	KEMPublicSize = 1216
	// KEMPrivateSize is the X-Wing private key encoding length.
	KEMPrivateSize = 32
)

// Scheme identifiers recorded in public files. They must stay identical to
// the crypto suite in crypto (DESIGN.md §6); renaming is a breaking change.
const (
	// SignatureScheme names the signature scheme.
	SignatureScheme = crypto.SignatureID
	// KEMID names the hybrid KEM.
	KEMID = crypto.KEMID
)

// MaxNameLength bounds identity names to keep public files small.
const MaxNameLength = 256

// Fingerprint is the BLAKE3 hash of both public keys (DESIGN.md §5). It is
// public and safe to display, log, and include in errors.
type Fingerprint [32]byte

// Equal reports whether f and other hold the same fingerprint.
func (f Fingerprint) Equal(other Fingerprint) bool {
	return f == other
}

// base32NoPad encodes fingerprints without padding.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// String returns the canonical machine form: lowercase unpadded base32
// (52 characters). File names and JSON store this form.
func (f Fingerprint) String() string {
	return strings.ToLower(base32NoPad.EncodeToString(f[:]))
}

// Grouped returns the human form: String grouped in fours separated by
// dashes (13 groups, DESIGN.md §5 "grouped base32"). The CLI always shows
// this form.
func (f Fingerprint) Grouped() string {
	s := f.String()
	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i:min(i+4, len(s))])
	}
	return b.String()
}

// ParseFingerprint parses a fingerprint in any accepted form: lowercase or
// uppercase base32 with or without dashes and spaces, hex (64 characters),
// each with an optional "b3:" prefix. Abbreviated fingerprints are rejected:
// callers must type the full value, so acceptance is always explicit
// (DESIGN.md §5.1). Non-canonical base32 is rejected for the same reason:
// the final character carries a single significant bit, so several
// spellings decode to the same bytes, and only the canonical one is valid.
// A malformed value wraps ErrUsage.
func ParseFingerprint(s string) (Fingerprint, error) {
	t := strings.TrimSpace(s)
	if len(t) >= 3 && strings.EqualFold(t[:3], "b3:") {
		t = t[3:]
	}
	t = strings.ReplaceAll(t, "-", "")
	t = strings.ReplaceAll(t, " ", "")
	t = strings.ReplaceAll(t, "\t", "")
	switch len(t) {
	case 64:
		raw, err := hex.DecodeString(t)
		if err != nil || len(raw) != 32 {
			return Fingerprint{}, fmt.Errorf("%w: invalid fingerprint %q: want 52 base32 or 64 hex chars", pverrors.ErrUsage, s)
		}
		var f Fingerprint
		copy(f[:], raw)
		return f, nil
	case 52:
		upper := strings.ToUpper(t)
		raw, err := base32NoPad.DecodeString(upper)
		if err != nil || len(raw) != 32 {
			return Fingerprint{}, fmt.Errorf("%w: invalid fingerprint %q: want 52 base32 or 64 hex chars", pverrors.ErrUsage, s)
		}
		if base32NoPad.EncodeToString(raw) != upper {
			return Fingerprint{}, fmt.Errorf("%w: invalid fingerprint %q: non-canonical base32", pverrors.ErrUsage, s)
		}
		var f Fingerprint
		copy(f[:], raw)
		return f, nil
	default:
		return Fingerprint{}, fmt.Errorf("%w: invalid fingerprint %q: want 52 base32 or 64 hex chars", pverrors.ErrUsage, s)
	}
}

// ComputeFingerprint returns the fingerprint for the given public keys. Keys
// of any other length are rejected; callers must validate before trusting.
func ComputeFingerprint(signPub, kemPub []byte) (Fingerprint, error) {
	if len(signPub) != SignPublicSize {
		return Fingerprint{}, fmt.Errorf("invalid signing public key length %d: want %d", len(signPub), SignPublicSize)
	}
	if len(kemPub) != KEMPublicSize {
		return Fingerprint{}, fmt.Errorf("invalid KEM public key length %d: want %d", len(kemPub), KEMPublicSize)
	}
	var buf bytes.Buffer
	writeField(&buf, []byte(FingerprintContext))
	writeField(&buf, signPub)
	writeField(&buf, kemPub)
	return Fingerprint(crypto.Sum256(buf.Bytes())), nil
}

func writeField(buf *bytes.Buffer, b []byte) {
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], uint64(len(b)))
	buf.Write(prefix[:])
	buf.Write(b)
}

// Sign signs message with the given private key under context. Each use has
// its own context string (DESIGN.md §4.3), so a signature for one purpose
// never verifies for another. The context must be non-empty.
func Sign(priv *mldsa.PrivateKey, context string, message []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("sign: private key is nil")
	}
	if context == "" {
		return nil, errors.New("sign: context is empty")
	}
	if len(context) > 255 {
		return nil, errors.New("sign: context too long")
	}
	sig, err := priv.Sign(nil, message, &mldsa.Options{Context: context})
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return sig, nil
}

// Verify reports whether sig is a valid signature of message by signPub under
// context. Malformed inputs return a plain error; a bad signature wraps
// ErrBadSignature (exit code 4) and yields no other detail.
func Verify(signPub []byte, context string, message, sig []byte) error {
	if context == "" {
		return errors.New("verify: context is empty")
	}
	if len(signPub) != SignPublicSize {
		return fmt.Errorf("verify: invalid public key length %d: want %d", len(signPub), SignPublicSize)
	}
	if len(sig) != SignSignatureSize {
		return fmt.Errorf("verify signature: %w", pverrors.ErrBadSignature)
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), signPub)
	if err != nil {
		return fmt.Errorf("verify: invalid public key: %w", err)
	}
	if err := mldsa.Verify(pk, message, sig, &mldsa.Options{Context: context}); err != nil {
		return fmt.Errorf("verify signature: %w", pverrors.ErrBadSignature)
	}
	return nil
}

// GenerateKEM creates a fresh X-Wing key pair.
func GenerateKEM() (hpke.PrivateKey, error) {
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate KEM key: %w", err)
	}
	return priv, nil
}

// Identity is the public half of a local identity (DESIGN.md §5): both
// public keys with metadata. The fingerprint is recomputed on every parse,
// never trusted from storage.
type Identity struct {
	Fingerprint Fingerprint
	Name        string
	CreatedAt   time.Time
	SignPublic  []byte
	KEMPublic   []byte
}

// PrivateIdentity pairs an Identity with its private keys. It never prints
// itself, so key material cannot leak through logs or errors.
type PrivateIdentity struct {
	Public   Identity
	signPriv *mldsa.PrivateKey
	kemPriv  hpke.PrivateKey
}

// Fingerprint returns the identity fingerprint.
func (p *PrivateIdentity) Fingerprint() Fingerprint {
	return p.Public.Fingerprint
}

// Sign signs message under context with the signing private key.
func (p *PrivateIdentity) Sign(context string, message []byte) ([]byte, error) {
	return Sign(p.signPriv, context, message)
}

// KEMPrivate returns the KEM private key. The caller must not retain it
// longer than needed.
func (p *PrivateIdentity) KEMPrivate() hpke.PrivateKey {
	return p.kemPriv
}

// Zero detaches the private key material best effort (DESIGN.md §4.4): the
// signing key struct is zero-assigned and the KEM key reference is dropped.
// Go cannot guarantee no copies survive in garbage-collected memory, and the
// KEM key is an interface whose concrete storage the standard library owns,
// so this bounds key lifetime rather than proving erasure; callers defer it
// at the end of each use.
func (p *PrivateIdentity) Zero() {
	if p == nil {
		return
	}
	if p.signPriv != nil {
		*p.signPriv = mldsa.PrivateKey{}
	}
	p.kemPriv = nil
}

// String redacts private key material.
func (PrivateIdentity) String() string {
	return "[redacted]"
}

// GoString redacts private key material.
func (PrivateIdentity) GoString() string {
	return "[redacted]"
}

// LogValue redacts private key material in structured logs.
func (PrivateIdentity) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

// publicFile is the wire form of an Identity: the `.pub` export, the
// keystore public.json, and the trust-store trusted-keys entry share it.
type publicFile struct {
	Version         int       `json:"version"`
	Name            string    `json:"name"`
	CreatedAt       time.Time `json:"created_at"`
	SignatureScheme string    `json:"signature_scheme"`
	KEM             string    `json:"kem"`
	SignPublic      string    `json:"sign_public"`
	KEMPublic       string    `json:"kem_public"`
	Fingerprint     string    `json:"fingerprint"`
}

// MarshalPublic encodes id as a public file. Times are UTC.
func MarshalPublic(id *Identity) ([]byte, error) {
	if id == nil {
		return nil, errors.New("marshal identity: identity is nil")
	}
	return json.Marshal(publicFile{
		Version:         Version,
		Name:            id.Name,
		CreatedAt:       id.CreatedAt.UTC(),
		SignatureScheme: SignatureScheme,
		KEM:             KEMID,
		SignPublic:      base64.StdEncoding.EncodeToString(id.SignPublic),
		KEMPublic:       base64.StdEncoding.EncodeToString(id.KEMPublic),
		Fingerprint:     id.Fingerprint.String(),
	})
}

// ParsePublic decodes and validates a public file. Unknown fields are
// rejected, key encodings are checked for well-formedness (not just length),
// and the fingerprint is recomputed and compared: a mismatch wraps
// ErrIntegrity and never yields a usable identity.
func ParsePublic(data []byte) (*Identity, error) {
	var wire publicFile
	if err := json.Unmarshal(data, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	if wire.Version != Version {
		return nil, fmt.Errorf("decode identity: unsupported version %d: want %d", wire.Version, Version)
	}
	if wire.SignatureScheme != SignatureScheme {
		return nil, fmt.Errorf("decode identity: signature scheme %q: want %q", wire.SignatureScheme, SignatureScheme)
	}
	if wire.KEM != KEMID {
		return nil, fmt.Errorf("decode identity: kem %q: want %q", wire.KEM, KEMID)
	}
	if wire.Name == "" || len(wire.Name) > MaxNameLength {
		return nil, fmt.Errorf("decode identity: invalid name length %d: want 1..%d", len(wire.Name), MaxNameLength)
	}
	if wire.CreatedAt.IsZero() {
		return nil, errors.New("decode identity: created_at is missing")
	}
	signPub, err := base64.StdEncoding.DecodeString(wire.SignPublic)
	if err != nil || len(signPub) != SignPublicSize {
		return nil, errors.New("decode identity: invalid signing public key")
	}
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), signPub); err != nil {
		return nil, fmt.Errorf("decode identity: invalid signing public key: %w", err)
	}
	kemPub, err := base64.StdEncoding.DecodeString(wire.KEMPublic)
	if err != nil || len(kemPub) != KEMPublicSize {
		return nil, errors.New("decode identity: invalid KEM public key")
	}
	if _, err := hpke.MLKEM768X25519().NewPublicKey(kemPub); err != nil {
		return nil, fmt.Errorf("decode identity: invalid KEM public key: %w", err)
	}
	want, err := ComputeFingerprint(signPub, kemPub)
	if err != nil {
		return nil, err
	}
	got, err := ParseFingerprint(wire.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		return nil, fmt.Errorf("decode identity: %w: fingerprint mismatch", pverrors.ErrIntegrity)
	}
	return &Identity{
		Fingerprint: want,
		Name:        wire.Name,
		CreatedAt:   wire.CreatedAt.UTC(),
		SignPublic:  signPub,
		KEMPublic:   kemPub,
	}, nil
}

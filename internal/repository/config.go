// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	json "encoding/json/v2"

	"petravault/internal/chunking"
	"petravault/internal/crypto"
	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
)

// Signed repository configuration (DESIGN.md §8). The config travels with
// the repository as a signed envelope at config/repository.json and is
// verified against the client's trust list before it is parsed or used. A
// client refuses a config with an invalid or untrusted signature and rejects
// any manifest naming a suite or chunking algorithm other than those in the
// signed config, so a hostile repository cannot downgrade the suite or
// quietly change parameters. Changing the config re-signs it.

// ConfigVersion is the repository config format version.
const ConfigVersion = 1

// ConfigKey is the repository object holding the signed config envelope.
const ConfigKey = "config/repository.json"

// DefaultPackSize is the default pack target (~16 MiB, DESIGN.md §8).
const DefaultPackSize = 16 << 20

// Signer signs repository configs with ML-DSA-65 (DESIGN.md §4.3, §6). The
// method set matches identity.PrivateIdentity without importing it.
type Signer interface {
	// Sign signs message under context.
	Sign(context string, message []byte) ([]byte, error)
}

// Config is the signed repository configuration. Chunking parameters are
// frozen at creation: switching algorithms later only costs dedup
// efficiency, and existing snapshots always restore (§3.1). ECC names the
// default erasure profile for objects written from now on; each sidecar
// records its own parameters, so changing it never breaks old objects
// (§4.5, phase 7).
type Config struct {
	Version                int       `json:"version"`
	RepositoryID           string    `json:"repository_id"`
	CreatedAt              time.Time `json:"created_at"`
	CryptoSuite            string    `json:"crypto_suite"`
	KEM                    string    `json:"kem"`
	Signature              string    `json:"signature"`
	Hash                   string    `json:"hash"`
	KDF                    string    `json:"kdf"`
	ChunkingAlgorithm      string    `json:"chunking_algorithm"`
	ChunkingLibrary        string    `json:"chunking_library"`
	ChunkingLibraryVersion string    `json:"chunking_library_version"`
	ChunkMin               int       `json:"chunk_min"`
	ChunkAverage           int       `json:"chunk_average"`
	ChunkMax               int       `json:"chunk_max"`
	PackSize               int       `json:"pack_size"`
	ECC                    string    `json:"ecc"`
}

// configEnvelope stores the exact signed config payload bytes (base64) with
// their signature. Verification decodes the payload and verifies over those
// bytes; it never re-serializes before verifying.
type configEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// GenerateID creates a random repository ID: 32 bytes from crypto/rand hex
// encoded. It is signed into every manifest so a valid snapshot cannot be
// replayed into a different repository (DESIGN.md §9).
func GenerateID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate repository id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// NewConfig builds a repository config with the frozen suite identifiers
// from crypto and the given chunking, pack, and ECC settings. Zero chunking
// selects the defaults; non-positive pack size selects DefaultPackSize;
// empty ECC selects "medium". Now supplies the creation time; nil means
// time.Now.
func NewConfig(repositoryID string, chunk chunking.Params, packSize int, ecc string, now func() time.Time) (Config, error) {
	if strings.TrimSpace(repositoryID) == "" {
		return Config{}, fmt.Errorf("%w: repository id is empty", pverrors.ErrUsage)
	}
	if chunk == (chunking.Params{}) {
		chunk = chunking.DefaultParams()
	}
	if err := chunk.Validate(); err != nil {
		return Config{}, fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
	}
	if packSize <= 0 {
		packSize = DefaultPackSize
	}
	if packSize < 1<<20 || packSize > 1<<30 {
		return Config{}, fmt.Errorf("%w: invalid pack size %d: want 1MiB..1GiB", pverrors.ErrUsage, packSize)
	}
	if strings.TrimSpace(ecc) == "" {
		ecc = "medium"
	}
	if err := validateECC(ecc); err != nil {
		return Config{}, err
	}
	if now == nil {
		now = time.Now
	}
	created := now().UTC()
	if created.IsZero() {
		return Config{}, errors.New("create repository config: creation time is missing")
	}
	cfg := Config{
		Version:                ConfigVersion,
		RepositoryID:           repositoryID,
		CreatedAt:              created,
		CryptoSuite:            crypto.SuiteID,
		KEM:                    crypto.KEMID,
		Signature:              crypto.SignatureID,
		Hash:                   crypto.HashID,
		KDF:                    crypto.KDFID,
		ChunkingAlgorithm:      crypto.ChunkingID,
		ChunkingLibrary:        chunking.Library,
		ChunkingLibraryVersion: chunking.LibraryVersion,
		ChunkMin:               chunk.MinSize,
		ChunkAverage:           chunk.AverageSize,
		ChunkMax:               chunk.MaxSize,
		PackSize:               packSize,
		ECC:                    ecc,
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks c without verifying a signature. Unknown suite or
// algorithm names fail closed so a hostile repository cannot downgrade them.
func (c Config) Validate() error {
	if c.Version != ConfigVersion {
		return fmt.Errorf("repository config has version %d, want %d", c.Version, ConfigVersion)
	}
	if strings.TrimSpace(c.RepositoryID) == "" {
		return fmt.Errorf("%w: repository config repository id is empty", pverrors.ErrUsage)
	}
	if c.CreatedAt.IsZero() {
		return errors.New("repository config created_at is missing")
	}
	if c.CryptoSuite != crypto.SuiteID {
		return fmt.Errorf("%w: repository config names crypto suite %q, want %q", pverrors.ErrIntegrity, c.CryptoSuite, crypto.SuiteID)
	}
	if c.KEM != crypto.KEMID {
		return fmt.Errorf("%w: repository config names kem %q, want %q", pverrors.ErrIntegrity, c.KEM, crypto.KEMID)
	}
	if c.Signature != crypto.SignatureID {
		return fmt.Errorf("%w: repository config names signature %q, want %q", pverrors.ErrIntegrity, c.Signature, crypto.SignatureID)
	}
	if c.Hash != crypto.HashID {
		return fmt.Errorf("%w: repository config names hash %q, want %q", pverrors.ErrIntegrity, c.Hash, crypto.HashID)
	}
	if c.KDF != crypto.KDFID {
		return fmt.Errorf("%w: repository config names kdf %q, want %q", pverrors.ErrIntegrity, c.KDF, crypto.KDFID)
	}
	if c.ChunkingAlgorithm != crypto.ChunkingID {
		return fmt.Errorf("%w: repository config names chunking %q, want %q", pverrors.ErrIntegrity, c.ChunkingAlgorithm, crypto.ChunkingID)
	}
	if c.ChunkingLibrary != chunking.Library {
		return fmt.Errorf("repository config names chunking library %q, want %q", c.ChunkingLibrary, chunking.Library)
	}
	if c.ChunkingLibraryVersion != chunking.LibraryVersion {
		return fmt.Errorf("repository config names chunking library version %q, want %q", c.ChunkingLibraryVersion, chunking.LibraryVersion)
	}
	if err := (chunking.Params{MinSize: c.ChunkMin, AverageSize: c.ChunkAverage, MaxSize: c.ChunkMax}).Validate(); err != nil {
		return fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
	}
	if c.PackSize < 1<<20 || c.PackSize > 1<<30 {
		return fmt.Errorf("%w: invalid pack size %d: want 1MiB..1GiB", pverrors.ErrUsage, c.PackSize)
	}
	if err := validateECC(c.ECC); err != nil {
		return err
	}
	return nil
}

// Marshal returns the deterministic config payload bytes.
func (c Config) Marshal() ([]byte, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal repository config: %w", err)
	}
	return raw, nil
}

// Sign signs the config payload under the repository-config context and
// returns the envelope bytes.
func SignConfig(signer Signer, cfg Config) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("sign repository config: signer is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	payload, err := cfg.Marshal()
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(crypto.ContextRepoConfig, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(configEnvelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

// VerifyConfig verifies the envelope with signPub and returns the config
// with the exact signed payload bytes. A bad signature wraps
// ErrBadSignature.
func VerifyConfig(envBytes, signPub []byte) (Config, []byte, error) {
	payload, sig, err := decodeConfigEnvelope(envBytes)
	if err != nil {
		return Config{}, nil, err
	}
	if len(signPub) != mldsa.MLDSA65PublicKeySize {
		return Config{}, nil, fmt.Errorf("verify repository config: invalid public key length %d: want %d", len(signPub), mldsa.MLDSA65PublicKeySize)
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), signPub)
	if err != nil {
		return Config{}, nil, fmt.Errorf("verify repository config: invalid public key: %w", err)
	}
	if err := mldsa.Verify(pk, payload, sig, &mldsa.Options{Context: crypto.ContextRepoConfig}); err != nil {
		return Config{}, nil, fmt.Errorf("verify repository config: %w", pverrors.ErrBadSignature)
	}
	var cfg Config
	if err := json.Unmarshal(payload, &cfg, json.RejectUnknownMembers(true)); err != nil {
		return Config{}, nil, fmt.Errorf("decode repository config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, nil, err
	}
	return cfg, payload, nil
}

// WriteConfig signs cfg and stores it at ConfigKey. Re-signing after a
// settings change overwrites atomically via PutObject.
func WriteConfig(ctx context.Context, repo Repository, signer Signer, cfg Config) error {
	if repo == nil {
		return errors.New("write repository config: repository is nil")
	}
	envBytes, err := SignConfig(signer, cfg)
	if err != nil {
		return err
	}
	if err := repo.PutObject(ctx, ConfigKey, bytes.NewReader(envBytes)); err != nil {
		return fmt.Errorf("write repository config: %w", err)
	}
	return nil
}

// ReadConfig returns the verified config, trying each trusted public key in
// sorted fingerprint order so the result is deterministic. Trusted maps
// fingerprint strings to ML-DSA-65 public keys from the client-local trust
// list. No key verifying wraps ErrUntrustedSigner: a hostile repository
// cannot forge a config and cannot add trust by editing repository-side
// copies. The returned string names the signing fingerprint.
func ReadConfig(ctx context.Context, repo Repository, trusted map[string][]byte) (Config, string, error) {
	if repo == nil {
		return Config{}, "", errors.New("read repository config: repository is nil")
	}
	if len(trusted) == 0 {
		return Config{}, "", fmt.Errorf("%w: no trusted keys", pverrors.ErrUntrustedSigner)
	}
	envBytes, err := ReadObject(ctx, repo, ConfigKey)
	if err != nil {
		return Config{}, "", fmt.Errorf("read repository config: %w", err)
	}
	// Decode once so corrupt envelopes report integrity without depending
	// on trust contents.
	if _, _, err := decodeConfigEnvelope(envBytes); err != nil {
		return Config{}, "", err
	}
	for _, fp := range slices.Sorted(slices.Values(sliceKeys(trusted))) {
		cfg, _, err := VerifyConfig(envBytes, trusted[fp])
		if err == nil {
			return cfg, fp, nil
		}
		// Only signature mismatches fall through to the next key;
		// structural damage fails fast.
		if !errors.Is(err, pverrors.ErrBadSignature) {
			return Config{}, "", err
		}
	}
	return Config{}, "", fmt.Errorf("%w: repository config signature is not trusted", pverrors.ErrUntrustedSigner)
}

func sliceKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func decodeConfigEnvelope(envBytes []byte) (payload, sig []byte, err error) {
	var env configEnvelope
	if err := json.Unmarshal(envBytes, &env, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, fmt.Errorf("decode repository config: %w", err)
	}
	payload, err = base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 {
		return nil, nil, errors.New("decode repository config: invalid payload")
	}
	sig, err = base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != mldsa.MLDSA65SignatureSize {
		return nil, nil, fmt.Errorf("decode repository config: %w: invalid signature", pverrors.ErrIntegrity)
	}
	return payload, sig, nil
}

// validateECC accepts off, a named profile, or a custom percentage and
// derives its shard counts with integer math (DESIGN.md §4.5). Out-of-range
// percentages and shard combinations beyond the Reed-Solomon limit fail
// closed as usage errors.
func validateECC(s string) error {
	if _, err := erasure.Parse(s); err != nil {
		return err
	}
	return nil
}

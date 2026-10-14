// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package manifest implements signed snapshot manifests (DESIGN.md §9).
// A manifest is a JSON document listing the files of one backup run. Its
// snapshot ID is the BLAKE3 hash of the exact signed payload bytes and
// doubles as the object name under snapshots/. The stored object is the
// envelope {payload, signature} over those bytes, then XChaCha20-Poly1305
// encrypted: signature inside the one snapshot object means there is no
// window where a manifest exists without its signature, and committing it
// is a single write that needs no cross-machine coordination (§10).
// Verification reads the stored bytes and never re-serializes before
// verifying. Trust resolution stays with the caller so this package never
// imports the identity package: callers look up the signer's public key in
// their client-local trust list and pass it in.
package manifest

import (
	"bytes"
	"cmp"
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/repository"
)

// Object type bound into snapshot associated data (DESIGN.md §4.1). The
// snapshot ID is known before encryption, so it is bound as the object ID.
const ObjectSnapshot = "snapshot"

// SnapshotPrefix is the repository key prefix for snapshot objects.
const SnapshotPrefix = "snapshots/"

// File types recorded in entries.
const (
	TypeFile    = "file"
	TypeDir     = "dir"
	TypeSymlink = "symlink"
)

// Signer signs manifest payloads with ML-DSA-65 (DESIGN.md §4.3, §6). The
// method set matches identity.PrivateIdentity without importing it, so the
// signing code stays behind a small interface and the stdlib implementation
// can be swapped for the CIRCL fallback without touching callers.
type Signer interface {
	// Sign signs message under context. Each use has its own context
	// string, so a signature for one purpose never verifies for another.
	Sign(context string, message []byte) ([]byte, error)
}

// File records one source path in a snapshot. Times are UTC and marshal as
// RFC 3339; Chunks holds hex keyed chunk IDs in file order. The JSON shape
// mirrors backup.FileEntry without importing the orchestration layer.
type File struct {
	Path   string    `json:"path"`
	Type   string    `json:"type"`
	Mode   uint32    `json:"mode,omitzero"`
	UID    uint32    `json:"uid,omitzero"`
	GID    uint32    `json:"gid,omitzero"`
	Size   int64     `json:"size,omitzero"`
	Inode  uint64    `json:"inode,omitzero"`
	Mtime  time.Time `json:"mtime,omitzero"`
	Ctime  time.Time `json:"ctime,omitzero"`
	Target string    `json:"target,omitempty"`
	Chunks []string  `json:"chunks,omitempty"`
}

// Manifest is one snapshot's signed payload (DESIGN.md §9). SnapshotID is
// not a field: it is the BLAKE3 hash of the exact marshaled payload bytes.
// Parent references the previous snapshot from the same source, or is empty
// for the first snapshot of a source. Files is ordered by path so the
// signed bytes are deterministic.
type Manifest struct {
	RepositoryID      string    `json:"repository_id"`
	SourceID          string    `json:"source_id"`
	Parent            string    `json:"parent,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	Identity          string    `json:"identity"`
	CryptoSuite       string    `json:"crypto_suite"`
	ChunkingAlgorithm string    `json:"chunking_algorithm"`
	Files             []File    `json:"files"`
}

// envelope stores the exact signed payload bytes (base64) with their
// signature. Verification decodes the payload and verifies the signature
// over those bytes; it never re-serializes before verifying.
type envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Marshal returns the deterministic payload bytes for m. Files must already
// be ordered by path; Marshal does not sort, so nondeterministic input
// fails validation in Commit rather than being silently reordered.
func (m Manifest) Marshal() ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	return raw, nil
}

// SnapshotID returns the BLAKE3 hash of the exact signed payload bytes. It
// doubles as the object name.
func SnapshotID(payload []byte) [32]byte {
	return crypto.Sum256(payload)
}

// FormatSnapshotID encodes a snapshot ID as lowercase hex for object names,
// parent references, and associated data.
func FormatSnapshotID(id [32]byte) string {
	return hex.EncodeToString(id[:])
}

// ParseSnapshotID decodes a snapshot ID in hex, accepting an optional "b3:"
// prefix. Abbreviated IDs are rejected.
func ParseSnapshotID(s string) ([32]byte, error) {
	t := strings.TrimSpace(s)
	if len(t) >= 3 && strings.EqualFold(t[:3], "b3:") {
		t = t[3:]
	}
	raw, err := hex.DecodeString(t)
	if err != nil || len(raw) != crypto.HashLength {
		return [32]byte{}, fmt.Errorf("invalid snapshot id %q: want 64 hex chars", s)
	}
	var id [32]byte
	copy(id[:], raw)
	return id, nil
}

// Validate checks m without verifying a signature. RepositoryID must equal
// wantRepo when non-empty. Files must be ordered by path with no duplicates.
func (m Manifest) Validate(wantRepo string) error {
	if m.RepositoryID == "" {
		return fmt.Errorf("%w: manifest repository id is empty", pverrors.ErrUsage)
	}
	if wantRepo != "" && m.RepositoryID != wantRepo {
		return fmt.Errorf("%w: manifest names repository %q, want %q", pverrors.ErrIntegrity, m.RepositoryID, wantRepo)
	}
	if m.SourceID == "" {
		return fmt.Errorf("%w: manifest source id is empty", pverrors.ErrUsage)
	}
	if m.CreatedAt.IsZero() {
		return errors.New("manifest created_at is missing")
	}
	if m.Identity == "" {
		return fmt.Errorf("%w: manifest identity is empty", pverrors.ErrUsage)
	}
	if m.CryptoSuite != crypto.SuiteID {
		return fmt.Errorf("%w: manifest names crypto suite %q, want %q", pverrors.ErrIntegrity, m.CryptoSuite, crypto.SuiteID)
	}
	if m.ChunkingAlgorithm != crypto.ChunkingID {
		return fmt.Errorf("%w: manifest names chunking %q, want %q", pverrors.ErrIntegrity, m.ChunkingAlgorithm, crypto.ChunkingID)
	}
	if m.Parent != "" {
		if _, err := ParseSnapshotID(m.Parent); err != nil {
			return fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
		}
	}
	if !slices.IsSortedFunc(m.Files, func(a, b File) int { return cmp.Compare(a.Path, b.Path) }) {
		return fmt.Errorf("%w: manifest files are not ordered by path", pverrors.ErrUsage)
	}
	seen := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		if f.Path == "" {
			return fmt.Errorf("%w: manifest holds an empty path", pverrors.ErrUsage)
		}
		if seen[f.Path] {
			return fmt.Errorf("%w: manifest holds duplicate path %q", pverrors.ErrUsage, f.Path)
		}
		seen[f.Path] = true
		if err := validateFile(f); err != nil {
			return err
		}
	}
	return nil
}

func validateFile(f File) error {
	switch f.Type {
	case TypeFile, TypeDir, TypeSymlink:
	default:
		return fmt.Errorf("%w: invalid file type %q for %q", pverrors.ErrUsage, f.Type, f.Path)
	}
	// Paths are untrusted filesystem input even after the signature
	// verifies (DESIGN.md §9): reject anything restore would refuse so
	// verify never attests an un-restorable repository.
	if f.Path == "" || !filepath.IsLocal(filepath.FromSlash(f.Path)) || f.Path == "." {
		return fmt.Errorf("%w: unsafe manifest path %q", pverrors.ErrIntegrity, f.Path)
	}
	if cleaned := path.Clean(f.Path); cleaned != f.Path {
		return fmt.Errorf("%w: manifest path %q is not canonical", pverrors.ErrIntegrity, f.Path)
	}
	if f.Type == TypeSymlink {
		if f.Target == "" {
			return fmt.Errorf("%w: symlink %q has no target", pverrors.ErrUsage, f.Path)
		}
		if filepath.IsAbs(f.Target) {
			return fmt.Errorf("%w: symlink %q points outside the destination", pverrors.ErrIntegrity, f.Path)
		}
		parent, _, found := strings.CutLast(f.Path, "/")
		if !found {
			parent = ""
		}
		if joined := filepath.Join(filepath.FromSlash(parent), f.Target); !filepath.IsLocal(joined) {
			return fmt.Errorf("%w: symlink %q points outside the destination", pverrors.ErrIntegrity, f.Path)
		}
	} else if f.Target != "" {
		return fmt.Errorf("%w: non-symlink %q has a target", pverrors.ErrUsage, f.Path)
	}
	if f.Type == TypeFile && f.Size < 0 {
		return fmt.Errorf("%w: file %q has negative size %d", pverrors.ErrIntegrity, f.Path, f.Size)
	}
	for _, id := range f.Chunks {
		raw, err := hex.DecodeString(id)
		if err != nil || len(raw) != crypto.HashLength {
			return fmt.Errorf("%w: invalid chunk id %q for %q", pverrors.ErrUsage, id, f.Path)
		}
	}
	if f.Type != TypeFile && len(f.Chunks) > 0 {
		return fmt.Errorf("%w: non-file %q lists chunks", pverrors.ErrUsage, f.Path)
	}
	return nil
}

// Sign signs payload with signer under the manifest context and returns the
// envelope bytes holding the exact payload. The signature covers the stored
// bytes; callers must not re-serialize before verifying.
func Sign(signer Signer, payload []byte) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("sign manifest: signer is nil")
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: manifest payload is empty", pverrors.ErrUsage)
	}
	sig, err := signer.Sign(crypto.ContextManifest, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

// Verify reports whether sig is a valid manifest signature of payload by
// signPub. Malformed inputs return plain errors; a bad signature wraps
// ErrBadSignature (exit code 4).
func Verify(signPub, payload, sig []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("%w: manifest payload is empty", pverrors.ErrUsage)
	}
	if len(signPub) != mldsa.MLDSA65PublicKeySize {
		return fmt.Errorf("verify manifest: invalid public key length %d: want %d", len(signPub), mldsa.MLDSA65PublicKeySize)
	}
	if len(sig) != mldsa.MLDSA65SignatureSize {
		return fmt.Errorf("verify manifest: %w", pverrors.ErrBadSignature)
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), signPub)
	if err != nil {
		return fmt.Errorf("verify manifest: invalid public key: %w", err)
	}
	if err := mldsa.Verify(pk, payload, sig, &mldsa.Options{Context: crypto.ContextManifest}); err != nil {
		return fmt.Errorf("verify manifest: %w", pverrors.ErrBadSignature)
	}
	return nil
}

// CommitParams carries the inputs for one snapshot commit.
type CommitParams struct {
	// RepositoryID binds every encrypted object and is signed into the
	// manifest so a snapshot cannot be replayed into another repository.
	RepositoryID string
	// SourceID names the backed-up source (defaults to the hostname at the
	// CLI layer; Manifest itself requires it non-empty).
	SourceID string
	// Parent is the previous snapshot ID from the same source, or empty
	// for the first snapshot.
	Parent string
	// Identity is the signer's fingerprint string. It is recorded
	// verbatim; trust is checked at Open time via lookup.
	Identity string
	// CreatedAt is the snapshot time; zero means time.Now in UTC.
	CreatedAt time.Time
	// Files must be ordered by path with no duplicates.
	Files []File
	// ECC selects the erasure sidecar profile for the snapshot object:
	// off, low, medium, high, or <N>%. Empty selects the repository
	// default (DESIGN.md §4.5).
	ECC string
}

// Commit builds the manifest, signs it, encrypts the envelope, and writes
// the single snapshot object. It returns the snapshot ID hex. Packs and the
// per-run index must already be durably written: the snapshot object is the
// commit point, and a failure before it leaves only orphans for prune to
// reclaim (DESIGN.md §9).
func Commit(ctx context.Context, repo repository.Repository, dataKey crypto.SecretKey, signer Signer, p CommitParams) (string, error) {
	if repo == nil {
		return "", errors.New("commit snapshot: repository is nil")
	}
	if p.RepositoryID == "" {
		return "", fmt.Errorf("%w: repository id is empty", pverrors.ErrUsage)
	}
	created := p.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	files := slices.Clone(p.Files)
	for i := range files {
		files[i].Mtime = files[i].Mtime.UTC()
		files[i].Ctime = files[i].Ctime.UTC()
	}
	m := Manifest{
		RepositoryID:      p.RepositoryID,
		SourceID:          p.SourceID,
		Parent:            strings.ToLower(strings.TrimSpace(p.Parent)),
		CreatedAt:         created.UTC(),
		Identity:          p.Identity,
		CryptoSuite:       crypto.SuiteID,
		ChunkingAlgorithm: crypto.ChunkingID,
		Files:             files,
	}
	if err := m.Validate(p.RepositoryID); err != nil {
		return "", err
	}
	payload, err := m.Marshal()
	if err != nil {
		return "", err
	}
	id := SnapshotID(payload)
	hexID := FormatSnapshotID(id)
	envBytes, err := Sign(signer, payload)
	if err != nil {
		return "", err
	}
	sealed, err := dataKey.Seal(envBytes, crypto.AssociatedData(p.RepositoryID, ObjectSnapshot, hexID))
	if err != nil {
		return "", fmt.Errorf("seal snapshot %s: %w", hexID, err)
	}
	key := SnapshotPrefix + hexID
	if err := repo.PutObject(ctx, key, bytes.NewReader(sealed)); err != nil {
		return "", fmt.Errorf("write snapshot %s: %w", hexID, err)
	}
	if err := repository.WriteSidecar(ctx, repo, key, sealed, p.ECC); err != nil {
		return "", err
	}
	return hexID, nil
}

// VerifySnapshot authenticates one snapshot object held in memory: AEAD
// opening, envelope decoding, ID binding, signature verification with
// signPub, and manifest validation. It backs repair-then-verify flows that
// must check repaired bytes without rereading storage. Failures wrap
// ErrIntegrity where they indicate tampering.
func VerifySnapshot(sealed []byte, repoID string, dataKey crypto.SecretKey, snapshotID string, signPub []byte) error {
	id, err := ParseSnapshotID(snapshotID)
	if err != nil {
		return fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
	}
	hexID := FormatSnapshotID(id)
	envPlain, err := dataKey.Open(sealed, crypto.AssociatedData(repoID, ObjectSnapshot, hexID))
	if err != nil {
		return fmt.Errorf("open snapshot %s: %w", hexID, err)
	}
	payload, sig, err := decodeEnvelope(envPlain)
	if err != nil {
		return err
	}
	if got := FormatSnapshotID(SnapshotID(payload)); got != hexID {
		return fmt.Errorf("snapshot %s: %w: id mismatch", hexID, pverrors.ErrIntegrity)
	}
	if err := Verify(signPub, payload, sig); err != nil {
		return fmt.Errorf("snapshot %s: %w", hexID, err)
	}
	var m Manifest
	if err := json.Unmarshal(payload, &m, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("decode snapshot %s: %w", hexID, err)
	}
	if err := m.Validate(repoID); err != nil {
		return fmt.Errorf("snapshot %s: %w", hexID, err)
	}
	return nil
}

// Open decrypts the snapshot object, verifies its signature with signPub,
// and returns the verified manifest. The snapshot ID must equal the BLAKE3
// hash of the signed payload, and the manifest must name repoID: mismatches
// wrap ErrIntegrity, so a valid snapshot cannot be replayed into a different
// repository or renamed.
func Open(ctx context.Context, repo repository.Repository, repoID string, dataKey crypto.SecretKey, snapshotID string, signPub []byte) (Manifest, error) {
	id, err := ParseSnapshotID(snapshotID)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
	}
	hexID := FormatSnapshotID(id)
	m, _, err := openWithKey(ctx, repo, repoID, dataKey, hexID, func(_ string) ([]byte, error) {
		return signPub, nil
	})
	return m, err
}

// OpenTrusted decrypts the snapshot object, resolves the signer's public
// key via lookup applied to the manifest's unverified identity hint, then
// verifies the signature. Lookup failures propagate verbatim so callers can
// return ErrUntrustedSigner for unknown identities. The hint is never
// trusted: verification with the looked-up key must succeed.
func OpenTrusted(ctx context.Context, repo repository.Repository, repoID string, dataKey crypto.SecretKey, snapshotID string, lookup func(identity string) ([]byte, error)) (Manifest, error) {
	id, err := ParseSnapshotID(snapshotID)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
	}
	if lookup == nil {
		return Manifest{}, errors.New("open snapshot: lookup is nil")
	}
	hexID := FormatSnapshotID(id)
	m, _, err := openWithKey(ctx, repo, repoID, dataKey, hexID, lookup)
	return m, err
}

func openWithKey(ctx context.Context, repo repository.Repository, repoID string, dataKey crypto.SecretKey, hexID string, lookup func(identity string) ([]byte, error)) (Manifest, []byte, error) {
	if repo == nil {
		return Manifest{}, nil, errors.New("open snapshot: repository is nil")
	}
	if repoID == "" {
		return Manifest{}, nil, fmt.Errorf("%w: repository id is empty", pverrors.ErrUsage)
	}
	key := SnapshotPrefix + hexID
	r, err := repo.GetObject(ctx, key)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("read snapshot %s: %w", hexID, err)
	}
	defer r.Close()
	envBytes, err := io.ReadAll(r)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("read snapshot %s: %w", hexID, err)
	}
	envPlain, err := dataKey.Open(envBytes, crypto.AssociatedData(repoID, ObjectSnapshot, hexID))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("open snapshot %s: %w", hexID, err)
	}
	payload, sig, err := decodeEnvelope(envPlain)
	if err != nil {
		return Manifest{}, nil, err
	}
	if got := FormatSnapshotID(SnapshotID(payload)); got != hexID {
		return Manifest{}, nil, fmt.Errorf("snapshot %s: %w: id mismatch", hexID, pverrors.ErrIntegrity)
	}
	var unverified Manifest
	if err := json.Unmarshal(payload, &unverified, json.RejectUnknownMembers(true)); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode snapshot %s: %w", hexID, err)
	}
	signPub, err := lookup(unverified.Identity)
	if err != nil {
		return Manifest{}, nil, err
	}
	if err := Verify(signPub, payload, sig); err != nil {
		return Manifest{}, nil, fmt.Errorf("snapshot %s: %w", hexID, err)
	}
	var m Manifest
	if err := json.Unmarshal(payload, &m, json.RejectUnknownMembers(true)); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode snapshot %s: %w", hexID, err)
	}
	if err := m.Validate(repoID); err != nil {
		return Manifest{}, nil, fmt.Errorf("snapshot %s: %w", hexID, err)
	}
	return m, payload, nil
}

func decodeEnvelope(envBytes []byte) (payload, sig []byte, err error) {
	var env envelope
	if err := json.Unmarshal(envBytes, &env, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, fmt.Errorf("decode snapshot envelope: %w", err)
	}
	payload, err = base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 {
		return nil, nil, errors.New("decode snapshot envelope: invalid payload")
	}
	sig, err = base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != mldsa.MLDSA65SignatureSize {
		return nil, nil, fmt.Errorf("decode snapshot envelope: %w: invalid signature", pverrors.ErrIntegrity)
	}
	return payload, sig, nil
}

// UnverifiedIdentity returns the identity hint from a decrypted snapshot
// envelope without verifying anything. The hint is untrusted: callers must
// resolve it against their client-local trust list and verify the envelope
// with the resolved key before use.
func UnverifiedIdentity(envPlain []byte) (string, error) {
	payload, _, err := decodeEnvelope(envPlain)
	if err != nil {
		return "", err
	}
	var hint struct {
		Identity string `json:"identity"`
	}
	if err := json.Unmarshal(payload, &hint); err != nil {
		return "", fmt.Errorf("decode snapshot identity hint: %w", err)
	}
	if hint.Identity == "" {
		return "", fmt.Errorf("%w: snapshot identity is empty", pverrors.ErrUsage)
	}
	return hint.Identity, nil
}

// List returns the sorted snapshot IDs (hex) present in the repository.
func List(ctx context.Context, repo repository.Repository) ([]string, error) {
	if repo == nil {
		return nil, errors.New("list snapshots: repository is nil")
	}
	keys, err := repo.List(ctx, SnapshotPrefix)
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if strings.HasSuffix(k, ".ecc") {
			continue
		}
		id, ok := strings.CutPrefix(k, SnapshotPrefix)
		if !ok {
			return nil, fmt.Errorf("list snapshots: unexpected key %q", k)
		}
		if _, err := ParseSnapshotID(id); err != nil {
			return nil, fmt.Errorf("list snapshots: key %q: %w", k, err)
		}
		out = append(out, strings.ToLower(id))
	}
	return out, nil
}

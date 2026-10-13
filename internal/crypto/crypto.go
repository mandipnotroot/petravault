// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package crypto implements Petravault's symmetric cryptographic foundation
// (DESIGN.md §4.1, §4.4): the repository master-key hierarchy, BLAKE3
// hashing, XChaCha20-Poly1305 authenticated encryption, Argon2id password
// key derivation, and password-sealed boxes for client-side key storage. It
// composes the approved libraries from DESIGN.md §6 and never hand-implements
// primitives (GO_GUIDELINES.md §7).
package crypto

// FormatVersion is the encrypted-object format version carried by every
// encrypted object and bound into its associated data (DESIGN.md §4.1).
const FormatVersion = 1

// Algorithm and suite identifiers recorded in repository metadata, so every
// component can be versioned and migrated without breaking old repositories
// (DESIGN.md §6).
const (
	// SuiteID is the full crypto suite name.
	SuiteID = "xwing-xchacha20poly1305-v1"
	// AEADID names the symmetric AEAD construction.
	AEADID = "xchacha20poly1305-v1"
	// KEMID names the hybrid KEM used for repository key slots.
	KEMID = "mlkem768-x25519"
	// SignatureID names the signature scheme.
	SignatureID = "ml-dsa-65"
	// HashID names the hash function.
	HashID = "blake3"
	// KDFID names the password key-derivation function.
	KDFID = "argon2id"
	// ChunkingID names the content-defined chunking algorithm.
	ChunkingID = "kfastcdc-v1"
	// ErasureID names the storage fault-tolerance code.
	ErasureID = "reed-solomon"
)

// BLAKE3 derive_key contexts separating the repository master key by purpose
// (DESIGN.md §4.1). Each context yields an independent subkey.
const (
	// DeriveData derives the XChaCha20-Poly1305 key for chunks, indexes, and manifests.
	DeriveData = "petravault v1 data"
	// DeriveChunkID derives the keyed-BLAKE3 key for chunk IDs.
	DeriveChunkID = "petravault v1 chunk-id"
	// DeriveChunker derives the key for the keyed chunker.
	DeriveChunker = "petravault v1 chunker"
)

// Signature contexts, one per signed object type, so a signature made for one
// purpose can never verify for another (DESIGN.md §4.3). Signing itself lands
// with identity and manifests (phases 4-5); the constants live here so every
// signer and verifier shares them.
const (
	// ContextManifest signs snapshot manifest bytes.
	ContextManifest = "petravault manifest v1"
	// ContextSlotGrant signs repository key-slot grants.
	ContextSlotGrant = "petravault slot-grant v1"
	// ContextRepoConfig signs the repository config.
	ContextRepoConfig = "petravault repo-config v1"
	// ContextRevocation signs revocation records.
	ContextRevocation = "petravault revocation v1"
)

// ContextKeystore is the associated-data context for password-sealed
// client-side key storage (DESIGN.md §4.4).
const ContextKeystore = "petravault keystore v1"

// Subkeys holds the purpose-separated keys derived from one repository master
// key (DESIGN.md §4.1).
type Subkeys struct {
	// Data encrypts chunks, indexes, and manifests.
	Data SecretKey
	// ChunkID computes keyed chunk IDs.
	ChunkID SecretKey
	// Chunker keys the content-defined chunker.
	Chunker SecretKey
}

// DeriveSubkeys derives the data-encryption, chunk-ID, and chunker subkeys
// from the master key. Each context yields an independent 256-bit key.
func (k SecretKey) DeriveSubkeys() Subkeys {
	return Subkeys{
		Data:    DeriveKey(DeriveData, k.b[:]),
		ChunkID: DeriveKey(DeriveChunkID, k.b[:]),
		Chunker: DeriveKey(DeriveChunker, k.b[:]),
	}
}

// Zero clears all three subkeys (best effort in Go).
func (s *Subkeys) Zero() {
	s.Data.Zero()
	s.ChunkID.Zero()
	s.Chunker.Zero()
}

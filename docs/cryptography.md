<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Cryptography

Composition of the approved libraries (`DESIGN.md` §6), never hand-rolled
primitives. Suite identifiers live in `internal/crypto/crypto.go` and are
recorded in `repository.json` so every component can be versioned:

```text
suite xwing-xchacha20poly1305-v1, kem mlkem768-x25519,
signature ml-dsa-65, hash blake3, kdf argon2id,
chunking kfastcdc-v1, erasure reed-solomon
```

## Libraries (pinned in `go.mod`)

| Purpose | Library | Version / license |
|---|---|---|
| Hybrid KEM (X-Wing) | `crypto/hpke` + `crypto/ecdh` + `crypto/mlkem` (stdlib) | Go 1.27 toolchain; `hpke.MLKEM768X25519()` |
| Signatures (ML-DSA-65) | `crypto/mldsa` (stdlib) behind a small `Signer` boundary | Go 1.27; fallback noted in `DESIGN.md` §6 is `github.com/cloudflare/circl/sign/mldsa/mldsa65` |
| XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` (`NewX`) | v0.58.0, BSD-3-Clause |
| Argon2id | `golang.org/x/crypto/argon2` (`IDKey`) | v0.58.0, BSD-3-Clause |
| BLAKE3 (plain, keyed, derive_key) | `github.com/zeebo/blake3` | v0.2.4, CC0-1.0 (reviewed at adoption) |
| Chunking (KFastCDC) | `github.com/PlakarKorp/go-cdc-chunkers` (`fastcdc-v1.0.0`) | v1.1.0, ISC |
| Compression (zstd) | `github.com/klauspost/compress/zstd` | v1.20.3, BSD-3-Clause |
| Erasure coding | `github.com/klauspost/reedsolomon` | v1.14.2, MIT |
| S3 / TLS | `github.com/aws/aws-sdk-go-v2` + `crypto/tls` | SDK v1.47.3, Apache-2.0; TLS 1.3 preferred, 1.2 minimum |
| CLI | `github.com/spf13/cobra` | v1.10.2, Apache-2.0 |
| YAML (human config only) | `go.yaml.in/yaml/v3` (strict `KnownFields`) | v3.0.5, MIT+Apache-2.0 |
| JSON (everything written) | `encoding/json` (stdlib) | — |
| Randomness | `crypto/rand` (stdlib) | all nonces, salts, key material |

`gopkg.in/yaml.v3` (archived), Viper, and any second BLAKE3 implementation
are refused by `depguard`. Dependency versions change only via reviewed
`build(deps):` PRs and are checked by `govulncheck` in CI.

## Key hierarchy (`DESIGN.md` §4.1)

One 256-bit master key (`crypto/rand`, created at `init`), then BLAKE3
`derive_key` subkeys (`internal/crypto/crypto.go`):

```text
master → derive_key("petravault v1 data")     → AEAD key (chunks, indexes, manifests)
       → derive_key("petravault v1 chunk-id") → K_chunkid (keyed chunk IDs)
       → derive_key("petravault v1 chunker")  → K_chunker (KFastCDC key)
```

## Authenticated encryption

`internal/crypto/aead.go`: `chacha20poly1305.NewX`, fresh random 192-bit
nonce per object, stored as `nonce || ciphertext || tag`. Associated data
binds `format_version`, `algorithm_id`, `repository_id`, object type, plus
`chunk_id` for chunk blobs and `snapshot_id` for snapshots. Open failures
return `ErrAuthFailed` and no plaintext. Packs/indexes are named by the hash
of their ciphertext, so they cannot bind their own name; swapping them is
caught because indexes reference packs by hash and each chunk blob binds its
own chunk ID.

## Hashing and chunk IDs

`internal/crypto/blake3.go` (`zeebo/blake3`): plain `Sum256`, keyed
`KeyedSum` for `chunk_id = BLAKE3-keyed(K_chunkid, plaintext_chunk)`, and
`DeriveKey` for subkeys. Chunk IDs only ever appear inside encrypted
objects. The chunker itself is keyed with `K_chunker`, so cut points are
secret per repository (`internal/chunking/chunking.go`, min 512 KiB /
average 1 MiB / max 8 MiB defaults).

## Passwords and keystore (`DESIGN.md` §4.4)

Private keys live on the client (`$XDG_DATA_HOME/petravault/identities/<fp>/`),
never in the repository. `internal/crypto/kdf.go` + `passwordbox.go`:
Argon2id defaults (time 3, memory 64 MiB, threads 4), 16-byte random salt,
sealed box with associated data `"petravault keystore v1"`. Unattended
unlock is `PETRAVAULT_PASSWORD_COMMAND`, then a mode-`0600`
`PETRAVAULT_PASSWORD_FILE`, then an interactive prompt; passwords never come
from flags, `config.yaml`, or job files. Key material is zeroed after use
(best effort) and core dumps are disabled while keys are loaded.

## Key slots (`DESIGN.md` §4.2)

`internal/crypto/keyslot.go` + `internal/identity/slot.go`: the master key
is sealed with HPKE base mode (`MLKEM768X25519`, HKDF-SHA256,
ChaCha20-Poly1305) with `info = "petravault key-slot v1" || repository_id
|| member fingerprint`, then ML-DSA-65-signed by the granter
(`"petravault slot-grant v1"`). Clients open a slot only when the granter
is in their own trust list, so anyone-forged slots are rejected.
`repository.json` records the KEM identifier; known-answer vectors are
pinned in tests. The HPKE draft caveat (`draft-ietf-hpke-pq`) is handled as
a detected migration, not silent breakage.

## Signatures (`DESIGN.md` §4.3)

ML-DSA-65 is the only signature scheme (`internal/identity/identity.go`,
stdlib `crypto/mldsa`, context ≤ 255 bytes via `mldsa.Options`). One scheme,
one code path. Contexts are constants in `internal/crypto/crypto.go`
(`petravault manifest v1`, `petravault slot-grant v1`,
`petravault repo-config v1`, `petravault revocation v1`), so a signature for
one purpose never verifies for another. The signature covers the exact
stored bytes; verification never re-serializes. Signing and KEM keys are
separate keypairs.

## Erasure coding interaction (`DESIGN.md` §4.5)

Reed-Solomon parity is computed over ciphertext. Repair identifies damaged
shards by per-shard BLAKE3 checksums, reconstructs them, and the result is
re-verified by AEAD. Parity never substitutes for authentication; anything
reconstructing to invalid ciphertext is rejected.

## What is not claimed (`DESIGN.md` §4.6)

No forward secrecy for data at rest. Revocation stops new snapshots from
being trusted but does not un-share a master key; cutting off read access
needs a new repository (re-keying is a non-goal in v1).

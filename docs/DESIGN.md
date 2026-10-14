<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Petravault — Secure Incremental Backup CLI

## Project Design Document (v4)

**Project:** Petravault
**Language:** Go (1.27+)
**Interface:** Command-line
**Storage:** Local filesystem, Amazon S3 (and S3-compatible stores)
**License:** GPL-3.0-only (SPDX: `GPL-3.0-only`; no "or later" clause)
**Objective:** Secure, incremental, content-addressed backup with hybrid classical/post-quantum key protection, signed snapshots, tamper detection, Reed-Solomon erasure coding, built-in scheduling, and verification.

---

## 1. Overview

Petravault is an open-source CLI backup tool built as a practical cryptography system, not a file-copy utility. It combines content-defined chunking, content-addressed dedup, client-side authenticated encryption, hybrid classical/post-quantum protection of the repository key, signed snapshot manifests with explicit public-key identity, Reed-Solomon erasure coding on both local and S3 repositories (`medium`, 5% overhead, by default; tunable with `low`/`medium`/`high` or a custom percentage), a built-in scheduler, and local/S3 storage.

**Core security assumption:**
> The repository may be observed, copied, modified, partially deleted, corrupted, or fully controlled by an attacker without that attacker being able to silently alter or forge a valid backup.

### Non-goals
No web-of-trust or certification chains, no enterprise IdM, no commercial CA, no proprietary cloud service, no storage backends beyond local and S3-compatible, no GUI, no distributed consensus, no general-purpose PGP replacement, and no key rotation or re-keying in v1 (§4.6).

---

## 2. Architecture

```text
                         USER
                          |
                  +---------------+
                  |  Petravault   |
                  |      CLI      |
                  +-------+-------+
                          |
              +-----------+-----------+
              |                       |
          Manual Job              Scheduler (§11)
              |                       |
              +-----------+-----------+
                          |
                  Backup Controller
                          |
        Filesystem Scanner (skips unchanged files, §3.4)
                          |
   keyed FastCDC -> keyed BLAKE3 -> Dedup (index) -> Zstandard -> XChaCha20-Poly1305
                          |
                  Pack writer (~16 MiB packs) -> Reed-Solomon parity sidecar
                          |
              +-----------+-----------+
              |                       |
        Local Repository          S3 Repository
              |                       |
              +-----------+-----------+
                          |
               Signed Snapshot (single object)
                          |
                    Verification
                          |
                       Restore
```

**Identity/trust** (ML-DSA-65 signing, client-pinned trust list) authenticates every manifest.
**Key protection** (a random repository master key sealed to each member with an X-Wing hybrid KEM) controls who can decrypt; it is kept separate from signing keys.
**Storage resilience** (Reed-Solomon parity over ciphertext, then AEAD verification) provides fault tolerance without weakening cryptographic integrity (§4.5).

### Data pipeline

```text
Source Files → Scanner → keyed FastCDC → keyed BLAKE3 chunk IDs → Dedup →
Zstandard → XChaCha20-Poly1305 (per chunk) → Pack → Reed-Solomon parity → Repository
```

### Metadata pipeline

```text
Snapshot metadata (JSON bytes) → ML-DSA-65 signature → envelope → XChaCha20-Poly1305 → one immutable object (+ parity sidecar)
```

---

## 3. Chunking, Hashing, Dedup

**FastCDC** produces content-defined chunk boundaries, so a small edit to a large file only invalidates the chunks touching that edit; the rest are reused across snapshots.

### 3.1 Chunker library

Petravault defines a small `Chunker` interface and ships one implementation, built on **`github.com/PlakarKorp/go-cdc-chunkers`** (ISC license), the chunking layer of the Plakar backup tool. Its v1.1.0 (June 2026) ships spec-faithful, **versioned** algorithm variants (e.g. `fastcdc-v1.0.0`), 100% statement coverage, a fuzz target, and cross-language conformance vectors. It also ships **KFastCDC**, a keyed variant that derives the Gear table from a key, which is what §3.2 needs. Verify the exact options API (min/avg/max, key) at adoption time.

The algorithm is fixed per repository in `repository.json` (e.g. `kfastcdc-v1`). If the library ever becomes unusable (abandoned, a security issue with no fix, or a breaking API change), the options are to vendor and maintain a fork (the ISC license allows it) or to adapt another keyed implementation behind the `Chunker` interface (`github.com/tigerwill90/fastcdc` is another maintained library, but a keyed variant would have to be confirmed). A different implementation does not produce identical boundaries, so it gets a new algorithm ID. Existing snapshots always restore regardless; switching algorithms on an existing repository only costs dedup efficiency for data chunked under the old one.

### 3.2 Keyed chunking and keyed chunk IDs

Chunk IDs are keyed, so an observer of the repository cannot hash a known file and confirm it is stored, and cut points are secret per repository:

- `chunk_id = BLAKE3-keyed(K_chunkid, plaintext_chunk)`, where `K_chunkid` is derived from the repository master key (§4.1). Chunk IDs only ever appear inside encrypted objects (indexes, pack headers, and snapshot manifests).
- The chunker is keyed with `K_chunker`, also derived from the master key and passed to KFastCDC (§3.1).
- Trade-off: no cross-repository dedup. Every client of one repository holds the master key, so dedup across machines (§10) is unaffected.

Defaults (configurable at `init`, then frozen in `repository.json`): min 512 KiB, average 1 MiB, max 8 MiB.

### 3.3 Determinism

Chunk boundaries must reproduce identically forever, or dedup silently degrades. `repository.json` records `chunking_algorithm` and the library version. `internal/chunking` carries a **golden-boundary test suite**: fixed inputs (empty, smaller than `MinSize`, exactly `MaxSize`, highly repetitive) with a fixed key and checked-in expected offsets. A library upgrade that changes cut points fails CI until the algorithm ID is deliberately bumped. A structural fuzz test (`go test -fuzz`) asserts only invariants: every chunk within `[MinSize, MaxSize]` except possibly the last, and chunks concatenate back to the original bytes.

### 3.4 Unchanged-file fast path

The scanner compares each file's `(path, size, mtime, inode, ctime)` with the **parent snapshot's** recorded entry (§9). If all match, the old chunk list is reused without reading the file, so incremental runs do not re-read the whole source. `--force-rescan` disables this. The known caveat (tools that preserve mtime while changing content) is documented, and `--force-rescan` is the remedy.

Two safeguards keep the fast path honest. Timestamps are compared at full (nanosecond) precision, and any file whose mtime or ctime falls within a couple of seconds of the parent snapshot's start is always re-read (the "racily clean" problem, where a later write lands in the same timestamp tick). A file is also `stat`ed before and after it is read; if it changed in between, it is re-read once, and if it is still changing the backup records it, logs a warning, and finishes with the warning exit code (§16).

### 3.5 Excludes

`--exclude <glob>`, `--exclude-file <path>`, `--exclude-caches`, and `--one-file-system` are part of `backup`. Excluded paths are not recorded in the manifest.

### Incremental logic

```text
File → unchanged vs parent? yes → reuse chunk list
                           no  → keyed FastCDC → chunks → keyed BLAKE3 id → in index?
                                                                  yes → reference
                                                                  no  → compress, encrypt, add to current pack
```

---

## 4. Cryptographic Design

### 4.1 Primitives and key hierarchy

| Purpose | Primitive | Standard |
|---|---|---|
| Content hashing / chunk IDs / key derivation | BLAKE3 (plain, keyed, derive_key) | — |
| Password KDF | Argon2id | RFC 9106 |
| Symmetric AEAD | XChaCha20-Poly1305 | RFC 8439 (ChaCha20-Poly1305) + draft-irtf-cfrg-xchacha (extended nonce) |
| Hybrid KEM (repository key slots) | X-Wing = ML-KEM-768 + X25519 | FIPS 203, RFC 7748, RFC 9180 (HPKE), draft-ietf-hpke-pq |
| Signature | ML-DSA-65 | FIPS 204 |
| Transport | TLS (1.3 preferred, 1.2 minimum) | RFC 8446 |
| Storage fault tolerance | Reed-Solomon | — |

**One master key, derived subkeys by purpose.**

```text
repository master key (256-bit, crypto/rand, created at init)
 ├─ derive_key("petravault v1 data")     → XChaCha20-Poly1305 key (chunks, indexes, manifests)
 ├─ derive_key("petravault v1 chunk-id") → keyed-BLAKE3 key K_chunkid (§3.2)
 └─ derive_key("petravault v1 chunker")  → K_chunker (§3.2)
```

Every encrypted object carries `format_version`, `algorithm_id`, a **random 192-bit nonce** (`crypto/rand`), ciphertext, and tag. Associated data always binds `repository_id`, `format_version`, `algorithm_id`, and the object type, plus an identifier wherever one is known before encryption: `chunk_id` for chunk blobs and `snapshot_id` for snapshots. Packs and indexes are named by the hash of their finished ciphertext, so they cannot bind their own name; swapping or renaming them is caught because indexes reference packs by hash and every chunk blob binds its own `chunk_id`, so a blob moved to another pack or offset fails authentication. Each chunk is its own AEAD blob inside a pack, so a single chunk can be fetched with a ranged read.

Random 192-bit nonces are what XChaCha20 is designed for, and they are sufficient here: packs are uniquely named and immutable. Duplicate chunks from concurrent clients are harmless (§10.1).

### 4.2 Repository key slots (hybrid KEM)

At `init`, the master key is created and sealed to the creator's KEM public key. Adding a member seals the same master key to that member's KEM public key. Each sealed copy is a **key slot**, wrapped in a granter-signed envelope (below) and stored at `keys/<fingerprint>.slot`.

```text
master key → crypto/hpke Seal(X-Wing public key, HKDF-SHA256, ChaCha20-Poly1305, info) → ML-DSA-65 sign (granter) → key slot
info = "petravault key-slot v1" || repository_id || member fingerprint
```

- **Implementation:** the Go standard library's `crypto/hpke` (Go 1.26+) provides the X-Wing KEM as `hpke.MLKEM768X25519()`, so there is no ad hoc combiner and no third-party dependency. The combiner, domain separation, and KDF come from the standard, not from this project.
- **Draft status:** X-Wing in HPKE comes from `draft-ietf-hpke-pq`, still an Internet-Draft. `repository.json` records the KEM identifier explicitly, and known-answer test vectors are pinned in CI, so a future identifier change is a detected migration, not silent breakage.
- **Why public-key slots instead of a password-only repository key:** a new member can be added without ever sharing a password, and the long-lived piece (the sealed master key) is protected against *harvest-now-decrypt-later*, which matters for archives stored for years. The bulk data is protected by symmetric 256-bit keys, which are already adequate against quantum attacks.
- **Slots are signed by the granter.** HPKE's base mode does not authenticate the sender: anyone who knows a member's (public) KEM key could create a slot for them containing a master key of the attacker's choosing, and that member's backups would then be readable by the attacker. Each slot is therefore an ML-DSA-65 envelope {sealed key, granter fingerprint, signature} (context `petravault slot-grant v1`), and a client refuses to open a slot unless the granter is in its own trust list (§5.2).

### 4.3 Signatures

ML-DSA-65 is the **only** signature scheme: snapshot manifests, key slots, the repository config, and revocation records all use it. One scheme means one code path to implement, test, and audit. Signing keys and KEM keys are separate keypairs, so compromising one does not expose the other.

```text
manifest bytes (as written) → ML-DSA-65 sign (context "petravault manifest v1") → envelope {payload, signature}
```

The signature covers the exact stored bytes; the envelope format is in §9. Each use has its own context string (`petravault manifest v1`, `petravault slot-grant v1`, `petravault repo-config v1`, `petravault revocation v1`), so a signature made for one purpose can never be replayed as another.

### 4.4 Password-protected key storage (client side)

```text
Password → Argon2id → Key Encryption Key → decrypts identity private keys (signing + KEM)
```

**Private keys live on the client, never in the repository**, so a stolen repository offers no offline password-guessing target. The repository holds only public key material and sealed key slots. Opening a slot requires the private KEM key from the client keystore (`$XDG_DATA_HOME/petravault/identities/<fingerprint>/`).

Argon2id parameters are stored alongside the keystore and default to current OWASP-recommended settings. Unattended unlock options are in §11. Key material is held in memory only while needed and zeroed afterwards (best effort in Go), and core dumps are disabled while keys are loaded.

### 4.5 Erasure coding (Reed-Solomon)

**Default: on, `medium` profile (5% parity overhead), for both local and S3 repositories.** AEAD and BLAKE3 detect corruption; Reed-Solomon parity lets Petravault *repair* it. This protects against bit rot and bad sectors, which is the common failure on local disks, USB drives, and NAS devices without a checksumming filesystem, and equally on S3-compatible stores running on commodity disks. On AWS S3 it is a second layer behind the provider's own durability. The cost is roughly the chosen overhead in storage plus one sidecar object per object, so a backend that already replicates data can set it to `off`.

**Layout (systematic, per object).** Parity is computed over **ciphertext**. The object (pack, index, or snapshot) is stored unchanged, and a single sidecar `<object>.ecc` holds the parity shards plus a BLAKE3 checksum of every data shard and the parameters used. Normal reads never touch the sidecar and need no extra objects.

**Parameters (derived from the setting you choose).** An object is split into `k` equal data shards plus `m` parity shards. You pick a profile or a percentage (the profiles are fixed percentages) and Petravault derives `k` and `m` from it, so you never choose shard counts by hand:

```text
m = max(1, floor(overhead × 20))        # parity shards
k = floor(m / overhead)                 # data shards
effective overhead = m / k              # always ≥ the requested value, within one shard of rounding
```

The calculation uses integer basis points (5% = 500) so floating-point rounding cannot change `k` or `m`. Allowed range for a custom percentage is 0.5% to 100% (`k + m` must stay within the Reed-Solomon limit of 255 shards); `off` disables ECC. The tool prints the effective overhead and the resulting `k`/`m` at `init` and in `petravault info`.

| Setting | Overhead | k data | m parity | Effective | Repairs up to |
|---|---|---|---|---|---|
| `low` | 2% | 50 | 1 | 2.0% | 1 damaged shard per object |
| `medium` (default) | 5% | 20 | 1 | 5.0% | 1 damaged shard per object |
| `high` | 15% | 20 | 3 | 15.0% | 3 damaged shards per object |
| custom `7%` | 7% | 14 | 1 | 7.1% | 1 damaged shard per object |
| custom `25%` | 25% | 20 | 5 | 25.0% | 5 damaged shards per object |

The profile names are shorthand for the percentages above and are frozen, so `medium` never silently changes meaning; if the recommended defaults ever change, they get a new name. Repair never depends on the name anyway, since each sidecar records its own `k` and `m`.

Lower overhead means more, smaller shards (finer checksums, same single-shard repair). For a 16 MiB pack at 5%, one shard is about 800 KiB, so any damage confined to a single 800 KiB region is repairable; at 2% a shard is about 330 KiB.

**Tuning.** The setting is chosen per repository at creation and can be overridden per run with a single `--ecc` flag, which takes `off`, `low`, `medium`, `high`, or a percentage:

```bash
petravault init <repo>                      # medium (5%), the default
petravault init <repo> --ecc high           # 15%
petravault init <repo> --ecc 8%             # custom percentage
petravault backup <src> --ecc low           # applies to objects written by this run
petravault init <repo> --ecc off            # disable (e.g. a backend that already replicates)
```

The parameters used are recorded in each sidecar, so objects written under different settings stay repairable. `config.yaml` accepts `ecc` (same values) as the default.

**Changing it later.** The setting can be changed at any time, and nothing breaks, because each sidecar records its own `k` and `m`. There are two separate actions:

```bash
petravault ecc set high        # new default for objects written from now on (same values as --ecc)
petravault ecc rebuild         # re-protect existing objects with the current setting
```

`ecc set` only changes the default recorded in the signed `repository.json` (the acting identity re-signs it); existing objects keep their old parity and stay repairable under it. `ecc rebuild` rewrites sidecars only. Parity is computed over ciphertext, so the objects themselves are never touched. Each object is first repaired if needed and AEAD-verified, so damage is never encoded into fresh parity, and the new sidecar is written before the old one is replaced. Rebuilding to `off` removes sidecars. It reads every object once (on S3 that means download cost) and takes the maintenance lock (§10.2; it cannot overlap a prune, and backups keep running), so it is meant to be run rarely. On S3 it needs maintenance credentials (§8). Prune's repack (§11.3) also writes fresh parity under the current setting, so a repository drifts toward its setting over time even without a rebuild.

**Repair.** Damaged shards are identified by their checksums (they become known erasures), reconstructed, and the result is **re-verified by AEAD**. Reed-Solomon recovers erasures; it is never a substitute for cryptographic integrity, and tampered shards that reconstruct to invalid ciphertext are rejected. Damage beyond the parity budget is reported as unrecoverable, never silently ignored. Parity does not protect against loss of the whole object or repository (§12).

### 4.6 What this design does not claim

Stored backups have no sessions, so **forward secrecy does not apply** to data at rest. The accurate statements are:

- Whoever holds a member's private KEM key *and* a copy of the repository can decrypt everything that member's key slot covers.
- Revoking a member (§5) stops new snapshots from being trusted; it does **not** un-share a master key they already held. Cutting off a former member's read access requires a new repository with a new master key (re-keying is a non-goal in v1; the docs say so plainly).
- Metadata that cannot be hidden (object sizes, counts, timing) is listed in §12.

---

## 5. Identity and Trust

Petravault does not use X.509 or a commercial CA. It uses a deliberately small, **OpenPGP-inspired** model: local identities, BLAKE3 fingerprints, **direct** trust decisions, and revocation.

```text
Identity
 ├─ Fingerprint (BLAKE3 of both public keys)
 ├─ Signing key (ML-DSA-65)
 ├─ KEM key (X-Wing)
 └─ Public metadata (name, created_at)
```

The fingerprint is BLAKE3 over a length-prefixed encoding of both public keys under a fixed domain-separation context, so the encoding is unambiguous. It is displayed in grouped base32 for reading aloud and comparing.

### 5.1 Direct trust only

```bash
petravault trust add <fingerprint>                # CLI shows the full fingerprint before accepting
petravault trust add <fingerprint> --grant-read   # also seals the master key to that identity's KEM key
petravault identity import bob.pub                # then verify the fingerprint out of band
```

Trust is an explicit list of fingerprints, which is sufficient for personal and small-team repositories. There is no transitive trust. `trust add` obtains the public keys from `identities/<fingerprint>.pub` or an imported `.pub` file and accepts them only if their hash equals the fingerprint the user confirmed, so the repository-side copy is safe to use. A new member must trust the granting identity's fingerprint before their client will open a key slot or the repository config that identity signed (§4.2, §8).

### 5.2 Trust anchors live on the client

A trust list stored in the repository would let an attacker who controls the repository add Mallory's key and sign fake snapshots. The **authoritative trust list is therefore a client-local file** (`$XDG_CONFIG_HOME/petravault/trust/{trusted-keys,revoked}/`). Copies of public keys in the repository are advisory only. A snapshot is accepted only if its signer's fingerprint is in the client's own trust list and not in its revoked list.

Revocation records (`fingerprint`, `reason`, `created_at`, `signature`) are signed by another trusted identity, or by the key itself for self-revocation. They immediately disqualify a key from verifying new snapshots; historical snapshots follow the repository's recorded policy. Records are also published to `revocations/` in the repository as an advisory channel; a client adds one to its local revoked list only after verifying its signature against its own trust list. A hostile repository can withhold a revocation but cannot forge one, and records can only add to the revoked list, never remove from it.

### 5.3 Explicit limitations

- Verifying a fingerprint never proves the real-world identity behind it. That binding rests on an initial human decision (in person, secure channel, printed fingerprint), which is why the CLI always shows full fingerprints.
- What revocation does and does not undo is covered in §4.6.

---

## 6. Recommended Go Libraries

**Policy:** Petravault implements protocol composition and application logic, never raw cryptographic primitives. AES, ChaCha20, Poly1305, ML-KEM, ML-DSA, X25519, Argon2id, and BLAKE3 are never hand-implemented. All dependency versions are pinned in `go.mod`, updated only via reviewed PRs, and checked by `govulncheck` in CI (§13).

**Licensing:** Petravault is GPL-3.0-only, so every dependency must be licensed compatibly with GPL-3.0 (permissive licenses such as BSD, MIT, ISC, and Apache-2.0 are; GPL-2.0-only, source-available, and proprietary licenses are not). Verify each dependency's license when adopting it; CI enforces this with a license scanner (§13). The repository is [REUSE](https://reuse.software/) compliant: every file carries `SPDX-FileCopyrightText:` and `SPDX-License-Identifier: GPL-3.0-only`, the verbatim license text lives in `LICENSES/GPL-3.0-only.txt` (the root `LICENSE` file is kept for convention), and `reuse lint` is clean in CI (§13).

| Component | Library | Type | Notes |
|---|---|---|---|
| X25519, ML-KEM-768, **X-Wing hybrid KEM** | `crypto/hpke` (with `crypto/ecdh`, `crypto/mlkem`) | stdlib | `hpke.MLKEM768X25519()` is the X-Wing KEM; available since Go 1.26 (Feb 2026), so it has months of runtime history. Draft-spec caveat in §4.2. |
| ML-DSA-65 | `crypto/mldsa` | stdlib | FIPS 204; shipped in Go 1.27 (released 19 Aug 2026), so its runtime history is short. Stdlib is preferred to avoid a security-critical third-party dependency, **but this is the one judgment call in the table**: the signing code sits behind a small `Signer` interface, and `github.com/cloudflare/circl/sign/mldsa/mldsa65` is the drop-in fallback if you want more runtime history before adopting. Both implement the same FIPS 204 algorithm, and signatures are interoperable. |
| XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` | Go supplementary | `NewX(...)` gives the 192-bit-nonce variant. |
| Argon2id | `golang.org/x/crypto/argon2` | Go supplementary | `argon2.IDKey(...)`. |
| BLAKE3 | `github.com/zeebo/blake3` | third-party | Used for plain hashing, **keyed mode** (chunk IDs), and **derive_key** (subkeys). One implementation, pinned, no second BLAKE3 dependency in the module graph. |
| Content-defined chunking | `github.com/PlakarKorp/go-cdc-chunkers` | third-party (ISC) | v1.1.x; versioned `fastcdc-v1.0.0` and keyed `kfastcdc` variants, fuzz-tested. Alternative library: `github.com/tigerwill90/fastcdc`. Replacement rules in §3.1. |
| Compression | `github.com/klauspost/compress/zstd` | third-party | De facto standard pure-Go zstd. |
| Reed-Solomon (§4.5) | `github.com/klauspost/reedsolomon` | third-party | Mature, SIMD-accelerated; used by `internal/erasure`. |
| TLS | `crypto/tls` | stdlib | Used implicitly via the AWS SDK's HTTP transport. Minimum TLS 1.2 (1.3 where the endpoint supports it); plaintext `http://` endpoints are refused unless explicitly enabled for local test servers. |
| S3 client / AWS auth | `github.com/aws/aws-sdk-go-v2` (`service/s3`, `config`, `credentials`) | official AWS SDK | IAM roles, env credentials, multipart upload, and built-in transient-error retry (so Petravault does not need its own S3 retry layer). |
| Secure random | `crypto/rand` | stdlib | All nonces, salts, key material. |
| CLI framework | `github.com/spf13/cobra` | third-party | Drives the subcommand tree in §16. |
| YAML (human config only) | `go.yaml.in/yaml/v3` | third-party | The YAML organization's maintained library. Do not use `gopkg.in/yaml.v3`; its repository was archived in April 2025. |
| JSON (manifests, repository state) | `encoding/json` | stdlib | Signatures cover the stored bytes (§9). |

**Do not use:** hand-written AES/ChaCha implementations, unaudited "toy" PQC packages, or any library last updated more than ~12 months ago without an active maintainer. Verify via `pkg.go.dev`'s "Published" date and the repository's actual commit/release history before adopting *any* dependency, and re-verify at each major version bump, since PQC support in particular is evolving quickly.

**Algorithm agility:** repository metadata always names the exact suite in use, so any component can be versioned and migrated without breaking old repositories:

```json
{
  "crypto_suite": "xwing-xchacha20poly1305-v1",
  "kem": "mlkem768-x25519",
  "signature": "ml-dsa-65",
  "hash": "blake3",
  "kdf": "argon2id",
  "chunking_algorithm": "kfastcdc-v1",
  "erasure": "reed-solomon",
  "ecc": {"profile": "medium", "overhead_percent": 5}
}
```

---

## 7. Configuration

**Two formats, each used for exactly one reason:**

- **YAML** for the single file a human edits: the global CLI config. It takes comments and forgiving syntax, which is the point of a hand-edited file.
- **JSON** for every file Petravault writes and reads (repository config, manifests, schedule state). Manifests are signed, and a JSON document is easy to inspect and diff. JSON is also the safer choice for data read from untrusted storage: unlike YAML it has no aliases, no implicit typing, and one obvious encoding, and it needs only the standard library's `encoding/json`.

| File | Format | Written by | Purpose |
|---|---|---|---|
| `$XDG_CONFIG_HOME/petravault/config.yaml` | YAML | Human | Global defaults: default repository, log level, concurrency, default identity, S3 profile/region. |
| `repository/config/repository.json` (§8) | JSON (signed envelope) | Petravault, at `init` and `ecc set` | Repository ID, crypto suite, chunker parameters, pack size, default ECC setting. Travels with the repository; signature checked on every open (§8) and by `petravault verify`. |
| `$XDG_CONFIG_HOME/petravault/schedule/*.json` and `$XDG_STATE_HOME/petravault/schedule/*.state.json` (§11) | JSON | Petravault, at `schedule add` / job run time | Job definitions (client-side, since a schedule belongs to a machine) and run state (`last_run`, `failure_count`, etc.). |

Client-side paths follow the XDG base directory convention (defaults `~/.config`, `~/.local/share`, `~/.local/state`, `~/.cache`); macOS and Windows use their platform equivalents.

**Precedence:** CLI flags → `PETRAVAULT_*` environment variables → `config.yaml` → built-in defaults. One order, used everywhere. Override the file location with `PETRAVAULT_CONFIG` or `--config <path>`. Every command except `init` picks its repository the same way: `--repository`/`-r`, then `PETRAVAULT_REPOSITORY`, then `default_repository`.

```yaml
# Petravault global configuration
default_repository: s3:my-backups
log_level: info
concurrency: 4
default_identity: alice
ecc: medium               # off | low | medium | high | <N>%
s3:
  profile: personal        # AWS named profile; credentials are never stored here
  region: us-east-1
verify_after_backup: true
```

**Security handling:** no secrets belong in `config.yaml` (passwords, private keys, and AWS credentials come from the keystore, `PETRAVAULT_PASSWORD_*`, and standard AWS credential providers; schedule job files hold none either). Parsing **rejects unknown keys** (fail closed), which also catches an accidentally pasted `password:` entry. Group/world-readable permissions produce a warning. Logs never contain passwords, key material, or chunk plaintext.

No config-merging framework (Viper etc.) is used.

---

## 8. Repository Layout

```go
type Repository interface {
    PutObject(ctx context.Context, key string, r io.Reader) error
    PutObjectIfAbsent(ctx context.Context, key string, r io.Reader) (created bool, err error) // locks; local = O_EXCL, S3 = If-None-Match: *
    GetObject(ctx context.Context, key string) (io.ReadCloser, error)
    GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)    // read one chunk out of a pack
    DeleteObject(ctx context.Context, key string) error
    Exists(ctx context.Context, key string) (bool, error)
    List(ctx context.Context, prefix string) ([]string, error)
}
```

`GetRange` lets restore fetch a single chunk without downloading a whole pack, and `PutObjectIfAbsent` backs the lock protocol on both backends (§10.2).

Implementations: `LocalRepository`, `S3Repository` (via `aws-sdk-go-v2`). A repository is addressed as a local path or `s3:<bucket>[/<prefix>]`. A write is durable before it is reported as done: `LocalRepository` writes a temporary file, `fsync`s it, renames it into place, and `fsync`s the directory; an S3 `PUT` is atomic, and an interrupted multipart upload is aborted.

```text
repository/
├── config/repository.json        # signed envelope: repository_id, crypto suite, chunker + pack + default ECC parameters
├── keys/<fingerprint>.slot       # master key sealed to each member, signed by the granter (§4.2)
├── identities/<fingerprint>.pub  # members' public keys (advisory; trust anchors are client-side, §5.2)
├── revocations/<fingerprint>.rev # signed revocation records (advisory; clients verify before use, §5.2)
├── snapshots/<snapshot-id>       # ONE immutable object: encrypted {signed manifest}
├── packs/<pack-id>               # ~16 MiB; many independently-encrypted chunk blobs + encrypted header
├── indexes/<index-id>            # immutable chunk-id → (pack, offset, length) maps, one per backup run
├── *.ecc                         # Reed-Solomon parity sidecar beside each pack, index, and snapshot (§4.5)
└── locks/                        # gc.lock (maintenance) and backup-<id> markers (§10.2)
```

**Why packs.** One object per chunk means about a million objects per TB at a 1 MiB average chunk, each its own request and latency on S3. Mature CDC tools (restic's default target pack size is 16 MiB) group chunks into packs for this reason. Pack and index names are the BLAKE3 hash of the stored bytes (ciphertext, so unkeyed hashing is fine).

**Why immutable per-run indexes.** A single shared index file would be a lost-update race between concurrent clients. Each backup run instead writes a **new immutable index file**; clients read all index files, merge them into a local cache, and prune compacts them under its exclusive lock.

**Local cache** (`$XDG_CACHE_HOME/petravault/<repository_id>/`): merged index plus the file-metadata cache used by the fast path (§3.4). It is disposable and always rebuildable from `indexes/`.

**Private keys, the keystore, and the trust list are not in the repository** (§4.4, §5.2).

**The repository config is authenticated.** `repository.json` is an ML-DSA-65 signed envelope (context `petravault repo-config v1`), verified against the client's trust list before it is parsed or used. A client refuses a config with an invalid or untrusted signature, and rejects any manifest that names a suite or chunking algorithm other than those in the signed config, so a hostile repository cannot downgrade the suite or quietly change parameters. Changing the config (for example `ecc set`) re-signs it.

S3 mirrors this layout under a bucket prefix. Enable **S3 Versioning** and, for stronger tamper resistance, **S3 Object Lock**; both are defense-in-depth, not a substitute for client-side signatures. Note that Object Lock retention blocks deletes, so its retention period must be no longer than the shortest snapshot retention you configure, or prune will fail. All content is encrypted client-side before upload; S3 server-side encryption may also be enabled but is not the confidentiality boundary. Credentials use standard AWS mechanisms and are never written into manifests or logs. Routine backup clients should use **write-only credentials**: an IAM policy allowing `s3:GetObject`, `s3:PutObject`, and `s3:ListBucket`, plus `s3:DeleteObject` only on `locks/*`. Maintenance (`prune`, `ecc rebuild`) runs from a separate administrative credential, so a compromised client machine cannot erase history.

---

## 9. Snapshots, Verification, Restore

### Snapshot model

The manifest is a JSON document. Its `snapshot_id` is **not** a field inside it; it is the BLAKE3 hash of the exact signed payload bytes, and doubles as the object name.

```json
{
  "repository_id": "...",
  "source_id": "laptop-alice",
  "parent": "b3:...",
  "created_at": "2026-10-11T10:00:00Z",
  "identity": "b3:...",
  "crypto_suite": "xwing-xchacha20poly1305-v1",
  "chunking_algorithm": "kfastcdc-v1",
  "files": [
    {"path": "Documents/report.pdf", "type": "file", "mode": "0644", "uid": 1000, "gid": 1000,
     "mtime": "2026-10-10T08:12:44Z", "ctime": "...", "inode": 123456, "size": 482113,
     "chunks": ["b3:...", "b3:..."]},
    {"path": "Documents/link", "type": "symlink", "target": "report.pdf"}
  ]
}
```

- `repository_id` is signed into every manifest so a valid snapshot cannot be replayed into a different repository.
- The `files` list is ordered by path, so the signed bytes are deterministic.
- File entries record the metadata a real restore needs: type (file/dir/symlink), mode, uid/gid, mtime, size, symlink target, and chunk list. They also record `ctime` and `inode` for the fast path (§3.4). Extended attributes, ACLs, and hard links are explicitly **post-v1**, so restores are faithful for ordinary trees and the gap is documented rather than silent.
- The signature is **not** a manifest field. The stored object is the envelope `{payload, signature}` over the exact payload bytes, then encrypted (§4.3). Verification reads the stored bytes and never re-serializes them.

`parent` references the **previous snapshot from the same `source_id`** — not "whatever the latest snapshot in the repository happens to be." A repository is therefore a small **forest** of independent chains, one per backed-up source (typically one per machine, since that's what's actually taking a linear series of backups of itself), not one global sequence. Verification detects unexpected rollback or forked history **within a given source's chain**; there's no meaningful "global latest" to defend across sources that back up unrelated things, and forcing one would be the single-writer assumption this design specifically avoids (§10). Pruned history is legitimate maintenance, not an attack: a retained snapshot whose parent was pruned by retention (§11.3) becomes a new root, so multiple roots and missing parents are allowed. Forks (two retained children of one parent), parents from another source, cycles, and multiple tips still fail. Deletion of the newest snapshot of a source is still detected via head records below, but deletion of old history via prune is not.

`source_id` defaults to the machine hostname and is set once at `petravault init`/first backup from that source; it's config rather than a secret, but like the rest of the manifest it is encrypted at rest and only visible to clients that hold the master key.

**Rollback and truncation.** A chain alone cannot reveal that the newest snapshots were deleted, because what remains is still a valid chain. Each client therefore keeps a **head record** per source and repository in its local state (`$XDG_STATE_HOME/petravault/heads/<repository_id>.json`), updated after every backup and verify. `verify` and `restore` fail if a recorded head is missing or is neither the current tip of its chain nor one of its ancestors. A client with no record (first use of a repository) can only check the chain's internal consistency and says so. A record is reset only by explicit operator action, never automatically, and prune never removes the most recent snapshot of any source (§11.3).

### Verification modes

| Mode | Command | Checks |
|---|---|---|
| Standard | `petravault verify` | repository config, key slots, index consistency, object and sidecar existence, ECC parameters, manifest + signature validity, identity trust, snapshot chain (per source), head records, chunk references |
| Deep | `petravault verify --deep` | + ECC parity check and repair, AEAD authentication, decryption, decompression, BLAKE3 recomputation, restored-metadata validation |

`verify` is the only integrity command. It covers the whole repository by default, or a single snapshot with `petravault verify <snapshot-id>`. Verify-after-backup (`--verify` on `backup`, `verify_after_backup` in `config.yaml`, `verify` on a schedule job) is just a standard `verify` of the snapshot that run created; `--no-verify` overrides the default.

### Restore

```bash
petravault restore <snapshot-id> ./restore
petravault restore <snapshot-id> ./restore --include Documents/report.pdf
```

Restore verifies the snapshot's signature, the signer's trust, and the history before reading any chunk, and writes a file only after all of its chunks pass AEAD and BLAKE3:

```text
locate snapshot → verify signature → verify identity is trusted →
verify parent/history (within its source's chain) → read chunks → verify AEAD → verify BLAKE3 → write files
```

**Restore safety.** A verified manifest is still treated as untrusted input to the filesystem. Restore rejects absolute paths and any `..` component, never follows a symlink out of the destination (including symlinks created earlier in the same restore), writes each file under a temporary name and renames it into place, and refuses to overwrite existing files unless `--overwrite` is given. Ownership is restored only when running as root, setuid/setgid bits are not restored, and decompression is capped at the repository's maximum chunk size so a crafted blob cannot expand without bound.

### Atomic commit

A snapshot is not part of repository history until every object it references is durably written and its single manifest object exists:

```text
write packs (+ parity) → write index (+ parity) → write snapshot object (signed + encrypted, ONE PUT) = commit → write the snapshot's parity sidecar
```

Because the signature lives inside the one snapshot object, there is no window where a manifest exists without its signature. The snapshot is an immutable object named by its own `snapshot_id`; committing it is a single write to a key no other snapshot ever touches, so **this step needs no cross-machine coordination at all** (§10). A failure before commit can leave orphaned packs and indexes; garbage collection reclaims them (§11), and a partial snapshot is never treated as valid. The snapshot's own sidecar is derived data written after the commit point; if a crash leaves it missing, `verify` reports it and the next backup or `ecc rebuild` regenerates it.

---

## 10. Concurrency & Multi-Client Backup

**A repository is designed to be backed up to by many machines at once.** Multiple sources upload packs and indexes and commit snapshots to the same repository concurrently; the only operations that ever take the exclusive maintenance lock are prune and `ecc rebuild`.

**Why shared, not per-machine.** Separate repositories per machine throw away cross-device dedup (a laptop and a desktop with overlapping files get zero reuse), do not fit the small-team case that §5's trust model targets, and are unnecessary: immutable, uniquely named objects plus per-source snapshot chains (§9) already remove nearly every point of contention. This mirrors how restic documents safe multi-host use, serializing only around pruning.

### 10.1 What needs zero coordination

- **Pack and index uploads.** Pack and index names are hashes of their stored bytes, so two machines never write the same key with different contents. If both store the same new chunk, the result is two packs that each contain it, a harmless duplicate that prune removes (§11).
- **Dedup lookups.** Each client works from the merged index it read at startup. A chunk another client added a second ago is not yet visible, which costs at most one duplicate blob, never an error.
- **Snapshot commit.** As established in §9, each snapshot is its own immutable object with no shared index to update.

### 10.2 What still needs a lock, and how small the surface is

- **The same source running two overlapping backups of itself.** This is a local problem: a single advisory `flock` on the machine actually running the backup is sufficient. It never needs to reach across the network.
- **Garbage collection / pruning (§11).** This is the one genuinely repository-wide operation: it computes `unreferenced = all_chunks − chunks_referenced_by_every_retained_snapshot_across_every_source`. Two races make that unsafe while a backup is running: a new pack that no committed snapshot references yet looks like garbage, and a backup may deduplicate against a chunk whose only references prune is about to delete. Prune therefore takes the maintenance lock and refuses to delete anything while a backup is in flight. One protocol, identical on both backends, does this:
  - **Lock objects.** `locks/gc.lock` (exclusive) and `locks/backup-<id>` (one per running backup, shared) are created with `PutObjectIfAbsent` (local `O_EXCL`, S3 `If-None-Match: *`), so creation itself is the compare-and-swap. Each records its holder, host, operation (`prune` or `ecc-rebuild` for `gc.lock`), and a timestamp, is heartbeat-refreshed while its holder runs, and is considered abandoned after its TTL (e.g. the holder crashed), after which anyone may remove it. A local repository uses lock objects rather than `flock`, because it may sit on a NAS shared by several machines.
  - **Backup:** write `backup-<id>`, then check for `gc.lock`, and only then read the indexes. If a **prune** holds the lock, remove the marker and retry with backoff. Delete the marker when the backup finishes.
  - **Prune:** create `gc.lock`, then list the `backup-*` markers. If a live marker exists, wait (bounded) for it to finish or expire; otherwise abort without deleting anything. Because a backup writes its marker before looking for the lock, and prune writes the lock before looking for markers, at least one of them always sees the other.
  - **`ecc rebuild`** also takes `gc.lock` so it cannot overlap a prune, but it does not wait for markers, and backups keep running while it holds the lock.

  This is best-effort rather than a perfectly linearizable distributed lock (clock skew can expire a TTL early), the same class of guarantee restic relies on. Anything that slips through is detectable: `verify` reports a snapshot that references a missing chunk.

### 10.3 What this doesn't solve

Two sources with the **same `source_id`** (e.g. hostname collision, or the same source re-used sloppily on a clone of a machine) racing to extend the same chain is a real conflict — two children of the same parent snapshot. This is treated as a configuration error, not a case the system silently resolves: `source_id` uniqueness is the operator's responsibility (default to hostname, override with `--source-id` for containers/VMs that clone hostnames), and `petravault verify` reports a forked chain if it ever happens rather than picking a winner.

---

## 11. Scheduling, Unattended Runs, Retention, Maintenance

Scheduling shares the exact same backup pipeline as manual runs; there is no separate, weaker code path.

### 11.1 Scheduler

```bash
petravault schedule {list|add|remove|enable|disable|run|status|daemon}
```

```bash
petravault schedule add --name daily-documents --source ~/Documents \
  --repository s3:my-backups --daily 02:00 --keep-daily 30 --keep-weekly 12 --keep-monthly 12
```

```json
{
  "name": "daily-documents",
  "source": "/home/user/Documents",
  "repository": "s3:my-backups",
  "frequency": "daily", "time": "02:00",
  "retention": {"daily": 30, "weekly": 12, "monthly": 12},
  "verify": true, "enabled": true
}
```

- **Running jobs.** `schedule daemon` is a foreground loop that runs jobs when due (suitable for systemd, launchd, a Windows service, or a container). `schedule run` executes all currently due jobs once and exits (suitable for a system cron entry every few minutes); `schedule run <name>` runs one job immediately. `schedule status` shows each job's state.
- **State per job:** `last_run`, `last_success`, `last_failure`, `failure_count`, `next_run`, kept separately from the job definition (§7).
- **Retry:** transient failures use bounded retry with exponential backoff (default 3 attempts, configurable per job). A failed attempt never leaves an inconsistent snapshot, because commit is atomic (§9).
- **Missed runs:** if the machine was off at the scheduled time, the job runs once at the next start (catch-up), never once per missed interval.
- **Overlap:** a job that is still running is not started again; the per-source local lock (§10.2) enforces this.
- **Retention:** when a job has a `retention` block, `prune` runs with those settings after a successful backup, under the maintenance lock. If the lock is held by another prune or rebuild, the job skips pruning and logs it rather than failing the backup.
- **Verification:** `"verify": true` runs verify-after-backup (§9) on each job's new snapshot; if omitted, the global `verify_after_backup` setting applies.
- **Exit codes and logging:** `schedule run` exits non-zero if any job failed; every attempt is logged with job name, snapshot ID (if committed), duration, and error.

### 11.2 Unattended unlock

Scheduled jobs cannot prompt for a password. The keystore (§4.4) is unlocked using, in order of preference:

1. `PETRAVAULT_PASSWORD_COMMAND`: a command that prints the password (works with `secret-tool`, `pass`, cloud secret managers, or a keyring).
2. `PETRAVAULT_PASSWORD_FILE`: a file that must be mode `0600`, refused otherwise.
3. Interactive prompt (manual runs only).

Passwords are never stored in `config.yaml` or job files and never passed as a command-line argument (visible in `ps`). Use a dedicated identity for scheduled machines so it can be revoked on its own. Example systemd unit for the daemon (more in `docs/unattended.md`):

```ini
[Service]
Environment=PETRAVAULT_PASSWORD_FILE=%h/.config/petravault/pw
ExecStart=/usr/local/bin/petravault schedule daemon
Restart=on-failure
```

### 11.3 Retention and garbage collection

Retention can also be applied manually:

```bash
petravault prune --keep-daily 30 --keep-weekly 12 --keep-monthly 12 --dry-run
```

Pruning computes `unreferenced = all_chunks − chunks_referenced_by_retained_snapshots`. Retention keeps the newest snapshot of every source plus the newest snapshot per UTC day/week/month for the last N distinct buckets per source. Packs whose chunks are all unreferenced are deleted together with their parity sidecars. Packs that are mostly unreferenced are **repacked** (rewritten without the dead chunks, with fresh parity) once their unused fraction reaches 50%; a chunk cannot be deleted individually from a pack. Prune also compacts index files and removes orphans from failed backups. Prune refuses to run without at least one keep rule, and always keeps the most recent snapshot of every source (§9). It takes the maintenance lock and waits out or aborts on in-flight backups (§10.2), and `--dry-run` previews everything without taking the lock or changing the repository.

---

## 12. Threat Model

| Attacker | Capabilities | Primary mitigations |
|---|---|---|
| Malicious storage provider | read/delete/modify/replay/reorder objects | encryption, signatures, BLAKE3, per-source snapshot chain, verification |
| Network attacker | intercept/modify/replay traffic, downgrade | TLS (1.3 preferred), SigV4 auth, application-layer AEAD, signed metadata |
| Stolen repository | full offline copy | client-side XChaCha20-Poly1305; **no private keys or password-verifiers in the repository** (§4.4); key slots need a client-held KEM private key |
| Unauthorized identity | forges a keypair, signs fake snapshots, edits repo-side key files, forges key slots or `repository.json` | **client-pinned trust list** (§5.2), fingerprints, signature verification (snapshots, key slots, repository config), revocation |
| Fingerprinting / confirmation-of-file | hashes a known file to check whether it is stored; matches chunk-size sequences | keyed chunk IDs, keyed chunker, IDs only inside encrypted objects (§3.2); residual size leakage listed below |
| Repository corruption | bit rot, hardware failure | AEAD, BLAKE3, Reed-Solomon parity (`medium`, 5%, by default; §4.5), deep verification |
| Scheduler attacker | modifies scheduled jobs (source, destination, retention) | job files `0600` and permission-checked at load, schema validation, no secrets in job files, logging of every run |
| Replay attacker | reintroduces old valid objects/snapshots | per-source snapshot chain and client-local head records (§9), `repository_id` in signed manifests, S3 Versioning/Object Lock; detection is scoped to a source's own chain since sources are independent (§10) |
| Compromised client machine | holds keys, can write, may try to delete or overwrite history | write-only S3 credentials for routine clients, S3 Versioning/Object Lock, a dedicated per-machine identity that can be revoked (§11.2); prune and `ecc rebuild` run from a separate administrative credential (§8) |

**What the storage provider can see:** pack and object sizes, counts, timing, repository structure, the set of key-slot fingerprints, and total data volume (chunk boundaries inside a pack live only in its encrypted header, so individual chunk sizes are hidden at rest, but total volume is not, and ranged reads during a restore reveal access patterns). **What it cannot see:** plaintext contents, backup encryption keys, private signing keys. Metadata leakage cannot be eliminated entirely; this is documented as a known limitation, not claimed away.

**If a signing key is stolen:** revoke the identity → create a replacement → add it to the trust store → record the revocation → continue verifying historical snapshots per their recorded identity and policy → if that identity also held read access, treat the master key as exposed (§4.6). Key compromise and storage compromise are handled as distinct incident types.

**If the repository is completely lost:** no on-repo mechanism, including parity sidecars, helps when everything is gone; parity covers damage within its budget, not loss of the whole object or repository. Mitigate with an independent secondary repository (e.g. local + S3), which the `Repository` abstraction supports without a second cloud provider.

---

## 13. Testing Strategy

| Layer | Coverage |
|---|---|
| Unit | encrypt/decrypt round-trip, sign/verify, key derivation and subkey separation, BLAKE3 known-answer tests (plain, keyed, derive_key), X-Wing key-slot seal/open with pinned vectors, pack write/read and ranged reads, index merge, unchanged-file fast path, `PutObjectIfAbsent` semantics, scheduler next-run/retry/catch-up/overlap/failure logic, ECC parameter derivation (overhead → k/m; effective overhead ≥ requested; out-of-range values rejected) |
| Chunking | golden-boundary tests with a fixed key and fixed inputs (§3.3); structural fuzz (chunks within bounds, concatenate back to the original); round-trip through backup/restore |
| Integration | create repo → identity → backup → modify → backup → verify → restore → assert byte-identical output, including symlinks, empty files, and modes |
| Concurrency | two clients backing up simultaneously to one repository (including identical new files); both snapshots must restore, then prune must dedupe; an interrupted backup must leave only orphans, never a partial snapshot; prune racing an in-flight backup never deletes a pack or chunk that a committing snapshot references (marker/lock ordering, §10.2) |
| Security/attack simulation | see table below |
| Multi-user | Alice (trusted) signs → valid; Bob signs → valid only on clients that have trusted him; Mallory (untrusted) signs → rejected |
| Unattended | `PETRAVAULT_PASSWORD_FILE` with wrong mode refused; password never appears in process arguments or logs; job file with loose permissions or unknown fields rejected |
| Erasure coding | flip bytes in 1..m shards of a pack, index, and snapshot object → repaired and AEAD-verified; flip bytes in m+1 shards → clear unrecoverable error; `low`/`medium`/`high` resolve to 2%/5%/15%; custom percentages and `off` behave as specified; the same tests run against `LocalRepository` and `S3Repository` (S3 via a local S3-compatible test server); `ecc set` leaves existing objects repairable, and `ecc rebuild` re-protects them (including to and from `off`) and refuses to encode damaged data |

### Attack simulations (must all pass)

| Attack | Expected result |
|---|---|
| Modify a byte of an encrypted chunk blob | AEAD authentication failure |
| Modify snapshot object | Signature invalid / AEAD failure |
| Unauthorized signer (Mallory) | Untrusted identity / invalid signature |
| Mallory adds her key to the repository's `identities/` copy | Rejected: client-pinned trust list unchanged |
| Replay an old snapshot as latest | Rollback detected within that source's chain |
| Replay a valid snapshot into a different repository | Rejected: `repository_id` mismatch |
| Revoked signer attempts new signature | Rejected |
| Swap chunk blobs between packs or offsets | AEAD authentication failure (the chunk ID is bound in the associated data) |
| Edit `repository.json` (downgrade the suite, disable ECC) | Rejected: signature invalid or signer untrusted |
| Mallory creates a key slot for Bob containing her own master key | Rejected: granter not in Bob's trust list |
| Delete the newest snapshot(s) of a source | Detected against the client's head record |
| Manifest path with `..`, an absolute path, or a symlink pointing outside the destination | Rejected at restore; nothing is written outside the destination |
| Wrong keystore password | Unlock failure, no partial decryption |
| Copy of the repository, no client keys | No private key material present; key slots cannot be opened |
| Known file hashed offline and searched for in the repository | No match possible (keyed IDs) |
| Corrupt or delete a shard within the parity budget | Detected by shard checksum, reconstructed, AEAD re-verified |
| Corrupt more shards than parity can cover | Recovery impossible, reported clearly |
| Modify a schedule job file (or loosen its permissions) | Job refused; logged |

CI runs formatting (`golangci-lint fmt`, i.e. gofumpt + goimports), `go vet`, `golangci-lint run`, `go test`, `go test -race`, `go build`, `go mod verify`, `govulncheck`, dependency scanning, a dependency license check (fails on anything incompatible with GPL-3.0-only), and a REUSE compliance check (`reuse lint`) on every push. Release builds aim for reproducibility, and release artifacts are published with checksums, a detached signature, and an SBOM.

---

## 14. Project Structure

```text
petravault/
├── cmd/petravault/main.go
├── internal/
│   ├── backup/       # scanning, unchanged-file fast path, excludes, orchestration, snapshot creation
│   ├── chunking/     # Chunker interface; go-cdc-chunkers (KFastCDC) adapter; golden tests
│   ├── pack/         # pack writer/reader, index files, local cache
│   ├── compression/  # zstd wrapper
│   ├── config/       # config.yaml, environment and flag precedence, schema validation (§7)
│   ├── crypto/       # AEAD, key slots (crypto/hpke), ML-DSA, Argon2id, subkey derivation
│   ├── erasure/      # Reed-Solomon parity sidecars (§4.5)
│   ├── identity/     # keygen, fingerprints, client-side keystore, export/import, trust list, revocation
│   ├── manifest/     # snapshot structs, signed envelope (sign/verify stored bytes)
│   ├── repository/   # Repository interface, Local + S3 impls, lock protocol
│   ├── restore/      # path-safe restore, partial restore (--include), file metadata (§9)
│   ├── scheduler/    # jobs, retry, catch-up, next-run calculation, daemon loop
│   └── verify/       # standard + deep verification, client-local head records (§9)
├── tests/attack/                # cross-package attack-simulation suite (§13); unit tests sit beside the code they cover
├── docs/{architecture,cryptography,threat-model,trust-model,storage,unattended}.md   # created in phase 13 (§15)
├── .github/workflows/ci.yml
├── AGENTS.md · README.md · CONTRIBUTING.md · SECURITY.md · DESIGN.md · LICENSE (GPL-3.0 text) · LICENSES/GPL-3.0-only.txt · go.mod · go.sum
```

---

## 15. Implementation Phases

1. **Repository foundation:** CLI, `LocalRepository` (ranged reads, `O_EXCL` conditional create, durable temp-file/`fsync`/rename writes), config, logging
2. **Crypto foundation:** BLAKE3 (plain/keyed/derive_key), XChaCha20-Poly1305, Argon2id, secure RNG, client-side keystore
3. **Chunking, packs, incremental backup:** `Chunker` interface, `go-cdc-chunkers` (KFastCDC) adapter, golden tests, keyed chunk IDs, packs, immutable indexes, dedup, unchanged-file fast path, excludes, file metadata capture
4. **Identity & trust:** keygen, fingerprints, client-local trust list, import/export, revocation
5. **Signed manifests:** ML-DSA-65 via `crypto/mldsa` behind a `Signer` interface; signed `repository.json`; single-object snapshot commit
6. **Key slots:** `crypto/hpke` X-Wing seal/open, granter-signed slot envelopes, `trust add --grant-read`, pinned test vectors
7. **Reed-Solomon:** parity sidecars, profiles (`low`/`medium`/`high`) and custom percentages (`medium` default), `ecc set` / `ecc rebuild`, shard checksums, repair, AEAD re-verification
8. **Restore & verification:** `restore` (with its path-safety rules), `verify`, `verify --deep`, verify-after-backup, client-local head records
9. **S3:** `S3Repository` on `aws-sdk-go-v2`, auth, TLS, multipart upload, ranged reads, conditional-create lock, ECC sidecars on S3
10. **Prune & retention:** retention flags, repack, index compaction, lock protocol (`gc.lock` and backup markers)
11. **Scheduling:** full `schedule` subcommand set, daemon, retry, catch-up
12. **Security testing:** the attack-simulation suite (§13)
13. **Open-source release:** README, AGENTS, CONTRIBUTING, SECURITY, DESIGN, threat model, crypto docs, `docs/unattended.md`, CI (including license and REUSE checks), GPL-3.0 `LICENSE` + `LICENSES/GPL-3.0-only.txt`, demo

---

## 16. CLI Reference

```bash
# Global flags: -r/--repository (all commands except init), --config, --identity, --log-level

petravault init [path|s3:bucket[/prefix]] [--ecc off|low|medium|high|N%]
petravault info
petravault ecc {set <level>|rebuild}

petravault identity {create|list|export|import}
petravault trust {list|add [--grant-read]|remove|revoke}

petravault backup <source> [--exclude GLOB] [--exclude-file F] [--exclude-caches]
                  [--one-file-system] [--force-rescan] [--verify|--no-verify] [--source-id ID] [--ecc LEVEL]
petravault snapshots {list|show <id>}
petravault restore <snapshot> <destination> [--include PATH] [--overwrite]

petravault verify [<snapshot>] [--deep]

petravault schedule {list|add|remove|enable|disable|run|status|daemon}

petravault prune [--keep-daily N] [--keep-weekly N] [--keep-monthly N] [--dry-run]
```

**Exit codes:** `0` success; `1` error; `2` usage error; `3` completed with warnings (for example, files unreadable or still changing during backup); `4` integrity or trust failure (tampering, bad signature, rollback detected, unrecoverable corruption).

---

## 17. Definition of Done

```text
create identity → create repository → first backup → modify files →
incremental backup (unchanged files skipped) → schedule future backup →
run verification → delete/corrupt a shard → recover via Reed-Solomon →
add a second member via key slot → second machine backs up concurrently →
tamper with encrypted data → detect integrity failure →
attempt unauthorized signing (including editing repo-side key files, forging a key slot, or editing `repository.json`) → reject it →
delete the newest snapshot → detect the rollback →
prune with retention → restore snapshot → verify restored data
```

---

## 18. Central Security Principle

> Encrypt and authenticate data before it enters potentially untrusted storage; use explicit, client-pinned public-key identity to authenticate backup metadata; verify the entire backup chain before trusting or restoring data; and build every step on actively maintained, standards-conformant libraries (§6), never on hand-rolled primitives.

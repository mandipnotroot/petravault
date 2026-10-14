<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Architecture

How Petravault is put together. Behavior authority is `DESIGN.md`
(§2 pipelines, §8 layout, §10 concurrency, §11 scheduling, §14 structure);
this file is the operator-oriented map from that design to the code.

## Pipelines

Backup (`DESIGN.md` §2):

```text
Manual Job / Scheduler → Backup Controller → Filesystem Scanner →
keyed FastCDC → keyed BLAKE3 → Dedup → Zstandard →
XChaCha20-Poly1305 → Pack (~16 MiB) → Reed-Solomon sidecar → Repository
→ Signed Snapshot (single object) → Verification → Restore
```

Metadata (`DESIGN.md` §2, §9):

```text
Snapshot JSON bytes → ML-DSA-65 signature → envelope →
XChaCha20-Poly1305 → one immutable object (+ parity sidecar)
```

Snapshots commit atomically: packs, then index, then the single snapshot
object, then its sidecar. A failure before the snapshot object leaves only
orphans for prune; a partial snapshot is never valid.

## Layering

Module `petravault` (`go 1.27.2`); imports are `petravault/internal/<pkg>`.
`cmd/petravault` only wires dependencies and maps errors to exit codes.
No business logic in `cmd`, no `init()`, no package-level mutable state,
no `util`/`common` packages, no import cycles (`GO_GUIDELINES.md` §5):

| Layer | Packages | May import |
|---|---|---|
| Leaf | `crypto`, `compression`, `chunking`, `erasure`, `config` | stdlib + approved deps only |
| Domain | `identity`, `manifest`, `repository`, `pack` | leaf |
| Orchestration | `backup`, `restore`, `verify`, `scheduler`, `prune` | leaf + domain (`scheduler` reuses `backup`) |
| Wiring | `cmd/petravault` | everything |

Seams are small consumer-side interfaces: `Repository` (`internal/repository/repository.go`),
`Chunker` (`internal/chunking/chunking.go`), and the ML-DSA `Signer` boundary
in `internal/identity`.

## Packages

- `internal/crypto`: master key, `derive_key("petravault v1 ...")` subkeys,
  XChaCha20-Poly1305 `Seal`/`Open`, BLAKE3 plain/keyed/derive, Argon2id,
  HPKE X-Wing slots. See `cryptography.md`.
- `internal/chunking`: `Chunker` interface + `go-cdc-chunkers` KFastCDC
  adapter (`kfastcdc-v1`, library `fastcdc-v1.0.0` v1.1.0). Always keyed.
- `internal/pack`: pack writer/reader, per-run immutable indexes, local
  merged-index cache. Pack names are the BLAKE3 of their ciphertext.
- `internal/compression`: zstd wrapper with a decode cap.
- `internal/erasure`: Reed-Solomon sidecars over ciphertext. See `storage.md`.
- `internal/identity`: keygen, BLAKE3 fingerprints, keystore, trust list,
  revocation, signed slot envelopes. See `trust-model.md`.
- `internal/manifest`: snapshot structs, signed envelope over stored bytes,
  atomic commit. Snapshot ID is the BLAKE3 of the signed payload bytes.
- `internal/repository`: `LocalRepository` + `S3Repository`, signed
  `config/repository.json`, `gc.lock` / `backup-<id>` lock protocol.
  See `storage.md`.
- `internal/backup`: scanner, unchanged-file fast path, excludes, dedup,
  snapshot creation. Shares its pipeline with the scheduler.
- `internal/restore`: `os.Root`-confined, path-safe restore.
- `internal/verify`: standard + `--deep` verification, client-local head
  records. See `threat-model.md`.
- `internal/scheduler`: job files, retry/backoff, catch-up, daemon.
  See `unattended.md`.
- `internal/prune`: retention buckets, repack, index compaction.
- `internal/config`: `config.yaml` (strict YAML), `PETRAVAULT_*` env,
  flag precedence. See `unattended.md`.
- `internal/errors`: `ErrIntegrity` (exit 4), `ErrUsage` (exit 2),
  `ErrWarnings` (exit 3).

## Determinism

Everything hashed, signed, or named by its hash is built from deterministic
bytes: manifests keep `files` sorted by path and are signed as stored bytes
(never re-serialized before verify); ECC `k`/`m` derive from integer basis
points, never floats; times are UTC RFC 3339; chunk boundaries are frozen
per repository with golden-boundary tests in `internal/chunking`.

## Concurrency

Many sources back up concurrently: packs/indexes/snapshots are immutable
and uniquely named, so uploads need no coordination. The same source
running twice is stopped by a local advisory lock. Only prune and
`ecc rebuild` take the repository-wide `locks/gc.lock`; backups write
`locks/backup-<id>` markers first, then check for the lock, then read
indexes. `ecc rebuild` holds the lock but lets backups keep running.
See `storage.md`.

## CLI

Thin `cobra` commands (`cmd/petravault`): parse flags, build dependencies,
call into `internal/...`, return an error. Results go to stdout, diagnostics
to stderr. Global flags: `-r/--repository`, `--config`, `--identity`,
`--log-level`. Exit codes: `0` ok, `1` error, `2` usage, `3` warnings,
`4` integrity/trust failure. Full command list is `DESIGN.md` §16.

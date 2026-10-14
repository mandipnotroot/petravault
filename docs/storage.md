<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Storage

Repository layout, backends, erasure coding, and the lock protocol
(`DESIGN.md` §4.5, §8, §10.2, §11.3). Code: `internal/repository/`,
`internal/erasure/`, `internal/pack/`, `internal/prune/`.

## Layout

```text
repository/
├── config/repository.json        # signed envelope: id, suite, chunker, pack size, default ECC
├── keys/<fingerprint>.slot       # master key sealed per member, granter-signed
├── identities/<fingerprint>.pub  # advisory public-key copies
├── revocations/<fingerprint>.rev # advisory revocation records
├── snapshots/<snapshot-id>       # one immutable object: encrypted {signed manifest}
├── packs/<pack-id>               # ~16 MiB; many AEAD chunk blobs + encrypted header
├── indexes/<index-id>            # immutable chunk-id → (pack, offset, length) maps, one per run
├── *.ecc                         # Reed-Solomon sidecar beside each pack, index, and snapshot
└── locks/                        # gc.lock (exclusive) and backup-<id> markers (shared)
```

Pack and index names are the BLAKE3 hash of their ciphertext. Each backup
run writes a new immutable index; clients merge all indexes into a local
cache (`$XDG_CACHE_HOME/petravault/<repository_id>/`, disposable and
rebuildable). Packs group chunks so 1 MiB-average data is not one S3 object
per chunk. The snapshot ID is the BLAKE3 of the signed payload bytes and
doubles as the object name.

## Local backend

`LocalRepository`: temp file in the same directory, `Sync`, `Close`,
`Rename`, then directory `Sync`. `PutObjectIfAbsent` uses `O_EXCL` as the
compare-and-swap for locks. `GetRange` seeks and reads exactly the
requested span. Addressed as a filesystem path; `Init` is idempotent.

## S3 backend

Addressed as `s3:<bucket>[/<prefix>]` (`ParseS3Address` enforces DNS bucket
rules and local prefixes). Buckets are never auto-created. `PUT` is atomic;
packs (~16 MiB) use a single `PUT`, no multipart, and objects are buffered
fully in memory during upload and download, so keep the default pack size
for S3 repositories. `PutObjectIfAbsent` uses
`If-None-Match: *` (412/409 means a lost race). `GetRange` uses inclusive
`bytes=start-end` so restore fetches one chunk without the whole pack.
`List` paginates and returns sorted keys.

Credentials use the standard AWS chain (IAM roles, env, profiles); they are
never written into manifests or logs. Routine clients get write-only keys
(`GetObject`, `PutObject`, `ListBucket`, plus `DeleteObject` only on
`locks/*`); prune and `ecc rebuild` run from a separate administrative
credential. Transport is TLS 1.3 preferred / 1.2 minimum; plaintext `http://`
is refused unless `PETRAVAULT_S3_ALLOW_HTTP=1` (local test servers only).
Enable S3 Versioning and, with care, Object Lock as defense-in-depth: Object
Lock retention must not exceed the shortest snapshot retention or prune
fails. Test endpoint override: `PETRAVAULT_TEST_S3_ENDPOINT` (plus
`AWS_ENDPOINT_URL_S3`).

## Erasure coding (`DESIGN.md` §4.5)

Default on, `medium` (5%), for local and S3. Parity is computed over
ciphertext; the object is stored unchanged and `<object>.ecc` holds parity
shards plus a BLAKE3 checksum per data shard and the `k`/`m` used. Normal
reads never touch the sidecar.

Derived from the chosen overhead with integer basis-point math
(5% = 500), never floats:

```text
m = max(1, floor(overhead × 20))
k = floor(m / overhead)
```

| Setting | Overhead | k | m | Repairs up to |
|---|---|---|---|---|
| `low` | 2% | 50 | 1 | 1 damaged shard per object |
| `medium` (default) | 5% | 20 | 1 | 1 damaged shard per object |
| `high` | 15% | 20 | 3 | 3 damaged shards per object |
| custom `7%` | 7% | 14 | 1 | 1 damaged shard per object |
| custom `25%` | 25% | 20 | 5 | 5 damaged shards per object |

Custom range is 0.5%–100% with `k + m ≤ 255`; `off` disables ECC.
Each sidecar records its own `k`/`m`, so mixed settings stay repairable.

```bash
petravault init <repo>                    # medium (5%)
petravault init <repo> --ecc high         # 15%
petravault init <repo> --ecc 8%           # custom
petravault backup <src> --ecc low         # this run's objects only
petravault ecc set high                   # new default (re-signs repository.json)
petravault ecc rebuild                    # re-protect existing objects (reads each once)
```

`ecc set` only changes the default for new objects. `ecc rebuild` repairs
(if needed), AEAD-verifies, then re-encodes — damaged data is never encoded
into fresh parity — and writes the new sidecar before replacing the old one.
Rebuilding to `off` removes sidecars. It takes `gc.lock` (no prune overlap)
while backups keep running; on S3 it needs maintenance credentials.

Repair: checksum-failed shards become known erasures, are reconstructed,
and the result is re-verified by AEAD. Beyond-budget damage is reported as
unrecoverable, never ignored. Parity covers damage within budget, not loss
of the whole object or repository.

## Lock protocol (`DESIGN.md` §10.2)

`locks/gc.lock` (exclusive: prune, `ecc rebuild`) and `locks/backup-<id>`
(one per running backup, shared). Creation via `PutObjectIfAbsent` is the
compare-and-swap. Entries record holder, host, operation, timestamps, are
heartbeat-refreshed, and expire after their TTL (default lock 10 min,
heartbeat 1 min).

Ordering is load-bearing: backup writes its marker, then checks for
`gc.lock`, then reads indexes; prune creates `gc.lock`, then lists markers
and waits (bounded, default 5 min) or aborts without deleting. Same-source
overlap is a local advisory lock on the running machine, never a network
lock. `source_id` uniqueness is the operator's job; `verify` reports forks.

## Prune and retention (`DESIGN.md` §11.3)

```bash
petravault prune --keep-daily 30 --keep-weekly 12 --keep-monthly 12 --dry-run
```

Keeps the newest snapshot of every source plus the newest per UTC
day/week/month bucket per source. All-dead packs are deleted with their
sidecars; packs ≥ 50% dead are repacked under the current pack/ECC settings;
indexes are compacted; orphans from failed backups are removed. Prune
refuses to run without at least one keep rule and never removes the newest
snapshot of any source. `--dry-run` previews without the lock or changes.

## Repository config

`config/repository.json` is a signed envelope
(`"petravault repo-config v1"`), verified against the client's trust list
before parsing. It freezes the suite, chunking algorithm + library version,
chunk sizes, pack size, and default ECC. Changing it (e.g. `ecc set`)
re-signs it; manifests naming anything else are rejected.

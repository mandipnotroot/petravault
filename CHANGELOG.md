<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Changelog

Notable changes to this project, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.html). Behavior authority
is `docs/DESIGN.md`; the section references below point at it.

## [Unreleased]

## [0.1.0] - 2026-10-14

First release: a usable CLI covering all 13 phases of `docs/DESIGN.md` §15.

### Added

- Local repositories with durable writes, ranged reads, and conditional
  create; S3-compatible backend with TLS, path-style addressing, and the
  same contract suite (§8–§9).
- Crypto foundation: BLAKE3 (plain/keyed/`derive_key`), XChaCha20-Poly1305,
  Argon2id keystore, and one derived-subkey hierarchy (§4.1, §4.4).
- Hybrid X-Wing key slots sealed per member inside granter-signed envelopes
  (`trust add --grant-read`) with pinned test vectors (§4.2).
- ML-DSA-65 signatures behind a small `Signer` interface: signed manifests,
  signed `repository.json`, signed revocations, each with its own context
  string (§4.3, §5).
- Keyed content-defined chunking (KFastCDC) with golden-boundary tests,
  keyed chunk IDs, packs, immutable per-run indexes, dedup, unchanged-file
  fast path, and excludes (§3, §8).
- Identity and direct trust: BLAKE3 fingerprints, client-pinned trust list,
  import/export, revocation; non-canonical fingerprint spellings rejected
  (§5).
- Atomic single-object snapshot commits, per-source chains with head
  records, standard and deep verification, verify-after-backup, and
  path-safe restore (§9).
- Reed-Solomon erasure coding on by default (`medium`, 5%), with `low` /
  `high` / custom profiles, `ecc set` / `ecc rebuild`, shard checksums, and
  AEAD re-verified repair (§4.5).
- Prune with retention buckets, repack, index compaction, and the
  `gc.lock` / `backup-<id>` maintenance lock protocol (§10–§11).
- Scheduling: full `schedule` command set, daemon, retry with backoff,
  catch-up, unattended unlock via password command or `0600` file (§11).
- Attack-simulation suite covering every row of the §13 table, plus the
  end-to-end demo walkthrough of the Definition of Done (§17).
- Operator docs (architecture, cryptography, threat/trust models, storage,
  unattended), contributor and security policy, CI with license and REUSE
  checks, and GPL-3.0-only REUSE compliance (§13, §15).
- Release artifacts: multi-platform binaries, `SHA256SUMS`, CycloneDX SBOM,
  and Sigstore build-provenance attestations (§13, §18).

[Unreleased]: https://github.com/mandipnotroot/petravault/compare/v0.1.0...main
[0.1.0]: https://github.com/mandipnotroot/petravault/releases/tag/v0.1.0

<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Threat Model

Authority is `DESIGN.md` §12 (with §4.6, §5.2, §9). This file restates it
for operators. Central principle (`DESIGN.md` §18): encrypt and
authenticate before untrusted storage, pin public-key identity on the
client, verify the whole chain before trusting or restoring, and build only
on maintained standard libraries.

## Attackers and mitigations

| Attacker | Capabilities | Primary mitigations |
|---|---|---|
| Malicious storage provider | read/delete/modify/replay/reorder objects | client-side XChaCha20-Poly1305, ML-DSA-65 signatures, BLAKE3, per-source snapshot chains, head records, `verify` |
| Network attacker | intercept/modify/replay, downgrade | TLS (1.3 preferred, 1.2 minimum), SigV4, application-layer AEAD, signed metadata |
| Stolen repository | full offline copy | no private keys or password verifiers in the repository; slots need a client-held KEM private key |
| Unauthorized identity | forged keypair, fake snapshots, edited repo-side keys/slots/config | client-pinned trust list, fingerprints, signature verification on snapshots, slots, and config; revocation |
| Confirmation-of-file | hashes a known file, matches chunk sizes | keyed chunk IDs, keyed chunker, IDs only inside encrypted objects |
| Corruption | bit rot, bad sectors | AEAD + BLAKE3 detection, Reed-Solomon repair (`medium` 5% default), deep verification |
| Scheduler attacker | modifies jobs, retention, destination | job files `0600` and permission-checked, strict schema, no secrets in job files, every run logged |
| Replay attacker | reintroduces old objects/snapshots | per-source chains + client-local head records, `repository_id` in every manifest, S3 Versioning/Object Lock |
| Compromised client machine | holds keys, can write, may delete history | write-only routine credentials, separate maintenance credential, S3 Versioning/Object Lock, per-machine identity that can be revoked |

Every row of `DESIGN.md` §13 has an attack test in `tests/attack/`
(tampered chunk, tampered snapshot, Mallory signer, repo-side key edits,
forged slot, config downgrade, rollback, unsafe restore paths, and more).

## What the provider can and cannot see

Sees: object sizes and counts, timing, repository structure, key-slot
fingerprints, total volume, and ranged-read access patterns during restore.
Chunk boundaries inside a pack live only in its encrypted header, so
individual chunk sizes are hidden at rest, but total volume is not.

Cannot see: plaintext contents, backup encryption keys, private signing
keys. Residual size/count/timing leakage cannot be eliminated and is a
documented limitation, not a claim.

## Incidents

- **Signing key stolen:** revoke the identity, create a replacement, add it
  to the trust store, record the revocation, keep verifying history per its
  recorded identity and policy. If the identity also held read access, treat
  the master key as exposed (`DESIGN.md` §4.6).
- **Repository completely lost:** no on-repo mechanism helps when everything
  is gone; parity covers damage within budget, not loss of the whole object
  or repository. Keep an independent secondary repository (local + S3); the
  `Repository` abstraction supports that without a second cloud provider.
- **Revocation withheld by hostile storage:** revocations are advisory in
  `revocations/` but authoritative on the client; an attacker can withhold
  one but cannot forge one, and records only add to the revoked list.

## Non-goals that stay non-goals

No key rotation or re-keying in v1: revoking a member stops new trusted
snapshots but does not un-share a master key they already held. Cutting off
read access requires a new repository with a new master key.

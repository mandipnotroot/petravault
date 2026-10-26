<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Trust Model

OpenPGP-inspired, deliberately small: local identities, BLAKE3
fingerprints, direct trust decisions, revocation (`DESIGN.md` §5).
Code: `internal/identity/`.

## Identities

An identity is a signing key (ML-DSA-65) plus a KEM key (X-Wing) plus public
metadata (name, `created_at`). The fingerprint is BLAKE3 over a
length-prefixed encoding of both public keys under
`"petravault identity v1"` (`ComputeFingerprint`). It displays as grouped
base32 for read-aloud comparison; `ParseFingerprint` also accepts 64-hex
and an optional `b3:` prefix. Non-canonical base32 spellings (differing
only in the unused trailing bits of the final character) are rejected, so
each identity has exactly one accepted spelling per form. Public files (`public.json`) are strict JSON:
unknown fields rejected, keys re-validated, fingerprint recomputed.

```bash
petravault identity create --name alice     # also self-trusts
petravault identity list
petravault identity export --output alice.pub
petravault identity import alice.pub        # then verify the fingerprint out of band
petravault identity import alice.pub --trust # same-step trust, only for your own keys on a new machine
```

Private keys live in `$XDG_DATA_HOME/petravault/identities/<fingerprint>/`
(`private.sealed` is mode `0600`); group/other-readable files are refused
at load. `Find` resolves a fingerprint or an exact name; ambiguous names
are an error.

## Direct trust only

```bash
petravault trust add <fingerprint>              # CLI shows the full fingerprint first
petravault trust add <fingerprint> --grant-access # also seals the master key to their KEM key
petravault trust list
petravault trust remove <fingerprint>
petravault trust publish   # back up your trust view to the repo (sealed, owner-only)
petravault trust recover   # rebuild a lost local store from it
```

There is no transitive trust. `trust add` loads the public keys from
`identities/<fingerprint>.pub` or an imported `.pub` file and accepts them
only when their hash equals the confirmed fingerprint, so the repository
copy is safe to use. `trust sync` lists those repo copies (fingerprint,
escaped name, slot, local state) for discovery, and `trust sync <fingerprint>`
approves one with the same hash check — the typed fingerprint is the
explicit decision. A new member must trust the granting identity before
their client opens a key slot or the repository config that identity signed.
Names are advisory metadata and are quoted in terminal output; always verify
the full fingerprint out of band before approval.

## Trust anchors live on the client

Authoritative trust is `$XDG_CONFIG_HOME/petravault/trust/{trusted-keys/*.json,revoked/*.rev}`.
Repository copies (`identities/`, `revocations/`) are advisory. A snapshot
is accepted only when its signer is in the local trust list and not in the
local revoked list. Mallory editing the repository-side copies changes
nothing on a client that never trusted her.

## Revocation

```bash
petravault trust revoke <fingerprint> --reason "..."
```

Records (`fingerprint`, `reason`, `created_at`, signature under
`"petravault revocation v1"`) are signed by another trusted identity or by
the key itself. They immediately disqualify new signatures; history follows
the recorded policy. Published copies in `revocations/` are verified against
the local trust list before use, and records only add to the revoked list,
never remove. A hostile repository can withhold a revocation but cannot
forge one.

## Trust backup

`publish` snapshots your `trusted-keys/` plus `revoked/` records into
`trust-lists/<your-fingerprint>.json`, sealed so only you open it and
signed by you. `recover` asks your password, verifies that signature,
opens the seal, and restores both, so a wiped client comes back without
repeating every fingerprint check. It reports the snapshot's age:
re-publish after every trust change, re-confirm revocations with the team
when it looks old, and let the next `verify` re-learn heads.
Exports include tombstones even after their target is removed from active
trust. Both recovery paths validate all identities and revocations before
granting authority, then write revocations before trusted keys. In particular,
an unavailable historical revocation signer causes a fail-closed import, not
a partial trust grant that omits the disqualification.

## Member roster

`members publish` (usually the granter) seals the non-revoked membership
under the repository key at `members.json`. A new machine with one trusted
granter runs `members sync` and adopts the rest in one explicit step —
no per-member checks to repeat. The roster never grants access by itself;
slots do. Re-publish it on every membership change.

## Offline bundle

`recovery export --output /mnt/usb/alice.recovery` writes one encrypted
file: your identity and trust view. `recovery import` restores both and
proves both passwords by unlocking. The bundle holds no head records, so
a recovered client re-learns rollback history on its next verify or
backup — deletions made while it was wiped are undetectable, and the
first post-recovery verify is trust-on-first-use. One file, same
password, USB drawer.

## Key slots and config

Each `keys/<fingerprint>.slot` is an HPKE-sealed master key inside a
granter-signed envelope (`"petravault slot-grant v1"`). `OpenSlotTrusted`
resolves the granter through the caller's own trust lookup; the embedded
hint is never trusted. `config/repository.json` is likewise a signed
envelope (`"petravault repo-config v1"`); clients refuse configs with an
invalid or untrusted signature, and refuse manifests naming any other suite
or chunking algorithm, so a hostile repository cannot downgrade parameters.
A config signed by a revoked or removed identity is also refused. There is no
safe recovery command for that config in the current CLI: `ecc set` verifies
the existing config before changing it and fails closed too. Do not restore
revoked trust to bypass this check.

## Limitations

A verified fingerprint never proves the real-world identity behind it; that
binding is the initial human check (in person, secure channel, printed
fingerprint), which is why the CLI always shows full fingerprints.
Revocation stops new trust but does not un-share a master key
(`DESIGN.md` §4.6).

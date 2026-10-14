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
and an optional `b3:` prefix. Public files (`public.json`) are strict JSON:
unknown fields rejected, keys re-validated, fingerprint recomputed.

```bash
petravault identity create --name alice     # also self-trusts
petravault identity list
petravault identity export --output alice.pub
petravault identity import alice.pub        # then verify the fingerprint out of band
```

Private keys live in `$XDG_DATA_HOME/petravault/identities/<fingerprint>/`
(`private.sealed` is mode `0600`); group/other-readable files are refused
at load. `Find` resolves a fingerprint or an exact name; ambiguous names
are an error.

## Direct trust only

```bash
petravault trust add <fingerprint>              # CLI shows the full fingerprint first
petravault trust add <fingerprint> --grant-read # also seals the master key to their KEM key
petravault trust list
petravault trust remove <fingerprint>
```

There is no transitive trust. `trust add` loads the public keys from
`identities/<fingerprint>.pub` or an imported `.pub` file and accepts them
only when their hash equals the confirmed fingerprint, so the repository
copy is safe to use. A new member must trust the granting identity before
their client opens a key slot or the repository config that identity signed.

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

## Key slots and config

Each `keys/<fingerprint>.slot` is an HPKE-sealed master key inside a
granter-signed envelope (`"petravault slot-grant v1"`). `OpenSlotTrusted`
resolves the granter through the caller's own trust lookup; the embedded
hint is never trusted. `config/repository.json` is likewise a signed
envelope (`"petravault repo-config v1"`); clients refuse configs with an
invalid or untrusted signature, and refuse manifests naming any other suite
or chunking algorithm, so a hostile repository cannot downgrade parameters.

## Limitations

A verified fingerprint never proves the real-world identity behind it; that
binding is the initial human check (in person, secure channel, printed
fingerprint), which is why the CLI always shows full fingerprints.
Revocation stops new trust but does not un-share a master key
(`DESIGN.md` §4.6).

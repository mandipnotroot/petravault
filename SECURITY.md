<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Security Policy

Threat model: `docs/DESIGN.md` §12. Cryptography: `docs/DESIGN.md` §4.
Petravault's rule is: encrypt and authenticate before untrusted storage,
client-pinned identity for metadata, verify the chain before restore —
never hand-rolled primitives (`docs/DESIGN.md` §6, §18).

## Supported versions

`main` and versioned `v*` releases are supported. Tagged releases ship
binaries with `SHA256SUMS`, a Sigstore build-provenance attestation, and a
CycloneDX SBOM (see `.github/workflows/release.yml`). Verify a binary with
`gh attestation verify <binary> --repo <owner>/<repo>`, then check it
against `SHA256SUMS`. Reports against `main` are
welcome; include the commit SHA you tested. Reports against a release
should name its tag.

## Reporting a vulnerability

- **Do not** open a public issue for a suspected vulnerability.
- Use GitHub → Security tab → **Report a vulnerability** (private) on this
  repository, so details stay hidden until a fix is ready.
- Include: affected commit/version, steps to reproduce, impact
  (confidentiality / integrity / availability), and whether exploit code exists.

## Scope notes

- In scope: repo code and design (crypto composition, trust, restore safety,
  scheduler, storage backends).
- Out of scope for reports: the PQC primitives themselves (report upstream /
  to standards bodies), and non-security bugs (use normal issues).

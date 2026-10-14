<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Petravault — Secure Incremental Backup CLI

[![ci](https://github.com/mandipnotroot/petravault/actions/workflows/ci.yml/badge.svg)](https://github.com/mandipnotroot/petravault/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/mandipnotroot/petravault)](https://github.com/mandipnotroot/petravault/releases)
[![license](https://img.shields.io/badge/License-GPL--3.0--only-blue.svg)](LICENSE)

Secure, incremental, content-addressed backup with hybrid classical/post-quantum
key protection, signed snapshots, tamper detection, Reed-Solomon erasure coding,
built-in scheduling, and verification. Local filesystem + S3-compatible storage.

Status: **usable CLI**. Phases 1–13 per `docs/DESIGN.md` §15 are
implemented (local + S3 repositories, crypto, chunking, identity/trust,
signed snapshots, key slots, erasure coding, restore/verify, prune,
scheduling, attack suite, operator guides, demo).

## Docs

- Design/behavior (authority): `docs/DESIGN.md`
- Architecture: `docs/architecture.md`
- Cryptography: `docs/cryptography.md`
- Threat model: `docs/threat-model.md`
- Trust model: `docs/trust-model.md`
- Storage (local/S3, erasure coding, locks, prune): `docs/storage.md`
- Unattended backups (schedule, unlock, retention): `docs/unattended.md`
- Go rules: `docs/GO_GUIDELINES.md`
- Commits: `docs/COMMIT_GUIDE.md`
- Agent entrypoint: `AGENTS.md`
- Contributing: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Changelog: `CHANGELOG.md`

## Prerequisites

- Go 1.27+ (`go version`)
- `pipx` (for the REUSE tool) + Node.js `npx` (for the Go-guidelines skill)

See `CONTRIBUTING.md` for install commands.

## Quickstart (local repository)

```bash
petravault identity create --name alice
petravault init /tmp/pv-repo --ecc medium
petravault backup ~/Documents -r /tmp/pv-repo
petravault snapshots list -r /tmp/pv-repo
petravault verify -r /tmp/pv-repo
petravault restore <snapshot-id> /tmp/pv-restore -r /tmp/pv-repo
petravault prune --keep-daily 30 --keep-weekly 12 --keep-monthly 12 -r /tmp/pv-repo
```

S3 repositories are addressed as `s3:<bucket>[/<prefix>]` (see
`docs/storage.md`); scheduled runs are covered in `docs/unattended.md`.
Exit codes: `0` ok, `1` error, `2` usage, `3` warnings, `4`
integrity/trust failure.

## Demo

```bash
make demo    # end-to-end Definition of Done walkthrough (docs/DESIGN.md §17)
```

Runs `demo/demo.sh`: identity → init → backup → incremental backup →
schedule → verify → second member → concurrent backups → erasure-coding
maintenance and fault injection → tamper/rollback/unauthorized-signer
detection → prune → byte-identical restore. All state is isolated under a
temporary workspace that is removed on success (see `demo/README.md`).

## Common commands

```bash
make check   # fmt, vet, lint, test, build, vuln, license, reuse — run before every PR
make test    # go test -race -shuffle=on ./...
make build   # CGO_ENABLED=0 go build -trimpath -o bin/petravault ./cmd/petravault
make reuse   # reuse lint (REUSE compliance)
```

## License

GPL-3.0-only. The repository is [REUSE](https://reuse.software/) compliant:
every file carries `SPDX-FileCopyrightText:` + `SPDX-License-Identifier:`,
license texts live in `LICENSES/`, and `reuse lint` is clean in CI.

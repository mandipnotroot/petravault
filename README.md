<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Petravault — Secure Incremental Backup CLI

Secure, incremental, content-addressed backup with hybrid classical/post-quantum
key protection, signed snapshots, tamper detection, Reed-Solomon erasure coding,
built-in scheduling, and verification. Local filesystem + S3-compatible storage.

Status: **usable CLI**. Phases 1–12 per `docs/DESIGN.md` §15 are
implemented (local + S3 repositories, crypto, chunking, identity/trust,
signed snapshots, key slots, erasure coding, restore/verify, prune,
scheduling, attack suite); this phase adds the operator guides below.

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
